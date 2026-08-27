package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// The same loss as local_solve_transition_test.go, one level up: through the
// command an operator actually runs.
//
// Those tests call the transition's helpers directly, so they say what each
// half of it does. They cannot say when `twinet deploy` calls them, and the
// loss was entirely a matter of when: the preservation ran after the first
// reference command in one arrangement and the prune ran after a plan that
// might never finish in another, and no helper is wrong in either. What is
// asserted here is therefore the order the shipped command performs a solve
// transition in --
//
//	settle what a retry may remove   (before anything else can change)
//	preserve every desired device and every prune candidate
//	write the marker that says the lab may hold the answer
//	the first reference command
//	prune exactly what was preserved, reading nothing
//	record the finished mode and forget the record, in that order
//
// -- across two processes, because the process that preserves a container is
// not necessarily the process that removes it.
//
// Two things are supplied where a machine would supply them: the container
// engine, in place of the one a manifest names, and the deployment DAG.
// Building that DAG is internal/deploy's own tested job, and executing a real
// one wants a container engine, a privileged namespace and the agent's /run
// state, none of which a decision about order depends on. Everything else here
// is the shipped command: its flags, its manifest, its placement, its mode
// markers, its refusals and its output.

const (
	// A lab name no live lab can carry: the prune this drives reaches the
	// host's own overlay objects, and it must never find another lab's.
	commandLabName = "local-solve-transition-command"
	commandNode    = "solve-transition-node"
	// The backend's name is load-bearing. Anything called docker, podman or
	// containerd takes the split-privilege FRR sidecar path, which wants host
	// directories a test has no business creating, so the engine supplied here
	// reports a name of its own.
	commandRuntimeName = "solve-transition-fake"
	// The container the manifest no longer wants, holding the only copy of
	// what the group that owned it configured.
	commandStaleContainer = "twinet-" + commandLabName + "-as3-old"
	commandStaleDevice    = "as3/OLD"
)

// commandLabManifest is a single-node lab with two student routers and their
// hosts. It is deliberately small: what is under test is the order of a
// transition, not a topology.
const commandLabManifest = `apiVersion: twinet.dev/v1
kind: Lab
metadata:
  name: ` + commandLabName + `
images:
  mode: development
kinds:
  router: {image: twinet-test/router:fixture}
  host: {image: twinet-test/host:fixture}
addressing:
  as_block: "{{ .AS }}.0.0.0/8"
  router_router: "{{ .AS }}.0.{{ .LinkIndex }}.0/24"
  router_host: "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24"
  router_loopback: "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24"
  inter_as: "179.{{ .Low }}.{{ .High }}.0/24"
templates:
  pair:
    routers:
      ATL: {id: 1}
      BOS: {id: 2}
    internal_links:
      - {a: ATL, b: BOS}
autonomous_systems:
  - list: [3]
    template: pair
    role: student
placement:
  strategy: single-node
  runtime: docker
  nodes:
    - {name: ` + commandNode + `, front: true}
`

// commandSolveRuntime is the container engine the command talks to: the
// devices the manifest places here, one container it has forgotten, and the
// contents of each under the test's control.
//
// It records what was read as well as what was removed. A prune finishing an
// interrupted solve must remove the stale container without reading it, and
// "did not read it" is only checkable if the reads are counted.
type commandSolveRuntime struct {
	rt.Runtime
	mu         sync.Mutex
	containers map[string]rt.Container
	config     map[string]string
	read       []string
	removed    []string
}

func newCommandSolveRuntime() *commandSolveRuntime {
	return &commandSolveRuntime{
		containers: map[string]rt.Container{},
		config:     map[string]string{},
	}
}

func (r *commandSolveRuntime) Name() string { return commandRuntimeName }

func (r *commandSolveRuntime) Ping(context.Context) (string, error) {
	return "fake", nil
}

func (r *commandSolveRuntime) Close() error { return nil }

// ImageDigest answers the pre-deployment image survey. A single-node lab asks
// its own engine, so a backend that cannot answer it never reaches the
// transition this file is about.
func (r *commandSolveRuntime) ImageDigest(_ context.Context, ref string) (string, error) {
	return fmt.Sprintf("sha256:%064x", len(ref)), nil
}

func (r *commandSolveRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []rt.Container
	for _, c := range r.containers {
		out = append(out, c)
	}
	return out, nil
}

func (r *commandSolveRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.containers[name]
	if !ok {
		return rt.Container{Name: name, State: rt.StateAbsent}, nil
	}
	return c, nil
}

// Exec records every command run in a container, not only the ones that come
// back with something. A deployment finishing an interrupted solve must not
// enter a container at all, and a reading it decided to discard is still a
// reading it took.
func (r *commandSolveRuntime) Exec(_ context.Context, name string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.read = append(r.read, name)
	switch {
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "test":
		// Nothing owes a restore here, so the capture is never asked to
		// withhold what it read.
		return rt.ExecResult{ExitCode: 1}, nil
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh":
		return rt.ExecResult{Stdout: r.config[name]}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *commandSolveRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.containers, name)
	r.removed = append(r.removed, name)
	return nil
}

func (r *commandSolveRuntime) add(container, device string, kind model.DeviceKind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers[container] = rt.Container{
		Name: container, State: rt.StateRunning,
		Labels: map[string]string{
			deploy.LabelLab: commandLabName, deploy.LabelNode: commandNode,
			deploy.LabelDeviceID: device, deploy.LabelKind: string(kind),
		},
	}
}

func (r *commandSolveRuntime) setConfig(container, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config[container] = body
}

// relabel is a container rebuilt under a name something else already used: the
// object is the same, what it carries is not.
func (r *commandSolveRuntime) relabel(container, key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.containers[container]
	labels := map[string]string{}
	for k, v := range c.Labels {
		labels[k] = v
	}
	labels[key] = value
	c.Labels = labels
	r.containers[container] = c
}

func (r *commandSolveRuntime) wasRemoved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.removed...)
}

func (r *commandSolveRuntime) wasRead() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.read...)
}

// forget drops what has been recorded so far, so one process's reads and
// removals are not read as the next one's.
func (r *commandSolveRuntime) forget() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.read, r.removed = nil, nil
}

// The engine a deployment talks to is supplied where a machine's own engine
// would be. The lab names a real backend, as every lab must; what a test may
// not do is add one to the registry the shipped documentation is checked
// against.
func selectCommandRuntime(t *testing.T, backend *commandSolveRuntime) {
	t.Helper()
	original := localDeployRuntime
	t.Cleanup(func() { localDeployRuntime = original })
	localDeployRuntime = func(*model.Topology) (rt.Runtime, error) { return backend, nil }
}

// commandLab is one lab on disk, its engine, and the state store the command
// will keep beside the manifest.
type commandLab struct {
	dir     string
	top     *model.Topology
	store   *state.Store
	backend *commandSolveRuntime
	routers []string
}

func newCommandLab(t *testing.T) *commandLab {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "twinet.yaml"),
		[]byte(commandLabManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	// The manifest is read once here for the container names, the node and the
	// topology hash the command will derive for itself. Nothing about the
	// transition is decided from it.
	top, err := loadAndPlace(&Options{Manifest: dir})
	if err != nil {
		t.Fatalf("the fixture manifest does not load: %v", err)
	}
	if node := localNode(top); node != commandNode {
		t.Fatalf("the fixture lab is placed on node %q, want %q", node, commandNode)
	}
	backend := newCommandSolveRuntime()
	lab := &commandLab{dir: dir, top: top, backend: backend}
	for _, d := range top.SortedDevices() {
		backend.add(d.Container, d.ID, d.Kind)
		if d.Kind == model.KindRouter {
			backend.setConfig(d.Container, commandStudentWork(d.ID))
			lab.routers = append(lab.routers, d.ID)
		}
	}
	// The autonomous system a course dropped: gone from the manifest, still
	// running, and holding the only copy of what its group configured.
	backend.add(commandStaleContainer, commandStaleDevice, model.KindRouter)
	backend.setConfig(commandStaleContainer, studentWork)
	selectCommandRuntime(t, backend)
	store, err := localStore(top)
	if err != nil {
		t.Fatal(err)
	}
	lab.store = store
	return lab
}

// commandStudentWork is what a group left on one of the devices the manifest
// still places here. Each device's is distinguishable, so a snapshot filed
// under the wrong identifier is visible rather than merely equal.
func commandStudentWork(device string) string {
	return fmt.Sprintf("router ospf\n network 3.0.9.0/24 area 0\n exit\n! %s\n", device)
}

// stored is what the state store would replay into a device. It never fails
// the test itself: it is read from inside the deployment's own workers as well
// as from the test, and what it returns is asserted either way.
func (l *commandLab) stored(device string) string {
	snap, err := l.store.Current(commandLabName, device, state.KindFRR)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("unreadable: %v", err)
	}
	return string(snap.Content)
}

func (l *commandLab) transition(t *testing.T) *localSolveTransition {
	t.Helper()
	record, err := readSolveTransition(l.top)
	if err != nil {
		t.Fatalf("read what the interrupted solve preserved: %v", err)
	}
	return record
}

// deployRun executes the real command tree and returns what a person would
// see. Every invocation is a separate process as far as the transition is
// concerned: nothing is carried over but the lab's own directory and the
// containers on the engine.
func deployRun(t *testing.T, dir string, args ...string) (out, errOut string, err error) {
	t.Helper()
	// The persistent flags take their defaults from the environment, and a
	// developer with TWINET_RUNTIME set would otherwise pick the engine.
	t.Setenv("TWINET_RUNTIME", "")
	t.Setenv("TWINET_RUNTIME_SOCKET", "")
	root := Root()
	var stdout, stderr strings.Builder
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"-m", dir}, args...))
	err = root.Execute()
	return stdout.String(), stderr.String(), err
}

// injectedPlan is the deployment DAG one run of the command executes, and what
// the steps of it observed about the lab at the moment they ran.
type injectedPlan struct {
	mu sync.Mutex
	// builds counts how many times the command asked for a plan at all. A
	// refusal that has already happened is a refusal that cost nothing: the
	// deployment had not yet built, let alone executed, anything.
	builds int
	// engines records how the command wired the deployment engine each time.
	engines []engineWiring
	// preserved is what the lab's durable state said at the moment the first
	// reference command ran.
	preserved []preservedAtMutation
}

// engineWiring is how the command wired the deployment engine: the few fields
// that decide what a transition may read, write and replay.
type engineWiring struct {
	previousMode        string
	writesReference     bool
	forceStudentReset   bool
	restoreStudentState bool
}

// preservedAtMutation is the lab as the first reference command found it.
type preservedAtMutation struct {
	mode     string
	record   *localSolveTransition
	stored   map[string]string
	removals []string
}

func (p *injectedPlan) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.builds
}

func (p *injectedPlan) engine(t *testing.T, i int) engineWiring {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.engines) {
		t.Fatalf("the command built %d plans, want at least %d", len(p.engines), i+1)
	}
	return p.engines[i]
}

func (p *injectedPlan) atFirstReference(t *testing.T) preservedAtMutation {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.preserved) == 0 {
		t.Fatal("no reference command ran, so nothing observed what preceded it")
	}
	return p.preserved[0]
}

// observe records what the lab's durable state says at the instant a reference
// command is about to write the answer over a device. It runs in the
// deployment's own worker, so it records rather than asserts.
func (p *injectedPlan) observe(lab *commandLab) {
	seen := preservedAtMutation{
		mode: labModeRecord(lab.top), stored: map[string]string{},
		removals: lab.backend.wasRemoved(),
	}
	record, err := readSolveTransition(lab.top)
	if err == nil {
		seen.record = record
	}
	for _, device := range append(append([]string(nil), lab.routers...), commandStaleDevice) {
		seen.stored[device] = lab.stored(device)
	}
	p.mu.Lock()
	p.preserved = append(p.preserved, seen)
	p.mu.Unlock()
}

// stubLocalPlan replaces the deployment DAG for the rest of the test.
func stubLocalPlan(t *testing.T, build func(*deploy.Engine, *model.Topology) (*plan.Plan, error)) *injectedPlan {
	t.Helper()
	original := buildLocalDeployPlan
	t.Cleanup(func() { buildLocalDeployPlan = original })
	injected := &injectedPlan{}
	buildLocalDeployPlan = func(eng *deploy.Engine, top *model.Topology) (*plan.Plan, error) {
		injected.mu.Lock()
		injected.builds++
		injected.engines = append(injected.engines, engineWiring{
			previousMode:        eng.PreviousMode,
			writesReference:     eng.WritesReference,
			forceStudentReset:   eng.ForceStudentReset,
			restoreStudentState: eng.RestoreStudentState,
		})
		injected.mu.Unlock()
		return build(eng, top)
	}
	return injected
}

// interruptedSolve is the first attempt: the reference solution reaches one
// router and the deployment then fails, exactly as a process killed part way
// through leaves the lab.
func interruptedSolve(t *testing.T, lab *commandLab) *injectedPlan {
	t.Helper()
	var injected *injectedPlan
	injected = stubLocalPlan(t, func(_ *deploy.Engine, top *model.Topology) (*plan.Plan, error) {
		p := plan.New()
		first := top.SortedDevices()[0]
		p.Add(&plan.Step{
			ID: "configure:" + first.ID, Stage: plan.StageConfigure, Scope: "as=3",
			Describe: "install the reference solution on " + first.ID,
			Run: func(context.Context) error {
				// The first destructive act of the transition. Everything it
				// may destroy has to be saved and written down by now, because
				// after this line nothing in the lab can be read as a
				// student's work again.
				injected.observe(lab)
				lab.backend.setConfig(first.Container, referenceAnswer)
				return nil
			},
		})
		p.Add(&plan.Step{
			ID: "configure:interrupted", Stage: plan.StageConfigure, Scope: "as=3",
			Describe: "install the reference solution on the rest",
			Needs:    []string{"configure:" + first.ID},
			Run: func(context.Context) error {
				return errors.New("the deployment was interrupted part way through")
			},
		})
		return p, nil
	})
	return injected
}

// The whole sequence, through the command: `deploy --solve --prune` fails part
// way, and a second process finishes it. The stale container must survive the
// first attempt with its contents saved, and be removed by the second without
// the second ever reading it.
func TestTheDeployCommandFinishesAnInterruptedSolveWithoutLosingAStaleContainer(t *testing.T) {
	lab := newCommandLab(t)
	first := interruptedSolve(t, lab)

	out, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune")
	if err == nil {
		t.Fatalf("a solve whose plan failed part way reported success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "degraded") {
		t.Fatalf("the interrupted solve failed with an unexpected error: %v", err)
	}

	// What the lab looked like at the instant the answer was first written.
	before := first.atFirstReference(t)
	if before.mode != localModeSolvePending {
		t.Errorf("the lab was marked %q when the first reference command ran; a retry or a "+
			"destroy would read a lab that may hold the answer as the students' own",
			before.mode)
	}
	for _, device := range lab.routers {
		if before.stored[device] != commandStudentWork(device) {
			t.Errorf("the work on %s was %q in the store when the reference solution was "+
				"first written; the devices the manifest still wants must be captured first",
				device, before.stored[device])
		}
	}
	if before.stored[commandStaleDevice] != studentWork {
		t.Fatalf("the stale container's work was %q in the store when the reference solution "+
			"was first written.\nThe prune that would have saved it runs after the plan, so a "+
			"plan that fails leaves nothing behind and the retry deletes a container nothing "+
			"ever read.", before.stored[commandStaleDevice])
	}
	if before.record == nil || len(before.record.Preserved) != 1 ||
		before.record.Preserved[0].Container != commandStaleContainer ||
		!before.record.Preserved[0].Stored || !before.record.Prune {
		t.Fatalf("what the transition preserved was recorded as %+v when the first reference "+
			"command ran; a second process has nothing else to go on", before.record)
	}
	if len(before.removals) != 0 {
		t.Errorf("the transition had already removed %v before it wrote anything",
			before.removals)
	}
	if removed := lab.backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("the interrupted deployment removed %v; its prune never ran", removed)
	}
	if labModeRecord(lab.top) != localModeSolvePending {
		t.Fatalf("an interrupted solve left the lab marked %q", labModeRecord(lab.top))
	}

	// The retry is a different process. What it may do comes off disk, and the
	// lab may hold the answer by now -- including, as far as anything can
	// tell, the stale container.
	preserved := lab.transition(t)
	lab.backend.setConfig(commandStaleContainer, referenceAnswer)
	lab.backend.forget()
	var second *injectedPlan
	second = stubLocalPlan(t, func(_ *deploy.Engine, top *model.Topology) (*plan.Plan, error) {
		p := plan.New()
		p.Add(&plan.Step{
			ID: "configure:rest", Stage: plan.StageConfigure, Scope: "as=3",
			Describe: "finish installing the reference solution",
			Run: func(context.Context) error {
				// Whatever this run was entitled to remove was settled before
				// it got here, by exactly one of the two things that can
				// produce it.
				second.observe(lab)
				for _, d := range top.SortedDevices() {
					lab.backend.setConfig(d.Container, referenceAnswer)
				}
				return nil
			},
		})
		return p, nil
	})

	out, _, err = deployRun(t, lab.dir, "deploy", "--solve", "--prune")
	if err != nil {
		t.Fatalf("a retry refused to finish the transition its own first attempt "+
			"recorded: %v", err)
	}
	// A retry that preserved again would have overwritten this with a reading
	// of a lab that may hold the answer, and the record is the only evidence
	// of what the first attempt proved it could remove.
	if during := second.atFirstReference(t).record; during == nil ||
		!during.Recorded.Equal(preserved.Recorded) ||
		fmt.Sprint(during.Preserved) != fmt.Sprint(preserved.Preserved) {
		t.Fatalf("the retry rewrote what was preserved: %+v, want the first attempt's %+v",
			during, preserved)
	}
	if removed := lab.backend.wasRemoved(); len(removed) != 1 ||
		removed[0] != commandStaleContainer {
		t.Fatalf("the retry removed %v, want exactly the container the first attempt "+
			"preserved", removed)
	}
	if read := lab.backend.wasRead(); len(read) != 0 {
		t.Fatalf("the retry read %v. A deployment finishing a solve must read nothing: what "+
			"is in a container now may be the reference answer, and filing that as a group's "+
			"work is the same loss by the other route.", read)
	}
	if got := lab.stored(commandStaleDevice); got != studentWork {
		t.Fatalf("the saved state of the removed container is %q, want the group's work", got)
	}
	for _, device := range lab.routers {
		if got := lab.stored(device); got != commandStudentWork(device) {
			t.Fatalf("the saved state of %s is %q after the retry; the answer was filed as "+
				"the group's work", device, got)
		}
	}
	if !strings.Contains(out, "pruned 1 stale container") {
		t.Errorf("the retry did not report what it removed:\n%s", out)
	}
	if mode := labModeRecord(lab.top); mode != string(render.ModeSolve) {
		t.Fatalf("the finished solve is recorded as %q, so the next deployment would still "+
			"think a transition is pending", mode)
	}
	if record := lab.transition(t); record != nil {
		t.Fatalf("a finished transition still claims to be pending: %+v", record)
	}

	// The two things that can hand a deployment permission to remove a
	// container are the preservation and the resume gate, and a lab must never
	// be in a state where both run: the first attempt found a lab in teaching
	// mode and preserved, the retry found one that may hold the answer and
	// read what that attempt left. A retry that also preserved would capture
	// the answer as the group's work on its way past.
	if opening := first.engine(t, 0); opening.previousMode != string(render.ModePlatform) {
		t.Errorf("the interrupted attempt deployed with previous=%q; it is the attempt that "+
			"preserves, so it must be the one that found a lab still in teaching mode",
			opening.previousMode)
	}
	engine := second.engine(t, 0)
	if engine.previousMode != string(render.ModeSolve) || engine.forceStudentReset ||
		!engine.writesReference {
		t.Fatalf("the retry deployed with previous=%q reset=%t writes-reference=%t; a lab "+
			"whose solve was interrupted is one that may already hold the answer",
			engine.previousMode, engine.forceStudentReset, engine.writesReference)
	}
}

// The gate is a decision about what may be destroyed, so it happens before the
// deployment builds or executes anything. Each of these is a lab where the
// preserved copies cannot be shown to be the containers in front of the retry,
// and each must end with the container still there, the lab still marked as
// mid-transition, and the record still on disk for whoever fixes it.
func TestTheDeployCommandSettlesAResumedPruneBeforeItChangesAnything(t *testing.T) {
	cases := []struct {
		what    string
		prepare func(*testing.T, *commandLab)
		first   []string
		says    string
	}{
		{
			what: "the record of what was preserved is gone",
			prepare: func(t *testing.T, lab *commandLab) {
				t.Helper()
				if err := os.Remove(filepath.Join(labPrivateDir(lab.top),
					localTransitionFile)); err != nil {
					t.Fatal(err)
				}
			},
			first: []string{"deploy", "--solve", "--prune"},
			says:  "no record of what",
		},
		{
			what: "the record cannot be read",
			prepare: func(t *testing.T, lab *commandLab) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(labPrivateDir(lab.top),
					localTransitionFile), []byte("{not json"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			first: []string{"deploy", "--solve", "--prune"},
			says:  "could not be read",
		},
		{
			what: "the manifest changed between the attempts",
			prepare: func(t *testing.T, lab *commandLab) {
				t.Helper()
				edited := strings.Replace(commandLabManifest,
					"      BOS: {id: 2}", "      BOS: {id: 2}\n      HOU: {id: 3}", 1)
				if edited == commandLabManifest {
					t.Fatal("the fixture manifest could not be edited")
				}
				if err := os.WriteFile(filepath.Join(lab.dir, "twinet.yaml"),
					[]byte(edited), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			first: []string{"deploy", "--solve", "--prune"},
			says:  "manifest has changed",
		},
		{
			what:    "the interrupted attempt was never asked to prune",
			prepare: func(*testing.T, *commandLab) {},
			first:   []string{"deploy", "--solve"},
			says:    "not asked to prune",
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			lab := newCommandLab(t)
			interruptedSolve(t, lab)
			if _, _, err := deployRun(t, lab.dir, c.first...); err == nil {
				t.Fatal("a solve whose plan failed part way reported success")
			}
			c.prepare(t, lab)
			lab.backend.forget()

			retry := stubLocalPlan(t, func(*deploy.Engine, *model.Topology) (*plan.Plan, error) {
				t.Error("the deployment built a plan before it had settled what its prune " +
					"was entitled to remove; by the time that is discovered the lab has " +
					"already been changed")
				return plan.New(), nil
			})
			out, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune")
			if err == nil {
				t.Fatalf("a retry pruned a container it could not prove had ever been "+
					"read:\n%s", out)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the refusal does not say %q: %v", c.says, err)
			}
			if !strings.Contains(err.Error(), "twinet deploy") {
				t.Errorf("the refusal does not say what to do instead: %v", err)
			}
			if retry.count() != 0 {
				t.Errorf("the command built %d plans before refusing", retry.count())
			}
			if removed := lab.backend.wasRemoved(); len(removed) != 0 {
				t.Errorf("a refused retry removed %v", removed)
			}
			if read := lab.backend.wasRead(); len(read) != 0 {
				t.Errorf("a refused retry read %v", read)
			}
			if out != "" && strings.Contains(out, "pruned") {
				t.Errorf("a refused retry reported a prune:\n%s", out)
			}
			// A refusal is not an outcome: the lab is still mid-transition,
			// and the next command must still be able to finish it.
			if mode := labModeRecord(lab.top); mode != localModeSolvePending {
				t.Errorf("a refused retry left the lab marked %q", mode)
			}
		})
	}
}

// A resumed prune may remove exactly the containers its record names, and it
// cannot read anything to check. So a candidate the record does not cover
// stops the whole prune -- and the command must leave the lab mid-transition
// when it does, or the next attempt would have no record left to finish with.
func TestAResumedPruneRemovesOnlyTheContainersItsRecordNames(t *testing.T) {
	cases := []struct {
		what    string
		appears func(*commandSolveRuntime)
		names   string
	}{
		{
			what: "a container appeared after the preservation",
			appears: func(backend *commandSolveRuntime) {
				// A leftover of the interrupted deployment, or a device a
				// student was working in. Nothing read what is in it.
				backend.add("twinet-"+commandLabName+"-as3-newer", "as3/NEW", model.KindRouter)
				backend.setConfig("twinet-"+commandLabName+"-as3-newer", studentWork)
			},
			names: "as3-newer",
		},
		{
			what: "a preserved container now carries another device",
			appears: func(backend *commandSolveRuntime) {
				// Same container name, rebuilt for something else: the
				// preserved copy is not this container's.
				backend.relabel(commandStaleContainer, deploy.LabelDeviceID, "as4/OLD")
			},
			names: "as4/OLD",
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			lab := newCommandLab(t)
			interruptedSolve(t, lab)
			if _, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune"); err == nil {
				t.Fatal("a solve whose plan failed part way reported success")
			}
			c.appears(lab.backend)
			lab.backend.setConfig(commandStaleContainer, referenceAnswer)
			lab.backend.forget()

			stubLocalPlan(t, func(*deploy.Engine, *model.Topology) (*plan.Plan, error) {
				return plan.New(), nil
			})
			out, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune")
			if err == nil {
				t.Fatalf("the retry removed a container nothing had ever read:\n%s", out)
			}
			if !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal does not name what stopped it: %v", err)
			}
			if removed := lab.backend.wasRemoved(); len(removed) != 0 {
				t.Fatalf("the retry removed %v; one candidate it cannot account for stops "+
					"the whole prune", removed)
			}
			if read := lab.backend.wasRead(); len(read) != 0 {
				t.Errorf("the retry read %v while the lab may hold the answer", read)
			}
			// The deployment did not finish, so the lab is still mid-transition
			// and still has the record whoever fixes this needs.
			if mode := labModeRecord(lab.top); mode != localModeSolvePending {
				t.Fatalf("a refused prune left the lab marked %q", mode)
			}
			record := lab.transition(t)
			if record == nil || len(record.Preserved) != 1 ||
				record.Preserved[0].Container != commandStaleContainer {
				t.Fatalf("a refused prune left the record as %+v; the retry that finishes "+
					"this has nothing else to go on", record)
			}
		})
	}
}

// The way back is a platform deployment, and it must remain available while a
// transition is pending: the students' work is on disk, and this is the
// command that replays it.
func TestThePlatformDeploymentFinishesAPendingSolveAndPutsTheWorkBack(t *testing.T) {
	lab := newCommandLab(t)
	interruptedSolve(t, lab)
	if _, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune"); err == nil {
		t.Fatal("a solve whose plan failed part way reported success")
	}
	lab.backend.setConfig(commandStaleContainer, referenceAnswer)
	lab.backend.forget()

	back := stubLocalPlan(t, func(*deploy.Engine, *model.Topology) (*plan.Plan, error) {
		return plan.New(), nil
	})
	out, _, err := deployRun(t, lab.dir, "deploy", "--prune")
	if err != nil {
		t.Fatalf("returning a lab with a pending solve to teaching mode refused: %v", err)
	}
	engine := back.engine(t, 0)
	if !engine.forceStudentReset || !engine.restoreStudentState ||
		engine.previousMode != string(render.ModeSolve) {
		t.Fatalf("the way back deployed with previous=%q reset=%t restore=%t; the students' "+
			"work would not be replayed", engine.previousMode, engine.forceStudentReset,
			engine.restoreStudentState)
	}
	// A plan with nothing in it is still a deployment that finished. It owes
	// the same two things: the stale container the transition preserved, and a
	// lab that is no longer mid-transition.
	if !strings.Contains(out, "no changes") {
		t.Fatalf("a converged lab did not take the empty-plan path:\n%s", out)
	}
	if removed := lab.backend.wasRemoved(); len(removed) != 1 ||
		removed[0] != commandStaleContainer {
		t.Fatalf("the empty-plan path removed %v, want exactly the container the "+
			"interrupted solve preserved", removed)
	}
	if read := lab.backend.wasRead(); len(read) != 0 {
		t.Fatalf("the empty-plan path read %v while a solve was still pending", read)
	}
	if got := lab.stored(commandStaleDevice); got != studentWork {
		t.Fatalf("the saved state of the removed container is %q, want the group's work", got)
	}
	if mode := labModeRecord(lab.top); mode != string(render.ModePlatform) {
		t.Fatalf("the lab is marked %q after being put back into teaching mode", mode)
	}
	if record := lab.transition(t); record != nil {
		t.Fatalf("a finished transition still claims to be pending: %+v", record)
	}
}

// A deployment that changes nothing must not leave a lab claiming a transition
// is under way, and a --dry-run must not start one.
func TestADryRunNeitherPreservesNorFinishesATransition(t *testing.T) {
	lab := newCommandLab(t)
	stubLocalPlan(t, func(*deploy.Engine, *model.Topology) (*plan.Plan, error) {
		p := plan.New()
		p.Add(&plan.Step{
			ID: "configure:dry", Stage: plan.StageConfigure, Scope: "as=3",
			Describe: "install the reference solution",
			Run: func(context.Context) error {
				t.Error("a dry run executed a reference command")
				return nil
			},
		})
		return p, nil
	})
	if _, _, err := deployRun(t, lab.dir, "deploy", "--solve", "--prune", "--dry-run"); err != nil {
		t.Fatalf("a dry run of a solve refused: %v", err)
	}
	if mode := labModeRecord(lab.top); mode != "" {
		t.Fatalf("a dry run marked the lab %q, so the next capture would withhold the "+
			"students' work", mode)
	}
	if record := lab.transition(t); record != nil {
		t.Fatalf("a dry run recorded permission to prune: %+v", record)
	}
	if removed := lab.backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("a dry run removed %v", removed)
	}
}
