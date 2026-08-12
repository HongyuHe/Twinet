// Package fault injects, verifies and resolves network faults.
//
// Twinet uses this for two things at once. In a course it is the scripted
// misconfiguration an exercise is built around, such as the BGP hijack that
// motivates RPKI. In an evaluation it is the incident an AI agent is asked to
// diagnose, following the taxonomy of the NIKA benchmark.
//
// Two rules shape the whole design.
//
// Every fault must be reversible. An episode is inject, observe, resolve, then
// verify the baseline is genuinely back; without that, episode n+1 inherits
// episode n's damage and no measurement is reproducible. So a fault is never
// applied by rewriting configuration wholesale. It records the state it
// replaced and restores exactly that.
//
// Ground truth must never be observable from inside the lab. A fault named in a
// container label, a file or an environment variable that an agent can read
// makes the task trivial. Ground truth lives only in the control plane.
package fault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Category is NIKA's root-cause taxonomy, reproduced so ground truth
// serialises into the shape its scoring already expects.
type Category string

const (
	CatEndHost    Category = "end_host_failure"
	CatLink       Category = "link_failure"
	CatMisconfig  Category = "misconfiguration"
	CatNodeError  Category = "network_node_error"
	CatAttack     Category = "network_under_attack"
	CatContention Category = "resource_contention"
	CatMultiple   Category = "multiple_faults"
)

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	switch c {
	case CatEndHost, CatLink, CatMisconfig, CatNodeError, CatAttack, CatContention, CatMultiple:
		return true
	}
	return false
}

// Capability names something a fault needs from the runtime, so a fault can be
// refused up front rather than injected half-way.
type Capability string

const (
	CapExec      Capability = "exec"
	CapInterface Capability = "interface"
	CapIP        Capability = "ip"
	CapRoute     Capability = "route"
	CapTC        Capability = "tc"
	CapNFT       Capability = "nft"
	CapProcess   Capability = "process"
	CapFile      Capability = "file"
	CapFRR       Capability = "frr"
	// CapLifecycle is the ability to change a container's run state, which is
	// held by the platform rather than by anything inside the container.
	CapLifecycle Capability = "lifecycle"
	CapOVS       Capability = "ovs"
	CapService   Capability = "service"
	CapDNS       Capability = "dns"
	CapTraffic   Capability = "traffic"
	CapLink      Capability = "link"
)

// Target selects what a fault is applied to.
type Target struct {
	AS     int               `yaml:"as,omitempty" json:"as,omitempty"`
	Device string            `yaml:"device,omitempty" json:"device,omitempty"`
	Iface  string            `yaml:"iface,omitempty" json:"iface,omitempty"`
	Peer   int               `yaml:"peer,omitempty" json:"peer,omitempty"`
	Prefix string            `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// DeviceID returns the target's device identity.
func (t Target) DeviceID() string {
	if t.Device == "" {
		return ""
	}
	if strings.Contains(t.Device, "/") {
		return t.Device
	}
	return model.DeviceID(t.AS, t.Device)
}

// Param reads a fault-specific argument.
func (t Target) Param(key, def string) string {
	if v, ok := t.Params[key]; ok && v != "" {
		return v
	}
	return def
}

// GroundTruth is the machine-readable answer, in NIKA's shape.
//
// It is returned to the control plane and written to the episode record. It is
// never placed inside the lab.
type GroundTruth struct {
	IsAnomaly     bool     `json:"is_anomaly"`
	FaultyDevices []string `json:"faulty_devices"`
	Category      string   `json:"root_cause_category"`
	Names         []string `json:"root_cause_name"`
	DetailedCause string   `json:"detailed_cause"`
}

// Evidence records what verification observed.
type Evidence struct {
	Verified bool   `json:"verified"`
	Detail   string `json:"detail,omitempty"`
	Observed string `json:"observed,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// Env is what a fault is given to work with.
type Env struct {
	// wantSymptom tells Settled which transition to wait for. Inject sets it
	// true, Resolve false; it is unexported because a fault must not be able
	// to decide what its own verification means.
	wantSymptom bool

	Topology *model.Topology
	// Exec runs a command inside a device.
	Exec func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)
	// Lifecycle changes a device container's run state: pause, unpause, stop,
	// start or restart. A crashed machine is a paused container, not one with
	// its interfaces taken down, because a paused container still holds its
	// addresses and simply never answers -- which is what makes the fault hard
	// to diagnose and therefore worth injecting.
	Lifecycle func(ctx context.Context, deviceID, action string) error
	// Reshape puts an interface back to the shaping the topology declares,
	// through the platform's own code rather than through tc's command line,
	// so that undoing a traffic-control fault cannot leave a link subtly
	// different from the one the lab describes.
	Reshape func(ctx context.Context, deviceID, iface string) error
	// NodeState reports a device container's run state: running, paused,
	// exited. A fault that freezes a machine can only be verified by asking
	// the platform, because the frozen machine cannot answer for itself and
	// its silence is equally consistent with an unreachable node.
	NodeState func(ctx context.Context, deviceID string) (string, error)
	// Seed makes a time-varying fault replay exactly rather than differing run
	// to run.
	Seed int64
}

// Device resolves a target to a device in the topology.
func (e *Env) Device(t Target) (*model.Device, error) {
	id := t.DeviceID()
	if id == "" {
		return nil, fmt.Errorf("the fault names no device")
	}
	d, ok := e.Topology.Device(id)
	if !ok {
		return nil, fmt.Errorf("no device %q in this lab", id)
	}
	return d, nil
}

// Run executes a command on a device and requires it to succeed.
func (e *Env) Run(ctx context.Context, deviceID string, args ...string) (string, error) {
	res, err := e.Exec(ctx, deviceID, args)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return res.Stdout, fmt.Errorf("%s: exit %d: %s",
			strings.Join(args, " "), res.ExitCode, firstLine(res.Stderr))
	}
	return res.Stdout, nil
}

// Sh runs a shell command on a device.
func (e *Env) Sh(ctx context.Context, deviceID, script string) (string, error) {
	return e.Run(ctx, deviceID, "sh", "-c", script)
}

// Try runs a shell command and tolerates a non-zero exit, for probes.
//
// A non-zero exit is a legitimate answer from the device. A transport failure
// is not an answer at all, and the two must not look alike: a verifier that
// reads an unreachable node as "the fault is not there" reports a successful
// undo on a lab that is still broken, and the contamination is invisible.
// Callers that need to tell them apart use TryE.
func (e *Env) Try(ctx context.Context, deviceID, script string) (string, int) {
	out, code, _ := e.TryE(ctx, deviceID, script)
	return out, code
}

// TryE is Try, but it reports whether the device could be reached at all.
func (e *Env) TryE(ctx context.Context, deviceID, script string) (string, int, error) {
	res, err := e.Exec(ctx, deviceID, []string{"sh", "-c", script})
	if err != nil {
		return "", -1, fmt.Errorf("%s could not be reached: %w", deviceID, err)
	}
	return res.Stdout, res.ExitCode, nil
}

// Vtysh runs an FRR command.
func (e *Env) Vtysh(ctx context.Context, deviceID, command string) (string, error) {
	return e.Run(ctx, deviceID, "vtysh", "-c", command)
}

// VtyshConfig applies FRR configuration lines.
func (e *Env) VtyshConfig(ctx context.Context, deviceID string, lines ...string) error {
	args := []string{"vtysh"}
	for _, l := range lines {
		args = append(args, "-c", l)
	}
	_, err := e.Run(ctx, deviceID, args...)
	return err
}

// State is what a fault saved so it can undo itself.
//
// Reversibility is a contract, not a convention: Inject returns the state it
// replaced and Resolve is given it back. A fault that cannot express its undo
// this way does not belong in the registry.
type State map[string]string

// Fault is one injectable failure mode.
type Fault struct {
	// Name is the registry key, matching NIKA's problem identifier where one
	// exists so the taxonomies line up.
	Name string
	// Category places it in NIKA's taxonomy.
	Category Category
	// Symptom is what an operator would report. It is what an agent is told,
	// and it must not give the cause away.
	Symptom string
	// Describe explains the mechanism, for ground truth and for staff.
	Describe string
	// Needs lists the capabilities required to inject it.
	Needs []Capability
	// Inject applies the fault and returns the state it replaced.
	Inject func(ctx context.Context, env *Env, t Target) (State, error)
	// Verify confirms the fault is actually active.
	//
	// It is given the state Inject recorded, because a predicate that only
	// looks at the target is almost always too loose: "a default route exists"
	// is true both while the gateway is wrong and after it has been put back.
	// Several faults were silently unresolvable until this argument existed.
	Verify func(ctx context.Context, env *Env, t Target, s State) (Evidence, error)
	// Resolve undoes the fault using the state Inject returned.
	Resolve func(ctx context.Context, env *Env, t Target, s State) error
}

// Truth builds the ground truth for an application of this fault.
func (f *Fault) Truth(t Target, detail string) GroundTruth {
	dev := t.DeviceID()
	var devices []string
	if dev != "" {
		devices = []string{dev}
	}
	if detail == "" {
		detail = f.Describe
	}
	return GroundTruth{
		IsAnomaly: true, FaultyDevices: devices,
		Category: string(f.Category), Names: []string{f.Name},
		DetailedCause: detail,
	}
}

// registry holds every known fault.
var registry = map[string]*Fault{}

// Register adds a fault. A duplicate name is a programming error.
func Register(f *Fault) {
	if f.Name == "" {
		panic("fault: registered with no name")
	}
	if !f.Category.Valid() {
		panic("fault: " + f.Name + " has an unknown category " + string(f.Category))
	}
	if f.Inject == nil || f.Verify == nil || f.Resolve == nil {
		// Enforced here rather than discovered mid-episode: a fault that cannot
		// be verified might never have taken effect, and one that cannot be
		// resolved contaminates every episode after it.
		panic("fault: " + f.Name + " must implement Inject, Verify and Resolve")
	}
	if _, dup := registry[f.Name]; dup {
		panic("fault: duplicate registration " + f.Name)
	}
	registry[f.Name] = f
}

// Lookup finds a fault by name.
func Lookup(name string) (*Fault, bool) { f, ok := registry[name]; return f, ok }

// All returns every registered fault, sorted by name.
func All() []*Fault {
	out := make([]*Fault, 0, len(registry))
	for _, f := range registry {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByCategory groups the registry.
func ByCategory() map[Category][]*Fault {
	out := map[Category][]*Fault{}
	for _, f := range All() {
		out[f.Category] = append(out[f.Category], f)
	}
	return out
}

// Injection is a fault applied to a target, with what it needs to undo itself.
type Injection struct {
	// ID identifies this injection, so one of several faults of the same kind
	// can be undone without touching the others.
	//
	// Resolution used to match on the fault's name alone, so resolving
	// `interface_down` on one router resolved it on every router it had been
	// injected on -- including, in a scenario built from several faults of one
	// kind, the ones that were meant to stay.
	ID         string      `json:"id"`
	Fault      string      `json:"fault"`
	Target     Target      `json:"target"`
	State      State       `json:"state,omitempty"`
	InjectedAt time.Time   `json:"injected_at"`
	Truth      GroundTruth `json:"ground_truth"`
	Evidence   Evidence    `json:"evidence"`
}

// Inject applies a fault and verifies it actually manifested.
//
// Verification is not optional. An incident that failed to inject but is
// presented to an agent as a puzzle produces a meaningless measurement, and in
// that case the agent is right and the benchmark is wrong.
// newInjectionID returns an identifier unique across every lab and machine, so
// two controllers injecting at once cannot produce the same one.
func newInjectionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// The clock is a poor unique identifier and a good last resort: the
		// alternative is refusing to inject because the system has no entropy.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func Inject(ctx context.Context, env *Env, name string, t Target) (*Injection, error) {
	f, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("no fault named %q; try `twinet fault list`", name)
	}
	if t.Device != "" {
		d, err := env.Device(t)
		if err != nil {
			return nil, err
		}
		// Fill in the AS from the device.
		//
		// Faults build commands like `router bgp %d` out of Target.AS, and it
		// is zero whenever a device was named without --as, which is the
		// obvious way to invoke this. That produced `router bgp 0`: on a good
		// day vtysh refused it and the fault reported a confusing error, on a
		// bad one it created a second empty BGP process next to the real one.
		// The device already knows which AS it belongs to.
		if t.AS == 0 {
			t.AS = d.ASN
		} else if t.AS != d.ASN {
			return nil, fmt.Errorf("device %s belongs to AS %d, not AS %d",
				d.ID, d.ASN, t.AS)
		}
	}

	// The device is fingerprinted before anything is changed, so that resolving
	// can be held to "the device is as it was" rather than the far weaker
	// "the fault predicate is now false". A fault can satisfy the second while
	// leaving the device permanently broken.
	base := ""
	if t.DeviceID() != "" {
		base = fingerprint(ctx, env, t.DeviceID())
	}

	state, err := f.Inject(ctx, env, t)
	if err != nil {
		return nil, fmt.Errorf("inject %s: %w", name, err)
	}
	if base != "" {
		if state == nil {
			state = State{}
		}
		if after := fingerprint(ctx, env, t.DeviceID()); after != "" {
			added, removed := delta(base, after)
			state[addedKey] = strings.Join(added, "\n")
			state[removedKey] = strings.Join(removed, "\n")
			state[versionKey] = fingerprintVersion
		}
	}
	inj := &Injection{
		ID:    newInjectionID(),
		Fault: name, Target: t, State: state,
		InjectedAt: time.Now().UTC(),
		Truth:      f.Truth(t, ""),
	}

	env.wantSymptom = true
	ev, err := f.Verify(ctx, env, t, state)
	if err != nil {
		if rerr := f.Resolve(ctx, env, t, state); rerr != nil {
			return inj, fmt.Errorf("inject %s: verification failed (%w) and rollback also failed (%v)",
				name, err, rerr)
		}
		return nil, fmt.Errorf("inject %s: could not verify it took effect, so it was rolled back: %w", name, err)
	}
	inj.Evidence = ev
	if !ev.Verified {
		if rerr := f.Resolve(ctx, env, t, state); rerr != nil {
			return inj, fmt.Errorf("inject %s: did not take effect (%s) and rollback failed (%v)",
				name, ev.Detail, rerr)
		}
		return nil, fmt.Errorf("inject %s: it did not take effect, so it was rolled back: %s", name, ev.Detail)
	}
	return inj, nil
}

// Resolve undoes an injection and confirms it is genuinely gone.
func Resolve(ctx context.Context, env *Env, inj *Injection) error {
	f, ok := Lookup(inj.Fault)
	if !ok {
		return fmt.Errorf("no fault named %q", inj.Fault)
	}
	// The undo is a means, not the verdict.
	//
	// It used to be fatal on its own, which made resolve impossible to repeat
	// and impossible to run on a lab somebody had already repaired by hand.
	// Undoing an OSPF area change removes the wrong network statement, and if
	// a student had already put it back the removal fails -- so the fault
	// could never be cleared from the ledger even though the lab was at
	// baseline, and every later injection was refused because of a fault that
	// was not there.
	//
	// The checks below decide, and they are strictly stronger than "the
	// commands exited zero": the fault must be verifiably absent, and the
	// device must be as it was found. An undo that errors and reaches the
	// right state is a success; one that exits zero and does not is a failure.
	undoErr := f.Resolve(ctx, env, inj.Target, inj.State)
	// A resolve that silently half-worked is the most damaging failure here,
	// because the contamination it leaves behind is invisible: the next episode
	// runs on a lab that is still broken, and its result is attributed to
	// whatever that episode injected.
	//
	// This fails closed. A verification that cannot run is not evidence that
	// the fault is gone; it is the absence of evidence either way, and treating
	// it as success is how contamination becomes silent.
	// The device is probed directly first. Every verifier reads the device, so
	// if it cannot be reached, whatever the verifier concludes is an artefact
	// of the failure rather than an observation of the lab.
	if err := env.reachable(ctx, inj.Target.DeviceID()); err != nil {
		return fmt.Errorf("resolve %s: %w, so the lab must be treated as contaminated%s",
			inj.Fault, err, alsoFailed(undoErr))
	}
	env.wantSymptom = false
	ev, err := f.Verify(ctx, env, inj.Target, inj.State)
	if err != nil {
		return fmt.Errorf("resolve %s: it could not be confirmed, "+
			"so the lab must be treated as contaminated: %w%s", inj.Fault, err, alsoFailed(undoErr))
	}
	if ev.Verified {
		return fmt.Errorf("resolve %s: the fault is still present afterwards: %s%s",
			inj.Fault, evidenceDetail(ev), alsoFailed(undoErr))
	}

	// "The predicate is false" is not "the device is as it was". A resolve can
	// satisfy the first by destroying the state the fault perturbed: deleting a
	// misdirected default route removes the misdirection and leaves the host
	// unable to reach anything. Comparing against the baseline is what
	// distinguishes an undo from a demolition.
	added := splitNonEmpty(inj.State[addedKey])
	removed := splitNonEmpty(inj.State[removedKey])
	if inj.State[versionKey] != fingerprintVersion {
		// Recorded by a build that compared different fields. The undo itself
		// ran and was verified; only the "left as found" check is skipped,
		// because it could not give a meaningful answer.
		added, removed = nil, nil
	}
	if len(added)+len(removed) > 0 {
		now := fingerprint(ctx, env, inj.Target.DeviceID())
		if now == "" {
			return fmt.Errorf("resolve %s: %s could not be re-read to confirm "+
				"it was left as it was found%s", inj.Fault, inj.Target.DeviceID(), alsoFailed(undoErr))
		}
		if r := residue(added, removed, now); r != "" {
			return fmt.Errorf("resolve %s: the fault is gone but %s was not left as it was found: %s%s",
				inj.Fault, inj.Target.DeviceID(), r, alsoFailed(undoErr))
		}
	}
	return nil
}

// alsoFailed appends the undo's own error to a failure the checks found.
//
// The checks are the verdict, but when they fail the undo's error is usually
// the reason, and reporting only "the fault is still present" leaves whoever
// reads it with nothing to act on.
func alsoFailed(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf(" (the undo also reported: %v)", err)
}

// evidenceDetail prefers the detail, falling back to what was observed, so a
// failure is never reported with an empty explanation.
func evidenceDetail(ev Evidence) string {
	if ev.Detail != "" {
		return ev.Detail
	}
	if ev.Observed != "" {
		return ev.Observed
	}
	return "no detail was recorded"
}

// State reports a device container's run state.
func (e *Env) State(ctx context.Context, deviceID string) (string, error) {
	if e.NodeState == nil {
		return "", fmt.Errorf("this environment cannot inspect container state")
	}
	return e.NodeState(ctx, deviceID)
}

// reachable reports whether a device can be asked anything at all.
//
// A paused container is deliberately excluded from this: host_crash freezes the
// device, and its own verifier is the one that must interpret the silence.
func (e *Env) reachable(ctx context.Context, deviceID string) error {
	if _, _, err := e.TryE(ctx, deviceID, "true"); err != nil {
		return err
	}
	return nil
}

// Do changes a device's run state, refusing clearly when the environment
// cannot. A fault that silently does nothing is worse than one that fails.
func (e *Env) Do(ctx context.Context, deviceID, action string) error {
	if e.Lifecycle == nil {
		return fmt.Errorf("this environment cannot %s a container", action)
	}
	return e.Lifecycle(ctx, deviceID, action)
}

// Reshaped asks the platform to restore an interface's declared shaping.
func (e *Env) Reshaped(ctx context.Context, deviceID, iface string) error {
	if e.Reshape == nil {
		return fmt.Errorf("this environment cannot restore the shaping of %s", iface)
	}
	return e.Reshape(ctx, deviceID, iface)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

// Verify re-checks that an injection is still doing what it claims.
//
// Injection verifies once and rolls back if the fault did not take, but a lab
// runs for a long time afterwards: an interface comes back up, a daemon is
// restarted, a student repairs the thing by accident, a container is replaced
// and the fault goes with it. An evaluation that assumes the fault is still
// present scores an agent's conclusion against a network that no longer has
// the problem, which is worse than having no fault at all -- the episode looks
// valid and its ground truth is wrong.
//
// This is the same predicate injection uses, so a fault cannot pass here and
// fail there.
func Verify(ctx context.Context, env *Env, inj *Injection) (Evidence, error) {
	f, ok := Lookup(inj.Fault)
	if !ok {
		return Evidence{}, fmt.Errorf("no fault named %q", inj.Fault)
	}
	// The question being asked is "is the fault still present", so the symptom
	// is what verification must wait for.
	//
	// This is not incidental. The field defaults to false, which means "wait
	// for the network to recover", and a caller who builds an Env and calls
	// this function -- which is every caller outside injection, since the
	// field is unexported and they cannot set it -- was asking whether the
	// fault had gone away while believing they were asking whether it was
	// there. A symptom-aware verifier would then report a working fault as
	// absent and an absent one as present. For a benchmark whose entire value
	// is the correctness of its ground truth, that is the worst available
	// failure: the episode still looks valid.
	env.wantSymptom = true
	return f.Verify(ctx, env, inj.Target, inj.State)
}

// Settled polls until the network agrees with the fault, or gives up.
//
// A verifier that reads back the configuration it just wrote proves only that
// vtysh accepted a line. The claim a fault makes is about behaviour -- the
// adjacency drops, the session stops establishing, the name resolves wrongly --
// and behaviour takes time to follow configuration: OSPF has a dead interval,
// BGP a hold timer. Checking immediately would fail on a fault that works, so
// the honest options are to poll for the symptom or to not check it at all.
// This is the first option; the three faults that used to take the second are
// the reason it exists.
//
// The returned Evidence carries the last observation either way, so a fault
// that never produced its symptom says what it saw instead.
func (e *Env) Settled(ctx context.Context, within time.Duration,
	observe func(context.Context) (string, error),
	satisfied func(string) bool) (string, error) {

	// Which way the transition runs depends on who is asking. After an
	// injection the symptom has to appear; after a resolve it has to clear.
	// Polling for "present" in both cases made every symptom-checking fault
	// impossible to resolve: the undo was applied, the check ran before the
	// protocol had reconverged, the symptom was still there, and resolve
	// declared the lab contaminated while it was in fact recovering normally.
	want := e.wantSymptom
	deadline := time.Now().Add(within)
	var last string
	var lastErr error
	for {
		out, err := observe(ctx)
		if err == nil {
			last, lastErr = out, nil
			if satisfied(out) == want {
				return out, nil
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return last, lastErr
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// SymptomWindow is how long a control-plane fault is given to show itself.
//
// FRR's default dead interval is 40s, and a neighbour is only declared down
// once it expires -- so an adjacency broken by an area change is still listed
// for the better part of a minute after the change lands. 45s was tried first
// and was not enough: the fault worked, the check ran a few seconds early, and
// the injection was rolled back as ineffective every time, which made the
// fault type unusable while looking like a bug in the fault.
//
// 90s leaves room for the dead interval plus the reconvergence that follows.
// It costs nothing when the symptom appears sooner, because Settled returns as
// soon as it sees what it is waiting for.
const SymptomWindow = 90 * time.Second
