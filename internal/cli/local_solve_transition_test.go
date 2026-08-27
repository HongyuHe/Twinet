package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// The sequence these cover lost a term's work while every command in it
// reported success.
//
// A single-node lab had one stale container the manifest no longer wanted --
// an autonomous system a course had dropped, still holding the group's
// configuration -- and the operator ran `deploy --solve --prune`. The pre-solve
// capture saved every device the manifest still placed here, which is not that
// container, and marked the lab as one that might now hold the answer. The
// reference plan then failed part way, so the prune, which is the last step,
// never ran and the stale container was never read by anything.
//
// The retry found the marker, correctly declined to read a lab that may hold
// the answer, and deleted the container it had never looked inside.
//
// Both halves of a solve are destructive, so both are preserved before either
// runs, and what was preserved is written down for whichever process has to
// finish the job.

const (
	// A name no live lab can carry: the prune this drives reaches the host's
	// own overlay objects, and it must never find another lab's.
	solveTransitionLabName = "local-solve-transition-regression"
	solveTransitionNode    = "local"
	// studentWork is what the dropped group left in the stale container. It is
	// the only copy: nothing else in the lab holds it.
	studentWork = "router ospf\n network 3.0.9.0/24 area 0\n"
	// referenceAnswer is what a partially applied solve puts on a device, and
	// what must never be filed as anybody's work.
	referenceAnswer = "router bgp 3\n neighbor 10.0.0.2 remote-as 4\n"
)

// solveTransitionRuntime is a node holding one device the manifest wants and
// one container it does not, with the contents of both under the test's
// control. It is shared by concurrent capture workers, so it locks.
type solveTransitionRuntime struct {
	rt.Runtime
	mu         sync.Mutex
	containers map[string]rt.Container
	config     map[string]string
	unreadable map[string]bool
	removed    []string
}

func (r *solveTransitionRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []rt.Container
	for _, c := range r.containers {
		out = append(out, c)
	}
	return out, nil
}

func (r *solveTransitionRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.containers[name]
	if !ok {
		return rt.Container{Name: name, State: rt.StateAbsent}, nil
	}
	return c, nil
}

func (r *solveTransitionRuntime) Exec(_ context.Context, name string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "test":
		// Nothing owes a restore here, so the capture is never asked to
		// withhold what it read.
		return rt.ExecResult{ExitCode: 1}, nil
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh":
		if r.unreadable[name] {
			return rt.ExecResult{}, errors.New("container is restarting")
		}
		return rt.ExecResult{Stdout: r.config[name]}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *solveTransitionRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.containers, name)
	r.removed = append(r.removed, name)
	return nil
}

func (r *solveTransitionRuntime) setConfig(container, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config[container] = body
}

func (r *solveTransitionRuntime) relabel(container, key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.containers[container]
	labels := map[string]string{}
	for k, v := range c.Labels {
		labels[k] = v
	}
	if value == "" {
		delete(labels, key)
	} else {
		labels[key] = value
	}
	c.Labels = labels
	r.containers[container] = c
}

func (r *solveTransitionRuntime) add(container, device string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers[container] = rt.Container{
		Name: container, State: rt.StateRunning,
		Labels: map[string]string{
			deploy.LabelLab: solveTransitionLabName, deploy.LabelNode: solveTransitionNode,
			deploy.LabelDeviceID: device, deploy.LabelKind: string(model.KindRouter),
		},
	}
}

func (r *solveTransitionRuntime) wasRemoved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.removed...)
}

// solveTransitionLab is the lab in front of the operator: one router the
// manifest places here, and one container it has forgotten.
func solveTransitionLab(t *testing.T) (*model.Topology, *state.Store, *solveTransitionRuntime) {
	t.Helper()
	kept := &model.Device{
		ID: "as3/ATL", Name: "ATL", ASN: 3, Kind: model.KindRouter,
		Container: "tw-atl", Node: solveTransitionNode,
	}
	top := &model.Topology{
		Name: solveTransitionLabName, Hash: "topology-as-written",
		Lab:     &model.Lab{Dir: t.TempDir()},
		Devices: map[string]*model.Device{kept.ID: kept},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{kept}},
		},
	}
	store, err := localStore(top)
	if err != nil {
		t.Fatal(err)
	}
	backend := &solveTransitionRuntime{
		containers: map[string]rt.Container{},
		config:     map[string]string{},
		unreadable: map[string]bool{},
	}
	backend.add("tw-atl", "as3/ATL")
	backend.add("tw-old", "as3/OLD")
	backend.setConfig("tw-atl", "router bgp 3\n")
	backend.setConfig("tw-old", studentWork)
	return top, store, backend
}

// prunedLocally runs the prune exactly as the deploy command runs it.
//
// previousSolved is the mode the command read *before* it began, which is what
// deploy passes: a first attempt reads teaching mode even though the marker
// says solve-pending by the time the prune runs.
func prunedLocally(t *testing.T, top *model.Topology, store *state.Store,
	backend *solveTransitionRuntime, previousSolved bool,
	preserved *deploy.OrphanPreservationSet,
) (string, error) {
	t.Helper()
	var out bytes.Buffer
	desired := &deploy.Engine{Runtime: backend, Node: solveTransitionNode, State: store}
	err := pruneLocalDeployment(context.Background(), desired, top, store,
		solveTransitionNode, previousSolved, true, false, &out, preserved)
	return out.String(), err
}

// storedConfig is what the state store would replay into a device.
func storedConfig(t *testing.T, store *state.Store, device string) string {
	t.Helper()
	snap, err := store.Current(solveTransitionLabName, device, state.KindFRR)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read the saved state of %s: %v", device, err)
	}
	return string(snap.Content)
}

func requireUntouched(t *testing.T, backend *solveTransitionRuntime, why string) {
	t.Helper()
	if removed := backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("%s, but %v had already been removed", why, removed)
	}
}

// The whole sequence: a solve that fails part way, and the retry that finishes
// it. The stale container must survive the first attempt with its contents
// saved, and must be removed by the second without the second ever reading it.
func TestAnInterruptedSolvePreservesTheOrphanItsRetryRemoves(t *testing.T) {
	top, store, backend := solveTransitionLab(t)

	preserved, err := preserveLocalSolveTransition(context.Background(), backend, top,
		store, solveTransitionNode, true)
	if err != nil {
		t.Fatalf("a solve refused to start on a lab it could read: %v", err)
	}
	requireUntouched(t, backend, "preserving is not removing")
	if got := storedConfig(t, store, "as3/OLD"); got != studentWork {
		t.Fatalf("the stale container's work was not saved before the reference solution "+
			"was written; the store holds %q.\nThe prune that would have saved it runs "+
			"after the plan, so a plan that fails leaves nothing behind.", got)
	}
	if got := storedConfig(t, store, "as3/ATL"); got == "" {
		t.Fatal("the devices the manifest still wants were not captured before the solve")
	}
	if labModeRecord(top) != localModeSolvePending || !labWasSolved(top) {
		t.Fatalf("the lab is marked %q; a destroy or a retry must treat an interrupted "+
			"solve as one that may hold the answer", labModeRecord(top))
	}
	if len(preserved.Preserved) != 1 || preserved.Preserved[0].Container != "tw-old" ||
		!preserved.Preserved[0].Stored {
		t.Fatalf("the transition recorded %+v, want the stale container preserved",
			preserved.Preserved)
	}

	// The plan now fails part way, and the retry is a different process: what
	// it may do comes off disk. The lab may hold the answer by this point, so
	// what is in the stale container can no longer be read as anybody's work.
	backend.setConfig("tw-old", referenceAnswer)
	proof, err := resumeLocalSolveTransition(top, solveTransitionNode)
	if err != nil {
		t.Fatalf("a retry refused to finish the transition its own first attempt "+
			"recorded: %v", err)
	}
	out, err := prunedLocally(t, top, store, backend, true, proof)
	if err != nil {
		t.Fatalf("the retry would not remove what the first attempt preserved: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 1 || removed[0] != "tw-old" {
		t.Fatalf("the retry removed %v, want the stale container", removed)
	}
	if !strings.Contains(out, "pruned 1 stale container") {
		t.Fatalf("the retry did not report what it removed: %q", out)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != studentWork {
		t.Fatalf("the saved state of the removed container is %q, want the student's work.\n"+
			"A retry that reads a container in a lab that may hold the answer files the "+
			"answer as their work; one that reads nothing and deletes anyway loses it.", got)
	}

	if err := finishLocalDeployment(top, string(render.ModeSolve)); err != nil {
		t.Fatal(err)
	}
	if labModeRecord(top) != string(render.ModeSolve) {
		t.Fatalf("a completed solve is recorded as %q", labModeRecord(top))
	}
	record, err := readSolveTransition(top)
	if err != nil || record != nil {
		t.Fatalf("a finished transition still claims to be pending: %+v (%v)", record, err)
	}
}

// One command, no interruption: the ordinary case must still prune.
func TestASuccessfulSolveWithPruneStillRemovesTheStaleContainer(t *testing.T) {
	top, store, backend := solveTransitionLab(t)

	preserved, err := preserveLocalSolveTransition(context.Background(), backend, top,
		store, solveTransitionNode, true)
	if err != nil {
		t.Fatal(err)
	}
	// The reference plan has run by the time the prune does. Nothing it touched
	// is a student's any more, so a prune that follows a preservation must file
	// nothing further -- what it is entitled to remove was settled before the
	// first reference command.
	backend.setConfig("tw-old", referenceAnswer)
	out, err := prunedLocally(t, top, store, backend, false, preserved)
	if err != nil {
		t.Fatalf("a successful solve refused to prune what it had just preserved: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 1 || removed[0] != "tw-old" {
		t.Fatalf("--prune removed %v, want the stale container", removed)
	}
	if !strings.Contains(out, "pruned 1 stale container") {
		t.Fatalf("the prune did not report what it removed: %q", out)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != studentWork {
		t.Fatalf("the removed container's work is %q in the store, want the student's", got)
	}
	if err := finishLocalDeployment(top, string(render.ModeSolve)); err != nil {
		t.Fatal(err)
	}
	if record, err := readSolveTransition(top); err != nil || record != nil {
		t.Fatalf("a finished transition still claims to be pending: %+v (%v)", record, err)
	}
}

// A prune of a lab that already holds the reference solution reads nothing.
// The container in front of it holds the answer, and filing that as a group's
// work is the same loss by a different route.
func TestASolvedLabsPruneNeverFilesTheAnswerAsStudentWork(t *testing.T) {
	top, store, backend := solveTransitionLab(t)
	backend.setConfig("tw-old", referenceAnswer)
	if err := recordLabMode(top, string(render.ModeSolve)); err != nil {
		t.Fatal(err)
	}
	if _, err := prunedLocally(t, top, store, backend, true, nil); err != nil {
		t.Fatalf("a solved lab's prune refused: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 1 || removed[0] != "tw-old" {
		t.Fatalf("a solved lab's prune removed %v, want the stale container", removed)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != "" {
		t.Fatalf("a solved lab's prune wrote %q into the state store as student work", got)
	}
}

// Anything that cannot be preserved stops the transition while the lab is
// still exactly as the students left it. A refusal after the first reference
// command has run is not a refusal, it is a report.
func TestAnOrphanThatCannotBePreservedStopsTheSolveBeforeItWritesAnything(t *testing.T) {
	cases := []struct {
		what   string
		breaks func(*solveTransitionRuntime)
		names  string
	}{
		{
			what:   "a stale container whose configuration cannot be read",
			breaks: func(r *solveTransitionRuntime) { r.unreadable["tw-old"] = true },
			names:  "tw-old",
		},
		{
			what: "a stale container with no canonical device identifier",
			breaks: func(r *solveTransitionRuntime) {
				r.relabel("tw-old", deploy.LabelDeviceID, "")
			},
			names: "tw-old",
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			top, store, backend := solveTransitionLab(t)
			c.breaks(backend)

			preserved, err := preserveLocalSolveTransition(context.Background(), backend,
				top, store, solveTransitionNode, true)
			if err == nil {
				t.Fatalf("the solve went ahead with %s; the prune it was asked for would "+
					"later delete a container nothing had read", c.what)
			}
			if preserved != nil {
				t.Fatal("a refused preservation still handed out permission to remove")
			}
			if !strings.Contains(err.Error(), c.names) {
				t.Errorf("the refusal does not name the container: %v", err)
			}
			if !strings.Contains(err.Error(), "reference solution") {
				t.Errorf("the refusal does not say what it refused: %v", err)
			}
			requireUntouched(t, backend, "a refused transition removes nothing")
			if mode := labModeRecord(top); mode == localModeSolvePending {
				t.Fatal("the lab was marked as possibly holding the answer by a transition " +
					"that refused to start, so the next capture would withhold student state")
			}
			if record, err := readSolveTransition(top); err != nil || record != nil {
				t.Fatalf("a refused transition recorded permission to prune: %+v (%v)", record, err)
			}
		})
	}
}

// What the retry is not allowed to assume. Each of these is a lab where the
// preserved copies cannot be shown to be the containers in front of it, and
// each ends with the container still there and the command saying why.
func TestARetryPrunesOnlyWhatItCanProveWasPreserved(t *testing.T) {
	t.Run("the first attempt was never asked to prune", func(t *testing.T) {
		top, store, backend := solveTransitionLab(t)
		if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
			store, solveTransitionNode, false); err != nil {
			t.Fatal(err)
		}
		_, err := resumeLocalSolveTransition(top, solveTransitionNode)
		if err == nil {
			t.Fatal("a retry pruned a container that no attempt had ever read; this is the " +
				"original loss, reached through a first attempt without --prune")
		}
		if !strings.Contains(err.Error(), "not asked to prune") {
			t.Errorf("the refusal does not say what is missing: %v", err)
		}
		if !strings.Contains(err.Error(), "twinet deploy") {
			t.Errorf("the refusal does not say what to do instead: %v", err)
		}
		requireUntouched(t, backend, "a refused retry removes nothing")
	})

	t.Run("nothing was recorded at all", func(t *testing.T) {
		top, _, backend := solveTransitionLab(t)
		if err := recordLabMode(top, localModeSolvePending); err != nil {
			t.Fatal(err)
		}
		if _, err := resumeLocalSolveTransition(top, solveTransitionNode); err == nil {
			t.Fatal("a pending solve with no record of what it preserved still pruned")
		}
		requireUntouched(t, backend, "a refused retry removes nothing")
	})

	t.Run("the record cannot be read", func(t *testing.T) {
		top, _, backend := solveTransitionLab(t)
		if err := recordLabMode(top, localModeSolvePending); err != nil {
			t.Fatal(err)
		}
		if err := recordSolveTransition(top, localSolveTransition{
			Lab: top.Name, Node: solveTransitionNode, Topology: top.Hash,
			Mode: localModeSolvePending, Prune: true,
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(labPrivateDir(top)+"/"+localTransitionFile,
			[]byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := resumeLocalSolveTransition(top, solveTransitionNode); err == nil {
			t.Fatal("an unreadable record was treated as a lab that was never in a transition")
		}
		requireUntouched(t, backend, "a refused retry removes nothing")
	})

	t.Run("the manifest changed between the attempts", func(t *testing.T) {
		top, store, backend := solveTransitionLab(t)
		if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
			store, solveTransitionNode, true); err != nil {
			t.Fatal(err)
		}
		// The course edits the manifest before retrying. Which containers are
		// stale was decided against the old one, so the preserved copies are
		// not evidence about these containers.
		top.Hash = "topology-as-edited"
		_, err := resumeLocalSolveTransition(top, solveTransitionNode)
		if err == nil {
			t.Fatal("a retry pruned against a manifest that had changed since anything " +
				"was preserved")
		}
		if !strings.Contains(err.Error(), "manifest has changed") {
			t.Errorf("the refusal does not say what changed: %v", err)
		}
		requireUntouched(t, backend, "a refused retry removes nothing")
	})

	t.Run("a container appeared that nothing preserved", func(t *testing.T) {
		top, store, backend := solveTransitionLab(t)
		if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
			store, solveTransitionNode, true); err != nil {
			t.Fatal(err)
		}
		// A second stale container between the attempts: an interrupted
		// deployment's leftover, or a device a student was working in.
		backend.add("tw-newer", "as3/NEW")
		backend.setConfig("tw-newer", studentWork)
		proof, err := resumeLocalSolveTransition(top, solveTransitionNode)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prunedLocally(t, top, store, backend, true, proof); err == nil {
			t.Fatal("a retry removed a container that appeared after the preservation, " +
				"so nothing had ever read what was in it")
		} else if !strings.Contains(err.Error(), "tw-newer") {
			t.Errorf("the refusal does not name the container: %v", err)
		}
		requireUntouched(t, backend, "one unprovable candidate stops the whole prune")
	})

	t.Run("a preserved container now carries another device", func(t *testing.T) {
		top, store, backend := solveTransitionLab(t)
		if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
			store, solveTransitionNode, true); err != nil {
			t.Fatal(err)
		}
		// Same name, different device: a rebuild under a reused container name
		// means the preserved copy belongs to something else.
		backend.relabel("tw-old", deploy.LabelDeviceID, "as4/OLD")
		proof, err := resumeLocalSolveTransition(top, solveTransitionNode)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := prunedLocally(t, top, store, backend, true, proof); err == nil {
			t.Fatal("a retry removed a container whose preserved copy belongs to another device")
		} else if !strings.Contains(err.Error(), "as4/OLD") {
			t.Errorf("the refusal does not name what the container carries now: %v", err)
		}
		requireUntouched(t, backend, "a preserved copy of another device proves nothing")
	})
}

// An interrupted solve is still a lab whose students' work is on disk, and the
// way back is a platform deployment that replays it. That path must keep
// working while the transition is pending, prune or no prune.
func TestAPendingSolveStillRestoresStudentStateOnTheWayBack(t *testing.T) {
	top, store, backend := solveTransitionLab(t)
	if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
		store, solveTransitionNode, true); err != nil {
		t.Fatal(err)
	}
	policy := localModeTransitionPolicy(labWasSolved(top), render.ModePlatform)
	if !policy.forceStudentReset || policy.previousMode != string(render.ModeSolve) {
		t.Fatalf("a pending solve returning to teaching mode is %+v; the students' work "+
			"would not be replayed", policy)
	}
	proof, err := resumeLocalSolveTransition(top, solveTransitionNode)
	if err != nil {
		t.Fatalf("the way back could not use what the interrupted solve preserved: %v", err)
	}
	if _, err := prunedLocally(t, top, store, backend, true, proof); err != nil {
		t.Fatalf("returning to teaching mode with --prune refused: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 1 || removed[0] != "tw-old" {
		t.Fatalf("the way back removed %v, want the stale container", removed)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != studentWork {
		t.Fatalf("the removed container's work is %q in the store, want the student's", got)
	}
	if err := finishLocalDeployment(top, string(render.ModePlatform)); err != nil {
		t.Fatal(err)
	}
	if labWasSolved(top) {
		t.Fatal("a lab put back into teaching mode still reads as one holding the answer")
	}
}

// The record is what one process leaves for another, so it has to survive the
// trip through disk with everything the second one decides on.
func TestThePreservationRecordSurvivesTheProcessThatWroteIt(t *testing.T) {
	top, store, backend := solveTransitionLab(t)
	if _, err := preserveLocalSolveTransition(context.Background(), backend, top,
		store, solveTransitionNode, true); err != nil {
		t.Fatal(err)
	}
	record, err := readSolveTransition(top)
	if err != nil {
		t.Fatal(err)
	}
	want := localSolveTransition{
		Lab: solveTransitionLabName, Node: solveTransitionNode, Topology: top.Hash,
		Mode: localModeSolvePending, Prune: true,
		Preserved: []deploy.OrphanPreservation{
			{Container: "tw-old", Device: "as3/OLD", Stored: true},
		},
	}
	got := fmt.Sprintf("%s/%s/%s/%s/%t/%+v", record.Lab, record.Node, record.Topology,
		record.Mode, record.Prune, record.Preserved)
	if expected := fmt.Sprintf("%s/%s/%s/%s/%t/%+v", want.Lab, want.Node, want.Topology,
		want.Mode, want.Prune, want.Preserved); got != expected {
		t.Fatalf("the record on disk is %s, want %s", got, expected)
	}
	if record.Recorded.IsZero() {
		t.Error("the record does not say when it was taken")
	}
}
