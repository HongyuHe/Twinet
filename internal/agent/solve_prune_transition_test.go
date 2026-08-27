package agent

import (
	"context"
	"encoding/json"
	"errors"
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

// The sequence these cover loses a term's work on a cluster while every node
// reports success.
//
// A lab had one stale container the manifest no longer wanted -- an autonomous
// system a course had dropped, still running, still holding the group's
// configuration and the only copy of it. The class was solved with
// `--prune`. Prepare captured every dirty device the manifest still places on
// the node, which is not that container, because a container the manifest has
// forgotten is not in the topology to be enumerated. The apply phase wrote the
// reference solution. Commit then pruned, with WritesReference set because the
// transaction's mode is solve, which is exactly the condition under which a
// prune reads nothing -- and it deleted the container having read nothing.
//
// So both halves are preserved before either runs, and what was preserved is
// journalled in the prepared transaction before the apply phase is allowed to
// run at all. These drive that durable boundary rather than a policy helper:
// they preserve, abandon the node, re-read the transaction from disk as a
// restarted agent would find it, and assert both what is removed and what the
// state store holds afterwards.

const (
	clusterSolveLabName = "cluster-solve-transition-regression"
	clusterSolveNode    = "n0"
	// clusterStudentWork is what the dropped group left in the stale
	// container. It is the only copy: nothing else in the lab holds it.
	clusterStudentWork = "router ospf\n network 10.9.0.0/24 area 0\n"
	// clusterReferenceAnswer is what a solve puts on a device, and what must
	// never be filed as anybody's work.
	clusterReferenceAnswer = "router bgp 3\n neighbor 10.0.0.2 remote-as 4\n"
)

// clusterSolveRuntime is a node holding the containers the manifest wants and
// the ones it has forgotten, with the contents of each under the test's
// control. Capture workers share it, so it locks.
type clusterSolveRuntime struct {
	rt.Runtime
	mu         sync.Mutex
	containers map[string]rt.Container
	config     map[string]string
	unreadable map[string]bool
	removed    []string
	reads      []string
}

func (r *clusterSolveRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]rt.Container, 0, len(r.containers))
	for _, c := range r.containers {
		out = append(out, c)
	}
	return out, nil
}

func (r *clusterSolveRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.containers[name]
	if !ok {
		return rt.Container{Name: name, State: rt.StateAbsent}, nil
	}
	return c, nil
}

func (r *clusterSolveRuntime) Exec(_ context.Context, name string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "test":
		// Nothing owes a restore here, so no capture is asked to withhold
		// what it read.
		return rt.ExecResult{ExitCode: 1}, nil
	case len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh":
		r.reads = append(r.reads, name)
		if r.unreadable[name] {
			return rt.ExecResult{}, errors.New("container is restarting")
		}
		return rt.ExecResult{Stdout: r.config[name]}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *clusterSolveRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.containers, name)
	r.removed = append(r.removed, name)
	return nil
}

func (r *clusterSolveRuntime) setConfig(container, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config[container] = body
}

func (r *clusterSolveRuntime) relabel(container, key, value string) {
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

func (r *clusterSolveRuntime) add(container, device, node string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.containers[container] = rt.Container{
		Name: container, State: rt.StateRunning,
		Labels: map[string]string{
			deploy.LabelLab: clusterSolveLabName, deploy.LabelNode: node,
			deploy.LabelDeviceID: device, deploy.LabelKind: string(model.KindRouter),
		},
	}
}

func (r *clusterSolveRuntime) wasRemoved() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.removed...)
}

func (r *clusterSolveRuntime) wasRead() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reads...)
}

// clusterSolveServer is one node of the lab: the router the manifest places
// here, and the container it has forgotten.
func clusterSolveServer(t *testing.T) (*Server, *model.Topology, *state.Store, *clusterSolveRuntime) {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	top := clusterSolveTopology("topology-as-written")
	backend := &clusterSolveRuntime{
		containers: map[string]rt.Container{},
		config:     map[string]string{},
		unreadable: map[string]bool{},
	}
	backend.add("tw-atl", "as3/ATL", clusterSolveNode)
	backend.add("tw-old", "as3/OLD", clusterSolveNode)
	backend.setConfig("tw-atl", "router bgp 3\n")
	backend.setConfig("tw-old", clusterStudentWork)

	s := coordinationTestServer(t, store)
	s.cfg.Node = clusterSolveNode
	s.rt = backend
	s.current[top.Name] = top
	return s, top, store, backend
}

func clusterSolveTopology(hash string) *model.Topology {
	kept := &model.Device{
		ID: "as3/ATL", Name: "ATL", ASN: 3, Kind: model.KindRouter,
		Container: "tw-atl", Node: clusterSolveNode,
	}
	lab := &model.Lab{
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: clusterSolveNode, FailureDomain: "rack-a", Front: true},
			{Name: "n1", FailureDomain: "rack-b"},
		}},
		State: model.StatePolicy{ReplicationFactor: 1, CaptureInterval: "1h", ReplicaRetention: "168h"},
	}
	lab.Normalize()
	return &model.Topology{
		Lab: lab, Name: clusterSolveLabName, Hash: hash,
		Devices: map[string]*model.Device{kept.ID: kept},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{kept},
				Routers: []*model.Device{kept}},
		},
		Services: map[string]*model.Service{},
	}
}

// preparedSolve is the transaction a `--solve --prune` deployment leaves on a
// node once prepare has persisted it and before anything has been applied.
func preparedSolve(t *testing.T, s *Server, top *model.Topology, prune bool) (Fence, applyTransaction) {
	t.Helper()
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: top.Name})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Serialise(top))
	if err != nil {
		t.Fatal(err)
	}
	tx := applyTransaction{
		Generation: "solve-generation", FenceGeneration: lease.Fence.Generation,
		Requested: raw, PreviousGen: "teaching-generation",
		PreviousMode: string(render.ModePlatform), Mode: string(render.ModeSolve),
		Prune: prune, Phase: transactionPrepared,
		Prestate: transactionInventory{
			StateSafe: true,
			Containers: []transactionContainer{
				{Name: "tw-atl", DeviceID: "as3/ATL", State: string(rt.StateRunning)},
				{Name: "tw-old", DeviceID: "as3/OLD", State: string(rt.StateRunning)},
			},
		},
	}
	s.mu.Lock()
	s.transactions[top.Name] = tx
	s.generations[top.Name] = generationState{
		Committed: "teaching-generation", Prepared: tx.Generation,
	}
	err = s.saveCoordinationLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return lease.Fence, tx
}

// restartedAgent is the node as the next process finds it: nothing in memory,
// everything read back off the journal this one wrote.
func restartedAgent(t *testing.T, store *state.Store, backend *clusterSolveRuntime,
	top *model.Topology,
) (*Server, applyTransaction) {
	t.Helper()
	s := coordinationTestServer(t, store)
	s.cfg.Node = clusterSolveNode
	s.rt = backend
	s.current[top.Name] = top
	s.loadCoordination()
	s.mu.Lock()
	tx := s.transactions[top.Name]
	s.mu.Unlock()
	return s, tx
}

// committedPrune is the prune exactly as commit runs it: the transaction's own
// engine, which writes the reference solution, carrying whatever the
// transition proved it may remove.
func committedPrune(t *testing.T, s *Server, top *model.Topology, tx applyTransaction) ([]string, error) {
	t.Helper()
	eng, err := s.transactionEngine(top, tx)
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := solvePruneEntitlement(tx, top, s.cfg.Node, render.Mode(tx.Mode))
	if err != nil {
		return nil, err
	}
	eng.PreservedOrphans = preserved
	return eng.PruneOrphans(context.Background(), top)
}

// storedConfig is what the state store would replay into a device.
func storedConfig(t *testing.T, store *state.Store, device string) string {
	t.Helper()
	snap, err := store.Current(clusterSolveLabName, device, state.KindFRR)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read the saved state of %s: %v", device, err)
	}
	return string(snap.Content)
}

// The whole sequence, uninterrupted: one deployment preserves the stale
// container before it writes a line of the answer, and its own commit removes
// precisely that container without reading it again.
func TestAClusterSolveWithPrunePreservesTheContainerItThenRemoves(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	fence, tx := preparedSolve(t, s, top, true)

	record, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err != nil {
		t.Fatalf("a solve refused to start on a lab it could read: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("preserving is not removing, but %v had already gone", removed)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
		t.Fatalf("the stale container's work was not saved before the reference solution "+
			"was written; the store holds %q.\nCommit's prune is the only pass that would "+
			"have read it, and by then this node is writing the answer and reads nothing.", got)
	}
	if len(record.Preserved) != 1 || record.Preserved[0].Container != "tw-old" ||
		!record.Preserved[0].Stored {
		t.Fatalf("the transition recorded %+v, want the stale container preserved",
			record.Preserved)
	}
	if err := s.recordGenerationSolveTransition(top.Name, fence, tx.Generation, record); err != nil {
		t.Fatalf("journal what the solve preserved: %v", err)
	}

	// The apply phase writes the answer. Nothing in this lab can be read as a
	// student's work from here on.
	backend.setConfig("tw-old", clusterReferenceAnswer)
	backend.setConfig("tw-atl", clusterReferenceAnswer)

	resumed, committed := restartedAgent(t, store, backend, top)
	if committed.SolveTransition == nil {
		t.Fatal("the journal a restarted agent reads back holds no record of what was preserved")
	}
	gone, err := committedPrune(t, resumed, top, committed)
	if err != nil {
		t.Fatalf("commit would not remove what its own prepare preserved: %v", err)
	}
	if len(gone) != 1 || gone[0] != "tw-old" {
		t.Fatalf("commit pruned %v, want the stale container", gone)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
		t.Fatalf("the saved state of the removed container is %q, want the student's work.\n"+
			"A prune that reads a container in a lab holding the answer files the answer as "+
			"their work; one that reads nothing and deletes anyway loses it.", got)
	}
}

// The regression itself, stated as the rule that stops it: a solve that was
// asked to prune and preserved nothing removes nothing.
func TestAClusterSolvePruneWithNoRecordRefusesBeforeItRemovesAnything(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	_, tx := preparedSolve(t, s, top, true)
	backend.setConfig("tw-old", clusterReferenceAnswer)

	_, err := committedPrune(t, s, top, tx)
	if err == nil {
		t.Fatal("a solve pruned a container nothing had ever read")
	}
	for _, want := range []string{clusterSolveLabName, "preserv", "--prune"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q: %v", want, err)
		}
	}
	if removed := backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("the refusal came after %v had already been removed", removed)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != "" {
		t.Fatalf("the refused prune stored %q for a container it never read", got)
	}
}

// The apply phase is the first thing that writes the answer, so it is the last
// place a missing record still costs only a deployment.
func TestApplyingAReferenceSolutionRefusesWithoutThePreservationRecord(t *testing.T) {
	s, top, _, _ := clusterSolveServer(t)
	_, tx := preparedSolve(t, s, top, true)

	if err := s.solveApplyRefusal(top.Name, tx); err == nil {
		t.Fatal("a node wrote the reference solution for a prune that had preserved nothing")
	}
	// A solve that was not asked to prune removes nothing, so it owes no
	// record; neither does an ordinary teaching deployment, which reads its
	// own orphans when it prunes them.
	noPrune := tx
	noPrune.Prune = false
	if err := s.solveApplyRefusal(top.Name, noPrune); err != nil {
		t.Fatalf("a solve that was not asked to prune was refused: %v", err)
	}
	platform := tx
	platform.Mode = string(render.ModePlatform)
	if err := s.solveApplyRefusal(top.Name, platform); err != nil {
		t.Fatalf("an ordinary pruning deployment was refused: %v", err)
	}
	solved := tx
	solved.PreviousMode = string(render.ModeSolve)
	if err := s.solveApplyRefusal(top.Name, solved); err != nil {
		t.Fatalf("a lab that already held the reference was refused: %v", err)
	}
	recorded := tx
	recorded.SolveTransition = &solveTransition{Lab: top.Name, Node: clusterSolveNode}
	if err := s.solveApplyRefusal(top.Name, recorded); err != nil {
		t.Fatalf("a solve that had preserved its candidates was refused: %v", err)
	}
}

// A crash after preservation and before the apply phase leaves the record and
// the containers exactly as they were. The attempt that follows may finish the
// job; it may not start it again.
func TestAPreparedSolveThatCrashedIsFinishedFromItsJournalledRecord(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	fence, tx := preparedSolve(t, s, top, true)
	record, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordGenerationSolveTransition(top.Name, fence, tx.Generation, record); err != nil {
		t.Fatal(err)
	}
	// The node dies here, having preserved everything and written nothing.
	resumed, recovered := restartedAgent(t, store, backend, top)
	if err := resumed.solveApplyRefusal(top.Name, recovered); err != nil {
		t.Fatalf("the attempt that resumed would not apply what its own record covers: %v", err)
	}
	gone, err := committedPrune(t, resumed, top, recovered)
	if err != nil {
		t.Fatalf("the resumed attempt would not remove what was preserved: %v", err)
	}
	if len(gone) != 1 || gone[0] != "tw-old" {
		t.Fatalf("the resumed attempt pruned %v, want the stale container", gone)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
		t.Fatalf("the resumed attempt left %q saved for the container it removed", got)
	}
}

// A second attempt at a lab whose apply phase has begun must not read it. The
// first thing prepare does is capture what it is about to destroy, and after a
// partial solve that is the answer rather than anybody's work.
func TestASecondPrepareNeverRecapturesAPossiblySolvedLab(t *testing.T) {
	s, top, _, _ := clusterSolveServer(t)
	fence, tx := preparedSolve(t, s, top, true)

	// Nothing has been written yet, so the same fenced attempt arriving twice
	// is a duplicate rather than a second attempt.
	if err := s.solveRecaptureRefusal(top.Name, tx.Generation, fence); err != nil {
		t.Fatalf("a duplicate prepare of an unstarted transaction was refused: %v", err)
	}
	for _, phase := range []transactionPhase{
		transactionApplying, transactionApplied, transactionRollbackNeeded,
		transactionRecovering, transactionCommitted,
	} {
		started := tx
		started.Phase = phase
		s.mu.Lock()
		s.transactions[top.Name] = started
		s.mu.Unlock()
		err := s.solveRecaptureRefusal(top.Name, tx.Generation, fence)
		if err == nil {
			t.Fatalf("a prepare read a lab whose solve was %s; the devices may already "+
				"hold the answer, and capturing files it as the students' own work", phase)
		}
		if !strings.Contains(err.Error(), "reference solution") {
			t.Fatalf("the refusal for %s does not say why: %v", phase, err)
		}
	}
	// A different generation is a fresh deployment over an unfinished solve,
	// which is the retry that lost the work.
	s.mu.Lock()
	applying := tx
	applying.Phase = transactionApplying
	s.transactions[top.Name] = applying
	s.mu.Unlock()
	if err := s.solveRecaptureRefusal(top.Name, "next-generation", fence); err == nil {
		t.Fatal("a new generation was prepared over an unfinished solve")
	}
	// A teaching transaction has no answer to protect, and must keep working.
	s.mu.Lock()
	platform := tx
	platform.Mode, platform.Phase = string(render.ModePlatform), transactionApplying
	s.transactions[top.Name] = platform
	s.mu.Unlock()
	if err := s.solveRecaptureRefusal(top.Name, "next-generation", fence); err != nil {
		t.Fatalf("an ordinary deployment was refused as if it were a solve: %v", err)
	}
}

// One unprovable candidate stops the whole prune. Each of these is a way the
// record can stop describing what is in front of the node, and each names the
// container and the remedy rather than guessing.
func TestAClusterPruneRefusesEveryRecordItCannotProve(t *testing.T) {
	base := func(t *testing.T) (*Server, *model.Topology, *state.Store, *clusterSolveRuntime,
		Fence, applyTransaction,
	) {
		t.Helper()
		s, top, store, backend := clusterSolveServer(t)
		fence, tx := preparedSolve(t, s, top, true)
		record, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.recordGenerationSolveTransition(top.Name, fence, tx.Generation, record); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		tx = s.transactions[top.Name]
		s.mu.Unlock()
		backend.setConfig("tw-old", clusterReferenceAnswer)
		return s, top, store, backend, fence, tx
	}

	cases := []struct {
		name   string
		want   string
		break_ func(*model.Topology, *clusterSolveRuntime, *applyTransaction)
	}{{
		name: "a record that could not be read back",
		want: "preserv",
		break_: func(_ *model.Topology, _ *clusterSolveRuntime, tx *applyTransaction) {
			tx.SolveTransition = nil
		},
	}, {
		name: "a first attempt that was never asked to prune",
		want: "not asked to prune",
		break_: func(_ *model.Topology, _ *clusterSolveRuntime, tx *applyTransaction) {
			tx.SolveTransition.Prune = false
		},
	}, {
		name: "a record preserved on another node",
		want: "on node",
		break_: func(_ *model.Topology, _ *clusterSolveRuntime, tx *applyTransaction) {
			tx.SolveTransition.Node = "n1"
		},
	}, {
		name: "a record from an earlier attempt",
		want: "generation",
		break_: func(_ *model.Topology, _ *clusterSolveRuntime, tx *applyTransaction) {
			tx.SolveTransition.Generation = "an-earlier-generation"
		},
	}, {
		name: "a record taken under an older fence",
		want: "fence",
		break_: func(_ *model.Topology, _ *clusterSolveRuntime, tx *applyTransaction) {
			tx.SolveTransition.Fence--
		},
	}, {
		name: "a manifest edited since the preservation",
		want: "manifest has changed",
		break_: func(top *model.Topology, _ *clusterSolveRuntime, _ *applyTransaction) {
			top.Hash = "topology-as-edited"
		},
	}, {
		name: "a container that appeared in the meantime",
		want: "tw-new",
		break_: func(_ *model.Topology, backend *clusterSolveRuntime, _ *applyTransaction) {
			backend.add("tw-new", "as4/NEW", clusterSolveNode)
			backend.setConfig("tw-new", clusterStudentWork)
		},
	}, {
		name: "a container now carrying a different identifier",
		want: "as9/OTHER",
		break_: func(_ *model.Topology, backend *clusterSolveRuntime, _ *applyTransaction) {
			backend.relabel("tw-old", deploy.LabelDeviceID, "as9/OTHER")
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, top, store, backend, _, tx := base(t)
			tc.break_(top, backend, &tx)
			_, err := committedPrune(t, s, top, tx)
			if err == nil {
				t.Fatal("the prune removed a container it could not prove it had preserved")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not name %q: %v", tc.want, err)
			}
			if removed := backend.wasRemoved(); len(removed) != 0 {
				t.Fatalf("the refusal came after %v had been removed", removed)
			}
			if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
				t.Fatalf("the refused prune left %q saved for the stale container", got)
			}
		})
	}
}

// The deployments that must keep working, unchanged.
func TestOrdinaryClusterPrunesAreUnaffectedByTheTransition(t *testing.T) {
	t.Run("a teaching deployment still reads and removes its own orphans", func(t *testing.T) {
		s, top, store, backend := clusterSolveServer(t)
		_, tx := preparedSolve(t, s, top, true)
		tx.Mode = string(render.ModePlatform)
		gone, err := committedPrune(t, s, top, tx)
		if err != nil {
			t.Fatalf("an ordinary pruning deployment refused: %v", err)
		}
		if len(gone) != 1 || gone[0] != "tw-old" {
			t.Fatalf("an ordinary prune removed %v, want the stale container", gone)
		}
		if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
			t.Fatalf("an ordinary prune saved %q for the container it removed", got)
		}
		if reads := backend.wasRead(); len(reads) == 0 {
			t.Fatal("an ordinary prune removed a container without reading it")
		}
	})

	t.Run("a lab that already holds the reference reads and writes nothing", func(t *testing.T) {
		s, top, store, backend := clusterSolveServer(t)
		_, tx := preparedSolve(t, s, top, true)
		tx.PreviousMode = string(render.ModeSolve)
		backend.setConfig("tw-old", clusterReferenceAnswer)
		gone, err := committedPrune(t, s, top, tx)
		if err != nil {
			t.Fatalf("a solved lab's prune refused: %v", err)
		}
		if len(gone) != 1 || gone[0] != "tw-old" {
			t.Fatalf("a solved lab's prune removed %v, want the stale container", gone)
		}
		if got := storedConfig(t, store, "as3/OLD"); got != "" {
			t.Fatalf("a solved lab's prune filed %q as a student's work", got)
		}
	})

	t.Run("a deployment that was not asked to prune removes nothing", func(t *testing.T) {
		s, top, _, backend := clusterSolveServer(t)
		fence, tx := preparedSolve(t, s, top, false)
		if solvePreservationRequired(render.Mode(tx.Mode), tx.PreviousMode, tx.Prune) {
			t.Fatal("a deployment that removes nothing was asked to preserve prune candidates")
		}
		if err := s.solveApplyRefusal(top.Name, tx); err != nil {
			t.Fatalf("a solve that was not asked to prune was refused: %v", err)
		}
		if _, err := solvePruneEntitlement(tx, top, s.cfg.Node, render.Mode(tx.Mode)); err != nil {
			t.Fatalf("a non-pruning transaction was refused an entitlement it never uses: %v", err)
		}
		_ = fence
		if removed := backend.wasRemoved(); len(removed) != 0 {
			t.Fatalf("a deployment that was not asked to prune removed %v", removed)
		}
	})
}

// Only this node's containers, and only this node's record. A lab split across
// nodes must not have one node's preservation used to justify another's
// removals, and a container another node owns is not this one's to remove.
func TestPreservationIsScopedToTheNodeThatTookIt(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	// A container the placement puts on the other node, which happens to be
	// visible here -- a partition healing, a migration part way through.
	backend.add("tw-far", "as5/FAR", "n1")
	backend.setConfig("tw-far", clusterStudentWork)
	fence, tx := preparedSolve(t, s, top, true)

	record, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range record.Preserved {
		if preserved.Container == "tw-far" {
			t.Fatal("a node preserved a container another node owns, which its own " +
				"preservation would then be entitled to remove")
		}
	}
	if record.Node != clusterSolveNode {
		t.Fatalf("the record names node %q, not the node that took it", record.Node)
	}
	if err := s.recordGenerationSolveTransition(top.Name, fence, tx.Generation, record); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	tx = s.transactions[top.Name]
	s.mu.Unlock()
	gone, err := committedPrune(t, s, top, tx)
	if err != nil {
		t.Fatalf("the prune refused what it had preserved: %v", err)
	}
	if len(gone) != 1 || gone[0] != "tw-old" {
		t.Fatalf("the prune removed %v; the other node's container is not this one's to "+
			"remove", gone)
	}
	if got := storedConfig(t, store, "as5/FAR"); got != "" {
		t.Fatalf("this node captured %q for a device another node owns", got)
	}
}

// A candidate that cannot be read is a candidate that cannot be preserved, and
// a solve that cannot preserve one does not start.
func TestASolveRefusesToStartWhenACandidateCannotBePreserved(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	backend.mu.Lock()
	backend.unreadable["tw-old"] = true
	backend.mu.Unlock()
	fence, tx := preparedSolve(t, s, top, true)

	if _, err := s.preserveSolveTransition(context.Background(), top, tx, fence); err == nil {
		t.Fatal("a solve began on a lab holding a container it could not read")
	}
	s.mu.Lock()
	stored := s.transactions[top.Name]
	s.mu.Unlock()
	if stored.SolveTransition != nil {
		t.Fatal("a refused preservation still recorded itself as proof")
	}
	if removed := backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("a refused preservation removed %v", removed)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != "" {
		t.Fatalf("a refused preservation stored %q", got)
	}
}

// A container with no canonical identifier cannot have its work filed under
// anything, so it cannot be preserved and the solve does not start.
func TestASolveRefusesToStartOnACandidateWithNoIdentity(t *testing.T) {
	s, top, _, backend := clusterSolveServer(t)
	backend.relabel("tw-old", deploy.LabelDeviceID, "")
	fence, tx := preparedSolve(t, s, top, true)

	_, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err == nil {
		t.Fatal("a solve began on a lab holding a container it could not identify")
	}
	if !strings.Contains(err.Error(), "canonical device identifier") {
		t.Fatalf("the refusal does not say what is ambiguous: %v", err)
	}
}

// The copies have to leave this node before the answer lands on it. A lab
// whose policy asks for peer failure domains and cannot reach them has not
// preserved anything against the failure the policy was written for.
func TestPreservationRefusesWhenItsCopiesCannotReachThePolicysPeers(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	top.Lab.State.ReplicationFactor = 2
	top.Lab.State.FailClosed = boolPointer(true)
	s.peerDial = func(context.Context, model.NodeSpec) (peerStateClient, error) {
		return nil, errors.New("peer unreachable")
	}
	fence, tx := preparedSolve(t, s, top, true)

	_, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err == nil {
		t.Fatal("a solve began with the only copy of a preserved container on the node " +
			"that was about to rewrite the lab")
	}
	if !strings.Contains(err.Error(), "reference solution") {
		t.Fatalf("the refusal does not say what it is refusing: %v", err)
	}
	if removed := backend.wasRemoved(); len(removed) != 0 {
		t.Fatalf("a refused preservation removed %v", removed)
	}
	// The local copy is still taken: refusing is about the proof, and the
	// reading is what a later attempt no longer has to make.
	if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
		t.Fatalf("the refused preservation left %q on this node", got)
	}

	// A policy that explicitly permits the audited bypass still deploys, and
	// says in the record that the copies never left.
	top.Lab.State.FailClosed = boolPointer(false)
	record, err := s.preserveSolveTransition(context.Background(), top, tx, fence)
	if err != nil {
		t.Fatalf("an explicitly fail-open lab was refused: %v", err)
	}
	if record.Replicated {
		t.Fatal("a record claims its copies reached the policy's peers when none did")
	}
}

// The rollback that undoes a failed solve meets both kinds of container at
// once: the ones the forward half wrote the answer into, and the ones it never
// touched.
func TestRollingBackASolveNeitherReadsTheAnswerNorStrandsTheRest(t *testing.T) {
	s, top, store, backend := clusterSolveServer(t)
	_, tx := preparedSolve(t, s, top, false)
	// The forward half created a device the old manifest never had, and wrote
	// the reference solution into it and into the router it adopted.
	backend.add("tw-new", "as4/NEW", clusterSolveNode)
	backend.setConfig("tw-new", clusterReferenceAnswer)
	backend.setConfig("tw-atl", clusterReferenceAnswer)
	forward := clusterSolveTopology("topology-as-written")
	added := &model.Device{
		ID: "as4/NEW", Name: "NEW", ASN: 4, Kind: model.KindRouter,
		Container: "tw-new", Node: clusterSolveNode,
	}
	forward.Devices[added.ID] = added
	forward.ASes[4] = &model.AS{ASN: 4, Role: model.RoleStudent,
		Devices: []*model.Device{added}, Routers: []*model.Device{added}}

	// The old manifest wanted neither the new device nor the stale container,
	// so a rollback's prune sees both.
	old := &model.Topology{
		Lab: top.Lab, Name: top.Name, Hash: "topology-before",
		Devices:  map[string]*model.Device{},
		ASes:     map[int]*model.AS{},
		Services: map[string]*model.Service{},
	}
	set := rollbackPrunePreservation(tx, forward, clusterSolveNode, render.ModePlatform)
	if set == nil {
		t.Fatal("a rollback of a solve was given no way to tell the answer from the work")
	}
	eng := &deploy.Engine{
		Runtime: backend, Node: clusterSolveNode, State: store, PreservedOrphans: set,
	}
	gone, err := eng.PruneOrphans(context.Background(), old)
	if err != nil {
		t.Fatalf("a rollback refused to remove what the transaction it undoes created: %v", err)
	}
	if len(gone) != 3 {
		t.Fatalf("a rollback removed %v, want every container the old manifest lacks", gone)
	}
	if got := storedConfig(t, store, "as4/NEW"); got != "" {
		t.Fatalf("a rollback filed %q as the work of a device the failed solve created", got)
	}
	if got := storedConfig(t, store, "as3/ATL"); got != "" {
		t.Fatalf("a rollback filed %q as the work of a router the failed solve solved", got)
	}
	if got := storedConfig(t, store, "as3/OLD"); got != clusterStudentWork {
		t.Fatalf("a rollback removed the container the failed solve never touched without "+
			"saving what was in it: the store holds %q", got)
	}
}

// A rollback whose prepared state was never proven durable may still remove
// what the transaction itself created, and must not remove what it adopted.
func TestARollbackWithoutProvenPriorStateKeepsWhatItCannotAccountFor(t *testing.T) {
	s, top, _, backend := clusterSolveServer(t)
	_, tx := preparedSolve(t, s, top, false)
	tx.Prestate.StateSafe = false
	backend.add("tw-new", "as4/NEW", clusterSolveNode)
	forward := clusterSolveTopology("topology-as-written")
	added := &model.Device{
		ID: "as4/NEW", Name: "NEW", ASN: 4, Kind: model.KindRouter,
		Container: "tw-new", Node: clusterSolveNode,
	}
	forward.Devices[added.ID] = added

	set := rollbackPrunePreservation(tx, forward, clusterSolveNode, render.ModePlatform)
	removable := map[string]bool{}
	for _, name := range set.Removable {
		removable[name] = true
	}
	if !removable["tw-new"] {
		t.Fatal("a rollback would not remove a container the transaction it undoes created")
	}
	if removable["tw-atl"] {
		t.Fatal("a rollback would remove a router the failed solve wrote the answer into, " +
			"although the student state it replaced was never proven durable")
	}
	unreadable := map[string]bool{}
	for _, name := range set.Unreadable {
		unreadable[name] = true
	}
	if !unreadable["tw-atl"] || !unreadable["tw-new"] {
		t.Fatalf("a rollback would read %v as student work", set.Unreadable)
	}
	if unreadable["tw-old"] {
		t.Fatal("a rollback would not read the container the failed solve never touched, " +
			"which holds the only copy of somebody's work")
	}
}

// A rollback of a deployment that never wrote a reference answer is the prune
// it always was.
func TestRollingBackATeachingDeploymentIsUnchanged(t *testing.T) {
	s, top, _, _ := clusterSolveServer(t)
	_, tx := preparedSolve(t, s, top, false)
	tx.Mode = string(render.ModePlatform)
	forward := clusterSolveTopology("topology-as-written")
	if set := rollbackPrunePreservation(tx, forward, clusterSolveNode, render.ModePlatform); set != nil {
		t.Fatalf("an ordinary rollback was given a transition record: %+v", set)
	}
	solved := tx
	solved.Mode = string(render.ModeSolve)
	if set := rollbackPrunePreservation(solved, forward, clusterSolveNode, render.ModeSolve); set != nil {
		t.Fatalf("a lab that already held the reference was given a transition record: %+v", set)
	}
}

func boolPointer(v bool) *bool { return &v }
