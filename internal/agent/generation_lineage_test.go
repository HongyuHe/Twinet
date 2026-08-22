package agent

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/HongyuHe/twinet/internal/state"
)

func lineageServer(t *testing.T) (*Server, Fence) {
	t.Helper()
	s := coordinationTestServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	return s, lease.Fence
}

func TestNoChangeCommitAdvancesLabGenerationWithoutRelabelingObjects(t *testing.T) {
	s, fence := lineageServer(t)
	s.generations["lab"] = generationState{Committed: "old"}
	s.transactions["lab"] = applyTransaction{
		Generation: "new", PreviousGen: "old", FenceGeneration: fence.Generation, Applied: true,
		TouchedKnown: true,
	}
	inventory := transactionInventory{
		Generation: "new",
		Containers: []transactionContainer{{
			Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "stable-spec",
			Generation: "old", State: "running",
		}},
		VNIs: []uint32{100},
	}
	s.overlayLineage["lab"] = map[uint32]string{100: "old"}
	if err := s.finishCommittedGeneration("lab", fence, "new", inventory); err != nil {
		t.Fatal(err)
	}
	if got := s.generations["lab"].Committed; got != "new" {
		t.Fatalf("lab committed generation = %q, want new", got)
	}
	if got := s.inventories["lab"].Containers[0].Generation; got != "old" {
		t.Fatalf("unchanged object generation = %q, want old", got)
	}
	if got := s.overlayLineage["lab"][100]; got != "old" {
		t.Fatalf("reused VNI lineage = %q, want old", got)
	}
	got, err := expectedObjectGeneration(applyTransaction{
		Generation: "new", TouchedKnown: true, Prestate: transactionInventory{
			Containers: inventory.Containers,
		},
	}, "as1/R1", "twinet-lab-r1", "stable-spec",
		map[string]transactionContainer{"as1/R1": inventory.Containers[0]}, nil)
	if err != nil || got != "old" {
		t.Fatalf("no-change object lineage = %q, %v; want old", got, err)
	}
	relabelled := inventory
	relabelled.Containers = append([]transactionContainer(nil), inventory.Containers...)
	relabelled.Containers[0].Generation = "new"
	if err := inventoryMatchesCommitted(inventory, relabelled); err == nil {
		t.Fatal("a no-change transaction accepted needless relabeling")
	}
}

func TestMixedTouchedInventoryKeepsOldAndNewCreationGenerations(t *testing.T) {
	s, fence := lineageServer(t)
	s.generations["lab"] = generationState{Committed: "old"}
	s.transactions["lab"] = applyTransaction{
		Generation: "new", PreviousGen: "old", FenceGeneration: fence.Generation, Applied: true,
		Touched: []string{"as2/R1"}, TouchedKnown: true,
	}
	inventory := transactionInventory{Generation: "new", Containers: []transactionContainer{
		{Name: "twinet-lab-stable", DeviceID: "as1/R1", Spec: "old-spec", Generation: "old", State: "running"},
		{Name: "twinet-lab-moved", DeviceID: "as2/R1", Spec: "new-spec", Generation: "new", State: "running"},
	}}
	if err := s.finishCommittedGeneration("lab", fence, "new", inventory); err != nil {
		t.Fatal(err)
	}
	if err := s.validateInventoryLineage("lab", inventory, "new"); err != nil {
		t.Fatalf("valid mixed lineage was rejected: %v", err)
	}
	tx := s.transactions["lab"]
	prestate := map[string]transactionContainer{
		"as1/R1": {Name: "twinet-lab-stable", DeviceID: "as1/R1", Spec: "old-spec", Generation: "old"},
	}
	stable, err := expectedObjectGeneration(tx, "as1/R1", "twinet-lab-stable", "old-spec", prestate, nil)
	if err != nil || stable != "old" {
		t.Fatalf("stable object lineage = %q, %v; want old", stable, err)
	}
	moved, err := expectedObjectGeneration(tx, "as2/R1", "twinet-lab-moved", "new-spec", prestate, nil)
	if err != nil || moved != "new" {
		t.Fatalf("recreated object lineage = %q, %v; want new", moved, err)
	}
}

func TestUnknownObjectGenerationAndWrongSpecAreRejected(t *testing.T) {
	s, _ := lineageServer(t)
	s.generations["lab"] = generationState{Committed: "old", Ancestors: []string{"older"}}
	unknown := transactionInventory{Containers: []transactionContainer{{
		Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "wrong",
		Generation: "foreign", State: "running",
	}}}
	if err := s.validateInventoryLineage("lab", unknown, "new"); err == nil {
		t.Fatal("unrelated object generation was accepted")
	}
	want := transactionInventory{Containers: []transactionContainer{{
		Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "right",
		Generation: "old", State: "running",
	}}}
	got := transactionInventory{Containers: []transactionContainer{{
		Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "wrong",
		Generation: "old", State: "running",
	}}}
	if err := inventoryMatches(want, got); err == nil {
		t.Fatal("wrong-spec object with ancestor generation was accepted")
	}
	tx := applyTransaction{
		Generation: "new", TouchedKnown: true,
		Prestate: transactionInventory{Containers: []transactionContainer{{
			Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "old-spec", Generation: "old",
		}}},
	}
	if _, err := expectedObjectGeneration(tx, "as1/R1", "twinet-lab-r1", "new-spec",
		map[string]transactionContainer{"as1/R1": tx.Prestate.Containers[0]}, nil); err == nil {
		t.Fatal("changed spec without a touched record was accepted")
	}
	if _, err := expectedObjectGeneration(tx, "as2/R1", "twinet-lab-r2", "new-spec", nil, nil); err == nil {
		t.Fatal("new object without a touched record was accepted")
	}
}

func TestMovedOrRecreatedObjectMustCarryCurrentGeneration(t *testing.T) {
	tx := applyTransaction{Generation: "new", Touched: []string{"as2/R1"}, TouchedKnown: true}
	want, err := expectedObjectGeneration(tx, "as2/R1", "twinet-lab-moved", "new-spec", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inventory := transactionInventory{Containers: []transactionContainer{{
		Name: "twinet-lab-moved", DeviceID: "as2/R1", Spec: "new-spec", Generation: want,
		State: "running",
	}}}
	stale := inventory
	stale.Containers = append([]transactionContainer(nil), inventory.Containers...)
	stale.Containers[0].Generation = "old"
	if err := inventoryMatchesCommitted(inventory, stale); err == nil {
		t.Fatal("recreated object with an old generation was accepted")
	}
}

func TestNonPruningCommitStillRejectsUnrecordedRecreate(t *testing.T) {
	expected := transactionInventory{
		Generation: "new", TopologyHash: "topology",
		Containers: []transactionContainer{{
			Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "stable-spec", Generation: "old", State: "running",
		}},
		VNIs: []uint32{100},
	}
	actual := transactionInventory{
		Containers: []transactionContainer{
			{Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "stable-spec", Generation: "new", State: "running"},
			{Name: "twinet-lab-extra", DeviceID: "as9/R9", Spec: "extra-spec", Generation: "old", State: "running"},
		},
		VNIs: []uint32{100, 101},
	}
	merged, err := mergePreservedInventory(expected, actual)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventoryMatchesCommitted(merged, actual); err == nil {
		t.Fatal("non-pruning commit accepted an unrecorded desired-object recreation")
	}
	actual.Containers[0].Generation = "old"
	if _, err := mergePreservedInventory(expected, actual); err != nil {
		t.Fatalf("matching desired object was rejected with preserved extra: %v", err)
	}
	actual.Containers[0].Spec = "wrong-spec"
	if _, err := mergePreservedInventory(expected, actual); err == nil {
		t.Fatal("non-pruning commit accepted a stale desired-object spec")
	}
}

func TestOverlayLineageTracksTouchedAndReusedVNIs(t *testing.T) {
	s, fence := lineageServer(t)
	s.generations["lab"] = generationState{Committed: "old"}
	s.overlayLineage["lab"] = map[uint32]string{100: "old", 101: "old"}
	s.transactions["lab"] = applyTransaction{
		Generation: "new", PreviousGen: "old", FenceGeneration: fence.Generation, Applied: true,
		TouchedVNIs: []uint32{100}, TouchedKnown: true,
	}
	inventory := transactionInventory{Generation: "new", VNIs: []uint32{100, 101}}
	if err := s.finishCommittedGeneration("lab", fence, "new", inventory); err != nil {
		t.Fatal(err)
	}
	if got := s.overlayLineage["lab"][100]; got != "new" {
		t.Fatalf("touched VNI lineage = %q, want new", got)
	}
	if got := s.overlayLineage["lab"][101]; got != "old" {
		t.Fatalf("reused VNI lineage = %q, want old", got)
	}
}

func TestLongLivedUnchangedObjectKeepsAncestry(t *testing.T) {
	s, _ := lineageServer(t)
	state := generationState{Committed: "generation-0"}
	for i := 1; i <= 40; i++ {
		next := fmt.Sprintf("generation-%d", i)
		state.Ancestors = appendGenerationLineage(state.Ancestors, state.Committed, next)
		state.Committed = next
	}
	s.generations["lab"] = state
	inventory := transactionInventory{Containers: []transactionContainer{{
		Name: "twinet-lab-stable", DeviceID: "as1/R1", Spec: "stable-spec",
		Generation: "generation-0", State: "running",
	}}}
	if err := s.validateInventoryLineage("lab", inventory, state.Committed); err != nil {
		t.Fatalf("long-lived unchanged object lost valid ancestry: %v", err)
	}
}

func TestTouchedSetPersistsBeforeApply(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, fence := lineageServerWithStore(t, store)
	raw, err := json.Marshal(&Wire{Lab: "lab", Mode: "platform"})
	if err != nil {
		t.Fatal(err)
	}
	if err := before.prepareGeneration("lab", fence, "", "new", raw,
		"platform", 0, nil, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := before.recordGenerationTouched("lab", fence, "new",
		[]string{"as2/R1", "as1/R1", "as2/R1"}, []uint32{101, 100, 101}, true); err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, store)
	after.loadCoordination()
	tx := after.transactions["lab"]
	if !tx.TouchedKnown || len(tx.Touched) != 2 || tx.Touched[0] != "as1/R1" || tx.Touched[1] != "as2/R1" ||
		len(tx.TouchedVNIs) != 2 || tx.TouchedVNIs[0] != 100 || tx.TouchedVNIs[1] != 101 {
		t.Fatalf("persisted pre-apply touched set = %+v", tx)
	}
}

func TestForwardLineageSurvivesAgentRestart(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, fence := lineageServerWithStore(t, store)
	before.generations["lab"] = generationState{Committed: "old", Ancestors: []string{"older"}}
	before.overlayLineage["lab"] = map[uint32]string{100: "older"}
	before.transactions["lab"] = applyTransaction{
		Generation: "new", PreviousGen: "old", FenceGeneration: fence.Generation,
		Touched: []string{"as2/R1"}, TouchedVNIs: []uint32{101}, TouchedKnown: true,
		Prestate: transactionInventory{Containers: []transactionContainer{{
			Name: "twinet-lab-stable", DeviceID: "as1/R1", Spec: "stable-spec", Generation: "older",
		}}},
	}
	if err := before.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, store)
	after.loadCoordination()
	tx := after.transactions["lab"]
	if !tx.TouchedKnown || len(tx.Touched) != 1 || tx.Touched[0] != "as2/R1" ||
		len(tx.TouchedVNIs) != 1 || tx.TouchedVNIs[0] != 101 {
		t.Fatalf("forward touched state did not survive restart: %+v", tx)
	}
	stable, err := expectedObjectGeneration(tx, "as1/R1", "twinet-lab-stable", "stable-spec",
		map[string]transactionContainer{"as1/R1": tx.Prestate.Containers[0]}, nil)
	if err != nil || stable != "older" {
		t.Fatalf("restart lost unchanged object lineage: %q, %v", stable, err)
	}
	moved, err := expectedObjectGeneration(tx, "as2/R1", "twinet-lab-moved", "new-spec", nil, nil)
	if err != nil || moved != "new" {
		t.Fatalf("restart lost recreated object lineage: %q, %v", moved, err)
	}
	if err := after.validateInventoryLineage("lab", transactionInventory{VNIs: []uint32{100}}, "new"); err != nil {
		t.Fatalf("restart lost overlay ancestry: %v", err)
	}
}

func lineageServerWithStore(t *testing.T, store *state.Store) (*Server, Fence) {
	t.Helper()
	s := coordinationTestServer(t, store)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	return s, lease.Fence
}
