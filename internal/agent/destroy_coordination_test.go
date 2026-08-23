package agent

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestFinishDestroyedLabClearsCommittedInventoryForRedeploy(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := coordinationTestServer(t, store)
	server.recoveryContainers = func(context.Context, string) ([]rt.Container, error) {
		return nil, nil
	}
	const lab = "clos-acceptance"
	server.generations[lab] = generationState{Committed: "20260823T022156"}
	server.inventories[lab] = transactionInventory{
		Generation: "20260823T022156",
		Containers: make([]transactionContainer, 11),
	}
	server.current[lab] = &model.Topology{Name: lab}
	server.modes[lab] = "solve"
	server.ungraded[lab] = 3
	server.peers[lab] = map[string]string{"node-1": "192.0.2.1"}
	server.overlayLineage[lab] = map[uint32]string{1001: "20260823T022156"}
	server.overlayClaims[1001] = overlayClaim{Lab: lab, Generation: 1, Live: true}
	if err := server.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}

	before := server.transactionInventoryStatus(context.Background(), lab)
	if before.Consistent || before.ExpectedContainers != 11 || before.ObservedContainers != 0 {
		t.Fatalf("test setup did not reproduce stale committed inventory: %+v", before)
	}
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.finishDestroyedLab(lab, lease.Fence); err != nil {
		t.Fatal(err)
	}
	if status := server.transactionInventoryStatus(context.Background(), lab); status.Phase != "idle" {
		t.Fatalf("destroy left stale recovery status: %+v", status)
	}

	restarted := coordinationTestServer(t, store)
	restarted.loadCoordination()
	if _, ok := restarted.generations[lab]; ok {
		t.Fatal("destroyed generation survived agent restart")
	}
	if _, ok := restarted.inventories[lab]; ok {
		t.Fatal("destroyed inventory survived agent restart")
	}
	if _, ok := restarted.overlayLineage[lab]; ok {
		t.Fatal("destroyed overlay lineage survived agent restart")
	}
	for _, claim := range restarted.overlayClaims {
		if claim.Lab == lab {
			t.Fatal("destroyed overlay ownership survived agent restart")
		}
	}

	nextLease, err := restarted.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"lab":"clos-acceptance","mode":"solve"}`)
	if err := restarted.prepareGeneration(lab, nextLease.Fence, "", "next-generation",
		raw, "solve", 0, nil, false, nil, nil); err != nil {
		t.Fatalf("destroyed lab could not be redeployed from an empty generation: %v", err)
	}
}
