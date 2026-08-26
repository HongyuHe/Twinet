package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/state"
)

// committedRecoveryServer is a node that acknowledged commit for a generation
// its cluster did not commit everywhere. Finalization never ran, so the
// rollback material is still here -- which is the only reason the split is
// recoverable at all.
func committedRecoveryServer(t *testing.T, st *state.Store) *Server {
	t.Helper()
	s, inventory := recoveryServer(t, st)
	tx := s.transactions["cos461"]
	tx.Applied, tx.Committed, tx.Phase = true, true, transactionCommitted
	s.transactions["cos461"] = tx
	s.generations["cos461"] = generationState{Committed: "failed-generation"}
	// The committed inventory is what this node actually holds, so an
	// ordinary recovery of it verifies rather than repairs.
	committed := inventory
	committed.Generation = "failed-generation"
	s.inventories["cos461"] = committed
	return s
}

func TestACommittedGenerationIsNotAbandonedWithoutAClusterDecision(t *testing.T) {
	s := committedRecoveryServer(t, nil)
	s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error {
		t.Fatal("a committed generation was rolled back without a cluster decision")
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.recoverTransaction(context.Background(), "cos461", lease.Fence); err != nil {
		t.Fatal(err)
	}
	if state := s.generations["cos461"]; state.Committed != "failed-generation" {
		t.Fatalf("an ordinary recovery moved a committed generation: %+v", state)
	}
}

func TestAnAcknowledgedSplitCommitRollsBackToThePreviousGeneration(t *testing.T) {
	s := committedRecoveryServer(t, nil)
	rolled := 0
	s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error {
		rolled++
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.recoverTransactionStrategyOptions(context.Background(), "cos461", lease.Fence,
		"rollback", recoveryRunOptions{rollbackCommitted: true})
	if err != nil {
		t.Fatalf("an acknowledged split commit could not be rolled back: %v", err)
	}
	if rolled != 1 {
		t.Fatalf("rollback ran %d times", rolled)
	}
	if !status.Consistent || status.Generation != "old-generation" {
		t.Fatalf("the node did not converge on the previous generation: %+v", status)
	}
	s.mu.Lock()
	generation := s.generations["cos461"]
	_, active := s.transactions["cos461"]
	s.mu.Unlock()
	if generation.Committed != "old-generation" || generation.Prepared != "" {
		t.Fatalf("committed generation after split-commit rollback = %+v", generation)
	}
	if active {
		t.Fatal("the abandoned transaction still blocks ordinary deploys")
	}
}

func TestASplitCommitRollbackDecisionSurvivesAnInterruption(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := committedRecoveryServer(t, store)
	if err := s.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reopenCommittedTransaction("cos461", lease.Fence, "failed-generation"); err != nil {
		t.Fatal(err)
	}

	reopenedStore, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := coordinationTestServer(t, reopenedStore)
	restarted.loadCoordination()
	tx, ok := restarted.transactions["cos461"]
	if !ok {
		t.Fatal("the reopened transaction did not survive a restart")
	}
	if tx.Committed {
		t.Fatal("an interruption restored the committed flag, so the split would be permanent again")
	}
	if tx.Phase != transactionRollbackNeeded {
		t.Fatalf("reopened transaction phase = %q, want rollback_needed", tx.Phase)
	}
	if generation := restarted.generations["cos461"]; generation.Committed != "old-generation" {
		t.Fatalf("the committed generation was not returned to its previous value: %+v", generation)
	}
}

func TestAFinalizedGenerationCannotBeAbandoned(t *testing.T) {
	s := committedRecoveryServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	// Finalization is the point after which the rollback material is gone.
	tx := s.transactions["cos461"]
	tx.FenceGeneration = lease.Fence.Generation
	s.transactions["cos461"] = tx
	if err := s.finalizeCommittedGeneration("cos461", lease.Fence, "failed-generation"); err != nil {
		t.Fatal(err)
	}
	_, err = s.reopenCommittedTransaction("cos461", lease.Fence, "failed-generation")
	if err == nil {
		t.Fatal("a finalized generation was reopened with no rollback material to restore")
	}
	if !strings.Contains(err.Error(), "rollback material") {
		t.Fatalf("the refusal does not explain why: %v", err)
	}
}

func TestASplitCommitIsNotAbandonedWithoutADurablePreState(t *testing.T) {
	s := committedRecoveryServer(t, nil)
	tx := s.transactions["cos461"]
	tx.Prestate.StateSafe = false
	s.transactions["cos461"] = tx
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.reopenCommittedTransaction("cos461", lease.Fence, "failed-generation")
	if err == nil {
		t.Fatal("a committed generation was abandoned over a node that never captured student state")
	}
	if !strings.Contains(err.Error(), "durably captured") {
		t.Fatalf("the refusal does not explain why: %v", err)
	}
}

func TestCommittedPendingIsVisibleToACoordinator(t *testing.T) {
	s := committedRecoveryServer(t, nil)
	status := s.transactionInventoryStatus(context.Background(), "cos461")
	if !status.CommittedPending {
		t.Fatalf("a committed but unfinalized generation is invisible to a coordinator: %+v", status)
	}
	if status.PreviousGeneration != "old-generation" {
		t.Fatalf("status does not name the generation a rollback would reach: %+v", status)
	}
	if len(status.AllowedStrategies) != 1 || status.AllowedStrategies[0] != "rollback" {
		t.Fatalf("allowed strategies = %v", status.AllowedStrategies)
	}
}
