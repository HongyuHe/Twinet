package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func recoveryInventory() transactionInventory {
	return transactionInventory{
		Generation:   "old-generation",
		TopologyHash: "old-topology",
		CapturedAt:   time.Now(),
		StateSafe:    true,
		Containers: []transactionContainer{{
			Name: "twinet-cos461-as1-r1", DeviceID: "as1/R1",
			Spec: "old-spec", Generation: "old-generation", State: string(rt.StateRunning),
		}},
		VNIs: []uint32{1001},
	}
}

func recoveryServer(t *testing.T, st *state.Store) (*Server, transactionInventory) {
	t.Helper()
	s := coordinationTestServer(t, st)
	inventory := recoveryInventory()
	s.recoveryContainers = func(context.Context, string) ([]rt.Container, error) {
		return []rt.Container{{
			Name: inventory.Containers[0].Name, State: rt.StateRunning,
			Labels: map[string]string{
				deploy.LabelManaged:  "true",
				deploy.LabelLab:      "cos461",
				deploy.LabelDeviceID: inventory.Containers[0].DeviceID,
				deploy.LabelSpec:     inventory.Containers[0].Spec,
				deploy.LabelGen:      inventory.Containers[0].Generation,
			},
		}}, nil
	}
	s.recoveryOverlays = func(string) ([]uint32, error) {
		return append([]uint32(nil), inventory.VNIs...), nil
	}
	s.transactions["cos461"] = applyTransaction{
		Generation: "failed-generation", PreviousGen: "old-generation",
		Phase: transactionRollbackNeeded, Prestate: inventory,
	}
	s.generations["cos461"] = generationState{
		Committed: "old-generation", Prepared: "failed-generation",
	}
	return s, inventory
}

func TestRecoveryRetriesRollbackAndVerifiesExactPrestate(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	attempts := 0
	s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error {
		attempts++
		if attempts == 1 {
			return errors.New("forced rollback failure")
		}
		return nil
	}
	if _, err := s.recoverTransaction(context.Background(), "cos461", lease.Fence); err == nil {
		t.Fatal("a failed rollback was reported as recovered")
	}
	tx := s.transactions["cos461"]
	if tx.Phase != transactionRollbackFailed || tx.RecoveryAttempts != 1 {
		t.Fatalf("failed recovery state = %+v, want rollback_failed attempt 1", tx)
	}
	raw, _ := json.Marshal(&Wire{Lab: "cos461"})
	if err := s.prepareGeneration("cos461", lease.Fence, "old-generation", "another-generation",
		raw, "platform", 0, nil, false, nil, nil); err == nil {
		t.Fatal("ordinary mutation was admitted while rollback_failed remained active")
	}
	status, err := s.recoverTransaction(context.Background(), "cos461", lease.Fence)
	if err != nil {
		t.Fatalf("retrying rollback: %v", err)
	}
	if !status.Consistent || status.Generation != "old-generation" {
		t.Fatalf("recovery did not prove the old inventory: %+v", status)
	}
	if _, active := s.transactions["cos461"]; active {
		t.Fatal("recovered transaction remained active and would block ordinary deploys")
	}
}

func TestAutomaticRecoveryUsesFreshFenceAfterControllerLoss(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
	s.resumeRecoveries(context.Background())
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		_, active := s.transactions["cos461"]
		s.mu.Unlock()
		if !active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic recovery left the failed transaction active")
		}
		time.Sleep(time.Millisecond)
	}
	if s.fenceHighWater["cos461"] == 0 {
		t.Fatal("automatic recovery did not issue a fresh fenced lease")
	}
	status := s.transactionInventoryStatus(context.Background(), "cos461")
	if !status.Consistent || status.Generation != "old-generation" {
		t.Fatalf("automatic recovery did not verify old service inventory: %+v", status)
	}
}

func TestRecoverySurvivesAgentRestartWithPersistedPrestate(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := recoveryServer(t, st)
	if err := before.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, st)
	after.loadCoordination()
	inventory := after.transactions["cos461"].Prestate
	after.recoveryContainers = func(context.Context, string) ([]rt.Container, error) {
		return []rt.Container{{
			Name: inventory.Containers[0].Name, State: rt.StateRunning,
			Labels: map[string]string{
				deploy.LabelManaged:  "true",
				deploy.LabelLab:      "cos461",
				deploy.LabelDeviceID: inventory.Containers[0].DeviceID,
				deploy.LabelSpec:     inventory.Containers[0].Spec,
				deploy.LabelGen:      inventory.Containers[0].Generation,
			},
		}}, nil
	}
	after.recoveryOverlays = func(string) ([]uint32, error) { return inventory.VNIs, nil }
	after.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
	lease, err := after.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	status, err := after.recoverTransaction(context.Background(), "cos461", lease.Fence)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Consistent || status.Generation != "old-generation" {
		t.Fatalf("restart recovery did not restore durable prestate: %+v", status)
	}
}

func TestTransactionFailpointsCoverApplyStages(t *testing.T) {
	stages := []plan.Stage{
		plan.StageImage, plan.StageCreate, plan.StageWire, plan.StageConfigure, plan.StageReady,
	}
	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			s := coordinationTestServer(t, nil)
			s.transactionFailpoint = func(phase string) error {
				if phase == string(stage) {
					return errors.New("forced " + phase)
				}
				return nil
			}
			p := plan.New()
			p.Add(&plan.Step{ID: string(stage), Stage: stage, Run: func(context.Context) error { return nil }})
			s.transactionFailpoints(p)
			rep, err := p.Execute(context.Background(), plan.Options{Workers: 1, ContinueOnError: true})
			if err != nil {
				t.Fatal(err)
			}
			if !rep.Failed() {
				t.Fatalf("%s failpoint did not fail the plan", stage)
			}
		})
	}
}

func TestTransactionBoundaryFailpointsAreExplicit(t *testing.T) {
	for _, phase := range []string{"apply", "prune", "commit", "rollback"} {
		t.Run(phase, func(t *testing.T) {
			s := coordinationTestServer(t, nil)
			s.transactionFailpoint = func(got string) error {
				if got == phase {
					return errors.New("forced " + got)
				}
				return nil
			}
			if err := s.transactionFail(phase); err == nil {
				t.Fatalf("%s failpoint was not reachable", phase)
			}
		})
	}
}

func TestForcedWireFailureMarksRecoveryInsteadOfClaimingAtomicity(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	s.transactionFailpoint = func(phase string) error {
		if phase == "wire" {
			return errors.New("forced multiplex overlay error")
		}
		return nil
	}
	err = s.transactionFail("wire")
	if err == nil {
		t.Fatal("forced multiplex hook did not fail wire phase")
	}
	if err := s.markTransactionPhase("cos461", lease.Fence, "failed-generation",
		transactionRollbackNeeded, err.Error()); err != nil {
		t.Fatal(err)
	}
	status := s.transactionInventoryStatus(context.Background(), "cos461")
	if status.Phase != string(transactionRollbackNeeded) || status.Consistent {
		t.Fatalf("wire failure looked atomic in status: %+v", status)
	}
}
