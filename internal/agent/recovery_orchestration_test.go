package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestRecoveryPhaseDeadlinePublishesTargetAndReleasesOperation(t *testing.T) {
	cases := []struct {
		name      string
		target    string
		configure func(*Server, chan<- struct{})
	}{
		{
			name:   "stuck-exec",
			target: "rollback restore prior runtime inventory",
			configure: func(s *Server, started chan<- struct{}) {
				s.recoveryRollback = func(ctx context.Context, _ string, _ Fence, _ applyTransaction) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				}
			},
		},
		{
			name:   "stuck-restore",
			target: "restore persist previous topology",
			configure: func(s *Server, started chan<- struct{}) {
				s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
				s.recoveryRestore = func(ctx context.Context, _ string, _ applyTransaction) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				}
			},
		},
		{
			name:   "stuck-peer",
			target: "replicate durable peer quorum",
			configure: func(s *Server, started chan<- struct{}) {
				s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
				s.recoveryReplicate = func(ctx context.Context, _ applyTransaction) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := recoveryServer(t, nil)
			s.recoveryPhaseTimeout = 25 * time.Millisecond
			s.recoveryTotalTimeout = 250 * time.Millisecond
			started := make(chan struct{})
			tc.configure(s, started)
			lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461", Holder: "operator"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.releaseMutationLease(LeaseReleaseRequest{Lab: "cos461", Fence: lease.Fence}) }()

			result := make(chan error, 1)
			go func() {
				_, err := s.recoverTransaction(context.Background(), "cos461", lease.Fence)
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("recovery never reached the injected phase")
			}
			status := s.transactionInventoryStatus(context.Background(), "cos461")
			if status.Owner != "operator" || status.Strategy != "rollback" ||
				status.CurrentTarget == "" || status.StartedAt.IsZero() ||
				status.LastProgressAt.IsZero() || status.Deadline.IsZero() {
				t.Fatalf("in-flight recovery did not expose structured progress: %+v", status)
			}
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), tc.target) ||
					!strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
					t.Fatalf("recovery error = %v, want timed %q", err, tc.target)
				}
			case <-time.After(time.Second):
				t.Fatal("timed recovery leaked its goroutine")
			}
			s.mu.Lock()
			_, busy := s.ops["cos461"]
			tx := s.transactions["cos461"]
			s.mu.Unlock()
			if busy {
				t.Fatal("timed recovery leaked its operation lease")
			}
			if tx.Phase != transactionRollbackFailed || !strings.Contains(tx.Failure, tc.target) {
				t.Fatalf("timed recovery did not persist retryable failure: %+v", tx)
			}
		})
	}
}

func TestStaleRecoveryCanBeTakenOverOnlyWithNewFence(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	old, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461", TTLSeconds: 1, Holder: "agent recovery"})
	if err != nil {
		t.Fatal(err)
	}
	tx := s.transactions["cos461"]
	tx.Phase = transactionRecovering
	tx.RecoveryStrategy = "rollback"
	tx.RecoveryDeadline = now.Add(time.Second)
	s.transactions["cos461"] = tx
	now = now.Add(2 * time.Second)
	next, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461", Holder: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Fence.Generation <= old.Fence.Generation {
		t.Fatalf("takeover fence %d did not advance old fence %d", next.Fence.Generation, old.Fence.Generation)
	}
	s.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
	if _, err := s.recoverTransactionStrategy(context.Background(), "cos461", next.Fence, "rollback"); err == nil {
		t.Fatal("stale recovery was taken over without explicit takeover")
	}
	status, err := s.recoverTransactionStrategyOptions(context.Background(), "cos461", next.Fence, "rollback",
		recoveryRunOptions{takeover: true})
	if err != nil {
		t.Fatalf("fenced stale takeover failed: %v", err)
	}
	if !status.Consistent || status.Generation != "old-generation" {
		t.Fatalf("takeover did not prove the previous generation: %+v", status)
	}
}

func TestRecoveryOperationTakeoverDoesNotReleaseNewLease(t *testing.T) {
	s := coordinationTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	cancelled := make(chan struct{})
	first, err := s.acquireRecoveryOperation("lab", now.Add(-time.Second), func() { close(cancelled) }, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.acquireRecoveryOperation("lab", now.Add(time.Minute), nil, false); err == nil {
		t.Fatal("healthy operation was replaced without takeover")
	}
	second, err := s.acquireRecoveryOperation("lab", now.Add(time.Minute), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("stale recovery was not cancelled")
	}
	s.releaseRecoveryOperation("lab", first)
	s.mu.Lock()
	held := s.ops["lab"]
	s.mu.Unlock()
	if held == nil || held.id != second {
		t.Fatal("old recovery release removed the new operation")
	}
	s.releaseRecoveryOperation("lab", second)
	s.mu.Lock()
	_, busy := s.ops["lab"]
	s.mu.Unlock()
	if busy {
		t.Fatal("new recovery operation leaked after release")
	}
}

func TestAutomaticTimedRecoveryReleasesFenceAndOperation(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	s.recoveryPhaseTimeout = 20 * time.Millisecond
	s.recoveryTotalTimeout = 200 * time.Millisecond
	started := make(chan struct{})
	s.recoveryRollback = func(ctx context.Context, _ string, _ Fence, _ applyTransaction) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	s.resumeRecoveries(context.Background())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("automatic recovery did not start")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		tx := s.transactions["cos461"]
		_, leased := s.mutations["cos461"]
		_, busy := s.ops["cos461"]
		s.mu.Unlock()
		if tx.Phase == transactionRollbackFailed && !leased && !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("automatic recovery leaked fence/operation: tx=%+v leased=%t busy=%t", tx, leased, busy)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRecoveryProgressSurvivesAgentRestart(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := recoveryServer(t, store)
	now := time.Now().Round(0)
	tx := before.transactions["cos461"]
	tx.Phase = transactionRecovering
	tx.RecoveryOwner = "agent recovery"
	tx.RecoveryStrategy = "rollback"
	tx.RecoveryStarted = now.Add(-time.Minute)
	tx.RecoveryProgress = now.Add(-time.Second)
	tx.RecoveryDeadline = now.Add(time.Minute)
	tx.RecoveryTotal = now.Add(5 * time.Minute)
	tx.RecoveryTarget = "restore exact runtime contracts: as10/ATL"
	before.transactions["cos461"] = tx
	if err := before.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}
	after := coordinationTestServer(t, store)
	after.loadCoordination()
	status := after.transactionInventoryStatus(context.Background(), "cos461")
	if status.Owner != tx.RecoveryOwner || status.Strategy != tx.RecoveryStrategy ||
		status.CurrentTarget != tx.RecoveryTarget || !status.StartedAt.Equal(tx.RecoveryStarted) ||
		!status.LastProgressAt.Equal(tx.RecoveryProgress) || !status.Deadline.Equal(tx.RecoveryDeadline) ||
		!status.TotalDeadline.Equal(tx.RecoveryTotal) {
		t.Fatalf("restart lost persisted recovery progress: %+v", status)
	}
}

func TestRestartImmediatelyReclaimsPersistedRecoveryWithFreshFence(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := recoveryServer(t, store)
	tx := before.transactions["cos461"]
	tx.Phase = transactionRecovering
	tx.RecoveryOwner = "agent recovery"
	tx.RecoveryStrategy = "rollback"
	tx.RecoveryStarted = time.Now()
	tx.RecoveryProgress = tx.RecoveryStarted
	tx.RecoveryDeadline = tx.RecoveryStarted.Add(time.Hour)
	tx.RecoveryTotal = tx.RecoveryStarted.Add(2 * time.Hour)
	before.transactions["cos461"] = tx
	if err := before.saveCoordinationLocked(); err != nil {
		t.Fatal(err)
	}
	after := coordinationTestServer(t, store)
	after.loadCoordination()
	inventory := after.transactions["cos461"].Prestate
	after.recoveryContainers = func(context.Context, string) ([]rt.Container, error) {
		container := inventory.Containers[0]
		return []rt.Container{{
			Name: container.Name, State: rt.StateRunning,
			Labels: map[string]string{
				deploy.LabelManaged: "true", deploy.LabelLab: "cos461",
				deploy.LabelDeviceID: container.DeviceID, deploy.LabelSpec: container.Spec,
				deploy.LabelGen: container.Generation,
			},
		}}, nil
	}
	after.recoveryOverlays = func(string) ([]uint32, error) { return inventory.VNIs, nil }
	after.recoveryRollback = func(context.Context, string, Fence, applyTransaction) error { return nil }
	after.resumeRecoveries(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for {
		after.mu.Lock()
		_, active := after.transactions["cos461"]
		fence := after.fenceHighWater["cos461"]
		_, leased := after.mutations["cos461"]
		_, busy := after.ops["cos461"]
		after.mu.Unlock()
		if !active && fence > 0 && !leased && !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("restart did not reclaim persisted recovery: active=%t fence=%d leased=%t busy=%t",
				active, fence, leased, busy)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRecoveryStatusBoundsStuckRuntimeObservation(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	s.recoveryStatusTimeout = 10 * time.Millisecond
	tx := s.transactions["cos461"]
	tx.Phase = transactionRecovering
	tx.RecoveryOwner = "agent recovery"
	tx.RecoveryStrategy = "rollback"
	tx.RecoveryStarted = time.Now()
	tx.RecoveryProgress = tx.RecoveryStarted
	tx.RecoveryDeadline = tx.RecoveryStarted.Add(time.Minute)
	tx.RecoveryTarget = "restore exact runtime contracts: as10/ATL"
	s.transactions["cos461"] = tx
	s.recoveryContainers = func(ctx context.Context, _ string) ([]rt.Container, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	status := s.transactionInventoryStatus(context.Background(), "cos461")
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("recovery status blocked for %s", elapsed)
	}
	if status.Owner != "agent recovery" || status.CurrentTarget == "" || status.Error == "" {
		t.Fatalf("bounded status lost recovery metadata: %+v", status)
	}
}

func TestRecoveryLeaseConflictIncludesProgress(t *testing.T) {
	s := coordinationTestServer(t, nil)
	held, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab", Holder: "agent recovery"})
	if err != nil {
		t.Fatal(err)
	}

	s.transactions["lab"] = applyTransaction{
		Generation: "failed", Phase: transactionRecovering, RecoveryStrategy: "rollback",
		RecoveryTarget:   "restore exact runtime contracts: as10/ATL",
		RecoveryProgress: time.Now(), RecoveryDeadline: time.Now().Add(time.Minute),
		FenceGeneration: held.Fence.Generation,
	}
	_, err = s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab", Holder: "operator"})
	if err == nil || !strings.Contains(err.Error(), `strategy="rollback"`) ||
		!strings.Contains(err.Error(), "as10/ATL") {
		t.Fatalf("lease conflict omitted recovery progress: %v", err)
	}
}

func TestCommittedRecoveryStatusUsesLabGenerationNotObjectCreationGeneration(t *testing.T) {
	s := coordinationTestServer(t, nil)
	inventory := transactionInventory{
		Generation: "object-created-generation",
		Containers: []transactionContainer{{
			Name: "twinet-lab-r1", DeviceID: "as1/R1", Spec: "spec",
			Generation: "object-created-generation", State: "running",
		}},
	}
	s.generations["lab"] = generationState{Committed: "lab-committed-generation"}
	s.inventories["lab"] = inventory
	s.recoveryContainers = func(context.Context, string) ([]rt.Container, error) {
		return []rt.Container{{
			Name: inventory.Containers[0].Name, State: rt.StateRunning,
			Labels: map[string]string{
				deploy.LabelManaged: "true", deploy.LabelLab: "lab",
				deploy.LabelDeviceID: inventory.Containers[0].DeviceID,
				deploy.LabelSpec:     inventory.Containers[0].Spec,
				deploy.LabelGen:      inventory.Containers[0].Generation,
			},
		}}, nil
	}
	s.recoveryOverlays = func(string) ([]uint32, error) { return nil, nil }
	status := s.transactionInventoryStatus(context.Background(), "lab")
	if status.Generation != "lab-committed-generation" || !status.Consistent {
		t.Fatalf("recovery status conflated lab and object generations: %+v", status)
	}
}
