package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

// ephemeralTestServer builds an agent whose clock is explicit. Every deadline
// in this file is proved by moving that clock, never by sleeping: a lifetime
// contract that is only testable by waiting is one nobody will test.
func ephemeralTestServer(t *testing.T, store *state.Store, now *time.Time) *Server {
	t.Helper()
	server := coordinationTestServer(t, store)
	server.now = func() time.Time { return *now }
	server.holds = map[string]*hold{}
	server.ephemeralDestroy = func(context.Context, string) error { return nil }
	return server
}

func deployEphemeral(t *testing.T, server *Server, lab, owner string, ttl int) {
	t.Helper()
	if err := server.noteEphemeralLease(lab, owner, ttl, "gen-1"); err != nil {
		t.Fatalf("recording the ephemeral lease for %s: %v", lab, err)
	}
	server.mu.Lock()
	server.current[lab] = &model.Topology{Name: lab, Ephemeral: true, EphemeralTTLSeconds: ttl}
	server.mu.Unlock()
}

func TestAnEphemeralLabIsReclaimedOnlyAfterItsLifetimeEnds(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)

	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	now = now.Add(9 * time.Minute)
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 0 {
		t.Fatalf("a harness inside its lifetime was reclaimed: %+v", summary)
	}

	// A live controller keeps saying it is there.
	if _, err := server.renewEphemeralLease(EphemeralRequest{
		Lab: "harness", Owner: "grade-batch@host/1", TTLSeconds: 600,
	}); err != nil {
		t.Fatalf("a live controller could not renew its harness: %v", err)
	}
	now = now.Add(9 * time.Minute)
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 0 {
		t.Fatalf("a renewed harness was reclaimed: %+v", summary)
	}

	// The controller is killed: nothing renews it again.
	now = now.Add(11 * time.Minute)
	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 1 || summary.Reclaimed[0] != "harness" {
		t.Fatalf("an abandoned harness was not reclaimed: %+v", summary)
	}
	server.mu.Lock()
	_, stillCurrent := server.current["harness"]
	_, stillLeased := server.ephemeral["harness"]
	server.mu.Unlock()
	if stillCurrent {
		t.Fatal("a reclaimed harness is still in the node's current topologies")
	}
	if stillLeased {
		t.Fatal("a reclaimed harness kept its lifetime record")
	}
}

func TestNoHeartbeatCanHoldAnEphemeralLabPastItsCeiling(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", maxEphemeralTTLSeconds)

	// A heartbeat loop that is itself stuck in a retry, or a run somebody
	// forgot about, renews forever. The ceiling is what makes that bounded.
	for elapsed := time.Duration(0); elapsed < maxEphemeralLifetime+time.Hour; elapsed += 30 * time.Minute {
		now = now.Add(30 * time.Minute)
		_, renewErr := server.renewEphemeralLease(EphemeralRequest{
			Lab: "harness", Owner: "grade-batch@host/1", TTLSeconds: maxEphemeralTTLSeconds,
		})
		summary := server.reapExpiredEphemeralLabs(context.Background())
		if len(summary.Reclaimed) > 0 {
			if elapsed+30*time.Minute < maxEphemeralLifetime {
				t.Fatalf("reclaimed before the ceiling at %s", elapsed)
			}
			if renewErr == nil {
				t.Fatal("a renewal past the ceiling was accepted")
			}
			return
		}
	}
	t.Fatalf("an endlessly renewed ephemeral lab was never reclaimed; the ceiling of %s did not apply",
		maxEphemeralLifetime)
}

func TestAnUnexpiredTTLIsClampedToTheNodesBound(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 0)

	resp, err := server.renewEphemeralLease(EphemeralRequest{
		Lab: "harness", Owner: "grade-batch@host/1", TTLSeconds: 10 * maxEphemeralTTLSeconds,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TTLSeconds != maxEphemeralTTLSeconds {
		t.Fatalf("a caller-chosen lifetime of %ds was granted; the node must clamp to %ds",
			resp.TTLSeconds, maxEphemeralTTLSeconds)
	}
	if resp.ExpiresAt.After(resp.HardExpiresAt) {
		t.Fatal("a granted lifetime exceeded the absolute ceiling")
	}
}

func TestReclamationPreemptsTheReconcileLeaseThatBlockedDestroy(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	// This is the exact shape that answered `twinet destroy` with 409: a
	// repair loop holding the lab's operation lease on a harness nobody wants.
	repairing := make(chan struct{})
	repairCtx, cancelRepair := context.WithCancel(context.Background())
	opID, opDone, err := server.acquireOperation("harness", "reconcile", cancelRepair)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { server.releaseOperation("harness", opID, opDone) }) }
	go func() {
		<-repairCtx.Done()
		close(repairing)
		release()
	}()

	if _, _, err := server.acquireOperation("harness", "destroy", nil); err == nil {
		t.Fatal("an ordinary destroy was not blocked; the test does not reproduce the failure")
	}

	now = now.Add(20 * time.Minute)
	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 1 {
		t.Fatalf("reclamation did not preempt the repair loop: %+v", summary)
	}
	select {
	case <-repairing:
	case <-time.After(5 * time.Second):
		t.Fatal("the repair loop was never cancelled")
	}
	release()
}

func TestReclamationLeavesDurableLabsAlone(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)

	server.mu.Lock()
	server.current["cos461"] = &model.Topology{Name: "cos461"}
	server.mu.Unlock()
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	now = now.Add(365 * 24 * time.Hour)
	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 1 || summary.Reclaimed[0] != "harness" {
		t.Fatalf("reclamation did not remove exactly the disposable lab: %+v", summary)
	}
	server.mu.Lock()
	_, teachingSurvived := server.current["cos461"]
	server.mu.Unlock()
	if !teachingSurvived {
		t.Fatal("a teaching lab with no ephemeral lease was collected")
	}
}

func TestAnUnrelatedLabStaysDeployableWhileAHarnessIsReclaimed(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	// The whole point of reclaiming is to return the cluster to service, so
	// nothing node-wide may be held while a large harness comes down.
	admitted := make(chan error, 1)
	releaseDestroy := make(chan struct{})
	reaped := make(chan struct{})
	server.ephemeralDestroy = func(ctx context.Context, _ string) error {
		go func() {
			_, _, err := server.acquireOperation("cos461", "apply", nil)
			admitted <- err
		}()
		select {
		case <-releaseDestroy:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	now = now.Add(20 * time.Minute)
	go func() {
		defer close(reaped)
		server.reapExpiredEphemeralLabs(context.Background())
	}()
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("an unrelated lab was refused while a harness was being reclaimed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an unrelated lab could not be deployed while a harness was being reclaimed")
	}
	close(releaseDestroy)
	<-reaped
}

func TestReclamationWaitsForALiveController(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	now = now.Add(20 * time.Minute)
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{
		Lab: "harness", Holder: "an operator", TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 0 || len(summary.Deferred) != 1 {
		t.Fatalf("reclamation ran underneath a live controller lease: %+v", summary)
	}
	if err := server.releaseMutationLease(LeaseReleaseRequest{
		Lab: "harness", Fence: lease.Fence,
	}); err != nil {
		t.Fatal(err)
	}
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("reclamation did not resume once the lease was released: %+v", summary)
	}
}

func TestAHeartbeatCannotMarkADurableLabDisposable(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	server.mu.Lock()
	server.current["cos461"] = &model.Topology{Name: "cos461"}
	server.mu.Unlock()

	if _, err := server.renewEphemeralLease(EphemeralRequest{Lab: "cos461", TTLSeconds: 60}); err == nil {
		t.Fatal("a heartbeat created a lifetime for a lab no deployment declared disposable")
	}
	server.mu.Lock()
	_, leased := server.ephemeral["cos461"]
	server.mu.Unlock()
	if leased {
		t.Fatal("a heartbeat marked a teaching lab collectable")
	}
}

func TestAnExpiredLeaseCannotBeRenewedBackToLife(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	now = now.Add(20 * time.Minute)
	if _, err := server.renewEphemeralLease(EphemeralRequest{
		Lab: "harness", Owner: "grade-batch@host/1", TTLSeconds: 600,
	}); err == nil {
		t.Fatal("a controller that returned after expiry renewed a lab already owed reclamation")
	}
}

func TestAnotherControllerCannotRenewSomebodyElsesHarness(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	if _, err := server.renewEphemeralLease(EphemeralRequest{
		Lab: "harness", Owner: "someone-else@host/2", TTLSeconds: 600,
	}); err == nil {
		t.Fatal("a different controller extended a harness it does not own")
	}
}

func TestAnEphemeralLifetimeSurvivesAnAgentRestart(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted := ephemeralTestServer(t, reopened, &now)
	restarted.loadCoordination()
	restarted.mu.Lock()
	lease, ok := restarted.ephemeral["harness"]
	restarted.mu.Unlock()
	if !ok {
		t.Fatal("an agent restart forgot that a lab was disposable")
	}
	if lease.Owner != "grade-batch@host/1" {
		t.Fatalf("the restored lease lost its owner: %+v", lease)
	}

	restarted.mu.Lock()
	restarted.current["harness"] = &model.Topology{Name: "harness", Ephemeral: true}
	restarted.mu.Unlock()
	now = now.Add(20 * time.Minute)
	if summary := restarted.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("a restarted agent did not reclaim the abandoned harness: %+v", summary)
	}
}

func TestARehydratedEphemeralTopologyWithNoDeadlineGetsABoundedGrace(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The crash case: topology.json says disposable, and the coordination
	// journal update that carried its deadline never landed.
	wire := Wire{
		Lab: "harness", Mode: "solve", Ungraded: 3, Generation: "gen-1",
		Ephemeral: true, EphemeralTTLSeconds: 600,
	}
	raw, err := json.Marshal(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutTopology("harness", raw); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	server.rehydrate()

	server.mu.Lock()
	lease, ok := server.ephemeral["harness"]
	server.mu.Unlock()
	if !ok {
		t.Fatal("a rehydrated ephemeral lab was given no lifetime at all, so it would live forever")
	}
	if !lease.Restored {
		t.Fatal("a synthesised restart grace was not marked as one")
	}
	if lease.deadline().Sub(now) < ephemeralRestartGrace {
		t.Fatalf("a rehydrated harness was given less than the restart grace: %s", lease.deadline().Sub(now))
	}
	if lease.deadline().After(now.Add(maxEphemeralLifetime)) {
		t.Fatal("a rehydrated harness was given an unbounded lifetime")
	}

	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 0 {
		t.Fatalf("a rehydrated harness was reclaimed inside its restart grace: %+v", summary)
	}
	now = now.Add(ephemeralRestartGrace + time.Minute)
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("a rehydrated harness outlived its restart grace: %+v", summary)
	}
}

func TestACrashLoopCannotKeepGrantingAFreshRestartGrace(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	wire := Wire{Lab: "harness", Mode: "solve", Generation: "gen-1", Ephemeral: true}
	raw, err := json.Marshal(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutTopology("harness", raw); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	first := ephemeralTestServer(t, store, &now)
	first.rehydrate()

	// Restart again just before the grace runs out. The deadline must be the
	// one already on disk, not a new one.
	now = now.Add(ephemeralRestartGrace - time.Minute)
	reopened, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	second := ephemeralTestServer(t, reopened, &now)
	second.loadCoordination()
	second.rehydrate()

	now = now.Add(2 * time.Minute)
	if summary := second.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("restarting reset the restart grace, so a crash loop would hold the lab forever: %+v",
			summary)
	}
}

func TestADeploymentThatDropsTheEphemeralMarkerMakesTheLabDurable(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	if err := server.forgetEphemeralLease("harness"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(365 * 24 * time.Hour)
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 0 {
		t.Fatalf("a lab redeployed as durable was still reclaimed: %+v", summary)
	}
}

func TestAPartialReclamationKeepsItsLeaseAndIsRetried(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	server := ephemeralTestServer(t, store, &now)
	deployEphemeral(t, server, "harness", "grade-batch@host/1", 600)

	failures := 0
	server.ephemeralDestroy = func(context.Context, string) error {
		failures++
		if failures == 1 {
			return errRuntimeUnavailableForTest
		}
		return nil
	}
	now = now.Add(20 * time.Minute)
	summary := server.reapExpiredEphemeralLabs(context.Background())
	if len(summary.Reclaimed) != 0 || len(summary.Problems) != 1 {
		t.Fatalf("a failed reclamation was reported as success: %+v", summary)
	}
	if !strings.Contains(summary.Problems[0], "harness") {
		t.Fatalf("the reported problem does not name the lab: %q", summary.Problems[0])
	}
	server.mu.Lock()
	_, stillLeased := server.ephemeral["harness"]
	server.mu.Unlock()
	if !stillLeased {
		t.Fatal("a lab that could not be reclaimed silently became durable")
	}
	if summary := server.reapExpiredEphemeralLabs(context.Background()); len(summary.Reclaimed) != 1 {
		t.Fatalf("reclamation was not retried after a transient failure: %+v", summary)
	}
}

var errRuntimeUnavailableForTest = errTestRuntimeUnavailable{}

type errTestRuntimeUnavailable struct{}

func (errTestRuntimeUnavailable) Error() string { return "runtime is unavailable" }
