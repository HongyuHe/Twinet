//go:build e2e && chaos

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentpkg "github.com/HongyuHe/twinet/internal/agent"
)

func chaosVNI(t *testing.T, nodes []e2eNodeObservation) uint32 {
	t.Helper()
	used := map[string]bool{}
	for _, node := range nodes {
		for vni := range node.Status.Overlays {
			used[vni] = true
		}
	}
	start := uint32(15_000_000 + time.Now().UnixNano()%1_000_000)
	for n := uint32(0); n < 100_000; n++ {
		vni := start + n
		if vni >= 16_777_215 {
			vni -= 1_000_000
		}
		if !used[fmt.Sprint(vni)] {
			return vni
		}
	}
	t.Fatal("could not find an unused test VNI")
	return 0
}

func chaosLabName(prefix string) string {
	return fmt.Sprintf("e2e-chaos-%s-%d", prefix, time.Now().UnixNano())
}

// A real controller must fail while another valid controller owns every node's
// mutation lease. Merely launching two quick idempotent deploys is not enough:
// either can complete before the other starts, which says nothing about fencing.
func TestChaosConcurrentControllerAttemptsAreFenced(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	cluster, top := clusterClient(t, dir)
	before := generationFor(t, nodes, top.Name)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	lease, err := cluster.AcquireMutationLease(ctx, top.Name)
	if err != nil {
		t.Fatalf("acquire the first controller lease: %v", err)
	}
	defer lease.Release()

	out, err := runController(t, ctx, "deploy", "-m", dir, "--quiet")
	if err == nil {
		t.Fatalf("a second controller deployed while another owned the mutation lease:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "mutation lease") &&
		!strings.Contains(strings.ToLower(out), "already leased") {
		t.Fatalf("second controller failed for an unrelated reason, not a fencing refusal:\n%s", out)
	}

	lease.Release()
	after := waitForHealthyMultiNodeCluster(t, dir, 2*time.Minute)
	if got := generationFor(t, after, top.Name); got != before {
		t.Fatalf("rejected controller changed committed generation from %q to %q", before, got)
	}
}

// One hundred controllers reserve the same unused VNI at the same instant.
// Exactly one may win; allowing zero makes the test vacuous and allowing two
// joins isolated labs into one broadcast domain.
func TestChaosOverlayReservationsAreAtomicUnderContention(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	cluster, _ := clusterClient(t, dir)
	node := cluster.Nodes[0]
	vni := chaosVNI(t, nodes)

	const contenders = 100
	type heldLease struct {
		lab   string
		fence agentpkg.Fence
	}
	held := make([]heldLease, contenders)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var acquire sync.WaitGroup
	errs := make(chan error, contenders)
	for i := range held {
		acquire.Add(1)
		go func(i int) {
			defer acquire.Done()
			lab := chaosLabName(fmt.Sprintf("overlay-%d", i))
			resp, err := node.AcquireMutationLease(ctx, agentpkg.LeaseAcquireRequest{
				Lab: lab, Holder: "e2e-overlay-contention", TTLSeconds: 30,
			})
			if err != nil {
				errs <- fmt.Errorf("acquire contender %d: %w", i, err)
				return
			}
			held[i] = heldLease{lab: lab, fence: resp.Fence}
		}(i)
	}
	acquire.Wait()
	close(errs)

	release := func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), time.Minute)
		defer releaseCancel()
		for _, lease := range held {
			if lease.lab == "" {
				continue
			}
			_ = node.ReleaseMutationLease(releaseCtx, lease.lab, lease.fence)
		}
	}
	t.Cleanup(release)
	for err := range errs {
		t.Fatal(err)
	}
	for i, lease := range held {
		if lease.lab == "" || lease.fence.Token == "" || lease.fence.Generation == 0 {
			t.Fatalf("contender %d did not receive a usable mutation fence", i)
		}
	}

	start := make(chan struct{})
	var reserve sync.WaitGroup
	var (
		mu        sync.Mutex
		successes []string
		failures  []error
	)
	for _, lease := range held {
		reserve.Add(1)
		go func(lease heldLease) {
			defer reserve.Done()
			<-start
			_, err := node.ReserveOverlays(ctx, agentpkg.OverlayReservationRequest{
				Lab: lease.lab, Fence: lease.fence, VNIs: []uint32{vni},
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes = append(successes, lease.lab)
				return
			}
			if !strings.Contains(err.Error(), "reserved or live") &&
				!strings.Contains(err.Error(), "already owned") {
				failures = append(failures, err)
			}
		}(lease)
	}
	close(start)
	reserve.Wait()
	if len(failures) > 0 {
		t.Fatalf("reservation contention had an unexpected error: %v", failures[0])
	}
	if len(successes) != 1 {
		t.Fatalf("VNI %d was reserved by %d contenders (%v), want exactly one", vni, len(successes), successes)
	}

	release()
	retry, err := node.AcquireMutationLease(ctx, agentpkg.LeaseAcquireRequest{
		Lab: chaosLabName("overlay-retry"), Holder: "e2e-overlay-retry", TTLSeconds: 30,
	})
	if err != nil {
		t.Fatalf("acquire retry lease after releases: %v", err)
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = node.ReleaseMutationLease(releaseCtx, retry.Lab, retry.Fence)
	}()
	if _, err := node.ReserveOverlays(ctx, agentpkg.OverlayReservationRequest{
		Lab: retry.Lab, Fence: retry.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("reservation %d remained stale after all contenders released: %v", vni, err)
	}
}

// Simulate a controller that exits after reserving an overlay and never sends
// release. The next fence must take over after the advertised TTL, not inherit
// an invisible reservation forever.
func TestChaosAbandonedOperationReservationsExpire(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	cluster, _ := clusterClient(t, dir)
	node := cluster.Nodes[0]
	vni := chaosVNI(t, nodes)
	lab := chaosLabName("abandoned")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, err := node.AcquireMutationLease(ctx, agentpkg.LeaseAcquireRequest{
		Lab: lab, Holder: "e2e-abandoned-controller", TTLSeconds: 2,
	})
	if err != nil {
		t.Fatalf("acquire abandoned-operation lease: %v", err)
	}
	t.Cleanup(func() {
		_ = node.ReleaseMutationLease(context.Background(), lab, first.Fence)
	})
	if _, err := node.ReserveOverlays(ctx, agentpkg.OverlayReservationRequest{
		Lab: lab, Fence: first.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("reserve VNI for abandoned operation: %v", err)
	}

	var second agentpkg.LeaseResponse
	deadline := time.Now().Add(15 * time.Second)
	for {
		second, err = node.AcquireMutationLease(ctx, agentpkg.LeaseAcquireRequest{
			Lab: lab, Holder: "e2e-recovery-controller", TTLSeconds: 30,
		})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired abandoned lease still blocked a new controller: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), time.Minute)
		defer releaseCancel()
		_ = node.ReleaseMutationLease(releaseCtx, lab, second.Fence)
	}()
	if _, err := node.ReserveOverlays(ctx, agentpkg.OverlayReservationRequest{
		Lab: lab, Fence: second.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("expired abandoned reservation %d was not collected: %v", vni, err)
	}
}

func TestChaosStrictAdmissionRefusesOversizedLabBeforeMutation(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	before := map[string]int{}
	for _, node := range nodes {
		before[node.Node] = node.Status.Containers
	}

	work := e2eArtifactDir(t, "strict_admission")
	oversized := filepath.Join(work, "oversized")
	copyTree(t, dir, oversized)
	manifestPath := filepath.Join(oversized, "twinet.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "  cpus: 2", "  cpus: 1000000", 1)
	if body == string(raw) {
		t.Fatal("missing capability: the scale manifest no longer exposes a defaults.cpus value to oversize")
	}
	if err := os.WriteFile(manifestPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := twinet(t, "deploy", "-m", oversized, "--quiet")
	if err == nil {
		t.Fatalf("oversized lab was admitted; strict admission is not enforced before mutation:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "fit") &&
		!strings.Contains(strings.ToLower(out), "admission") &&
		!strings.Contains(strings.ToLower(out), "capacity") {
		t.Fatalf("oversized lab failed without a strict-admission explanation:\n%s", out)
	}
	after := requireHealthyMultiNodeCluster(t, dir)
	for _, node := range after {
		if node.Status.Containers != before[node.Node] {
			t.Fatalf("strict-admission refusal changed managed containers on %s from %d to %d",
				node.Node, before[node.Node], node.Status.Containers)
		}
	}
}

func TestChaosAgentRestartRehydratesState(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	requireHealthyMultiNodeCluster(t, dir)
	const device = "as3/CHI"
	locations := runtimeNodeLocations(t, dir)
	node := locations[device]
	if node == "" {
		t.Fatalf("missing capability: runtime nodes did not identify the hosting node for %s", device)
	}
	before := deviceFingerprint(t, dir, device)
	recovered := false
	t.Cleanup(func() {
		if !recovered {
			chaosCleanupHook(t, "TWINET_CHAOS_AGENT_RESTART_CMD", node, "")
		}
	})
	chaosHook(t, "TWINET_CHAOS_AGENT_RESTART_CMD", node, "")
	waitForHealthyMultiNodeCluster(t, dir, 5*time.Minute)
	recovered = true
	if after := deviceFingerprint(t, dir, device); after != before {
		t.Fatalf("agent restart changed preserved configuration on %s\nbefore:\n%s\nafter:\n%s",
			device, before, after)
	}
	out, err := twinet(t, "runtime", "state", "-m", dir, device)
	if err != nil || !strings.Contains(out, `"state":"running"`) {
		t.Fatalf("%s did not return running after its agent restarted: %v\n%s", device, err, out)
	}
}

func TestChaosNodeRebootPreservesState(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	requireHealthyMultiNodeCluster(t, dir)
	const device = "as3/CHI"
	locations := runtimeNodeLocations(t, dir)
	node := locations[device]
	if node == "" {
		t.Fatalf("missing capability: runtime nodes did not identify the hosting node for %s", device)
	}
	before := deviceFingerprint(t, dir, device)
	recovered := false
	t.Cleanup(func() {
		if !recovered {
			chaosCleanupHook(t, "TWINET_CHAOS_AGENT_RESTART_CMD", node, "")
		}
	})
	chaosHook(t, "TWINET_CHAOS_NODE_REBOOT_CMD", node, "")
	waitForHealthyMultiNodeCluster(t, dir, 10*time.Minute)
	recovered = true
	if after := deviceFingerprint(t, dir, device); after != before {
		t.Fatalf("node reboot changed preserved configuration on %s\nbefore:\n%s\nafter:\n%s",
			device, before, after)
	}
}

func TestChaosMigrationPreservesStudentState(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	requireHealthyMultiNodeCluster(t, dir)
	migrationManifest := os.Getenv("TWINET_CHAOS_MIGRATION_MANIFEST")
	if migrationManifest == "" {
		t.Fatal("missing capability: set TWINET_CHAOS_MIGRATION_MANIFEST to a same-lab manifest " +
			"that deliberately moves AS 3; migration cannot be inferred from a no-op rebalance")
	}
	if _, err := os.Stat(migrationManifest); err != nil {
		t.Fatalf("migration manifest %s is not readable: %v", migrationManifest, err)
	}

	const device = "as3/CHI"
	const marker = "! twinet-chaos-migration-marker"
	if out, err := twinet(t, "exec", "-m", dir, device, "--", "sh", "-c",
		"grep -q '"+marker+"' /etc/frr/frr.conf || echo '"+marker+"' >> /etc/frr/frr.conf"); err != nil {
		t.Fatalf("seed migratable student configuration: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		out, err := runController(t, ctx, "deploy", "-m", dir, "--rebalance", "--solve", "--quiet")
		if err != nil {
			t.Errorf("restore original placement and reference after migration test: %v\n%s", err, out)
		}
	})
	if out, err := twinet(t, "deploy", "-m", dir, "--quiet"); err != nil {
		t.Fatalf("capture state before migration: %v\n%s", err, out)
	}
	beforeLocations := runtimeNodeLocations(t, dir)
	beforeNode := beforeLocations[device]
	before := deviceFingerprint(t, dir, device)

	if out, err := twinet(t, "deploy", "-m", migrationManifest, "--rebalance", "--quiet"); err != nil {
		t.Fatalf("migrate placement: %v\n%s", err, out)
	}
	afterLocations := runtimeNodeLocations(t, migrationManifest)
	if afterLocations[device] == "" || afterLocations[device] == beforeNode {
		t.Fatalf("migration manifest did not move %s from %s; provide a manifest with a real placement change",
			device, beforeNode)
	}
	if after := deviceFingerprint(t, migrationManifest, device); after != before {
		t.Fatalf("configuration did not survive migration of %s from %s to %s\nbefore:\n%s\nafter:\n%s",
			device, beforeNode, afterLocations[device], before, after)
	}
}

func TestChaosUnderlayFailureRecoversWithoutDrift(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	const device = "as3/CHI"
	before := deviceFingerprint(t, dir, device)
	from, to := nodes[0].Node, nodes[1].Node
	up := false
	t.Cleanup(func() {
		if !up {
			chaosCleanupHook(t, "TWINET_CHAOS_UNDERLAY_UP_CMD", from, to)
		}
	})
	chaosHook(t, "TWINET_CHAOS_UNDERLAY_DOWN_CMD", from, to)
	out, err := twinet(t, "node", "check", "-m", dir)
	if err == nil {
		t.Fatalf("underlay flap was not detected by node check:\n%s", out)
	}
	chaosHook(t, "TWINET_CHAOS_UNDERLAY_UP_CMD", from, to)
	up = true

	deadline := time.Now().Add(5 * time.Minute)
	for {
		out, err = twinet(t, "node", "check", "-m", dir)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("underlay did not recover within five minutes: %v\n%s", err, out)
		}
		time.Sleep(10 * time.Second)
	}
	if out, err := twinet(t, "deploy", "-m", dir, "--quiet"); err != nil {
		t.Fatalf("converge after underlay recovery: %v\n%s", err, out)
	}
	if after := deviceFingerprint(t, dir, device); after != before {
		t.Fatalf("underlay recovery drifted configuration on %s\nbefore:\n%s\nafter:\n%s",
			device, before, after)
	}
}

func TestChaosPartialApplyNeverCommitsMixedGeneration(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	nodes := requireHealthyMultiNodeCluster(t, dir)
	_, top := clusterClient(t, dir)
	before := generationFor(t, nodes, top.Name)
	node := nodes[0].Node
	restarted := false
	t.Cleanup(func() {
		if !restarted {
			chaosCleanupHook(t, "TWINET_CHAOS_AGENT_RESTART_CMD", node, "")
		}
	})

	chaosHook(t, "TWINET_CHAOS_AGENT_STOP_CMD", node, "")
	out, err := twinet(t, "deploy", "-m", dir, "--quiet")
	if err == nil {
		t.Fatalf("deploy reported success with %s unavailable, so partial apply can be reported as committed:\n%s", node, out)
	}
	chaosHook(t, "TWINET_CHAOS_AGENT_RESTART_CMD", node, "")
	restarted = true
	afterFailure := waitForHealthyMultiNodeCluster(t, dir, 5*time.Minute)
	if got := generationFor(t, afterFailure, top.Name); got != before {
		t.Fatalf("failed partial apply left committed generation %q, want unchanged %q", got, before)
	}
	if out, err := twinet(t, "deploy", "-m", dir, "--quiet"); err != nil {
		t.Fatalf("converge cleanly after partial apply recovery: %v\n%s", err, out)
	}
	generationFor(t, waitForHealthyMultiNodeCluster(t, dir, 2*time.Minute), top.Name)
}

func TestChaosReferenceGradeHasNoInfrastructureDeduction(t *testing.T) {
	requireDestructiveChaos(t)
	dir := labDir(t)
	const asn = 3
	solveAS(t, dir, asn)
	awarded, points, report := gradeAS(t, dir, asn)
	if len(points) == 0 {
		t.Fatalf("grade produced no questions, so it cannot establish absence of infrastructure deductions:\n%s", report)
	}
	for question, max := range points {
		if awarded[question] < max {
			t.Fatalf("reference answer lost marks on %s (%.2f of %.2f); this is an infrastructure-shaped deduction:\n%s",
				question, awarded[question], max, report)
		}
	}
}

func TestChaosOverlaySweepFindsNoAbandonedObjects(t *testing.T) {
	requireDestructiveChaos(t)
	sweepMustBeClean(t, labDir(t))
}
