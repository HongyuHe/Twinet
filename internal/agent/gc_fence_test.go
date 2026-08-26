package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/netx"
)

// gcFenceServer is a node with no managed containers and every collection seam
// injected, so a collection decision can be raced against a deployment without
// a host runtime or a netlink namespace.
func gcFenceServer(now *time.Time) *Server {
	server := &Server{
		cfg: Config{Node: "node-0", GCGrace: time.Second},
		rt:  &gcRuntime{},
		now: func() time.Time { return *now },
		gcFindOrphans: func(map[string]bool) ([]netx.Orphan, error) {
			return nil, nil
		},
		gcRemoveOverlay:        func(uint32) error { return nil },
		gcDeleteHostLink:       func(string) error { return nil },
		gcListMultiplex:        func(string) ([]netx.MultiplexOverlay, error) { return nil, nil },
		gcRemoveEmptyMultiplex: func(string) ([]string, error) { return nil, nil },
		gcFindOrphanBridges: func(map[string]bool) ([]netx.OrphanBridge, error) {
			return nil, nil
		},
		gcRemoveOrphanBridge: func(string) error { return nil },
	}
	server.initCoordination()
	return server
}

func TestCollectionDoesNotDeleteAnOverlayADeployJustClaimed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)

	// The scan says VNI 4242 belongs to a lab that is gone. Between that scan
	// and the deletion, a deployment of a different lab reserves it -- which
	// is legitimate, because at the moment it asked, nothing said otherwise.
	server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
		return []netx.Orphan{{VNI: 4242, Owner: "abandoned"}}, nil
	}
	var removed []uint32
	server.gcRemoveOverlay = func(vni uint32) error {
		removed = append(removed, vni)
		return nil
	}
	server.gcDeleteHostLink = func(string) error { return nil }

	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The claim lands inside the grace window, exactly as a real deploy would.
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: "arriving", TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.reserveOverlays(OverlayReservationRequest{
		Lab: "arriving", Fence: lease.Fence, VNIs: []uint32{4242},
	}); err != nil {
		t.Fatalf("a deployment could not claim an unclaimed identifier: %v", err)
	}

	now = now.Add(2 * time.Second)
	summary, err := server.gcOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 || len(summary.RemovedOverlays) != 0 {
		t.Fatalf("collection deleted VNI 4242 after a deployment claimed it: %+v", summary)
	}
	server.mu.Lock()
	claim, ok := server.overlayClaims[4242]
	server.mu.Unlock()
	if !ok || claim.Lab != "arriving" {
		t.Fatalf("the deployment's reservation did not survive collection: %+v", claim)
	}
}

func TestADeployCannotClaimAnIdentifierMidCollection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	server.gcFindOrphans = func(map[string]bool) ([]netx.Orphan, error) {
		return []netx.Orphan{{VNI: 4242, Owner: "abandoned"}}, nil
	}

	// The window that mattered: the collector has proved the object abandoned
	// and is deleting it. A reservation granted now hands a lab an overlay
	// that is about to disappear underneath it.
	reserving := make(chan error, 1)
	inside := make(chan struct{})
	server.gcRemoveOverlay = func(uint32) error {
		close(inside)
		return <-reserveDuring(server, reserving)
	}
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-inside:
	case <-time.After(5 * time.Second):
		t.Fatal("collection never reached the destructive step")
	}
	select {
	case err := <-reserving:
		if err == nil {
			t.Fatal("a deployment was granted an identifier that was being deleted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reservation neither succeeded nor was refused")
	}
}

// reserveDuring runs a reservation while the collector holds the object, and
// reports the result of the collection step itself as nil.
func reserveDuring(server *Server, out chan error) chan error {
	done := make(chan error, 1)
	go func() {
		lease, err := server.acquireMutationLease(LeaseAcquireRequest{
			Lab: "arriving", TTLSeconds: 600,
		})
		if err != nil {
			out <- err
			done <- nil
			return
		}
		_, reserveErr := server.reserveOverlays(OverlayReservationRequest{
			Lab: "arriving", Fence: lease.Fence, VNIs: []uint32{4242},
		})
		out <- reserveErr
		done <- nil
	}()
	return done
}

func TestCollectionYieldsToADeployThatTookTheLabsOperationLease(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)

	opID, _, err := server.acquireOperation("cos461", "apply", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed := server.beginLabRecordCollection("cos461"); claimed {
		t.Fatal("record collection ran while a deploy held the lab")
	}
	server.releaseOperation("cos461", opID, nil)

	id, claimed := server.beginLabRecordCollection("cos461")
	if !claimed {
		t.Fatal("record collection could not take an idle lab")
	}
	// While the collector holds the lab, a deploy is refused rather than
	// racing the removal of the records it is about to write.
	if _, _, err := server.acquireOperation("cos461", "apply", nil); err == nil {
		t.Fatal("a deploy was admitted while records were being collected")
	}
	server.endLabRecordCollection("cos461", id)
	if _, _, err := server.acquireOperation("cos461", "apply", nil); err != nil {
		t.Fatalf("the lab was not released after collection: %v", err)
	}
}

func TestConcurrentDeploysAndCollectionsNeverAgreeOnAnIdentifier(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)

	const rounds = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conflicts int
	for round := range rounds {
		vni := uint32(5000 + round)
		wg.Add(2)
		go func() {
			defer wg.Done()
			if !server.beginOverlayCollection(vni, "abandoned") {
				return
			}
			defer server.endOverlayCollection(vni, "abandoned")
			server.mu.Lock()
			claim, claimed := server.overlayClaims[vni]
			server.mu.Unlock()
			if claimed && claim.Lab != "" {
				mu.Lock()
				conflicts++
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			lease, err := server.acquireMutationLease(LeaseAcquireRequest{
				Lab: "lab" + string(rune('a'+round%26)), TTLSeconds: 600,
			})
			if err != nil {
				return
			}
			_, _ = server.reserveOverlays(OverlayReservationRequest{
				Lab: lease.Lab, Fence: lease.Fence, VNIs: []uint32{vni},
			})
		}()
	}
	wg.Wait()
	if conflicts > 0 {
		t.Fatalf("%d identifier(s) were simultaneously reserved and being collected", conflicts)
	}
}

func TestCollectionRemovesADemonstrablyOrphanedBridge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	var removed []string
	server.gcFindOrphanBridges = func(live map[string]bool) ([]netx.OrphanBridge, error) {
		if live["cos461"] {
			return []netx.OrphanBridge{{Name: "twbp0123456789a"}}, nil
		}
		return []netx.OrphanBridge{
			{Name: "twbp0123456789a"},
			{Name: "twbr1001", VNI: 1001},
			{Name: "twbr1002", VNI: 1002, Ports: 1},
		}, nil
	}
	server.gcRemoveOrphanBridge = func(name string) error {
		removed = append(removed, name)
		return nil
	}
	if _, err := server.gcOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("a bridge was removed on its first observation: %v", removed)
	}
	now = now.Add(2 * time.Second)
	summary, err := server.gcOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.RemovedBridges) != 2 {
		t.Fatalf("collected bridges = %v, want the two empty ones", summary.RemovedBridges)
	}
	for _, name := range removed {
		if name == "twbr1002" {
			t.Fatal("a bridge with a port on it was removed")
		}
	}
}

func TestAnUnreadableBridgeScanStopsCollectionRatherThanGuessing(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := gcFenceServer(&now)
	server.gcFindOrphanBridges = func(map[string]bool) ([]netx.OrphanBridge, error) {
		return nil, errTestRuntimeUnavailable{}
	}
	server.gcRemoveOrphanBridge = func(string) error {
		t.Fatal("a bridge was removed from an unreadable scan")
		return nil
	}
	if _, err := server.gcOnce(context.Background()); err == nil {
		t.Fatal("an unreadable link table was reported as a clean collection pass")
	}
}
