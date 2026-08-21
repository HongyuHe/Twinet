package agent

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/state"
)

func coordinationTestServer(t *testing.T, st *state.Store) *Server {
	t.Helper()
	s := &Server{
		cfg:           Config{Node: "node-0"},
		store:         st,
		current:       map[string]*model.Topology{},
		modes:         map[string]string{},
		ungraded:      map[string]int{},
		peers:         map[string]map[string]string{},
		ops:           map[string]*lease{},
		overlayOwners: func() (map[uint32]string, error) { return map[uint32]string{}, nil },
	}
	s.initCoordination()
	return s
}

// Ordered cluster acquisition relies on each node issuing at most one fence
// for a lab. If this becomes a check-then-set race, two controllers can each
// own a different node and neither can make progress.
func TestOnlyOneControllerGetsALabFence(t *testing.T) {
	s := coordinationTestServer(t, nil)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan LeaseResponse, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := s.acquireMutationLease(LeaseAcquireRequest{
				Lab: "cos461", Holder: string(rune('a' + i)),
			})
			if err != nil {
				errs <- err
				return
			}
			results <- resp
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	if len(results) != 1 || len(errs) != 1 {
		t.Fatalf("two racing controllers got %d fences and %d refusals; want one of each",
			len(results), len(errs))
	}
}

func TestExpiredFenceCannotMutateAfterANewerFence(t *testing.T) {
	s := coordinationTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	old, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461", TTLSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	newer, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if newer.Fence.Generation <= old.Fence.Generation {
		t.Fatalf("new fence generation %d did not advance past %d",
			newer.Fence.Generation, old.Fence.Generation)
	}
	if err := s.requireMutationFence("cos461", old.Fence); err == nil {
		t.Fatal("an expired controller retained authority after a newer fence was issued")
	}
	if err := s.requireMutationFence("cos461", newer.Fence); err != nil {
		t.Fatalf("the current controller was rejected: %v", err)
	}
}

func TestOverlayReservationIsAtomicAcrossLabs(t *testing.T) {
	s := coordinationTestServer(t, nil)
	a, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab-a"})
	if err != nil {
		t.Fatal(err)
	}

	b, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab-b"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, req := range []OverlayReservationRequest{
		{Lab: "lab-a", Fence: a.Fence, VNIs: []uint32{777}},
		{Lab: "lab-b", Fence: b.Fence, VNIs: []uint32{777}},
	} {
		req := req
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.reserveOverlays(req)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("%d labs reserved the same VNI; exactly one must win", success)
	}
}

func TestExpiredLeaseReleasesItsOverlayReservation(t *testing.T) {
	s := coordinationTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	first, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab-a", TTLSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "lab-a", Fence: first.Fence, VNIs: []uint32{778},
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	second, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "lab-b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "lab-b", Fence: second.Fence, VNIs: []uint32{778},
	}); err != nil {
		t.Fatalf("expired overlay reservation remained live: %v", err)
	}
}

func TestFenceHighWaterSurvivesAgentRestart(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := coordinationTestServer(t, st)
	old, err := before.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, st)
	after.loadCoordination()
	if err := after.requireMutationFence("cos461", old.Fence); err == nil {
		t.Fatal("a pre-restart fence remained valid after the agent forgot its active leases")
	}
	next, err := after.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Fence.Generation <= old.Fence.Generation {
		t.Fatalf("restart issued generation %d after %d; stale requests could be accepted",
			next.Fence.Generation, old.Fence.Generation)
	}
}

func TestPreparedGenerationFailsClosedAfterControllerLoss(t *testing.T) {
	s := coordinationTestServer(t, nil)
	first, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(&Wire{Lab: "cos461"})
	if err := s.prepareGeneration("cos461", first.Fence, "", "generation-a", raw,
		"platform", 0, nil, false, nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.mutations["cos461"].until = time.Now().Add(-time.Second)
	s.mu.Unlock()
	second, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.prepareGeneration("cos461", second.Fence, "", "generation-b", raw,
		"platform", 0, nil, false, nil); err == nil {
		t.Fatal("a new controller replaced an unfinished generation instead of failing closed")
	}
}
