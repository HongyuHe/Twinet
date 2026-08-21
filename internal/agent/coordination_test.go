package agent

import (
	"encoding/json"
	"errors"
	"fmt"
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

func crossNodeTopology(lab string, vnis ...uint32) *model.Topology {
	a := &model.Device{ID: lab + "/a", Name: "a", Node: "node-0"}
	b := &model.Device{ID: lab + "/b", Name: "b", Node: "node-1"}
	top := &model.Topology{
		Name:    lab,
		Devices: map[string]*model.Device{a.ID: a, b.ID: b},
	}
	for i, vni := range vnis {
		ai := &model.Iface{Device: a, Name: fmt.Sprintf("a%d", i)}
		bi := &model.Iface{Device: b, Name: fmt.Sprintf("b%d", i)}
		a.Ifaces = append(a.Ifaces, ai)
		b.Ifaces = append(b.Ifaces, bi)
		link := &model.Link{ID: fmt.Sprintf("%s-link-%d", lab, i), A: ai, B: bi, VNI: vni}
		ai.Link, bi.Link = link, link
		ai.Peer, bi.Peer = bi, ai
		top.Links = append(top.Links, link)
	}
	return top
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

func TestApplyRefusesAnUnreservedCrossLabVNI(t *testing.T) {
	server := coordinationTestServer(t, nil)
	top := crossNodeTopology("lab-a", 901)
	lease, err := server.acquireMutationLease(LeaseAcquireRequest{Lab: top.Name})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.requireOverlayReservations(top, lease.Fence); err == nil {
		t.Fatal("cross-node topology reached apply without a fenced VNI reservation")
	}
	if _, err := server.reserveOverlays(OverlayReservationRequest{
		Lab: top.Name, Fence: lease.Fence, VNIs: []uint32{901},
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.requireOverlayReservations(top, lease.Fence); err != nil {
		t.Fatalf("owned reservation was not accepted: %v", err)
	}
}

func TestLegacyActiveOverlayIsAdoptedOnlyForItsCurrentLab(t *testing.T) {
	const (
		lab = "cos461"
		vni = 2_434_251
	)
	s := coordinationTestServer(t, nil)
	s.current[lab] = crossNodeTopology(lab, vni)
	owners := map[uint32]string{vni: ""}
	var adopted []uint32
	s.overlayOwners = func() (map[uint32]string, error) { return owners, nil }
	s.overlayAdopter = func(got uint32, owner string) error {
		if owner != lab {
			t.Fatalf("adopted VNI for %q, want %q", owner, lab)
		}
		adopted = append(adopted, got)
		owners[got] = owner
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: lease.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("legacy active VNI was not adopted: %v", err)
	}
	if len(adopted) != 1 || adopted[0] != vni {
		t.Fatalf("adopted %v, want only VNI %d", adopted, vni)
	}
	claim := s.overlayClaims[vni]
	if !claim.Live || claim.Lab != lab {
		t.Fatalf("legacy VNI claim = %+v, want live ownership by %q", claim, lab)
	}
}

func TestLegacyActiveOverlayCanUsePersistedTopology(t *testing.T) {
	const (
		lab = "cos461"
		vni = 2_434_251
	)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Serialise(crossNodeTopology(lab, vni)))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutTopology(lab, raw); err != nil {
		t.Fatal(err)
	}
	s := coordinationTestServer(t, st)
	owners := map[uint32]string{vni: ""}
	s.overlayOwners = func() (map[uint32]string, error) { return owners, nil }
	s.overlayAdopter = func(got uint32, owner string) error {
		owners[got] = owner
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: lease.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("persisted topology did not permit safe legacy adoption: %v", err)
	}
}

func TestLegacyOwnerlessOverlayRefusesAnotherCurrentLab(t *testing.T) {
	const vni = 2_434_251
	s := coordinationTestServer(t, nil)
	s.current["cos461"] = crossNodeTopology("cos461", vni)
	s.current["other"] = crossNodeTopology("other", vni)
	s.overlayOwners = func() (map[uint32]string, error) {
		return map[uint32]string{vni: ""}, nil
	}
	adopted := false
	s.overlayAdopter = func(uint32, string) error {
		adopted = true
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "cos461", Fence: lease.Fence, VNIs: []uint32{vni},
	}); err == nil {
		t.Fatal("ownerless VNI claimed by another current lab was adopted")
	}
	if adopted {
		t.Fatal("conflicting ownerless VNI reached the alias adoption path")
	}
}

func TestLegacyOwnerlessOverlayRefusesDuplicateCurrentClaims(t *testing.T) {
	const vni = 2_434_251
	s := coordinationTestServer(t, nil)
	s.current["cos461"] = crossNodeTopology("cos461", vni, vni)
	s.overlayOwners = func() (map[uint32]string, error) {
		return map[uint32]string{vni: ""}, nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "cos461", Fence: lease.Fence, VNIs: []uint32{vni},
	}); err == nil {
		t.Fatal("ownerless VNI with duplicate current claims was adopted")
	}
}

func TestLegacyOwnerlessOverlayRefusesMissingTopology(t *testing.T) {
	const vni = 2_434_251
	s := coordinationTestServer(t, nil)
	s.overlayOwners = func() (map[uint32]string, error) {
		return map[uint32]string{vni: ""}, nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "cos461", Fence: lease.Fence, VNIs: []uint32{vni},
	}); err == nil {
		t.Fatal("ownerless VNI without a topology was adopted")
	}
}

func TestLegacyOwnerlessOverlayRefusesStaleNonCrossNodeTopology(t *testing.T) {
	const vni = 2_434_251
	s := coordinationTestServer(t, nil)
	top := crossNodeTopology("cos461", vni)
	top.Devices["cos461/b"].Node = "node-0"
	s.current["cos461"] = top
	s.overlayOwners = func() (map[uint32]string, error) {
		return map[uint32]string{vni: ""}, nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: "cos461", Fence: lease.Fence, VNIs: []uint32{vni},
	}); err == nil {
		t.Fatal("ownerless VNI with stale non-cross-node topology was adopted")
	}
}

func TestLegacyOverlayAdoptionRollsBackOnBatchFailure(t *testing.T) {
	const (
		lab = "cos461"
		one = 2_434_251
		two = 2_434_252
	)
	s := coordinationTestServer(t, nil)
	s.current[lab] = crossNodeTopology(lab, one, two)
	owners := map[uint32]string{one: "", two: ""}
	s.overlayOwners = func() (map[uint32]string, error) { return owners, nil }
	s.overlayAdopter = func(vni uint32, owner string) error {
		if vni == two {
			return errors.New("second alias write failed")
		}
		owners[vni] = owner
		return nil
	}
	var reverted []uint32
	s.overlayReverter = func(vni uint32, owner string) error {
		reverted = append(reverted, vni)
		owners[vni] = ""
		return nil
	}
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: lease.Fence, VNIs: []uint32{one, two},
	}); err == nil {
		t.Fatal("partially adopted legacy reservation reported success")
	}
	if len(reverted) != 1 || reverted[0] != one || owners[one] != "" || owners[two] != "" {
		t.Fatalf("first adopted VNI was not rolled back: reverted=%v owners=%v", reverted, owners)
	}
	if _, exists := s.overlayClaims[one]; exists {
		t.Fatal("rolled-back legacy VNI retained a reservation claim")
	}
	if _, exists := s.overlayClaims[two]; exists {
		t.Fatal("failed legacy VNI retained a reservation claim")
	}
}

func TestLegacyOverlayAdoptionPersistsAcrossRestart(t *testing.T) {
	const (
		lab = "cos461"
		vni = 2_434_251
	)
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	top := crossNodeTopology(lab, vni)
	raw, err := json.Marshal(Serialise(top))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutTopology(lab, raw); err != nil {
		t.Fatal(err)
	}

	owners := map[uint32]string{vni: ""}
	before := coordinationTestServer(t, st)
	before.current[lab] = top
	before.overlayOwners = func() (map[uint32]string, error) { return owners, nil }
	before.overlayAdopter = func(got uint32, owner string) error {
		owners[got] = owner
		return nil
	}
	lease, err := before.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := before.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: lease.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatal(err)
	}

	after := coordinationTestServer(t, st)
	after.overlayOwners = func() (map[uint32]string, error) { return owners, nil }
	after.loadCoordination()
	after.rehydrate()
	claim, ok := after.overlayClaims[vni]
	if !ok || !claim.Live || claim.Lab != lab {
		t.Fatalf("restart lost adopted live claim: %+v present=%v", claim, ok)
	}
	next, err := after.acquireMutationLease(LeaseAcquireRequest{Lab: lab})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: next.Fence, VNIs: []uint32{vni},
	}); err != nil {
		t.Fatalf("restart could not safely reuse persisted legacy ownership: %v", err)
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
		"platform", 0, nil, false, nil, nil); err != nil {
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
		"platform", 0, nil, false, nil, nil); err == nil {
		t.Fatal("a new controller replaced an unfinished generation instead of failing closed")
	}
}

// Source pruning is only reachable from commit. A migration transaction with
// imported state but no verified destination restore must therefore remain
// unable to commit across controller interruption at every earlier phase.
func TestInterruptedMigrationCannotPruneBeforeVerifiedRestore(t *testing.T) {
	s := coordinationTestServer(t, nil)
	lease, err := s.acquireMutationLease(LeaseAcquireRequest{Lab: "cos461"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(&Wire{Lab: "cos461"})
	proofs := []StateProof{{Device: "as3/MSP", Snapshots: []WireSnapshot{{
		Snapshot: state.Snapshot{Lab: "cos461", Device: "as3/MSP", Kind: state.KindFRR, Digest: "digest"},
		Content:  []byte("router bgp 3\n"),
	}}}}
	if err := s.prepareGeneration("cos461", lease.Fence, "", "generation-state", raw,
		"platform", 0, nil, true, nil, proofs); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transactionForCommit("cos461", lease.Fence, "generation-state"); err == nil {
		t.Fatal("an unapplied migration was allowed to commit")
	}
	if err := s.markGenerationApplied("cos461", lease.Fence, "generation-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transactionForCommit("cos461", lease.Fence, "generation-state"); err == nil {
		t.Fatal("source prune was permitted before destination restore verification")
	}
	if err := s.markStateVerified("cos461", lease.Fence, "generation-state"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transactionForCommit("cos461", lease.Fence, "generation-state"); err != nil {
		t.Fatalf("verified restore still could not commit: %v", err)
	}
}
