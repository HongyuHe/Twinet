package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

type coordinationStub struct {
	mu sync.Mutex

	name          string
	failAcquire   bool
	next          uint64
	leases        map[string]agent.Fence
	generations   map[string]string
	prepared      map[string]string
	releases      int
	applyCalls    int
	applied       []string
	order         *[]string
	firstAcquire  chan struct{}
	blockAcquire  chan struct{}
	didBlock      bool
	commitStarted chan<- string
	releaseCommit <-chan struct{}
	// failFinalize and staleRecovery break the two stages that run only after
	// every node has acknowledged commit.
	failFinalize  bool
	staleRecovery bool
	// failApply breaks a stage that runs before any node commits.
	failApply bool
	// unproven is what this node's forward apply reports it could not vouch
	// for. Its commit deliberately says nothing, which is what a real one
	// does: commit runs a narrower engine that never observed those devices.
	unproven map[string]string
}

func newCoordinationStub(name string, order *[]string) *coordinationStub {
	return &coordinationStub{
		name: name, leases: map[string]agent.Fence{}, generations: map[string]string{},
		prepared: map[string]string{}, order: order,
	}
}

func (s *coordinationStub) record(event string) {
	if s.order == nil {
		return
	}
	s.mu.Lock()
	*s.order = append(*s.order, event)
	s.mu.Unlock()
}

func (s *coordinationStub) handler(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(code int, err error) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	switch r.URL.Path {
	case "/v1/status":
		s.mu.Lock()
		gens := map[string]string{}
		for lab, generation := range s.generations {
			gens[lab] = generation
		}
		s.mu.Unlock()
		write(agent.StatusResponse{Node: s.name, Generations: gens})
	case "/v1/lease/acquire":
		var req agent.LeaseAcquireRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		if s.failAcquire || s.leases[req.Lab].Token != "" {
			s.mu.Unlock()
			fail(http.StatusConflict, fmt.Errorf("%s refuses acquisition", s.name))
			return
		}
		s.next++
		fence := agent.Fence{Token: fmt.Sprintf("%s-%d", s.name, s.next), Generation: s.next}
		s.leases[req.Lab] = fence
		block := !s.didBlock && s.blockAcquire != nil
		if block {
			s.didBlock = true
		}
		s.mu.Unlock()
		s.record("acquire:" + s.name)
		if block {
			close(s.firstAcquire)
			<-s.blockAcquire
		}
		write(agent.LeaseResponse{Lab: req.Lab, Fence: fence})
	case "/v1/lease/renew":
		var req agent.LeaseRenewRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		fence := s.leases[req.Lab]
		s.mu.Unlock()
		if fence != req.Fence {
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		write(agent.LeaseResponse{Lab: req.Lab, Fence: fence})
	case "/v1/lease/release":
		var req agent.LeaseReleaseRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		if s.leases[req.Lab] == req.Fence {
			delete(s.leases, req.Lab)
			s.releases++
		}
		s.mu.Unlock()
		s.record("release:" + s.name)
		write(struct{}{})
	case "/v1/overlay/reserve":
		var req agent.OverlayReservationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		ok := s.leases[req.Lab] == req.Fence
		s.mu.Unlock()
		if !ok {
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		write(agent.OverlayReservationResponse{Lab: req.Lab, VNIs: req.VNIs})
	case "/v1/recover":
		var req agent.RecoveryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		ok := s.leases[req.Lab] == req.Fence
		generation := s.generations[req.Lab]
		s.mu.Unlock()
		if !ok {
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		phase := "idle"
		if generation != "" {
			phase = "committed"
		}
		write(agent.RecoveryResponse{Status: agent.RecoveryStatus{
			Lab: req.Lab, Phase: phase, Generation: generation, Consistent: true,
		}})
	case "/v1/recovery":
		lab := r.URL.Query().Get("lab")
		s.mu.Lock()
		generation := s.generations[lab]
		stale := s.staleRecovery
		s.mu.Unlock()
		phase := "idle"
		if generation != "" {
			phase = "committed"
		}
		if stale {
			write(agent.RecoveryStatus{Lab: lab, Phase: phase, Generation: generation,
				Consistent: false, Error: "inventory does not match the committed generation"})
			return
		}
		write(agent.RecoveryStatus{Lab: lab, Phase: phase, Generation: generation, Consistent: true})
	case "/v1/destroy":
		var req agent.DestroyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		if s.leases[req.Lab] != req.Fence {
			s.mu.Unlock()
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		delete(s.generations, req.Lab)
		delete(s.prepared, req.Lab)
		s.mu.Unlock()
		write(agent.DestroyResponse{Status: "destroyed", Lab: req.Lab})
	case "/v1/apply":
		var req agent.ApplyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		if s.leases[req.Lab] != req.Fence {
			s.mu.Unlock()
			fail(http.StatusConflict, fmt.Errorf("stale fence"))
			return
		}
		switch req.Phase {
		case "prepare":
			if current := s.generations[req.Lab]; current != req.ExpectedGeneration {
				s.mu.Unlock()
				fail(http.StatusConflict, fmt.Errorf("generation compare-and-swap failed"))
				return
			}
			s.prepared[req.Lab] = req.Generation
		case "apply":
			if s.failApply {
				s.mu.Unlock()
				fail(http.StatusInternalServerError, fmt.Errorf("%s could not create a container", s.name))
				return
			}
			if s.prepared[req.Lab] != req.Generation {
				s.mu.Unlock()
				fail(http.StatusConflict, fmt.Errorf("not prepared"))
				return
			}
			if !req.AssignmentKnown || req.TargetNode != s.name {
				s.mu.Unlock()
				fail(http.StatusConflict, fmt.Errorf("missing placement witness for %s", s.name))
				return
			}
			top, placementErr := req.Topology.Rehydrate()
			if placementErr != nil {
				s.mu.Unlock()
				fail(http.StatusBadRequest, placementErr)
				return
			}
			var actual []string
			for _, device := range top.DevicesOnNode(s.name) {
				actual = append(actual, device.ID)
			}
			if fmt.Sprint(actual) != fmt.Sprint(req.AssignedDevices) {
				s.mu.Unlock()
				fail(http.StatusConflict, fmt.Errorf("placement witness does not match serialized topology"))
				return
			}
			s.applied = append([]string(nil), req.AssignedDevices...)
			s.applyCalls++
			unproven := s.unproven
			s.mu.Unlock()
			write(agent.ApplyResponse{
				Node: s.name, Generation: req.Generation, Phase: req.Phase,
				UnprovenNamespaces: unproven,
			})
			return
		case "commit":
			s.generations[req.Lab] = req.Generation
			started, release := s.commitStarted, s.releaseCommit
			s.mu.Unlock()
			if started != nil {
				started <- s.name
			}
			if release != nil {
				<-release
			}
			write(agent.ApplyResponse{Node: s.name, Generation: req.Generation, Phase: req.Phase})
			return
		case "finalize":
			if s.failFinalize {
				s.mu.Unlock()
				fail(http.StatusInternalServerError, fmt.Errorf("%s could not prune the previous generation", s.name))
				return
			}
			delete(s.prepared, req.Lab)
		case "abort":
			delete(s.prepared, req.Lab)
		}
		s.mu.Unlock()
		write(agent.ApplyResponse{Node: s.name, Generation: req.Generation, Phase: req.Phase})
	default:
		fail(http.StatusNotFound, fmt.Errorf("unexpected path %s", r.URL.Path))
	}
}

func stubNode(name string, stub *coordinationStub) (*Node, func()) {
	server := httptest.NewServer(http.HandlerFunc(stub.handler))
	return NewNode(name, server.URL, ""), server.Close
}

func TestCoordinatedApplyCommitsNodesConcurrently(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	a := newCoordinationStub("a", nil)
	b := newCoordinationStub("b", nil)
	a.commitStarted, b.commitStarted = started, started
	a.releaseCommit, b.releaseCommit = release, release
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()

	done := make(chan []NodeResult[agent.ApplyResponse], 1)
	go func() {
		done <- (&Cluster{Nodes: []*Node{na, nb}}).Apply(t.Context(),
			&model.Topology{Name: "scale", Lab: &model.Lab{}},
			agent.ApplyRequest{Generation: "parallel-commit", Mode: "solve"})
	}()

	seen := map[string]bool{}
	for range 2 {
		select {
		case node := <-started:
			seen[node] = true
		case <-time.After(2 * time.Second):
			t.Fatal("node commits were serialized")
		}
	}
	close(release)
	for _, result := range <-done {
		if result.Err != nil {
			t.Fatalf("commit on %s: %v", result.Node, result.Err)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("commit starters = %v, want both nodes", seen)
	}
}

func TestLeaseAcquisitionRollsBackAPartialPrefixInReverseOrder(t *testing.T) {
	var order []string
	a := newCoordinationStub("a", &order)
	b := newCoordinationStub("b", &order)
	b.failAcquire = true
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()

	// Deliberately reverse the supplied order. The coordinator must choose
	// names, not manifest order, and undo a partial prefix in reverse.
	c := &Cluster{Nodes: []*Node{nb, na}}
	if _, err := c.AcquireMutationLease(t.Context(), "cos461"); err == nil {
		t.Fatal("a partial lease acquisition was reported as successful")
	}
	want := []string{"acquire:a", "release:a"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("acquisition/rollback order %v, want %v", order, want)
	}
	a.mu.Lock()
	releases := a.releases
	a.mu.Unlock()
	if releases != 1 {
		t.Fatalf("the acquired node was not released after another node refused: %d releases", releases)
	}
}

func TestTwoControllersRaceOneLabAndOnlyOneCommits(t *testing.T) {
	a := newCoordinationStub("a", nil)
	b := newCoordinationStub("b", nil)
	a.firstAcquire = make(chan struct{})
	a.blockAcquire = make(chan struct{})
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()
	c := &Cluster{Nodes: []*Node{nb, na}}
	top := &model.Topology{Name: "cos461", Lab: &model.Lab{}}

	results := make(chan []NodeResult[agent.ApplyResponse], 2)
	go func() {
		results <- c.Apply(t.Context(), top, agent.ApplyRequest{Generation: "generation-a", Mode: "platform"})
	}()
	<-a.firstAcquire
	go func() {
		results <- c.Apply(t.Context(), top, agent.ApplyRequest{Generation: "generation-b", Mode: "platform"})
	}()
	close(a.blockAcquire)

	committed := 0
	for i := 0; i < 2; i++ {
		result := <-results
		ok := len(result) == 2
		for _, node := range result {
			ok = ok && node.Err == nil
		}
		if ok {
			committed++
		}
	}
	if committed != 1 {
		t.Fatalf("%d racing controllers committed; exactly one may commit", committed)
	}
	for _, stub := range []*coordinationStub{a, b} {
		stub.mu.Lock()
		generation := stub.generations["cos461"]
		stub.mu.Unlock()
		if generation != "generation-a" {
			t.Fatalf("%s recorded generation %q, not the sole committed generation", stub.name, generation)
		}
	}
}

func TestCoordinatedDestroyAllowsCleanRedeploy(t *testing.T) {
	a := newCoordinationStub("a", nil)
	b := newCoordinationStub("b", nil)
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()
	cluster := &Cluster{Nodes: []*Node{na, nb}}
	top := &model.Topology{Name: "clos-acceptance", Lab: &model.Lab{}}

	first := cluster.Apply(t.Context(), top, agent.ApplyRequest{
		Generation: "20260823T022156", Mode: "solve",
	})
	for _, result := range first {
		if result.Err != nil {
			t.Fatalf("initial apply on %s: %v", result.Node, result.Err)
		}
	}
	for _, result := range cluster.Destroy(t.Context(), top.Name, nil) {
		if result.Err != nil {
			t.Fatalf("destroy on %s: %v", result.Node, result.Err)
		}
	}
	second := cluster.Apply(t.Context(), top, agent.ApplyRequest{
		Generation: "redeployed", Mode: "solve",
	})
	for _, result := range second {
		if result.Err != nil {
			t.Fatalf("redeploy on %s: %v", result.Node, result.Err)
		}
	}
	for _, stub := range []*coordinationStub{a, b} {
		stub.mu.Lock()
		generation, calls := stub.generations[top.Name], stub.applyCalls
		stub.mu.Unlock()
		if generation != "redeployed" || calls != 2 {
			t.Fatalf("%s redeploy state = generation %q apply calls %d", stub.name, generation, calls)
		}
	}
}

func TestCoordinatedApplyCarriesThreeNodePlacementSubsets(t *testing.T) {
	stubs := []*coordinationStub{
		newCoordinationStub("node-0", nil),
		newCoordinationStub("node-1", nil),
		newCoordinationStub("node-2", nil),
	}
	var nodes []*Node
	for _, stub := range stubs {
		node, closeNode := stubNode(stub.name, stub)
		defer closeNode()
		nodes = append(nodes, node)
	}
	top := &model.Topology{
		Name: "clos-acceptance",
		Lab:  &model.Lab{},
		Devices: map[string]*model.Device{
			"spine-0": {ID: "spine-0", Node: "node-0"},
			"spine-1": {ID: "spine-1", Node: "node-0"},
			"leaf-0":  {ID: "leaf-0", Node: "node-0"},
			"host-0a": {ID: "host-0a", Node: "node-0"},
			"host-0b": {ID: "host-0b", Node: "node-0"},
			"leaf-1":  {ID: "leaf-1", Node: "node-1"},
			"host-1a": {ID: "host-1a", Node: "node-1"},
			"host-1b": {ID: "host-1b", Node: "node-1"},
			"leaf-2":  {ID: "leaf-2", Node: "node-2"},
			"host-2a": {ID: "host-2a", Node: "node-2"},
			"host-2b": {ID: "host-2b", Node: "node-2"},
		},
	}
	results := (&Cluster{Nodes: nodes}).Apply(t.Context(), top, agent.ApplyRequest{
		Generation: "clos-placement", Mode: "solve",
	})
	for _, result := range results {
		if result.Err != nil {
			t.Fatalf("apply on %s: %v", result.Node, result.Err)
		}
	}
	want := map[string][]string{
		"node-0": {"host-0a", "host-0b", "leaf-0", "spine-0", "spine-1"},
		"node-1": {"host-1a", "host-1b", "leaf-1"},
		"node-2": {"host-2a", "host-2b", "leaf-2"},
	}
	for _, stub := range stubs {
		stub.mu.Lock()
		got := append([]string(nil), stub.applied...)
		stub.mu.Unlock()
		if fmt.Sprint(got) != fmt.Sprint(want[stub.name]) {
			t.Fatalf("%s received placement subset %v, want %v", stub.name, got, want[stub.name])
		}
	}
}

func TestApplyRequestForNodeCarriesCanonicalTransactionMode(t *testing.T) {
	wire := &agent.Wire{Lab: "lab", Mode: "solve", Ungraded: 7}
	out := applyRequestForNode(agent.ApplyRequest{Mode: "solve", Ungraded: 7}, wire, nil,
		nil, "node-0", "prepare", "old", "new")
	if out.Mode != "solve" || out.Ungraded != 7 || out.Topology == nil ||
		out.Topology.Mode != "solve" || out.Topology.Ungraded != 7 ||
		!out.AssignmentKnown || out.TargetNode != "node-0" {
		t.Fatalf("node request lost canonical mode: %+v", out)
	}
}

func TestRecoverRejectsMixedNodeGenerations(t *testing.T) {
	a := newCoordinationStub("a", nil)
	b := newCoordinationStub("b", nil)
	a.generations["cos461"] = "old-generation"
	b.generations["cos461"] = "new-generation"
	na, closeA := stubNode("a", a)
	defer closeA()
	nb, closeB := stubNode("b", b)
	defer closeB()

	report, err := (&Cluster{Nodes: []*Node{na, nb}}).Recover(t.Context(), "cos461")
	if err == nil {
		t.Fatalf("mixed generations were reported recovered: %+v", report)
	}
	if report.Nodes["a"].Generation == report.Nodes["b"].Generation {
		t.Fatalf("test setup did not retain mixed node evidence: %+v", report)
	}
}

func TestRecoverRejectsLostNode(t *testing.T) {
	a := newCoordinationStub("a", nil)
	na, closeA := stubNode("a", a)
	defer closeA()
	lost := httptest.NewServer(http.NotFoundHandler())
	lostURL := lost.URL
	lost.Close()
	nb := NewNode("b", lostURL, "")

	if _, err := (&Cluster{Nodes: []*Node{na, nb}}).Recover(t.Context(), "cos461"); err == nil {
		t.Fatal("recovery accepted a node that could not report its inventory")
	}
}
