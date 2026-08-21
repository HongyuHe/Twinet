package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

type coordinationStub struct {
	mu sync.Mutex

	name         string
	failAcquire  bool
	next         uint64
	leases       map[string]agent.Fence
	generations  map[string]string
	prepared     map[string]string
	releases     int
	applyCalls   int
	order        *[]string
	firstAcquire chan struct{}
	blockAcquire chan struct{}
	didBlock     bool
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
			if s.prepared[req.Lab] != req.Generation {
				s.mu.Unlock()
				fail(http.StatusConflict, fmt.Errorf("not prepared"))
				return
			}
			s.applyCalls++
		case "commit":
			s.generations[req.Lab] = req.Generation
		case "finalize":
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
		results <- c.Apply(t.Context(), top, agent.ApplyRequest{Generation: "generation-a"})
	}()
	<-a.firstAcquire
	go func() {
		results <- c.Apply(t.Context(), top, agent.ApplyRequest{Generation: "generation-b"})
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
