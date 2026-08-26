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

func harnessTopologyForTest() *model.Topology {
	return &model.Topology{Name: "harness-as3", Hash: "harness-hash", Lab: &model.Lab{}}
}

type ephemeralStub struct {
	mu       sync.Mutex
	renewals []agent.EphemeralRequest
	refuse   bool
}

func (s *ephemeralStub) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/ephemeral" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var req agent.EphemeralRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	s.renewals = append(s.renewals, req)
	refuse := s.refuse
	s.mu.Unlock()
	if refuse {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not an ephemeral lab"})
		return
	}
	_ = json.NewEncoder(w).Encode(agent.EphemeralResponse{
		Lab: req.Lab, Ephemeral: !req.Release, Owner: req.Owner, TTLSeconds: req.TTLSeconds,
	})
}

func (s *ephemeralStub) observed() []agent.EphemeralRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]agent.EphemeralRequest(nil), s.renewals...)
}

func ephemeralCluster(t *testing.T, nodes int) (*Cluster, []*ephemeralStub) {
	t.Helper()
	cluster := &Cluster{}
	stubs := make([]*ephemeralStub, 0, nodes)
	for i := range nodes {
		stub := &ephemeralStub{}
		server := httptest.NewServer(http.HandlerFunc(stub.handler))
		t.Cleanup(server.Close)
		cluster.Nodes = append(cluster.Nodes, NewNode(fmt.Sprintf("node-%d", i), server.URL, ""))
		stubs = append(stubs, stub)
	}
	return cluster, stubs
}

func TestAHeartbeatRenewsEveryNodeUntilItIsStopped(t *testing.T) {
	cluster, stubs := ephemeralCluster(t, 2)
	owner := EphemeralOwnerName("grade-batch")
	// A short TTL only to make the interval short; the node clamps what it
	// actually grants.
	heartbeat := cluster.KeepEphemeralAlive(t.Context(), "harness", owner, 15*time.Second)

	deadline := time.Now().Add(10 * time.Second)
	for len(stubs[0].observed()) == 0 || len(stubs[1].observed()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the heartbeat never reached both nodes")
		}
		time.Sleep(20 * time.Millisecond)
	}
	heartbeat.Stop()
	after := len(stubs[0].observed())

	for _, stub := range stubs {
		for _, req := range stub.observed() {
			if req.Lab != "harness" || req.Owner != owner || req.Release {
				t.Fatalf("a heartbeat carried the wrong request: %+v", req)
			}
		}
	}

	// Once the controller stops, so does the renewal: that silence is the
	// whole signal the node acts on.
	time.Sleep(300 * time.Millisecond)
	if len(stubs[0].observed()) != after {
		t.Fatal("renewals continued after the heartbeat was stopped")
	}
}

func TestAHeartbeatDoesNotAbortAGradingRunWhenANodeRefuses(t *testing.T) {
	cluster, stubs := ephemeralCluster(t, 1)
	stubs[0].refuse = true
	heartbeat := cluster.KeepEphemeralAlive(t.Context(), "harness", "owner", 15*time.Second)
	defer heartbeat.Stop()

	deadline := time.Now().Add(10 * time.Second)
	for len(stubs[0].observed()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the heartbeat stopped after the first refusal")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A refusal is reported and retried, never fatal: a transient failure must
	// not end a class-scale run, and a real one is covered by the lease being
	// several heartbeats long.
	if err := cluster.RenewEphemeral(t.Context(), "harness", "owner", time.Minute); err == nil {
		t.Fatal("a refused renewal was reported as success")
	}
}

func TestReleasingEndsTheLifetimeOnEveryNode(t *testing.T) {
	cluster, stubs := ephemeralCluster(t, 2)
	cluster.ReleaseEphemeral(t.Context(), "harness", "owner")
	for i, stub := range stubs {
		observed := stub.observed()
		if len(observed) != 1 || !observed[0].Release {
			t.Fatalf("node-%d did not receive a release: %+v", i, observed)
		}
	}
}

func TestAnApplyCarriesTheDisposableMarkerOntoTheWire(t *testing.T) {
	var captured agent.ApplyRequest
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/apply" {
			mu.Lock()
			_ = json.NewDecoder(r.Body).Decode(&captured)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(agent.ApplyResponse{Node: "node-0"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	cluster := &Cluster{Nodes: []*Node{NewNode("node-0", server.URL, "")}}
	top := harnessTopologyForTest()
	cluster.unfencedApply(t.Context(), top, agent.ApplyRequest{
		Mode: "solve", Ungraded: 3, DryRun: true,
		Ephemeral: true, EphemeralTTLSeconds: 900, EphemeralOwner: "grade-batch@host/1",
	})
	mu.Lock()
	defer mu.Unlock()
	if captured.Topology == nil {
		t.Fatal("no topology reached the node")
	}
	// The marker has to be on the persisted topology, not only on the request:
	// topology.json is what a restarted agent reads.
	if !captured.Topology.Ephemeral {
		t.Fatal("the persisted topology does not say the lab is disposable")
	}
	if captured.Topology.EphemeralTTLSeconds != 900 {
		t.Fatalf("the persisted topology lost its lifetime: %d",
			captured.Topology.EphemeralTTLSeconds)
	}
	if captured.Topology.EphemeralOwner != "grade-batch@host/1" {
		t.Fatalf("the persisted topology lost its owner: %q", captured.Topology.EphemeralOwner)
	}
}

func TestATopologyMarkedDisposableIsCarriedEvenWhenTheRequestIsSilent(t *testing.T) {
	var captured agent.ApplyRequest
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/apply" {
			mu.Lock()
			_ = json.NewDecoder(r.Body).Decode(&captured)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(agent.ApplyResponse{Node: "node-0"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	cluster := &Cluster{Nodes: []*Node{NewNode("node-0", server.URL, "")}}
	top := harnessTopologyForTest()
	top.Ephemeral = true
	cluster.unfencedApply(t.Context(), top, agent.ApplyRequest{Mode: "solve", DryRun: true})
	mu.Lock()
	defer mu.Unlock()
	if captured.Topology == nil || !captured.Topology.Ephemeral {
		t.Fatal("a harness built by internal/harness lost its disposable marker on the wire")
	}
}
