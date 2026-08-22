package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestNoopPreflightUsesOnlyReadOnlyPlanEndpoints(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/plan":
			_ = json.NewEncoder(w).Encode(agent.PlanResponse{
				Node: "node-a", Generation: "g", FenceGeneration: 1,
				Hash: "h", Mode: "platform", Token: "witness", Noop: true,
			})
		case "/v1/plan/verify":
			_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: "node-a", Valid: true})
		default:
			http.Error(w, "mutating endpoint reached", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	top := &model.Topology{
		Name: "lab", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "node-a", Addr: server.URL}}}},
	}
	cluster := &Cluster{Nodes: []*Node{NewNode("node-a", server.URL, "token")}}
	preflight := cluster.NoopPreflight(context.Background(), top, agent.ApplyRequest{Mode: "platform"})
	if !preflight.Noop || len(preflight.Nodes) != 1 || preflight.Nodes[0].Err != nil {
		t.Fatalf("preflight = %#v", preflight)
	}
	if len(calls) != 2 || calls[0] != "/v1/plan" || calls[1] != "/v1/plan/verify" {
		t.Fatalf("endpoints = %v, want only read-only plan/verify", calls)
	}
}

func TestNoopPreflightFallsBackWhenLocalFenceChanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/plan" {
			_ = json.NewEncoder(w).Encode(agent.PlanResponse{
				Node: "node-a", Generation: "g", FenceGeneration: 1,
				Hash: "h", Mode: "platform", Token: "stale", Noop: true,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: "node-a", Valid: false})
	}))
	defer server.Close()
	top := &model.Topology{
		Name: "lab", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "node-a", Addr: server.URL}}}},
	}
	cluster := &Cluster{Nodes: []*Node{NewNode("node-a", server.URL, "token")}}
	preflight := cluster.NoopPreflight(context.Background(), top, agent.ApplyRequest{Mode: "platform"})
	if preflight.Noop {
		t.Fatal("stale no-op witness was accepted")
	}
	if got := preflight.Reasons["node-a"]; got != "local no-op witness changed before verification" {
		t.Fatalf("fallback reason = %q", got)
	}
}

func TestNoopPreflightRejectsMixedCommitEvidence(t *testing.T) {
	var verifies atomic.Int32
	newServer := func(node, generation string, fence uint64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/plan":
				_ = json.NewEncoder(w).Encode(agent.PlanResponse{
					Node: node, Generation: generation, FenceGeneration: fence,
					Hash: "h", Mode: "platform", Token: node + "-witness", Noop: true,
				})
			case "/v1/plan/verify":
				verifies.Add(1)
				_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: node, Valid: true})
			default:
				http.NotFound(w, r)
			}
		}))
	}
	a, b := newServer("node-a", "generation-a", 1), newServer("node-b", "generation-b", 1)
	defer a.Close()
	defer b.Close()
	top := &model.Topology{
		Name: "lab", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "node-a", Addr: a.URL}, {Name: "node-b", Addr: b.URL},
		}}},
	}
	cluster := &Cluster{Nodes: []*Node{
		NewNode("node-a", a.URL, "token"), NewNode("node-b", b.URL, "token"),
	}}
	preflight := cluster.NoopPreflight(context.Background(), top, agent.ApplyRequest{Mode: "platform"})
	if preflight.Noop {
		t.Fatal("mixed committed generations were accepted as a no-op")
	}
	if got := preflight.Reasons["node-b"]; got == "" {
		t.Fatalf("generation mismatch had no node-level fallback reason: %#v", preflight.Reasons)
	}
	if got := verifies.Load(); got != 0 {
		t.Fatalf("CAS verification ran after mixed evidence: %d calls", got)
	}
}

func TestNoopPreflightAllowsDifferentLocalFenceGenerations(t *testing.T) {
	newServer := func(node string, fence uint64) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/plan":
				_ = json.NewEncoder(w).Encode(agent.PlanResponse{
					Node: node, Generation: "generation-a", FenceGeneration: fence,
					Hash: "h", Mode: "platform", Token: node + "-witness", Noop: true,
				})
			case "/v1/plan/verify":
				_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: node, Valid: true})
			default:
				http.NotFound(w, r)
			}
		}))
	}
	a, b := newServer("node-a", 7), newServer("node-b", 41)
	defer a.Close()
	defer b.Close()
	top := &model.Topology{
		Name: "lab", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "node-a", Addr: a.URL}, {Name: "node-b", Addr: b.URL},
		}}},
	}
	cluster := &Cluster{Nodes: []*Node{
		NewNode("node-a", a.URL, "token"), NewNode("node-b", b.URL, "token"),
	}}
	preflight := cluster.NoopPreflight(context.Background(), top, agent.ApplyRequest{Mode: "platform"})
	if !preflight.Noop {
		t.Fatalf("different local fences rejected a healthy no-op: %#v", preflight)
	}
}
