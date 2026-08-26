package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

// A node can answer "nothing to do" from its rendered-hash diff while its own
// audit is publishing devices with semantic or runtime drift. The controller
// is the last place that can refuse to turn that contradiction into an exit-0
// "0 devices, 0 links", so it refuses it even when the node did not.
func TestNoopPreflightRefusesADegradedNodeThatClaimsNoWork(t *testing.T) {
	verified := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/plan" {
			_ = json.NewEncoder(w).Encode(agent.PlanResponse{
				Node: "node-0", Generation: "g", FenceGeneration: 1,
				Hash: "h", Mode: "solve", Token: "witness", Noop: true,
				SemanticHealth: agent.SemanticHealth{
					Healthy: 412, Broken: 110, Terminal: 3,
					Reasons: map[string]string{
						"as3/CHI": "terminal: binding vni:7140 is missing",
						"as5/MSP": "network semantics drifted: no route to 10.5.0.2",
					},
				},
			})
			return
		}
		verified++
		_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: "node-0", Valid: true})
	}))
	defer server.Close()
	top := &model.Topology{
		Name: "cos461", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "node-0", Addr: server.URL}}}},
	}
	cluster := &Cluster{Nodes: []*Node{NewNode("node-0", server.URL, "token")}}
	preflight := cluster.NoopPreflight(context.Background(), top, agent.ApplyRequest{Mode: "solve"})
	if preflight.Noop {
		t.Fatal("a zero-change deployment was accepted against a node reporting 110 drifted devices")
	}
	reason := preflight.Reasons["node-0"]
	if !strings.Contains(reason, "110 device(s) have semantic/runtime drift") {
		t.Fatalf("fallback reason = %q, want the published drift count", reason)
	}
	if !strings.Contains(reason, "as3/CHI") {
		t.Fatalf("fallback reason = %q, want the abandoned device named first", reason)
	}
	if verified != 0 {
		t.Fatalf("the controller verified a witness it had already refused (%d calls)", verified)
	}
}

// Unknown is an absence of evidence, not evidence of drift: an unreadable
// runtime must not turn every no-op into a full deployment.
func TestNoopPreflightAcceptsUnknownButNotBrokenHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/plan" {
			_ = json.NewEncoder(w).Encode(agent.PlanResponse{
				Node: "node-0", Generation: "g", FenceGeneration: 1,
				Hash: "h", Mode: "solve", Token: "witness", Noop: true,
				SemanticHealth: agent.SemanticHealth{Healthy: 8, Unknown: 2},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(agent.PlanVerifyResponse{Node: "node-0", Valid: true})
	}))
	defer server.Close()
	top := &model.Topology{
		Name: "cos461", Hash: "h",
		Lab: &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "node-0", Addr: server.URL}}}},
	}
	cluster := &Cluster{Nodes: []*Node{NewNode("node-0", server.URL, "token")}}
	if preflight := cluster.NoopPreflight(context.Background(), top,
		agent.ApplyRequest{Mode: "solve"}); !preflight.Noop {
		t.Fatalf("unreadable devices were treated as drift: %#v", preflight.Reasons)
	}
}
