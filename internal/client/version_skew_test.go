package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestApplyAllowsCompatibleRollingSourceBuilds(t *testing.T) {
	var (
		mu      sync.Mutex
		applied bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "node-1", Version: "bugfix-build-b", Compatibility: agent.Compatibility(),
			})
			return
		}
		mu.Lock()
		applied = true
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer srv.Close()

	c := &Cluster{
		Nodes:                []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")},
		RequireVersion:       "bugfix-build-a",
		RequireCompatibility: agent.Compatibility(),
	}
	c.Apply(context.Background(), &model.Topology{Name: "cos461", Lab: &model.Lab{}}, agent.ApplyRequest{})
	mu.Lock()
	defer mu.Unlock()
	if !applied {
		t.Fatal("compatible source builds were blocked instead of allowing a rolling upgrade")
	}
}

func TestCompatibilityAllowsDeclaredRendererRollingRange(t *testing.T) {
	controller := agent.Compatibility()
	controller.Renderer.MaxCompatible = "1.1.0"
	nodeContracts := controller
	nodeContracts.Renderer.Current = "1.1.0"
	nodeContracts.Renderer.MinCompatible = "1.0.0"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(agent.StatusResponse{
			Node: "node-1", Version: "renderer-1.1-source", Compatibility: nodeContracts,
		})
	}))
	defer srv.Close()
	c := &Cluster{
		Nodes:                []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")},
		RequireVersion:       "renderer-1.0-source",
		RequireCompatibility: controller,
	}
	if err := c.VersionSkew(context.Background()); err != nil {
		t.Fatalf("declared-compatible renderer rolling upgrade was refused: %v", err)
	}
}

func TestApplyRefusesAnIncompatibleRendererBeforeMutation(t *testing.T) {
	incompatible := agent.Compatibility()
	incompatible.Renderer.Current = "2.0.0"
	incompatible.Renderer.MinCompatible = "2.0.0"
	incompatible.Renderer.MaxCompatible = "2.0.0"

	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "node-1", Version: "renderer-v2", Compatibility: incompatible,
			})
			return
		}
		applied = true
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer srv.Close()

	c := &Cluster{
		Nodes:                []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")},
		RequireVersion:       "renderer-v1",
		RequireCompatibility: agent.Compatibility(),
	}
	results := c.Apply(context.Background(), &model.Topology{Name: "cos461", Lab: &model.Lab{}},
		agent.ApplyRequest{})
	if len(results) != 1 || results[0].Err == nil {
		t.Fatal("Apply reached an incompatible renderer")
	}
	if !strings.Contains(results[0].Err.Error(), "renderer contract") {
		t.Fatalf("renderer refusal does not name the contract: %v", results[0].Err)
	}
	if applied {
		t.Fatal("an incompatible renderer received a mutation request")
	}
}

func TestAClusterWithNoExpectedCompatibilityIsNotBlocked(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{Node: "node-1", Version: "whatever"})
			return
		}
		applied = true
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer srv.Close()

	c := &Cluster{Nodes: []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")}}
	c.Apply(context.Background(), &model.Topology{Name: "cos461", Lab: &model.Lab{}}, agent.ApplyRequest{})
	if !applied {
		t.Error("a narrow test cluster with no compatibility expectation refused to do anything")
	}
}
