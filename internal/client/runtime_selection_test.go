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

func TestApplyRefusesRuntimeMismatchBeforeMutation(t *testing.T) {
	var mutated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "node-0", Runtime: "docker", RuntimeVer: "27.0",
				Compatibility: agent.Compatibility(),
			})
			return
		}
		mutated = true
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer server.Close()

	cluster := &Cluster{
		Nodes:                []*Node{NewNode("node-0", strings.TrimPrefix(server.URL, "http://"), "")},
		RequestedRuntimes:    map[string]string{"node-0": "podman"},
		RequireCompatibility: agent.Compatibility(),
	}
	results := cluster.Apply(context.Background(), &model.Topology{Name: "lab", Lab: &model.Lab{}},
		agent.ApplyRequest{})
	if len(results) != 1 || results[0].Err == nil {
		t.Fatal("runtime mismatch reached a mutating request")
	}
	if !strings.Contains(results[0].Err.Error(), "manifest requests podman") {
		t.Fatalf("runtime mismatch error = %v", results[0].Err)
	}
	if mutated {
		t.Fatal("runtime mismatch mutated the agent")
	}
}
