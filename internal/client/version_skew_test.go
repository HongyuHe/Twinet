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

// The node agent renders device configuration. A node on a different build
// therefore produces different configuration from the same manifest, and
// nothing downstream reports it: every node returns success, and the lab is
// quietly not the lab anybody described.
//
// Deployment checked for this. Grading did not -- it called Apply directly --
// which is the worst way round, because grading's output is somebody's mark
// and a mark that cannot be attributed to a particular build of the software
// is not evidence of anything.
//
// So the check belongs to Apply, which is the one thing every caller goes
// through.
func TestApplyRefusesAClusterOfMixedBuilds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "node-1", Version: "an-older-build",
			})
			return
		}
		// Reaching this is the failure: the request should never be sent.
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer srv.Close()

	c := &Cluster{
		Nodes:          []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")},
		RequireVersion: "the-build-this-controller-is",
	}
	top := &model.Topology{
		Name: "cos461",
		Lab:  &model.Lab{},
	}

	t.Setenv("TWINET_ALLOW_VERSION_SKEW", "")
	results := c.Apply(context.Background(), top, agent.ApplyRequest{})
	if len(results) != 1 {
		t.Fatalf("expected one result per node, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("Apply proceeded against a node running a different build.\n" +
			"The agent renders the configuration, so the lab that gets built is not " +
			"the lab the manifest describes -- and every node still reports success. " +
			"Grading calls this directly, so a mark could be produced by software " +
			"nobody can identify.")
	}
	if !strings.Contains(results[0].Err.Error(), "an-older-build") {
		t.Fatalf("the refusal does not say which node is wrong: %v", results[0].Err)
	}
}

// An operator who knows the difference does not matter must have a way through,
// or the check gets patched out instead.
func TestApplyCanBeToldToProceedAnyway(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") {
			_ = json.NewEncoder(w).Encode(agent.StatusResponse{
				Node: "node-1", Version: "an-older-build",
			})
			return
		}
		applied = true
		_ = json.NewEncoder(w).Encode(agent.ApplyResponse{})
	}))
	defer srv.Close()

	c := &Cluster{
		Nodes:          []*Node{NewNode("node-1", strings.TrimPrefix(srv.URL, "http://"), "")},
		RequireVersion: "the-build-this-controller-is",
	}
	t.Setenv("TWINET_ALLOW_VERSION_SKEW", "1")
	c.Apply(context.Background(), &model.Topology{Name: "cos461", Lab: &model.Lab{}}, agent.ApplyRequest{})
	if !applied {
		t.Error("TWINET_ALLOW_VERSION_SKEW did not let a deliberate operator through; " +
			"a check with no escape hatch gets deleted rather than respected")
	}
}

// A cluster with no expectation must not start refusing everything: tests and
// single-node use build one without a version.
func TestAClusterWithNoExpectedVersionIsNotBlocked(t *testing.T) {
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
		t.Error("a cluster with no expected version refused to do anything")
	}
}
