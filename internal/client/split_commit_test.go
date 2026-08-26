package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
)

// splitCommitNode is one agent in a cluster that committed a generation on
// some nodes and not others. It answers recovery status from whatever it is
// currently holding, and rolls back only when explicitly told it may abandon a
// committed generation.
type splitCommitNode struct {
	mu sync.Mutex

	generation        string
	previous          string
	committedPending  bool
	rollbackRequests  []agent.RecoveryRequest
	refuseUnqualified bool
	lease             agent.Fence
}

func (n *splitCommitNode) status() agent.RecoveryStatus {
	status := agent.RecoveryStatus{
		Lab: "lab", Generation: n.generation, Consistent: true,
	}
	if n.committedPending {
		status.Phase = "committed"
		status.PreviousGeneration = n.previous
		status.CommittedPending = true
		status.AllowedStrategies = []string{"rollback"}
		return status
	}
	status.Phase = "committed"
	return status
}

func (n *splitCommitNode) handler(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	fail := func(code int, err error) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	switch r.URL.Path {
	case "/v1/recovery":
		write(n.status())
	case "/v1/lease/acquire":
		n.lease = agent.Fence{Token: "fence", Generation: 1}
		write(agent.LeaseResponse{Lab: "lab", Fence: n.lease})
	case "/v1/lease/release":
		n.lease = agent.Fence{}
		write(struct{}{})
	case "/v1/lease/renew":
		write(agent.LeaseResponse{Lab: "lab", Fence: n.lease})
	case "/v1/recover":
		var req agent.RecoveryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		n.rollbackRequests = append(n.rollbackRequests, req)
		if !n.committedPending {
			write(agent.RecoveryResponse{Status: n.status()})
			return
		}
		if !req.RollbackCommitted {
			// This is the agent's ordinary answer: a committed generation is
			// verified, never abandoned, unless a coordinator says so.
			if n.refuseUnqualified {
				fail(http.StatusConflict, fmt.Errorf("committed generation cannot be rolled back"))
				return
			}
			write(agent.RecoveryResponse{Status: n.status()})
			return
		}
		n.committedPending = false
		n.generation = n.previous
		write(agent.RecoveryResponse{Status: n.status()})
	default:
		fail(http.StatusNotFound, fmt.Errorf("unexpected path %s", r.URL.Path))
	}
}

func splitCommitCluster(t *testing.T, nodes map[string]*splitCommitNode) *Cluster {
	t.Helper()
	cluster := &Cluster{}
	for name, node := range nodes {
		server := httptest.NewServer(http.HandlerFunc(node.handler))
		t.Cleanup(server.Close)
		cluster.Nodes = append(cluster.Nodes, NewNode(name, server.URL, ""))
	}
	return cluster
}

func TestSplitCommitConvergesWithoutForceDestroyingTheLab(t *testing.T) {
	committed := &splitCommitNode{
		generation: "new-generation", previous: "old-generation", committedPending: true,
	}
	rolledBack := &splitCommitNode{generation: "old-generation"}
	cluster := splitCommitCluster(t, map[string]*splitCommitNode{
		"node-0": committed, "node-1": rolledBack,
	})

	report, err := cluster.Recover(t.Context(), "lab")
	if err != nil {
		t.Fatalf("a split cluster commit could not be recovered: %v", err)
	}
	if report.Generation != "old-generation" {
		t.Fatalf("the cluster did not converge on one generation: %+v", report)
	}
	for node, status := range report.Nodes {
		if status.Generation != "old-generation" {
			t.Fatalf("%s is still at %q", node, status.Generation)
		}
		if status.CommittedPending {
			t.Fatalf("%s still holds an unfinalized committed generation", node)
		}
	}
	committed.mu.Lock()
	requests := append([]agent.RecoveryRequest(nil), committed.rollbackRequests...)
	committed.mu.Unlock()
	acknowledged := false
	for _, req := range requests {
		if req.RollbackCommitted {
			acknowledged = true
		}
	}
	if !acknowledged {
		t.Fatal("the committed node was never asked to abandon its generation")
	}

	rolledBack.mu.Lock()
	for _, req := range rolledBack.rollbackRequests {
		if req.RollbackCommitted {
			rolledBack.mu.Unlock()
			t.Fatal("a node that had already rolled back was asked to abandon a committed generation")
		}
	}
	rolledBack.mu.Unlock()
}

func TestAWholeClusterAwaitingFinalizationIsNotTreatedAsSplit(t *testing.T) {
	first := &splitCommitNode{
		generation: "new-generation", previous: "old-generation", committedPending: true,
	}
	second := &splitCommitNode{
		generation: "new-generation", previous: "old-generation", committedPending: true,
	}
	report := RecoveryReport{Lab: "lab", Nodes: map[string]agent.RecoveryStatus{
		"node-0": first.status(), "node-1": second.status(),
	}}
	if split, found := detectSplitCommit(report); found {
		t.Fatalf("a cluster that committed everywhere was rolled back to %q", split.Target)
	}
}

func TestSplitCommitIsNotResolvedWhenTheRestOfTheClusterDisagrees(t *testing.T) {
	report := RecoveryReport{Lab: "lab", Nodes: map[string]agent.RecoveryStatus{
		"node-0": {Phase: "committed", Generation: "new", PreviousGeneration: "old",
			CommittedPending: true, Consistent: true},
		"node-1": {Phase: "committed", Generation: "old", Consistent: true},
		"node-2": {Phase: "committed", Generation: "older", Consistent: true},
	}}
	if _, found := detectSplitCommit(report); found {
		t.Fatal("a cluster with three generations was resolved automatically")
	}
}

func TestSplitCommitIsNotResolvedFromAnUnfinishedNode(t *testing.T) {
	report := RecoveryReport{Lab: "lab", Nodes: map[string]agent.RecoveryStatus{
		"node-0": {Phase: "committed", Generation: "new", PreviousGeneration: "old",
			CommittedPending: true, Consistent: true},
		"node-1": {Phase: "recovering", Generation: "new", Consistent: false},
	}}
	if _, found := detectSplitCommit(report); found {
		t.Fatal("a decision was taken while a node was still recovering")
	}
}

func TestSplitCommitIsNotResolvedWhenTheCommittedNodeCameFromElsewhere(t *testing.T) {
	report := RecoveryReport{Lab: "lab", Nodes: map[string]agent.RecoveryStatus{
		"node-0": {Phase: "committed", Generation: "new", PreviousGeneration: "unrelated",
			CommittedPending: true, Consistent: true},
		"node-1": {Phase: "committed", Generation: "old", Consistent: true},
	}}
	if _, found := detectSplitCommit(report); found {
		t.Fatal("rolling back would not have converged the cluster, but it was attempted")
	}
}

func TestSplitCommitNeedsEveryNodeObserved(t *testing.T) {
	report := RecoveryReport{Lab: "lab", Nodes: map[string]agent.RecoveryStatus{
		"node-0": {Phase: "committed", Generation: "new", PreviousGeneration: "old",
			CommittedPending: true, Consistent: true},
	}}
	if _, found := detectSplitCommit(report); found {
		t.Fatal("a single-node observation of a multi-node cluster produced a decision")
	}
}
