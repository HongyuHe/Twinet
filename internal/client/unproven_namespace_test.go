package client

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

// The commit response must not erase what the apply phase found.
//
// A coordinated deployment talks to each node three times, and the controller
// keeps the commit response as the node's answer, copying a handful of counts
// back from the apply. The forward apply is the phase that observes every
// device; commit runs a narrower engine over the same node. Taking commit's
// silence as the answer would report a node with nothing unresolved on it
// purely because the later phase never looked at the device the earlier one
// refused to vouch for.
func TestACommitResponseDoesNotEraseWhatTheApplyPhaseCouldNotVouchFor(t *testing.T) {
	applied := agent.ApplyResponse{
		Node: "node-0", Steps: 11,
		UnprovenNamespaces: map[string]string{
			"as3/ATL": "the saved address it was last seen with is not in it",
		},
	}
	commit := agent.ApplyResponse{Node: "node-0", Phase: "commit"}

	merged := mergeUnprovenNamespaces(applied.UnprovenNamespaces, commit.UnprovenNamespaces)
	if len(merged) != 1 || !strings.Contains(merged["as3/ATL"], "not in it") {
		t.Fatalf("merged = %v, want the device the apply phase refused to vouch for", merged)
	}

	// And the other way round: a commit that found something the apply did not
	// is added to it rather than replacing it.
	commit.UnprovenNamespaces = map[string]string{"as9/SW1": "its container is not running"}
	merged = mergeUnprovenNamespaces(applied.UnprovenNamespaces, commit.UnprovenNamespaces)
	if len(merged) != 2 {
		t.Fatalf("merged = %v, want both phases' findings", merged)
	}
	if merged["as3/ATL"] == "" || merged["as9/SW1"] == "" {
		t.Fatalf("merged = %v, want neither phase's finding dropped", merged)
	}
}

// Nothing unresolved stays nothing. A merge that invented an empty map would
// make every response carry the field and every summary print a heading for a
// problem nobody has.
func TestMergingTwoCleanPhasesReportsNothing(t *testing.T) {
	if merged := mergeUnprovenNamespaces(nil, nil); merged != nil {
		t.Fatalf("merged = %v, want nothing at all", merged)
	}
	if merged := mergeUnprovenNamespaces(map[string]string{}, nil); merged != nil {
		t.Fatalf("merged = %v, want nothing at all", merged)
	}
}

// The same thing through the whole three-phase mutation, because the merge
// above is only correct if it is the one the transaction actually performs.
func TestACoordinatedApplyPublishesWhatTheNodeCouldNotVouchFor(t *testing.T) {
	stub := newCoordinationStub("a", nil)
	stub.unproven = map[string]string{
		"as3/ATL": "the saved address it was last seen with is not in it (addr inet lo 3.156.0.1/24)",
	}
	node, closeNode := stubNode("a", stub)
	defer closeNode()

	results := (&Cluster{Nodes: []*Node{node}}).Apply(t.Context(),
		&model.Topology{Name: "cos461", Lab: &model.Lab{}},
		agent.ApplyRequest{Generation: "unproven", Mode: "solve"})
	if len(results) != 1 {
		t.Fatalf("results = %d, want one node", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("the deployment failed for another reason: %v", results[0].Err)
	}
	unproven := results[0].Value.UnprovenNamespaces
	if len(unproven) != 1 || !strings.Contains(unproven["as3/ATL"], "3.156.0.1/24") {
		t.Fatalf("the transaction reported %v; the commit phase, which never observed "+
			"that device, erased what the apply phase found", unproven)
	}
}
