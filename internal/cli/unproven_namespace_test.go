package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
)

// A deployment that leaves a device's saved state unpreservable is not a
// success, however healthy the node says the device is.
//
// The audit that produces semantic health deliberately skips every interface a
// student owns, so a router that came back from a restart with an empty
// namespace is counted healthy. What is wrong with it -- that its addressing,
// tunnels and switch ports are being withheld from the state store, because
// capturing what is in its namespace now would overwrite the only copy of the
// work -- appears in no other field. It has to be its own answer.
func TestDeploymentFailsWhenANodeCannotVouchForANamespace(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		{Node: "node-0", Value: agent.ApplyResponse{
			Node: "node-0", Steps: 11,
			SemanticHealth: agent.SemanticHealth{Healthy: 402},
			UnprovenNamespaces: map[string]string{
				"as3/ATL": "the saved address it was last seen with is not in it " +
					"(addr inet lo 3.156.0.1/24)",
			},
		}},
		{Node: "node-1", Value: agent.ApplyResponse{
			Node: "node-1", Steps: 0,
			SemanticHealth: agent.SemanticHealth{Healthy: 500},
		}},
	}
	unproven := clusterUnprovenNamespaces(results)
	if len(unproven) != 1 {
		t.Fatalf("unproven = %v, want the one device that could not be vouched for", unproven)
	}
	if !strings.Contains(unproven[0], "node-0/as3/ATL") {
		t.Fatalf("unproven = %q, want the node and the device", unproven[0])
	}
	if drift := clusterSemanticDrift(results); drift != "" {
		t.Fatalf("the fixture's nodes report drift as well, so this proves nothing: %q", drift)
	}
	err := unprovenNamespaceError(unproven)
	if err == nil {
		t.Fatal("a deployment that left a device's saved state unpreservable was reported " +
			"as a success because the audit, which does not look at student-owned state, " +
			"was happy")
	}
	for _, want := range []string{"as3/ATL", "not being preserved", "3.156.0.1/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("failure = %q, want it to name %q", err, want)
		}
	}
	// And through the decision the deployment summary actually makes, because
	// the check above is only worth anything if that is the one it performs.
	if err := deploymentAudit(io.Discard, results, unproven, 11); err == nil {
		t.Fatal("the deployment's own audit passed a cluster it cannot preserve the " +
			"student work on")
	}
}

// The clean case, which is the one that runs on every deployment. Nothing
// unresolved must not produce an error, a heading, or a line of output.
func TestDeploymentIsNotFailedWhenEveryNamespaceIsAccountedFor(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		{Node: "node-0", Value: agent.ApplyResponse{Node: "node-0", Steps: 3}},
		{Node: "node-1", Value: agent.ApplyResponse{Node: "node-1"}},
	}
	if unproven := clusterUnprovenNamespaces(results); len(unproven) != 0 {
		t.Fatalf("a clean cluster reported %v", unproven)
	}
	if err := unprovenNamespaceError(nil); err != nil {
		t.Fatalf("a clean cluster failed the deployment: %v", err)
	}
	if err := deploymentAudit(io.Discard, results, nil, 3); err != nil {
		t.Fatalf("a clean cluster failed its deployment's audit: %v", err)
	}
}

// A node that failed outright still gets to say what it could not vouch for.
// The failure is reported either way, and the devices whose work is no longer
// being preserved are the part an operator has to act on separately.
func TestAFailedNodeStillReportsWhatItCouldNotVouchFor(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		{Node: "node-0", Err: errUnreachableNode, Value: agent.ApplyResponse{
			UnprovenNamespaces: map[string]string{"as3/ATL": "its container is not running"},
		}},
		{Node: "node-1", Err: errUnreachableNode},
	}
	unproven := clusterUnprovenNamespaces(results)
	if len(unproven) != 1 || !strings.Contains(unproven[0], "node-0/as3/ATL") {
		t.Fatalf("unproven = %v, want the device the failed node named", unproven)
	}
}
