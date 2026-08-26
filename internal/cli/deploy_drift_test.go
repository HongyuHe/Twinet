package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
)

func applyResult(node string, steps int, health agent.SemanticHealth) client.NodeResult[agent.ApplyResponse] {
	return client.NodeResult[agent.ApplyResponse]{
		Node:  node,
		Value: agent.ApplyResponse{Node: node, Steps: steps, SemanticHealth: health},
	}
}

// `twinet deploy` printed "0 devices, 0 links" and exited zero while the
// agents it had just spoken to were reporting more than a hundred devices
// with semantic or runtime drift. Zero-change success and degraded health are
// answers to the same question, and they cannot both be true.
func TestZeroChangeDeploymentFailsWhileNodesReportDrift(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		applyResult("node-0", 0, agent.SemanticHealth{
			Healthy: 402, Broken: 110, Terminal: 2,
			Reasons: map[string]string{
				"as3/CHI": "terminal: binding vni:7140 is missing",
				"as5/MSP": "network semantics drifted: no route to 10.5.0.2",
			},
		}),
		applyResult("node-1", 0, agent.SemanticHealth{Healthy: 500}),
	}
	drift := clusterSemanticDrift(results)
	if !strings.Contains(drift, "node-0 reports 110 device(s) with semantic/runtime drift") {
		t.Fatalf("drift summary = %q, want the degraded node and its count", drift)
	}
	if strings.Contains(drift, "node-1") {
		t.Fatalf("drift summary named a healthy node: %q", drift)
	}
	if !strings.Contains(drift, "as3/CHI") {
		t.Fatalf("drift summary = %q, want the abandoned device as the example", drift)
	}
	err := zeroChangeDriftError(0, drift)
	if err == nil {
		t.Fatal("a zero-change deployment against a degraded cluster was reported as success")
	}
	if !strings.Contains(err.Error(), "made no changes") ||
		!strings.Contains(err.Error(), "node-0 reports 110") {
		t.Fatalf("failure = %q, want it to name the drift", err)
	}
}

// A deployment that did change something has reported that work. Its
// remaining drift is audited on stderr rather than turned into a failure,
// which is the "coordinate repair and report changes" half of the same rule.
func TestDeploymentThatReportedChangesIsNotFailedByRemainingDrift(t *testing.T) {
	drift := clusterSemanticDrift([]client.NodeResult[agent.ApplyResponse]{
		applyResult("node-0", 12, agent.SemanticHealth{Broken: 1,
			Reasons: map[string]string{"as3/CHI": "network semantics drifted"}}),
	})
	if drift == "" {
		t.Fatal("degraded health disappeared from a deployment that did work")
	}
	if err := zeroChangeDriftError(12, drift); err != nil {
		t.Fatalf("a deployment that reported 12 changes was failed: %v", err)
	}
}

func TestConvergedZeroChangeDeploymentStillSucceeds(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		applyResult("node-0", 0, agent.SemanticHealth{Healthy: 512}),
		applyResult("node-1", 0, agent.SemanticHealth{Healthy: 512, Unknown: 1}),
	}
	if drift := clusterSemanticDrift(results); drift != "" {
		t.Fatalf("converged cluster reported drift: %q", drift)
	}
	if err := zeroChangeDriftError(0, clusterSemanticDrift(results)); err != nil {
		t.Fatalf("converged no-op deployment failed: %v", err)
	}
}

// An unreachable node is a different failure with its own message; it must not
// be silently counted as converged evidence here.
func TestUnreachableNodeIsNotTreatedAsConvergedEvidence(t *testing.T) {
	results := []client.NodeResult[agent.ApplyResponse]{
		{Node: "node-0", Err: errUnreachableNode},
		applyResult("node-1", 0, agent.SemanticHealth{Broken: 4,
			Reasons: map[string]string{"as9/SFO": "container is absent"}}),
	}
	drift := clusterSemanticDrift(results)
	if strings.Contains(drift, "node-0") {
		t.Fatalf("drift summary invented health for an unreachable node: %q", drift)
	}
	if !strings.Contains(drift, "node-1 reports 4 device(s)") {
		t.Fatalf("drift summary = %q, want the node that did answer", drift)
	}
}

var errUnreachableNode = &unreachableNode{}

type unreachableNode struct{}

func (*unreachableNode) Error() string { return "dial node-0: connection refused" }
