package client

import (
	"context"
	"fmt"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

// NoopPreflightResult describes a read-only no-op decision. Reasons are keyed
// by node name (or "controller" before a node request can be made) so callers
// can distinguish harmless local fence divergence from an actual fallback.
type NoopPreflightResult struct {
	Nodes   []NodeResult[agent.PlanResponse] `json:"nodes"`
	Noop    bool                             `json:"noop"`
	Reasons map[string]string                `json:"fallback_reasons,omitempty"`
}

// NoopPreflight runs a read-only desired/observed plan on every node, then
// immediately verifies each node's generation/hash/mode witness. It never
// acquires a mutation lease or creates a transaction. Fence generations are
// deliberately node-local: every token verifies its own fence, while only the
// committed lab generation must agree cluster-wide.
func (c *Cluster) NoopPreflight(ctx context.Context, top *model.Topology,
	req agent.ApplyRequest,
) NoopPreflightResult {
	ctx = operationContext(ctx)
	if top == nil || top.Hash == "" {
		return NoopPreflightResult{Reasons: map[string]string{
			"controller": "topology hash is required for no-op preflight",
		}}
	}
	mode, err := agent.RequireTransactionMode(req.Mode)
	if err != nil {
		return NoopPreflightResult{Reasons: map[string]string{
			"controller": err.Error(),
		}}
	}
	wire := agent.Serialise(top)
	peers := map[string]string{}
	if top.Lab != nil {
		for _, node := range top.Lab.Placement.Nodes {
			if node.UnderlayIP != "" {
				peers[node.Name] = node.UnderlayIP
			}
		}
	}
	results := fanOut(ctx, c.sortedNodes(), func(ctx context.Context, node *Node) (agent.PlanResponse, error) {
		return node.Plan(ctx, agent.PlanRequest{
			Lab: top.Name, Topology: wire, Mode: mode, Ungraded: req.Ungraded, PeerUnderlay: peers,
		})
	})
	out := NoopPreflightResult{Nodes: results, Reasons: map[string]string{}}
	if len(results) == 0 {
		out.Reasons["controller"] = "no nodes are available for no-op preflight"
		return out
	}
	var generation string
	for _, result := range results {
		if reason := planFallbackReason(result, top.Hash, mode); reason != "" {
			out.Reasons[result.Node] = reason
			continue
		}
		if generation == "" {
			generation = result.Value.Generation
		} else if result.Value.Generation != generation {
			out.Reasons[result.Node] = fmt.Sprintf(
				"committed generation %q differs from cluster generation %q",
				result.Value.Generation, generation)
		}
	}
	if len(out.Reasons) > 0 {
		return out
	}

	tokens := make(map[string]string, len(results))
	for _, result := range results {
		tokens[result.Node] = result.Value.Token
	}
	verified := fanOut(ctx, c.sortedNodes(), func(ctx context.Context, node *Node) (agent.PlanVerifyResponse, error) {
		return node.PlanVerify(ctx, agent.PlanVerifyRequest{Lab: top.Name, Token: tokens[node.Name]})
	})
	for _, result := range verified {
		if result.Err != nil {
			out.Reasons[result.Node] = fmt.Sprintf("no-op witness verification failed: %v", result.Err)
		} else if result.Value.Node != result.Node {
			out.Reasons[result.Node] = fmt.Sprintf(
				"no-op witness verification answered as %q", result.Value.Node)
		} else if !result.Value.Valid {
			out.Reasons[result.Node] = "local no-op witness changed before verification"
		}
	}
	if len(out.Reasons) > 0 {
		return out
	}
	out.Noop = true
	out.Reasons = nil
	return out
}

func planFallbackReason(result NodeResult[agent.PlanResponse], hash, mode string) string {
	if result.Err != nil {
		return fmt.Sprintf("read-only plan failed: %v", result.Err)
	}
	value := result.Value
	if value.Node != result.Node {
		return fmt.Sprintf("plan answered as %q", value.Node)
	}
	if !value.Noop {
		if value.Reason != "" {
			return value.Reason
		}
		return "desired/observed plan has mutations"
	}
	if value.Token == "" {
		return "no-op witness token is missing"
	}
	if value.Generation == "" {
		return "committed generation is missing"
	}
	if value.FenceGeneration == 0 {
		return "local fence generation is missing"
	}
	if value.Hash != hash {
		return fmt.Sprintf("committed topology hash %q differs from desired hash %q", value.Hash, hash)
	}
	if value.Mode != mode {
		return fmt.Sprintf("committed mode %q differs from desired mode %q", value.Mode, mode)
	}
	return ""
}
