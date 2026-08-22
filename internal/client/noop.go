package client

import (
	"context"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/model"
)

// NoopPreflight runs a read-only desired/observed plan on every node, then
// immediately verifies each node's generation/hash/mode witness. It never
// acquires a mutation lease or creates a transaction.
func (c *Cluster) NoopPreflight(ctx context.Context, top *model.Topology, req agent.ApplyRequest) ([]NodeResult[agent.PlanResponse], bool) {
	ctx = operationContext(ctx)
	if top == nil || top.Hash == "" {
		return nil, false
	}
	mode, err := agent.RequireTransactionMode(req.Mode)
	if err != nil {
		return nil, false
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
	var (
		generation string
		fence      uint64
	)
	for _, result := range results {
		if result.Err != nil || !result.Value.Noop || result.Value.Token == "" ||
			result.Value.Node != result.Node || result.Value.Generation == "" ||
			result.Value.FenceGeneration == 0 || result.Value.Hash != top.Hash || result.Value.Mode != mode {
			return results, false
		}
		if generation == "" {
			generation, fence = result.Value.Generation, result.Value.FenceGeneration
		} else if result.Value.Generation != generation || result.Value.FenceGeneration != fence {
			return results, false
		}
	}
	verified := fanOut(ctx, c.sortedNodes(), func(ctx context.Context, node *Node) (agent.PlanVerifyResponse, error) {
		var token string
		for _, result := range results {
			if result.Node == node.Name {
				token = result.Value.Token
				break
			}
		}
		return node.PlanVerify(ctx, agent.PlanVerifyRequest{Lab: top.Name, Token: token})
	})
	for _, result := range verified {
		if result.Err != nil || !result.Value.Valid || result.Value.Node != result.Node {
			return results, false
		}
	}
	return results, true
}
