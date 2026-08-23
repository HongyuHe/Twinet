package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
)

func tryClusterNoop(ctx context.Context, top *model.Topology, token, mode string, ungraded int,
	verbose, asJSON bool,
	out, errOut interface{ Write([]byte) (int, error) },
) (bool, error) {
	start := time.Now()
	preflight := client.NewCluster(top.Lab, token).NoopPreflight(ctx, top, agent.ApplyRequest{
		Mode: mode, Ungraded: ungraded,
	})
	if !preflight.Noop {
		if err := writeNoopFallback(errOut, preflight.Reasons, verbose, asJSON); err != nil {
			return false, err
		}
		return false, nil
	}
	results := preflight.Nodes
	if asJSON {
		return true, json.NewEncoder(out).Encode(noopSuccess{
			Noop: true, Nodes: noopNodeResults(results), TopologyHash: top.Hash,
			Generation: results[0].Value.Generation, Mode: mode, ElapsedMS: time.Since(start).Milliseconds(),
		})
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTEPS\tDURATION\tSTATUS")
	for _, result := range results {
		if result.Err != nil {
			return false, nil //nolint:nilerr // a failed witness falls back to normal deployment
		}
		duration := time.Duration(result.Value.Stats.ObserveMS+result.Value.Stats.DiffMS) * time.Millisecond
		fmt.Fprintf(w, "%s\t0\t%s\tok\n", result.Node, duration)
	}
	_ = w.Flush()
	fmt.Fprintf(out, "\n0 devices, 0 links (0 cross-node) across %d nodes in %s\n",
		len(results), time.Since(start).Round(time.Millisecond))
	fmt.Fprintf(errOut, "controller no-op preflight: observe/diff + semantic CAS=%s\n",
		time.Since(start).Round(time.Millisecond))
	if len(results) > 0 {
		witness := results[0].Value
		fmt.Fprintf(errOut,
			"AUDIT: no-op source=agent-read-only-plan-verify runtime_contract=%s topology_hash=%s generation=%s local_fences=%s mode=%s\n",
			deploy.RuntimeSpecContractVersion, top.Hash, witness.Generation, noopFences(results), mode)
	}
	return true, nil
}

type noopNode struct {
	Node       string `json:"node"`
	Steps      int    `json:"steps"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"`
}

type noopSuccess struct {
	Noop         bool       `json:"noop"`
	Nodes        []noopNode `json:"nodes"`
	TopologyHash string     `json:"topology_hash"`
	Generation   string     `json:"generation"`
	Mode         string     `json:"mode"`
	ElapsedMS    int64      `json:"elapsed_ms"`
}

type noopFallback struct {
	Noop    bool              `json:"noop"`
	Reasons map[string]string `json:"fallback_reasons"`
}

func noopNodeResults(results []client.NodeResult[agent.PlanResponse]) []noopNode {
	out := make([]noopNode, 0, len(results))
	for _, result := range results {
		out = append(out, noopNode{
			Node: result.Node, DurationMS: result.Value.Stats.ObserveMS + result.Value.Stats.DiffMS,
			Status: "ok",
		})
	}
	return out
}

func noopFences(results []client.NodeResult[agent.PlanResponse]) string {
	fences := make([]string, 0, len(results))
	for _, result := range results {
		fences = append(fences, fmt.Sprintf("%s:%d", result.Node, result.Value.FenceGeneration))
	}
	sort.Strings(fences)
	return strings.Join(fences, ",")
}

func writeNoopFallback(out interface{ Write([]byte) (int, error) },
	reasons map[string]string, verbose, asJSON bool,
) error {
	if len(reasons) == 0 {
		reasons = map[string]string{"controller": "no-op preflight declined without a diagnostic"}
	}
	if asJSON {
		return json.NewEncoder(out).Encode(noopFallback{Noop: false, Reasons: reasons})
	}
	if !verbose {
		return nil
	}
	nodes := make([]string, 0, len(reasons))
	for node := range reasons {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	if _, err := fmt.Fprintln(out, "no-op preflight fallback:"); err != nil {
		return err
	}
	for _, node := range nodes {
		if _, err := fmt.Fprintf(out, "  %s: %s\n", node, reasons[node]); err != nil {
			return err
		}
	}
	return nil
}
