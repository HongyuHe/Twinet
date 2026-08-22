package cli

import (
	"context"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
)

func tryClusterNoop(ctx context.Context, top *model.Topology, token, mode string, ungraded int,
	out, errOut interface{ Write([]byte) (int, error) },
) (bool, error) {
	start := time.Now()
	results, ok := client.NewCluster(top.Lab, token).NoopPreflight(ctx, top, agent.ApplyRequest{
		Mode: mode, Ungraded: ungraded,
	})
	if !ok {
		return false, nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTEPS\tDURATION\tSTATUS")
	for _, result := range results {
		if result.Err != nil {
			return false, nil
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
			"AUDIT: no-op source=agent-read-only-plan-verify runtime_contract=%s topology_hash=%s generation=%s fence=%d mode=%s\n",
			deploy.RuntimeSpecContractVersion, top.Hash, witness.Generation, witness.FenceGeneration, mode)
	}
	return true, nil
}
