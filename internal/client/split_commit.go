package client

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/agent"
)

// A cluster apply commits on every node or on none. When it commits on some,
// the nodes that failed roll back to the previous generation and delete the
// transaction that recorded what happened; the nodes that succeeded keep the
// new one and refuse to give it up, because ordinarily a committed generation
// is the answer.
//
// The result is a lab permanently at two generations. Every later apply reads
// the cluster generation first, finds no single compare-and-swap value, and
// refuses -- correctly, and forever. The only escape was to force-destroy the
// lab, which for a teaching lab means deleting a term of student work to
// resolve a control-plane disagreement.
//
// Convergence here is a coordinator decision made from the whole cluster's
// state rather than from any one node's: if every node still holds the new
// generation uncommitted-or-committed it can be finished forward, and
// otherwise the generation is abandoned everywhere and the cluster returns to
// the generation the majority of it is already on. Both outcomes preserve
// student state, because rollback restores each node's captured pre-state.

// splitCommit describes a cluster that does not agree on one generation.
type splitCommit struct {
	// Target is the generation the cluster will converge on.
	Target string
	// Rollback names the nodes holding a committed-but-unfinalized generation
	// that must be abandoned to reach Target.
	Rollback []string
}

// detectSplitCommit reports whether the report describes a divergence that can
// be resolved by abandoning a committed generation, and on what.
//
// It fails closed. If the nodes that are not holding the disputed generation
// do not themselves agree, or if a committed node's previous generation is not
// the one the rest of the cluster is on, no automatic decision is made: the
// caller reports the divergence instead of guessing which half is right.
func detectSplitCommit(report RecoveryReport) (splitCommit, bool) {
	if len(report.Nodes) < 2 {
		return splitCommit{}, false
	}
	var (
		pending     []string
		previous    = map[string]bool{}
		settled     = map[string]bool{}
		settledList []string
	)
	for node, status := range report.Nodes {
		if status.CommittedPending {
			pending = append(pending, node)
			previous[status.PreviousGeneration] = true
			continue
		}
		if status.Phase == "recovering" || (status.Phase != "idle" && !status.Consistent) {
			// Still moving, or not verifiably anywhere. Deciding the cluster's
			// generation from an unfinished node is exactly the guess this
			// exists to avoid.
			return splitCommit{}, false
		}
		settled[status.Generation] = true
		settledList = append(settledList, node)
	}
	if len(pending) == 0 || len(settledList) == 0 {
		// Either nothing is disputed, or every node holds the generation and
		// the cluster is simply awaiting finalization. Neither is a split.
		return splitCommit{}, false
	}
	if len(settled) != 1 || len(previous) != 1 {
		return splitCommit{}, false
	}
	var target string
	for generation := range settled {
		target = generation
	}
	if target == "" {
		return splitCommit{}, false
	}
	if !previous[target] {
		// The committed nodes did not come from where the rest of the cluster
		// is. Rolling back would not converge them.
		return splitCommit{}, false
	}
	sort.Strings(pending)
	return splitCommit{Target: target, Rollback: pending}, true
}

// resolveSplitCommit asks the committed nodes to abandon their generation so
// the cluster converges on the one the rest of it is already holding.
func (c *Cluster) resolveSplitCommit(ctx context.Context, lab string, lease *MutationLease,
	split splitCommit, options RecoveryOptions,
) error {
	var problems []string
	for _, name := range split.Rollback {
		node := c.node(name)
		if node == nil {
			problems = append(problems, fmt.Sprintf("%s is not in this cluster", name))
			continue
		}
		fence, ok := lease.Fence(name)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no recovery fence", name))
			continue
		}
		if _, err := node.Recover(ctx, agent.RecoveryRequest{
			Lab: lab, Fence: fence, Strategy: "rollback", Takeover: options.Takeover,
			RollbackCommitted: true,
		}); err != nil {
			problems = append(problems, fmt.Sprintf("%s abandon committed generation: %v", name, err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("converging lab %q on generation %q: %s",
		lab, split.Target, strings.Join(problems, "; "))
}
