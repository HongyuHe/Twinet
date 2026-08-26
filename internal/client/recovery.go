package client

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
)

// RecoveryReport proves what every node observed after a rollback/resume.
type RecoveryReport struct {
	Lab        string                          `json:"lab"`
	Generation string                          `json:"generation,omitempty"`
	Nodes      map[string]agent.RecoveryStatus `json:"nodes"`
}

// RecoveryOptions controls bounded observation of an in-progress recovery.
// Progress receives independently observed node state and must not mutate the
// cluster. Takeover is honored only after agents report a stale deadline.
type RecoveryOptions struct {
	Wait                time.Duration
	Takeover            bool
	ForwardAcknowledged bool
	Progress            func(RecoveryReport)
}

const defaultRecoveryWait = 2 * time.Minute

// Recover asks one agent to restore its durable pre-transaction inventory.
func (n *Node) Recover(ctx context.Context, req agent.RecoveryRequest) (agent.RecoveryResponse, error) {
	var out agent.RecoveryResponse
	err := n.doWithTimeout(ctx, "POST", "/v1/recover", req, &out,
		agent.MaximumRecoveryTotalTimeout)
	return out, err
}

func recoveryStatusWorkItems(status agent.RecoveryStatus) int {
	items := status.ExpectedContainers
	for _, value := range []int{
		status.ObservedContainers,
		status.ExpectedLogicalBindings,
		status.ObservedLogicalBindings,
		status.ExpectedPhysicalTrunks,
		status.ObservedPhysicalTrunks,
		status.ExpectedVNIs,
		status.ObservedVNIs,
	} {
		if value > items {
			items = value
		}
	}
	return items
}

// RecoveryStatus reads one node's independently verified recovery state.
func (n *Node) RecoveryStatus(ctx context.Context, lab string) (agent.RecoveryStatus, error) {
	var out agent.RecoveryStatus
	err := n.do(ctx, "GET", "/v1/recovery?lab="+url.QueryEscape(lab), nil, &out)
	return out, err
}

// Recover resumes a failed transaction under a fresh cluster lease and waits
// until every reachable node proves the same generation and exact inventory.
func (c *Cluster) Recover(ctx context.Context, lab string) (RecoveryReport, error) {
	return c.RecoverWithStrategy(ctx, lab, "rollback")
}

// RecoverWithStrategy chooses the only two explicit outcomes for a failed
// transaction. Forward is never selected by automatic deploy recovery.
func (c *Cluster) RecoverWithStrategy(ctx context.Context, lab, strategy string) (RecoveryReport, error) {
	return c.RecoverWithOptions(ctx, lab, strategy, RecoveryOptions{Wait: defaultRecoveryWait})
}

// RecoverWithOptions either starts a fenced recovery or joins the same
// strategy already running on agents. It never repeatedly contends for a
// healthy agent-recovery lease: callers receive structured progress while
// waiting and an immediate conflict for a different strategy.
func (c *Cluster) RecoverWithOptions(ctx context.Context, lab, strategy string,
	options RecoveryOptions,
) (RecoveryReport, error) {
	if strategy != "rollback" && strategy != "forward" {
		return RecoveryReport{Lab: lab}, fmt.Errorf("unknown recovery strategy %q", strategy)
	}
	ctx = operationContext(ctx)
	initial, pending, err := c.readRecoveryStatuses(ctx, lab)
	if err != nil {
		return initial, err
	}
	c.emitRecoveryProgress(options, initial)
	if !pending {
		return initial, nil
	}
	if active, conflict, stale := recoveryActivity(initial, strategy); active {
		if conflict != "" {
			return initial, fmt.Errorf("recovery for lab %q is already running strategy %q; requested %q",
				lab, conflict, strategy)
		}
		if stale && options.Takeover {
			return c.takeoverRecovery(ctx, lab, strategy, options)
		}
		return c.waitForRecovery(ctx, lab, strategy, initial, options)
	}
	lease, err := c.AcquireMutationLease(ctx, lab)
	if err != nil {
		// A recovery can acquire its lease between our status sample and this
		// request. Re-read once and join it rather than sleeping through the
		// lease TTL.
		current, _, statusErr := c.readRecoveryStatuses(ctx, lab)
		if statusErr == nil {
			c.emitRecoveryProgress(options, current)
			if active, conflict, stale := recoveryActivity(current, strategy); active {
				if conflict != "" {
					return current, fmt.Errorf("recovery for lab %q is already running strategy %q; requested %q",
						lab, conflict, strategy)
				}
				if stale && options.Takeover {
					return c.takeoverRecovery(ctx, lab, strategy, options)
				}
				return c.waitForRecovery(ctx, lab, strategy, current, options)
			}
		}
		return initial, err
	}
	if lease == nil {
		return initial, nil
	}
	defer lease.Release()
	return c.recoverWithLeaseStrategyOptions(lease.Context(), lab, lease, strategy, options)
}

func (c *Cluster) emitRecoveryProgress(options RecoveryOptions, report RecoveryReport) {
	if options.Progress != nil {
		options.Progress(report)
	}
}

// recoveryActivity returns whether a node reports an active recovery, a
// conflicting active strategy, and whether every active reporter has passed
// its operator-safe takeover deadline.
func recoveryActivity(report RecoveryReport, strategy string) (active bool, conflict string, stale bool) {
	stale = true
	for _, status := range report.Nodes {
		if status.Phase != "recovering" {
			continue
		}
		active = true
		if status.Strategy != "" && status.Strategy != strategy {
			return true, status.Strategy, false
		}
		if !status.TakeoverAllowed {
			stale = false
		}
	}
	return active, "", active && stale
}

func (c *Cluster) waitForRecovery(ctx context.Context, lab, strategy string,
	report RecoveryReport, options RecoveryOptions,
) (RecoveryReport, error) {
	if options.Wait <= 0 {
		return report, recoveryWaitError(lab, report)
	}
	deadline := time.NewTimer(options.Wait)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-deadline.C:
			return report, recoveryWaitError(lab, report)
		case <-ticker.C:
		}
		next, pending, err := c.readRecoveryStatuses(ctx, lab)
		if err != nil {
			return next, err
		}
		report = next
		c.emitRecoveryProgress(options, report)
		if !pending {
			return report, nil
		}
		if active, conflict, stale := recoveryActivity(report, strategy); active {
			if conflict != "" {
				return report, fmt.Errorf("recovery for lab %q switched to strategy %q; requested %q",
					lab, conflict, strategy)
			}
			if stale {
				if options.Takeover {
					return c.takeoverRecovery(ctx, lab, strategy, options)
				}
				return report, fmt.Errorf("recovery for lab %q exceeded its phase deadline; retry with --takeover", lab)
			}
		} else {
			lease, leaseErr := c.AcquireMutationLease(ctx, lab)
			if leaseErr != nil {
				return report, leaseErr
			}
			if lease == nil {
				return report, nil
			}
			defer lease.Release()
			return c.recoverWithLeaseStrategyOptions(lease.Context(), lab, lease, strategy, options)
		}
	}
}

func (c *Cluster) takeoverRecovery(ctx context.Context, lab, strategy string,
	options RecoveryOptions,
) (RecoveryReport, error) {
	deadline := time.NewTimer(options.Wait)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		lease, err := c.AcquireMutationLease(ctx, lab)
		if err == nil {
			if lease == nil {
				return RecoveryReport{Lab: lab}, nil
			}
			defer lease.Release()
			return c.recoverWithLeaseStrategyOptions(lease.Context(), lab, lease, strategy,
				RecoveryOptions{Wait: options.Wait, Takeover: true,
					ForwardAcknowledged: options.ForwardAcknowledged, Progress: options.Progress})
		}
		report, _, statusErr := c.readRecoveryStatuses(ctx, lab)
		if statusErr != nil {
			return RecoveryReport{Lab: lab}, err
		}
		c.emitRecoveryProgress(options, report)
		if active, conflict, stale := recoveryActivity(report, strategy); active {
			if conflict != "" {
				return report, fmt.Errorf("recovery for lab %q is already running strategy %q; requested %q",
					lab, conflict, strategy)
			}
			if !stale {
				return c.waitForRecovery(ctx, lab, strategy, report, options)
			}
		}
		if options.Wait <= 0 {
			return report, fmt.Errorf("recovery takeover for lab %q is not yet fenced: %w", lab, err)
		}
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-deadline.C:
			return report, fmt.Errorf("recovery takeover for lab %q is not yet fenced: %w", lab, err)
		case <-ticker.C:
		}
	}
}

func recoveryWaitError(lab string, report RecoveryReport) error {
	var progress []string
	for node, status := range report.Nodes {
		if status.Phase != "recovering" {
			continue
		}
		progress = append(progress, fmt.Sprintf("%s owner=%q strategy=%q target=%q last_progress=%s deadline=%s",
			node, status.Owner, status.Strategy, status.CurrentTarget,
			status.LastProgressAt.Format(time.RFC3339), status.Deadline.Format(time.RFC3339)))
	}
	sort.Strings(progress)
	if len(progress) == 0 {
		return fmt.Errorf("recovery for lab %q is incomplete", lab)
	}
	return fmt.Errorf("recovery for lab %q is still in progress: %s", lab, strings.Join(progress, "; "))
}

// readRecoveryStatuses separates a cluster that cannot be read from a cluster
// that can be read and disagrees.
//
// They used to be the same error, and that is what made a split commit
// terminal: the divergence itself aborted recovery before recovery could look
// at it, so the one thing that could have converged the cluster never ran. A
// node that does not answer is still fatal -- deciding a generation from a
// subset of the cluster is how the split happens in the first place.
func (c *Cluster) readRecoveryStatuses(ctx context.Context, lab string) (RecoveryReport, bool, error) {
	report := RecoveryReport{Lab: lab, Nodes: map[string]agent.RecoveryStatus{}}
	pending := false
	var problems []string
	for _, node := range c.sortedNodes() {
		status, err := node.RecoveryStatus(ctx, lab)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s recovery status: %v", node.Name, err))
			continue
		}
		report.Nodes[node.Name] = status
		if status.Generation != "" {
			if report.Generation == "" {
				report.Generation = status.Generation
			} else if report.Generation != status.Generation {
				pending = true
			}
		}
		if status.Phase != "idle" && (!status.Consistent || status.Phase != "committed") {
			pending = true
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return report, true, fmt.Errorf("recovery status for lab %q is unavailable: %s",
			lab, strings.Join(problems, "; "))
	}
	return report, pending, nil
}

func (c *Cluster) recoverWithLease(ctx context.Context, lab string, lease *MutationLease) (RecoveryReport, error) {
	return c.recoverWithLeaseStrategyOptions(ctx, lab, lease, "rollback", RecoveryOptions{})
}

func (c *Cluster) recoverWithLeaseStrategyOptions(ctx context.Context, lab string, lease *MutationLease,
	strategy string, options RecoveryOptions,
) (RecoveryReport, error) {
	report := RecoveryReport{Lab: lab, Nodes: map[string]agent.RecoveryStatus{}}
	var problems []string
	type result struct {
		node   string
		status agent.RecoveryStatus
		err    error
	}
	nodes := c.sortedNodes()
	results := make(chan result, len(nodes))
	for _, node := range nodes {
		node := node
		fence, ok := lease.Fence(node.Name)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no recovery fence", node.Name))
			continue
		}
		go func() {
			response, err := node.Recover(ctx, agent.RecoveryRequest{
				Lab: lab, Fence: fence, Strategy: strategy, Takeover: options.Takeover,
				ForwardAcknowledged: options.ForwardAcknowledged,
			})
			results <- result{node: node.Name, status: response.Status, err: err}
		}()
	}
	for range len(nodes) - len(problems) {
		result := <-results
		if result.err != nil {
			problems = append(problems, fmt.Sprintf("%s recovery: %v", result.node, result.err))
			continue
		}
		report.Nodes[result.node] = result.status
	}
	// A first pass can leave the cluster split: nodes that failed have rolled
	// back and forgotten, while nodes that committed kept the generation the
	// rest of the cluster no longer has. That is not an error to report and
	// walk away from -- it is a state with exactly one safe resolution, and
	// leaving it is what previously required force-destroying the lab.
	if strategy == "rollback" {
		observed := c.observeNodes(ctx, lab, report)
		if split, found := detectSplitCommit(observed); found {
			if err := c.resolveSplitCommit(ctx, lab, lease, split, options); err != nil {
				problems = append(problems, err.Error())
			}
		}
	}

	for _, node := range nodes {
		status, err := node.RecoveryStatus(ctx, lab)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s recovery status: %v", node.Name, err))
			continue
		}
		report.Nodes[node.Name] = status
		if status.Phase != "idle" && !status.Consistent {
			problems = append(problems, fmt.Sprintf("%s is %s: %s", node.Name, status.Phase, status.Error))
			continue
		}
		if status.Generation != "" {
			if report.Generation == "" {
				report.Generation = status.Generation
			} else if report.Generation != status.Generation {
				problems = append(problems, fmt.Sprintf("%s recovered generation %q, not %q",
					node.Name, status.Generation, report.Generation))
			}
		}
	}
	if err := lease.Err(); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return report, fmt.Errorf("recovery for lab %q is incomplete: %s", lab, strings.Join(problems, "; "))
	}
	return report, nil
}

// observeNodes re-reads every node's state, keeping whatever the caller
// already has for a node that cannot be reached. A split-commit decision is
// only made when every node answered; observing a subset and acting on it
// would be the same partial-information mistake in a new place.
func (c *Cluster) observeNodes(ctx context.Context, lab string, fallback RecoveryReport) RecoveryReport {
	out := RecoveryReport{Lab: lab, Nodes: map[string]agent.RecoveryStatus{}}
	for _, node := range c.sortedNodes() {
		status, err := node.RecoveryStatus(ctx, lab)
		if err != nil {
			if known, ok := fallback.Nodes[node.Name]; ok {
				out.Nodes[node.Name] = known
				continue
			}
			// An unreachable node with no prior observation makes the cluster
			// unknowable; return an empty report so no decision is taken.
			return RecoveryReport{Lab: lab, Nodes: map[string]agent.RecoveryStatus{}}
		}
		out.Nodes[node.Name] = status
	}
	return out
}
