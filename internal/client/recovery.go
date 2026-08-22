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

// Recover asks one agent to restore its durable pre-transaction inventory.
func (n *Node) Recover(ctx context.Context, req agent.RecoveryRequest) (agent.RecoveryResponse, error) {
	var out agent.RecoveryResponse
	err := n.do(ctx, "POST", "/v1/recover", req, &out)
	return out, err
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
	ctx = operationContext(ctx)
	initial, pending, err := c.readRecoveryStatuses(ctx, lab)
	if err != nil {
		return initial, err
	}
	if !pending {
		return initial, nil
	}
	// Agent-side recovery owns a maximum-TTL internal fence while it rebuilds
	// a full topology. Wait through that bounded window instead of returning a
	// misleading lease-conflict error to an operator who asked to recover.
	deadline := time.Now().Add(12 * time.Minute)
	var lease *MutationLease
	for {
		lease, err = c.AcquireMutationLease(ctx, lab)
		if err == nil || ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return RecoveryReport{Lab: lab}, err
	}
	if lease == nil {
		return RecoveryReport{Lab: lab}, nil
	}
	defer lease.Release()
	return c.recoverWithLease(lease.Context(), lab, lease)
}

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
				problems = append(problems, fmt.Sprintf("%s generation %q, not %q",
					node.Name, status.Generation, report.Generation))
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
	report := RecoveryReport{Lab: lab, Nodes: map[string]agent.RecoveryStatus{}}
	var problems []string
	for _, node := range c.sortedNodes() {
		fence, ok := lease.Fence(node.Name)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s has no recovery fence", node.Name))
			continue
		}
		response, err := node.Recover(ctx, agent.RecoveryRequest{Lab: lab, Fence: fence})
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s recovery: %v", node.Name, err))
			continue
		}
		report.Nodes[node.Name] = response.Status
	}
	for _, node := range c.sortedNodes() {
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
