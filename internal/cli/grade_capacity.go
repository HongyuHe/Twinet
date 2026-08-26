package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
)

// execProbeBudget is the agent work class grading commands are charged to. It
// is the number the node itself publishes, so the controller does not have to
// guess what the machine on the other end can take.
const execProbeBudget = "exec_probe"

// execBudgetQueryTimeout bounds how long capacity discovery may take. The
// nodes have already answered a hold request by the time this runs, so a node
// that is slow here is a node under pressure -- which is an answer in itself,
// and the conservative reading of it is what the plan applies.
const execBudgetQueryTimeout = 15 * time.Second

// gradeExecBudgets asks every node that holds part of this lab what it will
// admit.
//
// A node that does not answer, answers without backpressure, or runs an agent
// too old to publish it is left Known=false. That is not the same as a node
// with no capacity: the plan treats unknown as "assume room for one grade",
// which is the conservative reading, whereas treating it as zero would refuse
// to grade and treating it as unlimited would reproduce the defect this exists
// to prevent.
func gradeExecBudgets(ctx context.Context, top *model.Topology, token string,
	footprints []grade.RunFootprint,
) []grade.NodeExecBudget {
	nodes := map[string]bool{}
	for _, footprint := range footprints {
		for node := range footprint.ByNode {
			nodes[node] = true
		}
	}
	names := make([]string, 0, len(nodes))
	for node := range nodes {
		names = append(names, node)
	}
	sort.Strings(names)

	if !clustered(top) {
		// No agent stands between this process and the containers, so the
		// budget is the one this host would enforce for itself.
		local := limiter.WithDefaultsForRuntime(limiter.Config{},
			top.Lab.RuntimeForNode(localNode(top))).ExecProbe
		out := make([]grade.NodeExecBudget, 0, len(names))
		for _, name := range names {
			out = append(out, grade.NodeExecBudget{
				Node: name, Limit: local, Known: true, Source: "this host",
			})
		}
		return out
	}

	tok, err := tokenFor(token)
	if err != nil {
		return nil
	}
	// Capacity is advisory: it decides how fast to read the lab, not whether
	// the marks are sound. A node that cannot answer promptly is recorded as
	// unknown rather than allowed to delay grading by a full request timeout.
	ctx, cancel := context.WithTimeout(ctx, execBudgetQueryTimeout)
	defer cancel()
	out := make([]grade.NodeExecBudget, 0, len(names))
	for _, result := range client.NewCluster(top.Lab, tok).Status(ctx) {
		if !nodes[result.Node] {
			continue
		}
		budget := grade.NodeExecBudget{Node: result.Node, Source: "node " + result.Node}
		if result.Err == nil {
			// What the node is already serving is subtracted, so a machine
			// busy with another lab, a deploy, or its own repair loop admits
			// fewer grades than an idle one.
			if stats, ok := result.Value.Backpressure[execProbeBudget]; ok && stats.Limit > 0 {
				budget.Limit = stats.Limit
				budget.InFlight = stats.InFlight
				budget.Queued = stats.QueueDepth
				budget.Known = true
			}
		}
		out = append(out, budget)
	}
	return out
}

// planGradeRun derives the outer width for a `grade run`, or applies the one
// an operator named.
//
// The width is announced either way. An operator watching a run that is
// narrower than the number of systems is entitled to know why before deciding
// whether to widen it, and an operator who widened it past what the cluster
// advertises is entitled to have that recorded next to the marks it produced.
func planGradeRun(ctx context.Context, top *model.Topology, token string, targets []int,
	requested, checkParallel, activeParallel int, out io.Writer,
) (*grade.Admission, *grade.SchedulingRecord) {
	footprints := make([]grade.RunFootprint, 0, len(targets))
	for _, as := range targets {
		footprints = append(footprints, grade.Footprint(top, as))
	}
	if len(targets) <= 1 {
		// There is nothing to schedule, so there is nothing to ask the
		// cluster. One system at a time is the configuration the reference
		// solution is measured in, and it must cost no extra round trip.
		return grade.FixedAdmission(1), &grade.SchedulingRecord{
			Width: 1, Reason: "one system was selected", Safe: 1,
		}
	}
	plan := grade.PlanConcurrency(grade.ConcurrencyRequest{
		Footprints:          footprints,
		Budgets:             gradeExecBudgets(ctx, top, token, footprints),
		CheckParallel:       checkParallel,
		ObservationParallel: checkParallel,
		ActiveParallel:      activeParallel,
	})

	if requested > 0 {
		width := requested
		if width > len(targets) {
			width = len(targets)
		}
		record := &grade.SchedulingRecord{
			Width: width, Reason: plan.Reason, Requested: requested, Safe: plan.Width,
		}
		if width > plan.Width {
			record.Reason = fmt.Sprintf("operator chose --parallel %d, above the "+
				"capacity-safe width of %d (%s)", requested, plan.Width, plan.Reason)
			fmt.Fprintf(out, "AUDIT: grading %d system(s) at --parallel %d, above the "+
				"capacity-safe width of %d (%s). Checks that time out under an operator-chosen "+
				"width are still quarantined rather than marked.\n",
				len(targets), requested, plan.Width, plan.Reason)
		} else if len(targets) > 1 {
			record.Reason = fmt.Sprintf("operator chose --parallel %d; the capacity-safe "+
				"width was %d", requested, plan.Width)
			fmt.Fprintf(out, "grading %d system(s) at --parallel %d (capacity-safe width is %d)\n",
				len(targets), requested, plan.Width)
		}
		return grade.FixedAdmission(width), record
	}

	if len(targets) > 1 {
		fmt.Fprintf(out, "grading %d system(s), at most %d at a time: %s\n",
			len(targets), plan.Width, plan.Reason)
		if len(plan.Unknown) > 0 {
			fmt.Fprintf(out, "  %s did not report an exec budget, so grading assumes "+
				"room for one system there; pass --parallel to override\n",
				strings.Join(plan.Unknown, ", "))
		}
	}
	return plan.Admission(), &grade.SchedulingRecord{
		Width: plan.Width, Reason: plan.Reason, Safe: plan.Width,
	}
}
