package grade

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// contendedNode is one machine holding a whole lab, serving the commands every
// grade sends it.
//
// Overload is modelled as worse than proportional, because that is what was
// measured: eight grades at eight checks each offered 64 concurrent execs to
// an agent advertising 56 -- a fourteen per cent overcommit -- and the result
// was not commands that took fourteen per cent longer but commands that never
// returned inside a two-minute budget at all. A container exec is not a unit
// of pure CPU: it competes with 212 running routing daemons, one container
// runtime, one page cache, and a tool-integrity read per call.
type contendedNode struct {
	capacity int
	base     time.Duration

	mu     sync.Mutex
	active int
	peak   int
	calls  int
}

func (n *contendedNode) run(ctx context.Context) error {
	n.mu.Lock()
	n.active++
	n.calls++
	if n.active > n.peak {
		n.peak = n.active
	}
	active := n.active
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		n.active--
		n.mu.Unlock()
	}()

	cost := n.base
	if active > n.capacity {
		over := float64(active) / float64(n.capacity)
		cost = time.Duration(float64(n.base) * over * over)
	}
	timer := time.NewTimer(cost)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *contendedNode) exec(ctx context.Context, _ string, _ []string) (rt.ExecResult, error) {
	if err := n.run(ctx); err != nil {
		return rt.ExecResult{}, err
	}
	return rt.ExecResult{Stdout: "ok\n"}, nil
}

// batch mirrors the agent: one request per node, served by a bounded pool of
// workers, under one request deadline. When the pool cannot drain the request
// in time the whole batch fails, which is exactly how the live run reported
// `Post "https://10.0.1.1:7200/v1/exec": context deadline exceeded`.
func (n *contendedNode) batch(ctx context.Context, requests []BatchExecRequest) ([]BatchExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, batchDeadline)
	defer cancel()
	results := make([]BatchExecResult, len(requests))
	sem := make(chan struct{}, agentBatchWorkers)
	var wg sync.WaitGroup
	for index := range requests {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[index].Err = ctx.Err()
				return
			}
			defer func() { <-sem }()
			result, err := n.exec(ctx, requests[index].DeviceID, requests[index].Command)
			results[index].Result, results[index].Err = result, err
		}()
	}
	wg.Wait()
	return results, nil
}

const (
	// The live budgets, scaled so a regression test costs a second rather
	// than six minutes: a two-minute check budget and a two-minute node
	// request timeout become 300ms, and one control-plane dump becomes 20ms.
	checkDeadline = 300 * time.Millisecond
	batchDeadline = 300 * time.Millisecond
	dumpCost      = 15 * time.Millisecond
	// readsPerCheck is how many separate commands one check runs: a check
	// gathers evidence from the system under test and from what its
	// neighbours saw, and each of those is a command of its own.
	readsPerCheck = 8
)

// surveyReader is a state provider that costs what a control-plane dump costs:
// one command through the batching executor the snapshot builds.
type surveyReader struct{}

func (surveyReader) ReadState(ctx context.Context, device *model.Device, exec netstate.Executor,
	query netstate.Query,
) (netstate.State, error) {
	if exec != nil {
		if _, err := exec.Exec(ctx, device.ID, []string{"vtysh", "-c", "show running-config"}); err != nil {
			return netstate.State{}, err
		}
	}
	state := netstate.State{}
	if query.Has(netstate.QueryInterfaces) {
		state.Interfaces = []netstate.Interface{{Name: "lo"}}
	}
	return state, nil
}

const contentionCheck = "test.control_plane_dump"

func init() {
	Register(&Check{
		Name: contentionCheck, Describe: "reads a router's tables",
		Run: func(ctx context.Context, env *Env) Result {
			router, ok := env.Device("R")
			if !ok {
				return Errored(contentionCheck, fmt.Errorf("as%d has no router R", env.AS))
			}
			// A passive read, which the snapshot deduplicates across checks,
			// and then evidence that cannot be shared: an active probe is
			// never cached, because a cached packet is not a witness.
			if _, err := env.Vtysh(ctx, "R", "show ip bgp json"); err != nil {
				return Errored(contentionCheck, err)
			}
			for i := 0; i < readsPerCheck; i++ {
				if _, err := env.Probe(ctx, router.ID,
					[]string{"ping", "-c", "1", "10.0.0.1"}); err != nil {
					return Errored(contentionCheck, err)
				}
			}
			return Pass(contentionCheck, Evidence{})
		},
	})
}

func contentionRubric() *Rubric {
	r := &Rubric{Metadata: RubricMeta{Name: "contention"}}
	for i := 1; i <= 6; i++ {
		r.Questions = append(r.Questions, QuestionSpec{
			ID: fmt.Sprintf("q%d", i), Title: fmt.Sprintf("question %d", i), Points: 1,
			Checks: []CheckSpec{{Check: contentionCheck}},
		})
	}
	return r
}

func gradeAllAtWidth(t *testing.T, top *model.Topology, node *contendedNode,
	gate *Admission, checkParallel int,
) []*Report {
	t.Helper()
	rubric := contentionRubric()
	targets := studentTargets(top)
	return RunEach(context.Background(), targets, gate,
		func(ctx context.Context, as int) *Report {
			env := &Env{
				Topology: top, AS: as, StateReader: surveyReader{},
				Exec: node.exec, BatchExec: node.batch,
			}
			report := Run(ctx, rubric, env, RunOptions{
				CheckTimeout:        checkDeadline,
				Parallel:            checkParallel,
				ReadParallel:        checkParallel,
				ActiveParallel:      4,
				ObservationParallel: checkParallel,
			})
			report.Submission = fmt.Sprintf("as%d", as)
			return report
		}, nil)
}

func quarantined(reports []*Report) []string {
	var out []string
	for _, report := range reports {
		if report == nil {
			out = append(out, "missing")
			continue
		}
		if report.NeedsReview {
			out = append(out, report.Submission)
		}
	}
	return out
}

// The whole defect in one test: the same lab, the same rubric, the same node,
// graded once at the width that shipped and once at the width this planner
// derives.
//
// The shipped default read all eight systems at once against the single agent
// that holds them, checks ran out of time, and every report came back needing
// review with no releasable mark -- against a lab in which nothing is wrong.
// The derived width reads the same eight systems and marks all eight.
func TestHighContentionGradingCompletesAtTheDerivedWidthAndNotAtTheOldDefault(t *testing.T) {
	top := classTopology(8)
	footprints := footprintsFor(top)
	budgets := []NodeExecBudget{{Node: "node-0", Limit: 56, Known: true, Source: "node node-0"}}
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprints, Budgets: budgets, CheckParallel: 8,
	})
	if plan.Width >= len(footprints) {
		t.Fatalf("the plan did not narrow anything: width %d", plan.Width)
	}
	capacity := plan.Budget["node-0"]

	// What shipped: eight submissions, eight checks each, no regard for the
	// one agent underneath them.
	old := &contendedNode{capacity: capacity, base: dumpCost}
	oldReports := gradeAllAtWidth(t, top, old, FixedAdmission(8), 8)
	oldHeld := quarantined(oldReports)
	if len(oldHeld) == 0 {
		t.Fatalf("the old default no longer overloads the node (peak %d concurrent exec(s), "+
			"capacity %d, %d call(s)); this test would not detect the regression it exists for",
			old.peak, capacity, old.calls)
	}

	// What is derived: the same work, admitted against what the node says it
	// can serve.
	fresh := &contendedNode{capacity: capacity, base: dumpCost}
	newReports := gradeAllAtWidth(t, top, fresh, plan.Admission(), 8)
	if held := quarantined(newReports); len(held) != 0 {
		t.Fatalf("the derived width still quarantined %v (peak %d concurrent exec(s), capacity %d)",
			held, fresh.peak, capacity)
	}
	if len(newReports) != 8 {
		t.Fatalf("got %d reports, want 8", len(newReports))
	}
	for _, report := range newReports {
		if report.Total != report.MaxTotal {
			t.Errorf("%s scored %.2f/%.2f against a lab in which nothing is wrong",
				report.Submission, report.Total, report.MaxTotal)
		}
	}
	if fresh.peak > capacity {
		t.Errorf("the derived width offered %d concurrent exec(s) to a node that admits %d",
			fresh.peak, capacity)
	}
	t.Logf("old default: %d of %d quarantined, peak %d concurrent exec(s); "+
		"derived width %d: 8 of 8 marked, peak %d",
		len(oldHeld), len(oldReports), old.peak, plan.Width, fresh.peak)
}

// Narrowing the outer width must not weaken the guarantee that matters: a run
// that is cancelled while systems are still queued at the gate returns a
// report for every one of them, needing review and carrying no total, rather
// than a silent absence or a zero that a spreadsheet cannot tell from a
// student who did nothing.
func TestASystemStillQueuedAtTheGateIsQuarantinedNotLost(t *testing.T) {
	top := classTopology(4)
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints:    footprintsFor(top),
		Budgets:       []NodeExecBudget{{Node: "node-0", Limit: 16, Known: true}},
		CheckParallel: 8,
	})
	node := &contendedNode{capacity: plan.Budget["node-0"], base: dumpCost}
	rubric := contentionRubric()
	targets := studentTargets(top)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reports := RunEach(ctx, targets, plan.Admission(),
		func(ctx context.Context, as int) *Report {
			env := &Env{
				Topology: top, AS: as, StateReader: surveyReader{},
				Exec: node.exec, BatchExec: node.batch,
			}
			report := Run(ctx, rubric, env, RunOptions{CheckTimeout: checkDeadline, Parallel: 8})
			report.Submission = fmt.Sprintf("as%d", as)
			return report
		}, nil)

	if len(reports) != len(targets) {
		t.Fatalf("got %d reports for %d targets", len(reports), len(targets))
	}
	for index, report := range reports {
		if report == nil {
			t.Fatalf("as%d produced no report at all", targets[index])
		}
		if !report.NeedsReview {
			t.Errorf("%s released a mark from a cancelled run", report.Submission)
		}
		if report.Total != 0 {
			t.Errorf("%s carries a total of %.2f from a cancelled run", report.Submission, report.Total)
		}
	}
}

// Independent systems must still be read together under the same executor:
// the fix must not have bought correctness by making every run serial.
func TestIndependentSystemsStillGradeConcurrentlyUnderContention(t *testing.T) {
	top := isolatedTopology(8)
	budgets := make([]NodeExecBudget, 0, 8)
	for i := 0; i < 8; i++ {
		budgets = append(budgets, NodeExecBudget{
			Node: fmt.Sprintf("node-%d", i), Limit: 56, Known: true,
		})
	}
	plan := PlanConcurrency(ConcurrencyRequest{
		Footprints: footprintsFor(top), Budgets: budgets, CheckParallel: 8,
	})
	if plan.Width != 8 {
		t.Fatalf("independent systems were narrowed to %d: %s", plan.Width, plan.Reason)
	}
	// Each node serves only its own system here, so the aggregate executor is
	// asked for eight systems at once and must still mark all eight.
	node := &contendedNode{capacity: 8 * 8, base: dumpCost}
	reports := gradeAllAtWidth(t, top, node, plan.Admission(), 8)
	if held := quarantined(reports); len(held) != 0 {
		t.Fatalf("independent systems were quarantined: %v", held)
	}
	if node.peak <= 8 {
		t.Errorf("eight independent systems never overlapped: peak %d", node.peak)
	}
}
