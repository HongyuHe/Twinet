package grade

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// `grade run --converge-timeout` set RunOptions.ConvergeTimeout and Run read
// the field nowhere. The flag documented a wait, `grade batch` and
// `grade class` performed one, and the one command with nobody to converge the
// lab for it did not: a freshly deployed reference was read while its
// adjacencies were still forming, and the marks were of a network that did not
// exist yet.
//
// These two runs differ in exactly one field. If the option goes unread again
// they produce the same report, and the first assertion fails.
func TestGradeRunWaitsForTheControlPlaneItWasGivenABudgetFor(t *testing.T) {
	const checkName = "test.converge_interior_full"
	registerConvergeCheck(t, checkName)
	rubric := convergeRubric(checkName, "ospf")

	waited := Run(context.Background(), rubric, convergeEnv(newSettlingReader(2)),
		RunOptions{WaitForConvergence: true, ConvergeTimeout: 10 * time.Second})
	if waited.NeedsReview || waited.Err != "" || waited.Total != 1 {
		t.Fatalf("a lab that settles inside the budget was not graded on what settled: %#v", waited)
	}

	read := Run(context.Background(), rubric, convergeEnv(newSettlingReader(2)),
		RunOptions{ConvergeTimeout: 10 * time.Second})
	if read.Total != 0 {
		t.Fatalf("without the option the run must read the lab as it stands: %#v", read)
	}
}

// Zero is an operator saying "read it now", and it must not become a sleep.
// It is also the value every caller that converges for itself passes.
func TestAZeroBudgetDoesNotWait(t *testing.T) {
	const checkName = "test.converge_zero_budget"
	registerConvergeCheck(t, checkName)
	reader := newSettlingReader(1 << 30)

	start := time.Now()
	report := Run(context.Background(), convergeRubric(checkName, "ospf"), convergeEnv(reader),
		RunOptions{WaitForConvergence: true, ConvergeTimeout: 0})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("a disabled budget still waited %s", elapsed)
	}
	if report.NeedsReview || report.Err != "" {
		t.Fatalf("reading a lab as it stands is not a fault: %#v", report)
	}
	if hasPhase(report, "converge") {
		t.Fatalf("a disabled wait recorded a convergence phase: %#v", report.PhaseTimings)
	}
}

// A lab that never settles is not a student who scored zero. The checks still
// run, because what a moving network reached is worth reporting, but the
// report says the marks are provisional and the gradebook must not release
// them as a total.
func TestALabThatNeverSettlesIsNotGivenAReleasedMark(t *testing.T) {
	const checkName = "test.converge_never_settles"
	registerConvergeCheck(t, checkName)

	report := Run(context.Background(), convergeRubric(checkName, "ospf"),
		convergeEnv(newSettlingReader(1<<30)),
		RunOptions{WaitForConvergence: true, ConvergeTimeout: 400 * time.Millisecond})
	if !report.NeedsReview {
		t.Fatalf("an unsettled lab was reported as a releasable mark: %#v", report)
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "had not settled") {
		t.Fatalf("the report does not say the network was still changing: %#v", report.Warnings)
	}
	if len(report.Questions) == 0 {
		t.Fatal("the evidence a moving network did reach was thrown away")
	}
	report.Submission = "alice"
	if got := len(Summarise("rubric", []*Report{report}, 0).Quarantined()); got != 1 {
		t.Fatal("an unsettled lab's total was released into the gradebook")
	}
	if !hasPhase(report, "converge") {
		t.Fatalf("the wait left no machine-readable evidence: %#v", report.PhaseTimings)
	}
}

// Cancellation is the caller's decision, not the submission's failure, and
// nothing was assessed. A total of zero and an ungraded report look the same
// in a spreadsheet, so the report must carry the difference.
func TestCancellingAConvergenceWaitGradesNothing(t *testing.T) {
	const checkName = "test.converge_cancelled"
	registerConvergeCheck(t, checkName)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	report := Run(ctx, convergeRubric(checkName, "ospf"), convergeEnv(newSettlingReader(1<<30)),
		RunOptions{WaitForConvergence: true, ConvergeTimeout: 30 * time.Second})
	if !report.NeedsReview || !strings.Contains(report.Err, "cancelled") {
		t.Fatalf("a cancelled run was not reported as one: %#v", report)
	}
	if len(report.Questions) != 0 || report.Total != 0 {
		t.Fatalf("a cancelled run produced marks: %#v", report)
	}
}

// And the distinction that matters most: a lab nobody could reach is a
// platform fault. Reporting it as "did not settle" would put a plausible zero
// in a gradebook with nothing to say it should be questioned.
func TestALabThatCannotBeReachedIsAnInfrastructureFailureNotAMark(t *testing.T) {
	const checkName = "test.converge_unreachable"
	registerConvergeCheck(t, checkName)
	env := convergeEnv(nil)
	env.Exec = func(context.Context, string, []string) (rt.ExecResult, error) {
		return rt.ExecResult{}, errNodeUnreachable
	}

	report := Run(context.Background(), convergeRubric(checkName, "ospf"), env,
		RunOptions{WaitForConvergence: true, ConvergeTimeout: 400 * time.Millisecond})
	if !report.NeedsReview || report.Err == "" {
		t.Fatalf("an unreachable lab was graded: %#v", report)
	}
	if !strings.Contains(report.Err, "could not observe") ||
		!strings.Contains(report.Err, errNodeUnreachable.Error()) {
		t.Fatalf("the report does not name the machinery failure: %q", report.Err)
	}
	if len(report.Questions) != 0 || report.Total != 0 {
		t.Fatalf("an unreachable lab produced marks: %#v", report)
	}
}

// Batch and class grading converge each submission themselves before calling
// Run. Waiting again here would double the largest fixed cost of a class run
// and observe nothing new, so the options they pass must produce no wait at
// all -- not a short one, not a cached one, none.
func TestPreConvergedGradingDoesNotWaitASecondTime(t *testing.T) {
	const checkName = "test.converge_no_double_wait"
	registerConvergeCheck(t, checkName)
	reader := newSettlingReader(1 << 30)

	start := time.Now()
	report := Run(context.Background(), convergeRubric(checkName, ""), convergeEnv(reader),
		RunOptions{ConvergeTimeout: 30 * time.Second})
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("a submission that was already converged was waited for again (%s)", elapsed)
	}
	if hasPhase(report, "converge") {
		t.Fatalf("a pre-converged run recorded a convergence phase: %#v", report.PhaseTimings)
	}
	// One OSPF read, made by the observation snapshot. A second wait would
	// have polled it many times over.
	if got := reader.ospfReads.Load(); got != 1 {
		t.Fatalf("interior state was read %d times, want the snapshot's single survey", got)
	}
}

// The rubric says which part of the control plane its questions are about.
// Waiting for more than that reports a student whose interior is perfect as
// ungradeable because their BGP is not written yet.
func TestTheWaitIsNarrowedToWhatTheRubricAsksFor(t *testing.T) {
	for _, c := range []struct {
		name  string
		spec  []QuestionSpec
		scope string
	}{
		{"one scope", []QuestionSpec{{Converge: true, ConvergeScope: "ospf"}}, convergeScopeOSPF},
		{"bgp", []QuestionSpec{{Converge: true, ConvergeScope: "bgp"}}, convergeScopeBGP},
		{"mixed scopes", []QuestionSpec{
			{Converge: true, ConvergeScope: "ospf"}, {Converge: true},
		}, convergeScopeAll},
		{"nothing declared", []QuestionSpec{{ID: "q"}}, convergeScopeAll},
		{"scope without converge", []QuestionSpec{{ConvergeScope: "ospf"}}, convergeScopeAll},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := rubricConvergeScope(&Rubric{Questions: c.spec}); got != c.scope {
				t.Fatalf("scope = %q, want %q", got, c.scope)
			}
		})
	}
}

var errNodeUnreachable = errors.New("node node-1 is unreachable")

// registerConvergeCheck registers a check that passes only when the interior
// it is given is actually up, which is what makes a missing wait visible.
func registerConvergeCheck(t *testing.T, name string) {
	t.Helper()
	registerTestCheck(name, func(ctx context.Context, env *Env) Result {
		state, err := env.RouterState(ctx, "R", netstate.QueryOSPF)
		if err != nil {
			return Errored(name, err)
		}
		for _, peer := range state.OSPF {
			if !strings.HasPrefix(peer.State, "Full") {
				return Fail(name, Evidence{Observed: peer.State})
			}
		}
		if len(state.OSPF) == 0 {
			return Fail(name, Evidence{Observed: "no adjacencies"})
		}
		return Pass(name, Evidence{})
	}, nil)
	if check, ok := Lookup(name); ok {
		check.Observations = []ObservationDependency{
			{Scope: ObservationTargetRouters, Query: netstate.QueryOSPF},
		}
	}
}

func convergeRubric(check, scope string) *Rubric {
	return &Rubric{
		Metadata: RubricMeta{Name: "converge"},
		Questions: []QuestionSpec{{
			ID: "q", Title: "q", Points: 1, Converge: true, ConvergeScope: scope,
			Checks: []CheckSpec{{Check: check}},
		}},
	}
}

func convergeEnv(reader netstate.Reader) *Env {
	return &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: reader,
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
			return rt.ExecResult{}, nil
		},
	}
}

// settlingReader is an interior that comes up after a few polls, which is what
// a freshly deployed lab does and what a wait exists to absorb.
type settlingReader struct {
	fullAfter int64
	ospfReads atomic.Int64
}

func newSettlingReader(fullAfter int64) *settlingReader {
	return &settlingReader{fullAfter: fullAfter}
}

func (r *settlingReader) ReadState(_ context.Context, _ *model.Device, _ netstate.Executor,
	query netstate.Query,
) (netstate.State, error) {
	state := netstate.State{}
	if query.Has(netstate.QueryOSPF) {
		peer := netstate.OSPFPeer{RouterID: "10.3.0.2", Address: "10.3.0.2", State: "Init"}
		if r.ospfReads.Add(1) > r.fullAfter {
			peer.State = "Full/DR"
		}
		state.OSPF = []netstate.OSPFPeer{peer}
	}
	return state, nil
}

func hasPhase(report *Report, name string) bool {
	for _, phase := range report.PhaseTimings {
		if phase.Name == name {
			return true
		}
	}
	return false
}
