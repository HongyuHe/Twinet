package grade

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type countingStateReader struct {
	calls atomic.Int64
	err   error
}

func (r *countingStateReader) ReadState(_ context.Context, _ *model.Device, _ netstate.Executor,
	query netstate.Query,
) (netstate.State, error) {
	r.calls.Add(1)
	if r.err != nil {
		return netstate.State{}, r.err
	}
	state := netstate.State{}
	if query.Has(netstate.QueryInterfaces) {
		state.Interfaces = []netstate.Interface{{Name: "lo", Addresses: []netstate.Address{{
			Prefix: "10.3.0.1/32", Family: "ipv4",
		}}}}
	}
	return state, nil
}

func observationTestTopology() *model.Topology {
	router := &model.Device{ID: "as3/R", Name: "R", ASN: 3, Kind: model.KindRouter}
	return &model.Topology{
		Name: "observation-test", Hash: "snapshot",
		Devices: map[string]*model.Device{router.ID: router},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Routers: []*model.Device{router}, Devices: []*model.Device{router}},
		},
	}
}

func registerTestCheck(name string, run CheckFunc, resources ProbeResourceResolver) {
	if _, found := Lookup(name); found {
		return
	}
	Register(&Check{Name: name, Describe: name, Run: run, Resources: resources})
}

func TestGradeSnapshotDeduplicatesStateAndReadOnlyExec(t *testing.T) {
	const (
		stateCheck = "test.snapshot_state"
		execCheck  = "test.snapshot_exec"
	)
	registerTestCheck(stateCheck, func(ctx context.Context, env *Env) Result {
		state, err := env.RouterState(ctx, "R", netstate.QueryInterfaces)
		if err != nil || len(state.Interfaces) != 1 {
			return Errored(stateCheck, errors.New("state unavailable"))
		}
		return Pass(stateCheck, Evidence{})
	}, nil)
	registerTestCheck(execCheck, func(ctx context.Context, env *Env) Result {
		if _, err := env.Vtysh(ctx, "R", "show running-config"); err != nil {
			return Errored(execCheck, err)
		}
		return Pass(execCheck, Evidence{})
	}, nil)

	reader := &countingStateReader{}
	var execCalls atomic.Int64
	env := &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: reader,
		Exec: func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
			if len(command) == 3 && command[0] == "vtysh" && command[2] == "show running-config" {
				execCalls.Add(1)
			}
			return rt.ExecResult{Stdout: "router bgp 3\n"}, nil
		},
	}
	rubric := &Rubric{Metadata: RubricMeta{Name: "snapshot"}, Questions: []QuestionSpec{
		{ID: "state-a", Title: "state a", Points: 1, Checks: []CheckSpec{{Check: stateCheck}}},
		{ID: "state-b", Title: "state b", Points: 1, Checks: []CheckSpec{{Check: stateCheck}}},
		{ID: "exec-a", Title: "exec a", Points: 1, Checks: []CheckSpec{{Check: execCheck}}},
		{ID: "exec-b", Title: "exec b", Points: 1, Checks: []CheckSpec{{Check: execCheck}}},
	}}
	report := Run(context.Background(), rubric, env, RunOptions{Parallel: 4})
	if report.NeedsReview || report.Total != 4 {
		t.Fatalf("report = %#v", report)
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("netstate calls = %d, want one snapshot collection", got)
	}
	if got := execCalls.Load(); got != 1 {
		t.Fatalf("read-only vtysh calls = %d, want one shared observation", got)
	}
	if report.Observation == nil || !report.Observation.Frozen || len(report.Observation.States) != 1 {
		t.Fatalf("report did not retain a frozen state snapshot: %#v", report.Observation)
	}
	if len(report.PhaseTimings) == 0 {
		t.Fatal("report has no machine-readable phase timings")
	}
	if report.Observation.Stats.Hits == 0 || report.Observation.Stats.Misses == 0 ||
		report.ExecCalls != 1 || report.UncachedExecLowerBound <= report.ExecCalls {
		t.Fatalf("snapshot/exec accounting = stats=%#v execs=%d uncached=%d",
			report.Observation.Stats, report.ExecCalls, report.UncachedExecLowerBound)
	}
	var traced bool
	for _, phase := range report.PhaseTimings {
		if phase.Name == "check" && phase.Check == execCheck && phase.Cache.Hits > 0 {
			traced = true
		}
	}
	if !traced || report.SchedulerCriticalPath.Duration == "" {
		t.Fatalf("missing per-check trace or critical path: %#v", report)
	}
}

func TestSnapshotProviderErrorIsInfrastructureError(t *testing.T) {
	const checkName = "test.snapshot_error"
	registerTestCheck(checkName, func(ctx context.Context, env *Env) Result {
		_, err := env.RouterState(ctx, "R", netstate.QueryInterfaces)
		if err == nil {
			return Pass(checkName, Evidence{})
		}
		return Fail(checkName, Evidence{Observed: err.Error()})
	}, nil)

	reader := &countingStateReader{err: errors.New("agent unavailable")}
	report := Run(context.Background(), &Rubric{
		Metadata: RubricMeta{Name: "snapshot-error"},
		Questions: []QuestionSpec{{ID: "q", Title: "q", Points: 1,
			Checks: []CheckSpec{{Check: checkName}}}},
	}, &Env{
		Topology: observationTestTopology(), AS: 3,
		StateReader: reader,
		Exec:        func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{})
	if !report.NeedsReview || len(report.Questions) != 1 ||
		report.Questions[0].Results[0].Status != StatusError {
		t.Fatalf("provider failure became a student verdict: %#v", report)
	}
	if report.Observation == nil || len(report.Observation.Errors) == 0 {
		t.Fatalf("snapshot did not retain provider error: %#v", report.Observation)
	}
	if got := reader.calls.Load(); got != 1 {
		t.Fatalf("failing state query ran %d times, want one cached infrastructure error", got)
	}
}

func TestActiveBGPWitnessesBypassPassiveSnapshot(t *testing.T) {
	for _, name := range []string{"bgp.ibgp_full_mesh", "bgp.ebgp_established"} {
		check, ok := Lookup(name)
		if !ok || !check.LiveObservations {
			t.Fatalf("%s must read live before/after state around its route refresh", name)
		}
	}
}

func TestConflictAwareSchedulerSerializesOnlySharedResources(t *testing.T) {
	var active, maxActive atomic.Int64
	check := &Check{Name: "conflict", Run: func(context.Context, *Env) Result {
		now := active.Add(1)
		for {
			old := maxActive.Load()
			if now <= old || maxActive.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		active.Add(-1)
		return Pass("conflict", Evidence{})
	}, Resources: func(*Env, map[string]any) []ProbeResource {
		return []ProbeResource{{Kind: ProbeCounter, ID: "as3/H"}}
	}}
	jobs := []scheduledCheck{
		{order: 0, check: check, env: &Env{}},
		{order: 1, check: check, env: &Env{}},
	}
	got := scheduleChecks(context.Background(), jobs, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if maxActive.Load() != 1 {
		t.Fatalf("conflicting counter checks overlapped: max=%d", maxActive.Load())
	}
	if got[0].Check != "conflict" || got[1].Check != "conflict" {
		t.Fatalf("scheduler did not retain deterministic result order: %#v", got)
	}

	active.Store(0)
	maxActive.Store(0)
	check.Resources = func(_ *Env, args map[string]any) []ProbeResource {
		return []ProbeResource{{Kind: ProbeCounter, ID: args["id"].(string)}}
	}
	jobs[0].spec.Args = map[string]any{"id": "as3/H1"}
	jobs[1].spec.Args = map[string]any{"id": "as3/H2"}
	_ = scheduleChecks(context.Background(), jobs, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if maxActive.Load() < 2 {
		t.Fatalf("independent counter checks were unnecessarily serialized: max=%d", maxActive.Load())
	}
}

func TestECMPChecksShareTransportResources(t *testing.T) {
	check, ok := Lookup("ospf.ecmp_paths")
	if !ok {
		t.Fatal("ospf.ecmp_paths is not registered")
	}
	env := &Env{Topology: observationTestTopology(), AS: 3}
	resources := resourcesFor(scheduledCheck{check: check, env: env})
	if len(resources) != 2 {
		t.Fatalf("ECMP resources = %#v, want TCP and UDP resources", resources)
	}
	running := map[int][]ProbeResource{0: resources}
	owners, conflicts := blockingResources(resources, running)
	if len(owners) != 1 || owners[0] != 0 || len(conflicts) != len(resources) {
		t.Fatalf("second ECMP check did not conflict: owners=%v conflicts=%v resources=%v",
			owners, conflicts, resources)
	}
}

func TestSchedulerTimeoutStaysAnInfrastructureError(t *testing.T) {
	check := &Check{Name: "timeout", Run: func(ctx context.Context, _ *Env) Result {
		<-ctx.Done()
		return Fail("timeout", Evidence{})
	}}
	got := scheduleChecks(context.Background(), []scheduledCheck{{order: 0, check: check, env: &Env{}}},
		RunOptions{Parallel: 1, CheckTimeout: 10 * time.Millisecond})
	if got[0].Status != StatusError {
		t.Fatalf("timed-out check was not held as infrastructure error: %#v", got[0])
	}
}

func TestSchedulerKeepsEvidenceInRubricOrder(t *testing.T) {
	slow := &Check{Name: "slow", Run: func(context.Context, *Env) Result {
		time.Sleep(15 * time.Millisecond)
		return Pass("slow", Evidence{Detail: "first"})
	}}
	fast := &Check{Name: "fast", Run: func(context.Context, *Env) Result {
		return Pass("fast", Evidence{Detail: "second"})
	}}
	results := scheduleChecks(context.Background(), []scheduledCheck{
		{order: 0, check: slow, env: &Env{}},
		{order: 1, check: fast, env: &Env{}},
	}, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if results[0].Check != "slow" || results[0].Evidence.Detail != "first" ||
		results[1].Check != "fast" || results[1].Evidence.Detail != "second" {
		t.Fatalf("completion order changed deterministic output: %#v", results)
	}
}

func TestIndependentQuestionsRunConcurrentlyInRubricOrder(t *testing.T) {
	const (
		first  = "test.scheduler_first"
		second = "test.scheduler_second"
	)
	var started atomic.Int64
	barrier := make(chan struct{})
	awaitBoth := func(ctx context.Context) bool {
		if started.Add(1) == 2 {
			close(barrier)
		}
		select {
		case <-barrier:
			return true
		case <-ctx.Done():
			return false
		}
	}
	registerTestCheck(first, func(ctx context.Context, _ *Env) Result {
		if !awaitBoth(ctx) {
			return Errored(first, ctx.Err())
		}
		return Pass(first, Evidence{})
	}, nil)
	registerTestCheck(second, func(ctx context.Context, _ *Env) Result {
		if !awaitBoth(ctx) {
			return Errored(second, ctx.Err())
		}
		return Pass(second, Evidence{})
	}, nil)
	report := Run(context.Background(), &Rubric{
		Metadata: RubricMeta{Name: "parallel-questions"},
		Questions: []QuestionSpec{
			{ID: "first", Title: "first", Points: 1, Checks: []CheckSpec{{Check: first}}},
			{ID: "second", Title: "second", Points: 1, Checks: []CheckSpec{{Check: second}}},
		},
	}, &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if report.Total != 2 || len(report.Questions) != 2 ||
		report.Questions[0].ID != "first" || report.Questions[1].ID != "second" {
		t.Fatalf("independent question run changed deterministic report order: %#v", report)
	}
}

func TestDependentQuestionsExecuteSpeculativelyButScoreInOrder(t *testing.T) {
	const (
		first  = "test.scheduler_dependency_first"
		second = "test.scheduler_dependency_second"
	)
	var started atomic.Int64
	barrier := make(chan struct{})
	waitBoth := func(ctx context.Context) Result {
		if started.Add(1) == 2 {
			close(barrier)
		}
		select {
		case <-barrier:
			return Pass("unused", Evidence{})
		case <-ctx.Done():
			return Errored("unused", ctx.Err())
		}
	}
	registerTestCheck(first, func(ctx context.Context, _ *Env) Result {
		result := waitBoth(ctx)
		result.Check = first
		return result
	}, nil)
	registerTestCheck(second, func(ctx context.Context, _ *Env) Result {
		result := waitBoth(ctx)
		result.Check = second
		return result
	}, nil)
	report := Run(context.Background(), &Rubric{
		Metadata: RubricMeta{Name: "speculative-dependencies"},
		Questions: []QuestionSpec{
			{ID: "first", Title: "first", Points: 1, Checks: []CheckSpec{{Check: first}}},
			{ID: "second", Title: "second", Points: 1, DependsOn: []string{"first"},
				Checks: []CheckSpec{{Check: second}}},
		},
	}, &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if report.Total != 2 || report.Questions[0].ID != "first" || report.Questions[1].ID != "second" {
		t.Fatalf("dependency execution changed deterministic scoring: %#v", report)
	}
}

func TestLiveRunDoesNotSpendConvergenceBudgetBeforeSnapshot(t *testing.T) {
	const checkName = "test.snapshot_without_wait"
	registerTestCheck(checkName, func(context.Context, *Env) Result {
		return Pass(checkName, Evidence{})
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	report := Run(ctx, &Rubric{
		Metadata: RubricMeta{Name: "no-global-convergence-wait"},
		Questions: []QuestionSpec{{ID: "q", Title: "q", Points: 1, Converge: true,
			ConvergeScope: "ospf", Checks: []CheckSpec{{Check: checkName}}}},
	}, &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{ConvergeTimeout: time.Minute})
	if report.Err != "" || report.Total != 1 {
		t.Fatalf("healthy live snapshot was delayed behind convergence: %#v", report)
	}
}
