package grade

import (
	"context"
	"testing"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestReportIncludesExactResourceWaitAndCriticalPath(t *testing.T) {
	const checkName = "test.scheduler_trace_lock"
	registerTestCheck(checkName, func(context.Context, *Env) Result {
		time.Sleep(15 * time.Millisecond)
		return Pass(checkName, Evidence{})
	}, func(*Env, map[string]any) []ProbeResource {
		return []ProbeResource{{Kind: ProbeCounter, ID: "as3/H/tcp"}}
	})
	report := Run(context.Background(), &Rubric{
		Metadata: RubricMeta{Name: "scheduler-trace"},
		Questions: []QuestionSpec{
			{ID: "one", Title: "one", Points: 1, Checks: []CheckSpec{{Check: checkName}}},
			{ID: "two", Title: "two", Points: 1, Checks: []CheckSpec{{Check: checkName}}},
		},
	}, &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{Parallel: 2, CheckTimeout: time.Second})
	if report.SchedulerCriticalPath.Duration == "" || len(report.SchedulerCriticalPath.Checks) < 2 {
		t.Fatalf("critical path is missing serialized checks: %#v", report.SchedulerCriticalPath)
	}
	var waited, criticalPhase bool
	for _, phase := range report.PhaseTimings {
		if phase.Name == "check_wait" && phase.WaitReason != "" &&
			len(phase.Resources) == 1 && phase.Resources[0] == "counter/as3/H/tcp" {
			waited = true
		}
		if phase.Name == "scheduler_critical_path" && phase.Duration == report.SchedulerCriticalPath.Duration {
			criticalPhase = true
		}
	}
	if !waited || !criticalPhase {
		t.Fatalf("report did not name the exact resource wait: %#v", report.PhaseTimings)
	}
}

func TestSpeculativeDependentFailureStillRendersSkipped(t *testing.T) {
	const (
		first  = "test.speculative_failure_first"
		second = "test.speculative_failure_second"
	)
	registerTestCheck(first, func(context.Context, *Env) Result {
		return Fail(first, Evidence{})
	}, nil)
	registerTestCheck(second, func(context.Context, *Env) Result {
		return Pass(second, Evidence{})
	}, nil)
	report := Run(context.Background(), &Rubric{
		Metadata: RubricMeta{Name: "speculative-skip"},
		Questions: []QuestionSpec{
			{ID: "first", Title: "first", Points: 1, Checks: []CheckSpec{{Check: first}}},
			{ID: "second", Title: "second", Points: 1, DependsOn: []string{"first"},
				Checks: []CheckSpec{{Check: second}}},
		},
	}, &Env{
		Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) { return rt.ExecResult{}, nil },
	}, RunOptions{Parallel: 2})
	if report.Questions[1].Status != StatusSkipped || len(report.Questions[1].Results) != 0 {
		t.Fatalf("dependent check leaked speculative evidence into report: %#v", report.Questions[1])
	}
}
