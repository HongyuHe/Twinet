package grade

import (
	"context"
	"fmt"
	"testing"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestDeterministicSyntheticReleaseBenchmark100Submissions(t *testing.T) {
	const checkName = "test.release_benchmark_score"
	registerTestCheck(checkName, func(_ context.Context, env *Env) Result {
		return Partial(checkName, float64(env.ArgInt("score", 10))/10, Evidence{})
	}, nil)
	cases := make([]BenchmarkCase, 0, 100)
	for index := 0; index < 100; index++ {
		index := index
		expected := ScoreClassFull
		total := 10.0
		switch index % 10 {
		case 3, 7:
			expected, total = ScoreClassPartial, 6
		case 9:
			expected, total = ScoreClassZero, 0
		}
		score := int(total)
		cases = append(cases, BenchmarkCase{
			Submission: fmt.Sprintf("mutation-%03d", index), Expected: expected,
			Grade: func(ctx context.Context) *Report {
				return Run(ctx, &Rubric{
					Metadata: RubricMeta{Name: "release-benchmark"},
					Questions: []QuestionSpec{{ID: "q", Title: "q", Points: 10,
						Checks: []CheckSpec{{Check: checkName, Args: map[string]any{"score": score}}}}},
				}, &Env{
					Topology: observationTestTopology(), AS: 3, StateReader: &countingStateReader{},
					Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
						return rt.ExecResult{}, nil
					},
				}, RunOptions{Parallel: 2})
			},
		})
	}
	start := time.Now()
	report := RunDeterministicBenchmark(context.Background(), 24, cases)
	if err := BenchmarkFailure(report); err != nil {
		t.Fatal(err)
	}
	if len(report.Cases) != 100 {
		t.Fatalf("benchmark returned %d cases, want 100", len(report.Cases))
	}
	if elapsed := time.Since(start); elapsed >= 15*time.Minute {
		t.Fatalf("synthetic benchmark took %s, exceeds 15-minute release target", elapsed)
	}
	t.Logf("100 deterministic synthetic submissions in %s with %d workers", report.Duration, report.Workers)
}

func TestBenchmarkReportsUnexpectedScoreClass(t *testing.T) {
	report := RunDeterministicBenchmark(context.Background(), 1, []BenchmarkCase{{
		Submission: "wrong", Expected: ScoreClassFull,
		Grade: func(context.Context) *Report { return &Report{Total: 0, MaxTotal: 1} },
	}})
	if report.Passed {
		t.Fatalf("unexpected score class passed: %#v", report)
	}
	if err := BenchmarkFailure(report); err == nil {
		t.Fatal("unexpected score class did not produce a release-gate error")
	}
}
