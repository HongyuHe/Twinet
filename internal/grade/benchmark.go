package grade

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ScoreClass is the stable qualitative outcome expected from a deterministic
// benchmark submission. It catches a regression where totals happen to match
// while a different rubric check changed class.
type ScoreClass string

const (
	ScoreClassFull    ScoreClass = "full"
	ScoreClassPartial ScoreClass = "partial"
	ScoreClassZero    ScoreClass = "zero"
	ScoreClassReview  ScoreClass = "review"
)

// BenchmarkCase identifies one deterministic synthetic mutation. Grade must
// create an isolated grade; this package deliberately does not make a shared
// class lab look like a benchmark harness.
type BenchmarkCase struct {
	Submission string
	Expected   ScoreClass
	Grade      func(context.Context) *Report
}

// BenchmarkCaseResult is one machine-readable outcome.
type BenchmarkCaseResult struct {
	Submission string     `json:"submission"`
	Expected   ScoreClass `json:"expected"`
	Observed   ScoreClass `json:"observed"`
	Duration   string     `json:"duration"`
	Error      string     `json:"error,omitempty"`
}

// BenchmarkReport is suitable for a release artifact. Its duration measures
// the supplied isolated grade path, not controller startup or unrelated setup.
type BenchmarkReport struct {
	StartedAt time.Time             `json:"started_at"`
	EndedAt   time.Time             `json:"ended_at"`
	Duration  string                `json:"duration"`
	Workers   int                   `json:"workers"`
	Cases     []BenchmarkCaseResult `json:"cases"`
	Passed    bool                  `json:"passed"`
}

// RunDeterministicBenchmark grades cases at a bounded width and returns
// results in submission order. It never cancels remaining submissions after a
// failed mutation: a release report needs every unexpected score class.
func RunDeterministicBenchmark(ctx context.Context, workers int, cases []BenchmarkCase) BenchmarkReport {
	if workers < 1 {
		workers = 1
	}
	start := time.Now().UTC()
	report := BenchmarkReport{StartedAt: start, Workers: workers, Passed: true,
		Cases: make([]BenchmarkCaseResult, len(cases))}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for index, fixture := range cases {
		index, fixture := index, fixture
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				report.Cases[index] = BenchmarkCaseResult{
					Submission: fixture.Submission, Expected: fixture.Expected,
					Observed: ScoreClassReview, Error: ctx.Err().Error(),
				}
				return
			}
			defer func() { <-sem }()
			caseStart := time.Now()
			result := BenchmarkCaseResult{Submission: fixture.Submission, Expected: fixture.Expected}
			if fixture.Grade == nil {
				result.Observed, result.Error = ScoreClassReview, "benchmark case has no grade function"
			} else if grade := fixture.Grade(ctx); grade == nil {
				result.Observed, result.Error = ScoreClassReview, "grade function returned no report"
			} else {
				result.Observed = scoreClass(grade)
				if grade.Err != "" {
					result.Error = grade.Err
				}
			}
			result.Duration = time.Since(caseStart).Round(time.Millisecond).String()
			report.Cases[index] = result
		}()
	}
	wg.Wait()
	for _, result := range report.Cases {
		if result.Expected != result.Observed || result.Error != "" {
			report.Passed = false
		}
	}
	report.EndedAt = time.Now().UTC()
	report.Duration = report.EndedAt.Sub(start).Round(time.Millisecond).String()
	return report
}

func scoreClass(report *Report) ScoreClass {
	if report == nil || report.Err != "" || report.NeedsReview {
		return ScoreClassReview
	}
	switch {
	case report.MaxTotal <= 0 || report.Total <= 0:
		return ScoreClassZero
	case report.Total+0.000001 >= report.MaxTotal:
		return ScoreClassFull
	default:
		return ScoreClassPartial
	}
}

// BenchmarkFailure returns deterministic, concise evidence suitable for a
// release gate's error message.
func BenchmarkFailure(report BenchmarkReport) error {
	if report.Passed {
		return nil
	}
	var bad []string
	for _, result := range report.Cases {
		if result.Expected == result.Observed && result.Error == "" {
			continue
		}
		line := fmt.Sprintf("%s expected %s, observed %s", result.Submission, result.Expected, result.Observed)
		if result.Error != "" {
			line += ": " + result.Error
		}
		bad = append(bad, line)
	}
	sort.Strings(bad)
	return fmt.Errorf("deterministic grading benchmark failed:\n  %s", joinBenchmarkLines(bad))
}

func joinBenchmarkLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	out := lines[0]
	for _, line := range lines[1:] {
		out += "\n  " + line
	}
	return out
}
