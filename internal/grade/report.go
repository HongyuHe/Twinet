// Package grade implements Twinet's autograding engine.
//
// The design point that matters most: grading operates on a *submission* in an
// isolated, ephemeral lab, not on the live class network.
//
// Both generations of the platform this replaces graded in place. The first
// disconnected a student's AS from the running mini-Internet with ovs-vsctl,
// spliced in a test container, and reconnected afterwards. The second built a
// shadow AS beside the live network, one student at a time, in a plain for
// loop, with a twenty-second sleep invoked more than eight times per AS. Both
// were destructive, neither was reproducible, and the second lost the coarse
// parallelism the first had. A full class took hours and could not be replayed
// for an appeal.
//
// Here a submission is graded in its own lab, so grading is embarrassingly
// parallel, never perturbs the class, and is a pure function of (submission,
// class manifest, rubric). Waiting is done with convergence predicates rather
// than the clock, which is where most of the remaining time goes.
package grade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is the outcome of a check or a question.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusPartial Status = "partial"
	// StatusSkipped means a prerequisite failed, so running this would only
	// produce a cascade of derived failures that tell the student nothing.
	StatusSkipped Status = "skipped"
	// StatusError means the check itself could not run, which is the grader's
	// problem and not the student's. It never silently costs marks.
	StatusError Status = "error"
)

// Evidence is machine-readable proof of what was observed.
//
// Feedback that says "expected three equal-cost paths, observed two, missing
// ATL-PHY-NYC-BOS" teaches something. "FAIL" does not. Every check is therefore
// required to return what it saw, not merely whether it liked it.
type Evidence struct {
	Observed any    `json:"observed,omitempty"`
	Expected any    `json:"expected,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Hint     string `json:"hint,omitempty"`
	// Command records how the observation was made, so a disputed result can
	// be reproduced by hand.
	Command string `json:"command,omitempty"`
}

// Result is the outcome of one check.
type Result struct {
	Check    string   `json:"check"`
	Status   Status   `json:"status"`
	Score    float64  `json:"score"` // 0..1, scaled by the check's weight
	Evidence Evidence `json:"evidence,omitempty"`
	Err      string   `json:"error,omitempty"`
	Duration string   `json:"duration,omitempty"`
}

// Passed reports whether the result earned full marks.
func (r Result) Passed() bool { return r.Status == StatusPass }

// Pass builds a passing result.
func Pass(check string, ev Evidence) Result {
	return Result{Check: check, Status: StatusPass, Score: 1, Evidence: ev}
}

// Fail builds a failing result.
func Fail(check string, ev Evidence) Result {
	return Result{Check: check, Status: StatusFail, Score: 0, Evidence: ev}
}

// Partial builds a partially correct result.
func Partial(check string, score float64, ev Evidence) Result {
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	st := StatusPartial
	if score == 0 {
		st = StatusFail
	} else if score == 1 {
		st = StatusPass
	}
	return Result{Check: check, Status: st, Score: score, Evidence: ev}
}

// Errored builds a result recording that the check could not run.
func Errored(check string, err error) Result {
	return Result{Check: check, Status: StatusError, Score: 0, Err: err.Error()}
}

// QuestionResult aggregates the checks belonging to one assignment question.
type QuestionResult struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Points  float64  `json:"points"`
	Awarded float64  `json:"awarded"`
	Status  Status   `json:"status"`
	Results []Result `json:"results"`
	Skipped string   `json:"skipped_because,omitempty"`
}

// Report is one student's complete result.
type Report struct {
	Submission string           `json:"submission"`
	AS         int              `json:"as"`
	Lab        string           `json:"lab"`
	Rubric     string           `json:"rubric"`
	Manifest   string           `json:"manifest_hash"`
	GradedAt   time.Time        `json:"graded_at"`
	Duration   string           `json:"duration"`
	Total      float64          `json:"total"`
	MaxTotal   float64          `json:"max_total"`
	Questions  []QuestionResult `json:"questions"`
	Warnings   []string         `json:"warnings,omitempty"`
	Err        string           `json:"error,omitempty"`
}

// Percent returns the score as a percentage.
func (r *Report) Percent() float64 {
	if r.MaxTotal == 0 {
		return 0
	}
	return 100 * r.Total / r.MaxTotal
}

// JSON renders the report.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Text renders the report for a human.
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (AS %d)\n", r.Submission, r.AS)
	fmt.Fprintf(&b, "%s  %.2f / %.2f (%.0f%%)\n\n", strings.Repeat("=", 60),
		r.Total, r.MaxTotal, r.Percent())
	if r.Err != "" {
		fmt.Fprintf(&b, "grading failed: %s\n", r.Err)
		return b.String()
	}
	for _, q := range r.Questions {
		mark := "x"
		switch q.Status {
		case StatusPass:
			mark = "ok"
		case StatusPartial:
			mark = "~"
		case StatusSkipped:
			mark = "-"
		}
		fmt.Fprintf(&b, "[%-2s] %-8s %-42s %.2f / %.2f\n", mark, q.ID, q.Title, q.Awarded, q.Points)
		if q.Skipped != "" {
			fmt.Fprintf(&b, "        skipped: %s\n", q.Skipped)
		}
		for _, res := range q.Results {
			if res.Passed() {
				continue
			}
			fmt.Fprintf(&b, "        %s: %s\n", res.Check, describe(res))
			if res.Evidence.Detail != "" {
				for _, line := range strings.Split(res.Evidence.Detail, "\n") {
					fmt.Fprintf(&b, "          %s\n", line)
				}
			}
			if res.Evidence.Hint != "" {
				fmt.Fprintf(&b, "          hint: %s\n", res.Evidence.Hint)
			}
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nwarning: %s\n", w)
	}
	return b.String()
}

func describe(r Result) string {
	if r.Err != "" {
		return "could not run: " + r.Err
	}
	if r.Evidence.Expected != nil || r.Evidence.Observed != nil {
		return fmt.Sprintf("expected %v, observed %v", r.Evidence.Expected, r.Evidence.Observed)
	}
	return string(r.Status)
}

// Summary aggregates a whole class, which is what a course staff actually needs
// after a run: not a directory of text files, but a distribution and a list of
// the checks most students failed, so the next lecture can address them.
type Summary struct {
	Rubric    string         `json:"rubric"`
	GradedAt  time.Time      `json:"graded_at"`
	Count     int            `json:"count"`
	Mean      float64        `json:"mean"`
	Median    float64        `json:"median"`
	Min       float64        `json:"min"`
	Max       float64        `json:"max"`
	MaxTotal  float64        `json:"max_total"`
	Duration  string         `json:"duration"`
	Reports   []*Report      `json:"reports"`
	FailCount map[string]int `json:"failures_by_check"`
}

// Summarise builds a class summary.
func Summarise(rubric string, reports []*Report, dur time.Duration) *Summary {
	s := &Summary{
		Rubric: rubric, GradedAt: time.Now().UTC(), Count: len(reports),
		Duration:  dur.Round(time.Millisecond).String(),
		FailCount: map[string]int{},
	}
	if len(reports) == 0 {
		return s
	}
	scores := make([]float64, 0, len(reports))
	for _, r := range reports {
		scores = append(scores, r.Total)
		s.MaxTotal = maxF(s.MaxTotal, r.MaxTotal)
		for _, q := range r.Questions {
			for _, res := range q.Results {
				if res.Status == StatusFail || res.Status == StatusPartial {
					s.FailCount[res.Check]++
				}
			}
		}
	}
	sort.Float64s(scores)
	s.Min, s.Max = scores[0], scores[len(scores)-1]
	var sum float64
	for _, v := range scores {
		sum += v
	}
	s.Mean = sum / float64(len(scores))
	s.Median = scores[len(scores)/2]
	if len(scores)%2 == 0 {
		s.Median = (scores[len(scores)/2-1] + scores[len(scores)/2]) / 2
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Submission < reports[j].Submission })
	s.Reports = reports
	return s
}

// CSV renders one row per student, one column per question, ready for a
// gradebook import.
func (s *Summary) CSV() string {
	var b strings.Builder
	var qids []string
	if len(s.Reports) > 0 {
		for _, q := range s.Reports[0].Questions {
			qids = append(qids, q.ID)
		}
	}
	b.WriteString("submission,as,total,max")
	for _, q := range qids {
		b.WriteString("," + q)
	}
	b.WriteString("\n")
	for _, r := range s.Reports {
		fmt.Fprintf(&b, "%s,%d,%.2f,%.2f", r.Submission, r.AS, r.Total, r.MaxTotal)
		byID := map[string]float64{}
		for _, q := range r.Questions {
			byID[q.ID] = q.Awarded
		}
		for _, id := range qids {
			fmt.Fprintf(&b, ",%.2f", byID[id])
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Text renders the class summary.
func (s *Summary) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "graded %d submission(s) against %s in %s\n", s.Count, s.Rubric, s.Duration)
	fmt.Fprintf(&b, "  mean %.2f  median %.2f  min %.2f  max %.2f  (out of %.2f)\n\n",
		s.Mean, s.Median, s.Min, s.Max, s.MaxTotal)
	if len(s.FailCount) > 0 {
		type kv struct {
			k string
			v int
		}
		var fails []kv
		for k, v := range s.FailCount {
			fails = append(fails, kv{k, v})
		}
		sort.Slice(fails, func(i, j int) bool {
			if fails[i].v != fails[j].v {
				return fails[i].v > fails[j].v
			}
			return fails[i].k < fails[j].k
		})
		b.WriteString("most-missed checks:\n")
		for i, f := range fails {
			if i >= 10 {
				break
			}
			fmt.Fprintf(&b, "  %-40s %d of %d\n", f.k, f.v, s.Count)
		}
	}
	return b.String()
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ctxErr converts a cancelled context into a clear message.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("grading was cancelled: %w", err)
	}
	return nil
}
