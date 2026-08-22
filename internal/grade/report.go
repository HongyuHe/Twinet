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
	// StatusNotApplicable means the question this check asks cannot arise in
	// this AS: a stub with no customers cannot withhold transit from one.
	//
	// It is distinct from StatusError, which is the grader failing and calls
	// for a human, and from StatusPass, which would be a mark awarded for a
	// property nobody established. The check is left out of the weighting, so
	// the question's marks rest on the checks that could be asked.
	StatusNotApplicable Status = "not_applicable"
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
	switch score {
	case 0:
		st = StatusFail
	case 1:
		st = StatusPass
	}
	return Result{Check: check, Status: st, Score: score, Evidence: ev}
}

// Errored builds a result recording that the check could not run.
func Errored(check string, err error) Result {
	return Result{Check: check, Status: StatusError, Score: 0, Err: err.Error()}
}

// NotApplicable builds a result recording that the property this check is about
// cannot arise here, so no verdict about it is possible or needed.
//
// The reason is carried as evidence rather than as an error, because it is a
// fact about the topology and not a malfunction: a student reading their report
// should see why the check was set aside, and a marker should not be summoned.
func NotApplicable(check, why string) Result {
	return Result{Check: check, Status: StatusNotApplicable, Score: 0,
		Evidence: Evidence{Observed: why}}
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
	// NeedsReview marks a question whose mark is not trustworthy because the
	// grader, not the student, fell short.
	NeedsReview bool   `json:"needs_review,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Report is one student's complete result.
type Report struct {
	Submission string `json:"submission"`
	AS         int    `json:"as"`
	Lab        string `json:"lab"`
	// Course and Term identify the class a mark belongs to.
	//
	// The manifest has carried them since the first version and nothing read
	// them, so two runs of the same lab in successive terms produced reports
	// that were indistinguishable -- which matters exactly when a mark is
	// disputed a year later.
	Course string `json:"course,omitempty"`
	// RubricNotes is what the rubric says about how it splits the marks.
	//
	// Every bundled rubric writes several sentences explaining why a question
	// is worth what it is worth -- why isolation is worth nothing on its own,
	// why the absence of BGP in the core is the larger share -- and the field
	// was read by nothing, so none of it ever reached the person being marked.
	// A student disputing a grade is entitled to the reasoning.
	RubricNotes string           `json:"rubric_notes,omitempty"`
	Term        string           `json:"term,omitempty"`
	Rubric      string           `json:"rubric"`
	Manifest    string           `json:"manifest_hash"`
	GradedAt    time.Time        `json:"graded_at"`
	Duration    string           `json:"duration"`
	Total       float64          `json:"total"`
	MaxTotal    float64          `json:"max_total"`
	Questions   []QuestionResult `json:"questions"`
	Warnings    []string         `json:"warnings,omitempty"`
	Err         string           `json:"error,omitempty"`
	// NeedsReview marks a report that must not be released without a human
	// looking at it, because some part of the grading did not run correctly.
	NeedsReview bool `json:"needs_review,omitempty"`
	// Images records the exact image digests the lab ran on.
	//
	// A mark is only defensible if it can be reproduced, and an image tag does
	// not identify software: the same tag rebuilt months later can move FRR by
	// a minor version, change a JSON field a check parses, and regrade a class
	// differently with the manifest and the rubric unchanged. The digest is
	// what makes a regrade comparable, and a dispute answerable.
	Images map[string]string `json:"images,omitempty"`
	// ImageLock is the content hash of the checked lock document that bound
	// this run to immutable image manifests.
	ImageLock string `json:"image_lock,omitempty"`
	// Controller is the build of the grader that produced this report.
	Controller string `json:"controller,omitempty"`
	// Agents retains exact source builds for every node that participated.
	// These are audit provenance; contract compatibility, not source equality,
	// determines whether a rolling upgrade is safe.
	Agents map[string]string `json:"agents,omitempty"`
	// Observation is the one passive, immutable observation set shared by
	// this grade. Active delivery witnesses are intentionally represented in
	// check evidence instead: a cached counter/capture is not a witness.
	Observation *ObservationSnapshot `json:"observation_snapshot,omitempty"`
	// PhaseTimings is machine-readable timing evidence for capacity planning
	// and benchmark regression detection. It is ordered by phase start/name,
	// not by goroutine completion order.
	PhaseTimings []PhaseTiming `json:"phase_timings,omitempty"`
}

// PhaseTiming records a bounded phase of one grade.
type PhaseTiming struct {
	Name       string    `json:"name"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   string    `json:"duration"`
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
	// A report that was never completed carries no score line.
	//
	// It used to print "0.00 / 10.00 (0%)" across the top, which is what a
	// student who did nothing looks like -- and this is the artifact a student
	// is handed. A corrupt upload, a harness that failed to deploy and an
	// empty submission were typographically identical. The CSV had already
	// been taught to leave the total empty for exactly this reason; the human
	// -readable version had not, and it is the one anybody actually reads.
	if r.Err != "" {
		fmt.Fprintf(&b, "%s  not graded\n\n", strings.Repeat("=", 60))
		fmt.Fprintf(&b, "grading failed: %s\n", r.Err)
		fmt.Fprintf(&b, "\nNo mark has been given. This is not a score of zero: "+
			"nothing about the work was assessed.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%s  %.2f / %.2f (%.0f%%)\n\n", strings.Repeat("=", 60),
		r.Total, r.MaxTotal, r.Percent())
	if r.NeedsReview {
		b.WriteString("NEEDS REVIEW: part of this run did not complete correctly; " +
			"the marks below are provisional.\n\n")
	}
	if n := strings.TrimSpace(r.RubricNotes); n != "" {
		b.WriteString("How these marks are split\n")
		for _, line := range strings.Split(n, "\n") {
			fmt.Fprintf(&b, "  %s\n", strings.TrimSpace(line))
		}
		b.WriteString("\n")
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
		case StatusError:
			mark = "!"
		}
		fmt.Fprintf(&b, "[%-2s] %-8s %-42s %.2f / %.2f\n", mark, q.ID, q.Title, q.Awarded, q.Points)
		if q.Skipped != "" {
			fmt.Fprintf(&b, "        skipped: %s\n", q.Skipped)
		}
		if q.Note != "" {
			fmt.Fprintf(&b, "        %s\n", q.Note)
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
	// Graded is how many submissions the statistics are computed from, which
	// is fewer than Count whenever something could not be graded.
	Graded int    `json:"graded"`
	Note   string `json:"note,omitempty"`
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
	defer func() {
		if n := len(s.Quarantined()); n > 0 {
			s.Note = fmt.Sprintf("%d submission(s) are excluded from these statistics because "+
				"they could not be graded", n)
		}
	}()
	scores := make([]float64, 0, len(reports))
	for _, r := range reports {
		if r == nil {
			continue
		}
		s.MaxTotal = maxF(s.MaxTotal, r.MaxTotal)
		// A report that could not be graded contributes no score. Including its
		// zero would drag the class mean down by an amount that measures the
		// platform's reliability rather than anything a student did, and the
		// number would look exactly like a real one.
		if r.NeedsReview || r.Err != "" {
			continue
		}
		scores = append(scores, r.Total)
		for _, q := range r.Questions {
			for _, res := range q.Results {
				if res.Status == StatusFail || res.Status == StatusPartial {
					s.FailCount[res.Check]++
				}
			}
		}
	}
	sort.Float64s(scores)
	s.Graded = len(scores)
	if len(scores) == 0 {
		// Every submission was quarantined. There is no distribution to report,
		// and inventing zeros would describe the platform rather than the class.
		// The reports themselves are still attached: they are the whole point.
		sort.Slice(reports, func(i, j int) bool { return reports[i].Submission < reports[j].Submission })
		s.Reports = reports
		return s
	}
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

// Quarantined returns the reports that must not be released as marks.
//
// A report needs review when some part of the grading did not run correctly:
// the harness failed to deploy, an agent was unreachable, a submission could
// not be loaded. Its total is zero, and a zero produced that way is
// indistinguishable, in a spreadsheet, from a student who did nothing. Keeping
// them identifiable is the difference between a grading run and a liability.
func (s *Summary) Quarantined() []*Report {
	var out []*Report
	for _, r := range s.Reports {
		if r != nil && (r.NeedsReview || r.Err != "") {
			out = append(out, r)
		}
	}
	return out
}

// CSV renders one row per student, one column per question, ready for a
// gradebook import.
//
// Every row carries a status, and a report that needs review carries no total
// at all rather than a zero. A grader who imports this file cannot silently
// award a zero that the platform, not the student, is responsible for.
func (s *Summary) CSV() string {
	var b strings.Builder
	// Columns are the union of every question seen, not the questions of
	// whichever report happens to be first. If the first submission failed to
	// deploy it has no questions at all, and every other student's marks would
	// silently collapse into no columns.
	var qids []string
	seen := map[string]bool{}
	for _, r := range s.Reports {
		if r == nil {
			continue
		}
		for _, q := range r.Questions {
			if !seen[q.ID] {
				seen[q.ID] = true
				qids = append(qids, q.ID)
			}
		}
	}
	b.WriteString("submission,as,status,total,max")
	for _, q := range qids {
		b.WriteString("," + q)
	}
	b.WriteString(",note\n")
	for _, r := range s.Reports {
		if r == nil {
			continue
		}
		if r.NeedsReview || r.Err != "" {
			// No total, no per-question marks: there is nothing here that may
			// be pasted into a gradebook by accident.
			fmt.Fprintf(&b, "%s,%d,needs-review,,%.2f", r.Submission, r.AS, r.MaxTotal)
			for range qids {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, ",%s\n", csvField(firstProblem(r)))
			continue
		}
		fmt.Fprintf(&b, "%s,%d,graded,%.2f,%.2f", r.Submission, r.AS, r.Total, r.MaxTotal)
		byID := map[string]float64{}
		for _, q := range r.Questions {
			byID[q.ID] = q.Awarded
		}
		for _, id := range qids {
			fmt.Fprintf(&b, ",%.2f", byID[id])
		}
		b.WriteString(",\n")
	}
	return b.String()
}

func firstProblem(r *Report) string {
	if r.Err != "" {
		return r.Err
	}
	if len(r.Warnings) > 0 {
		return r.Warnings[0]
	}
	return "grading did not complete correctly"
}

// csvField quotes a field so an error message containing a comma, a quote or a
// newline cannot shift every subsequent column of a gradebook.
func csvField(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if strings.ContainsAny(s, ",\"") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// Text renders the class summary.
func (s *Summary) Text() string {
	var b strings.Builder
	// The distribution is over the submissions that were actually graded, so
	// the count beside it has to be that one. Printing the number of
	// submissions *attempted* described a wider set than the statistics did,
	// and when every one of them was held for review the line read
	// "mean 0.00 median 0.00 min 0.00 max 0.00" -- which is what a class that
	// scored nothing looks like, and was in fact a class nobody had marked.
	held := s.Count - s.Graded
	switch {
	case s.Graded == 0:
		fmt.Fprintf(&b, "graded 0 of %d submission(s) against %s in %s\n",
			s.Count, s.Rubric, s.Duration)
		fmt.Fprintf(&b, "  no marks: every submission needs review, so there is no "+
			"distribution to report (out of %.2f)\n\n", s.MaxTotal)
	case held > 0:
		fmt.Fprintf(&b, "graded %d of %d submission(s) against %s in %s\n",
			s.Graded, s.Count, s.Rubric, s.Duration)
		fmt.Fprintf(&b, "  mean %.2f  median %.2f  min %.2f  max %.2f  (out of %.2f, "+
			"over the %d graded; %d need review)\n\n",
			s.Mean, s.Median, s.Min, s.Max, s.MaxTotal, s.Graded, held)
	default:
		fmt.Fprintf(&b, "graded %d submission(s) against %s in %s\n",
			s.Count, s.Rubric, s.Duration)
		fmt.Fprintf(&b, "  mean %.2f  median %.2f  min %.2f  max %.2f  (out of %.2f)\n\n",
			s.Mean, s.Median, s.Min, s.Max, s.MaxTotal)
	}
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
