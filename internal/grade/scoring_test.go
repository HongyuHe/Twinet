package grade

import (
	"math"
	"testing"
	"time"
)

// Everything here decides a mark. A bug in this arithmetic does not crash and
// does not look wrong: it produces a number, and the number is believed.

func TestAQuestionIsScoredByWeightNotByCount(t *testing.T) {
	// Two checks, one worth three times the other. A student who passes only
	// the heavy one must score three quarters, not a half.
	q := QuestionSpec{
		ID: "q1", Points: 4,
		Checks: []CheckSpec{{Check: "a", Weight: 3}, {Check: "b", Weight: 1}},
	}
	results := []Result{
		{Check: "a", Status: StatusPass, Score: 1},
		{Check: "b", Status: StatusFail, Score: 0},
	}
	got := awardFor(q, results)
	if math.Abs(got-3.0) > 1e-9 {
		t.Errorf("awarded %.3f of 4, want 3.000", got)
	}
}

// A check that could not run is excluded from the weighting rather than scored
// zero. Scoring it zero turns the grader's outage into the student's mark.
func TestABrokenCheckIsExcludedRatherThanFailed(t *testing.T) {
	q := QuestionSpec{
		ID: "q1", Points: 2,
		Checks: []CheckSpec{{Check: "a", Weight: 1}, {Check: "b", Weight: 1}},
	}
	results := []Result{
		{Check: "a", Status: StatusPass, Score: 1},
		{Check: "b", Status: StatusError, Score: 0},
	}
	// One check passed, one could not run: full marks for what was assessed.
	if got := awardFor(q, results); math.Abs(got-2.0) > 1e-9 {
		t.Errorf("awarded %.3f of 2, want 2.000; a grader outage was charged to the student", got)
	}
}

// A property that cannot arise in this AS is neither a pass nor a zero.
//
// A stub with no customers cannot withhold transit from one. Marking that a
// pass awards a mark for something nobody established; marking it a failure
// charges a student for a topology they were given; and marking it an error
// summons a human to look at a network that is fine.
func TestAnInapplicableCheckIsSetAsideNotScored(t *testing.T) {
	q := QuestionSpec{
		ID: "q1", Points: 2,
		Checks: []CheckSpec{{Check: "a", Weight: 1}, {Check: "b", Weight: 1}},
	}
	results := []Result{
		{Check: "a", Status: StatusPass, Score: 1},
		NotApplicable("b", "this AS has no customers"),
	}
	if got := awardFor(q, results); math.Abs(got-2.0) > 1e-9 {
		t.Errorf("awarded %.3f of 2, want 2.000; a question that could not be asked was "+
			"charged to the student", got)
	}
	// And it must not be mistaken for a pass by anything reading the report.
	if results[1].Passed() {
		t.Error("a check that was never run reports itself as passed")
	}
	if results[1].Score != 0 {
		t.Errorf("an inapplicable check carries a score of %.2f", results[1].Score)
	}
}

func TestPartialCreditIsCarriedThrough(t *testing.T) {
	q := QuestionSpec{ID: "q1", Points: 10, Checks: []CheckSpec{{Check: "a", Weight: 1}}}
	results := []Result{{Check: "a", Status: StatusPartial, Score: 0.5}}
	if got := awardFor(q, results); math.Abs(got-5.0) > 1e-9 {
		t.Errorf("awarded %.3f of 10 for half credit, want 5.000", got)
	}
}

// The rubric's own total is what every report is measured against and what a
// gradebook column is scaled to.
func TestRubricTotalIsTheSumOfItsQuestions(t *testing.T) {
	r := &Rubric{Questions: []QuestionSpec{
		{ID: "a", Points: 1.5}, {ID: "b", Points: 2}, {ID: "c", Points: 0.5},
	}}
	if got := r.MaxTotal(); math.Abs(got-4.0) > 1e-9 {
		t.Errorf("MaxTotal is %.3f, want 4.000", got)
	}
}

func TestStatusReflectsTheFraction(t *testing.T) {
	cases := []struct {
		frac float64
		want Status
	}{
		{1, StatusPass},
		{0, StatusFail},
		{0.5, StatusPartial},
	}
	for _, c := range cases {
		if got := statusFor(c.frac); got != c.want {
			t.Errorf("statusFor(%v) = %s, want %s", c.frac, got, c.want)
		}
	}
}

// The class statistics are read by a human deciding whether an assignment was
// too hard. A quarantined submission's zero measures the platform, not the
// class, and must not be in them.
func TestClassStatisticsExcludeWhatCouldNotBeGraded(t *testing.T) {
	s := Summarise("r", []*Report{
		{Submission: "a", Total: 10, MaxTotal: 10},
		{Submission: "b", Total: 6, MaxTotal: 10},
		{Submission: "c", Total: 0, MaxTotal: 10, NeedsReview: true, Err: "node unreachable"},
	}, time.Second)

	if s.Graded != 2 {
		t.Errorf("statistics were computed from %d submissions, want 2", s.Graded)
	}
	if math.Abs(s.Mean-8.0) > 1e-9 {
		t.Errorf("mean is %.3f, want 8.000; a platform failure moved the class average", s.Mean)
	}
	if s.Min != 6 {
		t.Errorf("min is %.1f, want 6; a quarantined zero became the minimum", s.Min)
	}
	if s.Note == "" {
		t.Error("nothing records that a submission was excluded")
	}
	// The excluded report is still present: it is the thing someone must act on.
	if len(s.Reports) != 3 {
		t.Errorf("the summary holds %d reports, want 3", len(s.Reports))
	}
}

func TestAClassWhereNothingCouldBeGradedReportsNoDistribution(t *testing.T) {
	s := Summarise("r", []*Report{
		{Submission: "a", MaxTotal: 10, NeedsReview: true, Err: "boom"},
	}, time.Second)
	if s.Graded != 0 {
		t.Errorf("Graded is %d, want 0", s.Graded)
	}
	if s.Mean != 0 || s.Max != 0 {
		t.Errorf("a distribution was invented from no data: mean %.2f max %.2f", s.Mean, s.Max)
	}
	if len(s.Quarantined()) != 1 {
		t.Error("the failed submission is not quarantined")
	}
}
