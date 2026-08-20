package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/grade"
)

func refReport(total float64, needsReview bool, statuses ...grade.Status) *grade.Report {
	var results []grade.Result
	for i, s := range statuses {
		results = append(results, grade.Result{
			Check:  []string{"policy.transit_for_customers", "bgp.session_up", "rpki.roa_published"}[i%3],
			Status: s,
		})
	}
	return &grade.Report{
		Total:       total,
		NeedsReview: needsReview,
		Questions:   []grade.QuestionResult{{Results: results}},
	}
}

// A stub AS sells transit to nobody, so the check asking whether it withholds
// transit from a customer does not arise. The scorer leaves such a check out of
// the weighting -- which is why the AS scores full marks -- but the gate that
// attests the lab is the reference solution counted any status other than pass
// against it. cos461 has four stub systems, so `grade class` refused to run on
// the reference solution itself, and told the operator to redeploy it (which
// cannot help) or to pass --skip-reference-check, disabling the one gate that
// keeps a class from being marked against a broken internet.
func TestNotApplicableIsNotAFailedReference(t *testing.T) {
	rep := refReport(10, false, grade.StatusNotApplicable, grade.StatusPass, grade.StatusPass)
	if why := referenceComplaint(rep, 10); why != "" {
		t.Errorf("refused a reference solution that scores full marks: %s", why)
	}
}

// The gate still has to fire on everything it was built for.
func TestReferenceComplaintStillCatchesRealProblems(t *testing.T) {
	cases := []struct {
		what string
		rep  *grade.Report
		want string
	}{
		{
			what: "a check that failed while the total still reads full",
			rep:  refReport(10, false, grade.StatusNotApplicable, grade.StatusFail, grade.StatusPass),
			want: "did not pass",
		},
		{
			what: "a check the grader could not run",
			rep:  refReport(10, false, grade.StatusPass, grade.StatusError, grade.StatusPass),
			want: "did not pass",
		},
		{
			what: "marks missing from the reference",
			rep:  refReport(9.7, false, grade.StatusPass, grade.StatusPass, grade.StatusFail),
			want: "scores 9.70 of 10.00",
		},
		{
			what: "a report the grader itself flagged",
			rep:  refReport(10, true, grade.StatusPass, grade.StatusPass, grade.StatusPass),
			want: "flagged for review",
		},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			why := referenceComplaint(c.rep, 10)
			if !strings.Contains(why, c.want) {
				t.Errorf("accepted %s: complaint was %q, want it to mention %q", c.what, why, c.want)
			}
		})
	}
}

// A not-applicable check took no marks away, so naming it among the reasons a
// system scored below full marks points the operator at the one result that
// cannot be the cause.
func TestNotApplicableIsNotBlamedForMissingMarks(t *testing.T) {
	rep := refReport(9.7, false, grade.StatusNotApplicable, grade.StatusPass, grade.StatusFail)
	why := referenceComplaint(rep, 10)
	if strings.Contains(why, "not_applicable") {
		t.Errorf("blamed a check that does not arise for the missing marks: %s", why)
	}
	if !strings.Contains(why, "rpki.roa_published") {
		t.Errorf("did not name the check that actually failed: %s", why)
	}
}

// The complaint about a total is printed with two decimal places, so a
// shortfall smaller than that came out as "scores 10.00 of 10.00" -- a refusal
// whose stated reason denies itself, and which names no check at all. The
// reachability check scores in proportion to the probes that arrived, and one
// lost ping in a hundred and forty-four takes about a thousandth of a mark.
func TestAReferenceIsNeverRefusedForLessThanItPrints(t *testing.T) {
	rep := refReport(10-0.0014, false, grade.StatusPass, grade.StatusPass, grade.StatusPass)
	why := referenceComplaint(rep, 10)
	if strings.Contains(why, "scores 10.00 of 10.00") {
		t.Fatalf("the reason a lab was refused contradicts itself: %s", why)
	}
	if why != "" {
		t.Fatalf("every check passed and the shortfall does not survive printing: %s", why)
	}
}

// But a shortfall that does survive printing is still a complaint, and the
// smallest such must be caught rather than rounded away.
func TestAShortfallThatPrintsIsStillRefused(t *testing.T) {
	rep := refReport(9.99, false, grade.StatusPass, grade.StatusPass, grade.StatusPartial)
	why := referenceComplaint(rep, 10)
	if !strings.Contains(why, "scores 9.99 of 10.00") {
		t.Fatalf("a shortfall the operator can see must be reported: %q", why)
	}
}

// And a check that did not pass is named even when the marks it cost round
// away, so tolerating the total never tolerates a broken lab.
func TestACheckThatDidNotPassIsNamedEvenWhenItCostAlmostNothing(t *testing.T) {
	rep := refReport(10-0.0014, false, grade.StatusPass, grade.StatusPartial, grade.StatusPass)
	why := referenceComplaint(rep, 10)
	if !strings.Contains(why, "bgp.session_up") {
		t.Fatalf("a check that did not pass must be named: %q", why)
	}
	if !strings.Contains(why, "did not pass") {
		t.Fatalf("want the per-check complaint, got %q", why)
	}
}

// This gate refuses the whole class run, so a complaint raised on the weather
// costs every student their marks until an operator gives up and passes
// --skip-reference-check, which turns the gate off entirely. A lab that is
// really not the reference solution fails the second grading as surely as the
// first; a lab that lost one probe of a hundred and forty-four does not.
func TestAComplaintMustSurviveBeingAskedAgain(t *testing.T) {
	asked := 0
	why := settledComplaint(referenceAttempts, func() string {
		asked++
		if asked == 1 {
			return "scores 9.90 of 10.00"
		}
		return ""
	})
	if why != "" {
		t.Fatalf("a lab that grades clean the second time is not a broken lab: %q", why)
	}
	if asked < 2 {
		t.Fatalf("the reference was refused on one grading, after %d attempt(s)", asked)
	}
}

// A lab that really is not the reference solution must still be caught, and the
// complaint reported must be the one that was still true at the end.
func TestAComplaintThatSurvivesIsStillReported(t *testing.T) {
	asked := 0
	why := settledComplaint(referenceAttempts, func() string {
		asked++
		return fmt.Sprintf("scores 9.70 of 10.00 (grading %d)", asked)
	})
	if !strings.Contains(why, "9.70") {
		t.Fatalf("a broken lab must still be refused, got %q", why)
	}
	if !strings.Contains(why, fmt.Sprintf("grading %d", referenceAttempts)) {
		t.Fatalf("want the complaint that was still true at the end, got %q", why)
	}
	if asked != referenceAttempts {
		t.Fatalf("want %d gradings, got %d", referenceAttempts, asked)
	}
}

// Retrying is worth nothing if the gate is not retried at all.
func TestTheReferenceIsGradedMoreThanOnceBeforeARefusal(t *testing.T) {
	if referenceAttempts < 2 {
		t.Fatal("one grading is the defect this exists to prevent")
	}
}
