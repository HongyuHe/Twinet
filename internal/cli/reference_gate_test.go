package cli

import (
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
