package grade

import (
	"strings"
	"testing"
)

// The .txt report is the artifact a student is handed, and it used to open
// with "0.00 / 10.00 (0%)" for a submission that was never graded at all.
func TestAnUngradedReportDoesNotShowAZero(t *testing.T) {
	r := &Report{
		Submission: "group6", MaxTotal: 10,
		Err:         "this submission could not be read, so it was not graded: unexpected EOF",
		NeedsReview: true,
	}
	got := r.Text()
	if strings.Contains(got, "0.00 / 10.00") || strings.Contains(got, "(0%)") {
		t.Fatalf("a submission that was never graded is shown as a zero:\n%s", got)
	}
	for _, want := range []string{"not graded", "not a score of zero", "unexpected EOF"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report should say %q:\n%s", want, got)
		}
	}
}

func TestAGradedReportStillShowsItsScore(t *testing.T) {
	r := &Report{Submission: "group3", AS: 3, Total: 8.5, MaxTotal: 10}
	got := r.Text()
	if !strings.Contains(got, "8.50 / 10.00") {
		t.Fatalf("a graded report lost its score line:\n%s", got)
	}
}
