package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
)

// A class of a hundred must not go unmarked because one upload was truncated.
//
// Every per-submission failure used to come out of readSubmissions as an error,
// and both grading commands returned it, so nothing at all was graded. The
// operator's only remedy was to take the bad file out of the directory by
// hand -- which is also how a student silently gets no mark at all.

func classOfEight(t *testing.T) *model.Topology {
	t.Helper()
	top := &model.Topology{Name: "cos461", Lab: &model.Lab{}, ASes: map[int]*model.AS{}}
	for n := 3; n <= 10; n++ {
		top.ASes[n] = &model.AS{
			ASN: n, Role: model.RoleStudent, OwnerGroup: fmt.Sprintf("group%d", n),
		}
	}
	// A staff AS, which no submission may claim.
	top.ASes[1] = &model.AS{ASN: 1, Role: model.RoleStaff}
	return top
}

// goodSubmission writes a directory submission that will be read successfully.
func goodSubmission(t *testing.T, dir, group string) {
	t.Helper()
	d := filepath.Join(dir, group)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "router bgp 3\n bgp router-id 3.0.0.1\n"
	if err := os.WriteFile(filepath.Join(d, "BOS.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOneCorruptArchiveDoesNotStopTheClass(t *testing.T) {
	dir := t.TempDir()
	for _, g := range []string{"group3", "group4", "group5"} {
		goodSubmission(t, dir, g)
	}
	// A truncated upload: the name says tarball, the bytes are not one.
	if err := os.WriteFile(filepath.Join(dir, "group6.tar.gz"),
		[]byte("this is not a gzip stream"), 0o644); err != nil {
		t.Fatal(err)
	}

	subs, bad, err := readSubmissions(dir, classOfEight(t))
	if err != nil {
		t.Fatalf("one corrupt archive among four submissions stopped the whole run: %v\n"+
			"the other three students would have received no marks", err)
	}
	if len(subs) != 3 {
		t.Fatalf("expected the 3 readable submissions, got %d", len(subs))
	}
	if len(bad) != 1 {
		t.Fatalf("expected the corrupt archive to be carried out as unreadable, got %d", len(bad))
	}
	if bad[0].Name != "group6" {
		t.Errorf("the unreadable submission must be named as the student uploaded it, got %q",
			bad[0].Name)
	}
}

func TestAnUnreadableSubmissionIsQuarantinedAndNotScoredZero(t *testing.T) {
	rubric := &grade.Rubric{}
	rubric.Metadata.Name = "cos461-routing"
	rubric.Questions = []grade.QuestionSpec{{ID: "q1", Points: 10}}

	graded := &grade.Report{
		Submission: "group3", AS: 3, Total: 8, MaxTotal: 10,
	}
	quarantined := quarantineUnreadable(
		[]unreadable{{Name: "group6", Reason: "unexpected EOF"}}, rubric, "cos461")
	if len(quarantined) != 1 {
		t.Fatalf("expected one report, got %d", len(quarantined))
	}
	q := quarantined[0]
	if q.Total != 0 || !q.NeedsReview || q.Err == "" {
		t.Fatalf("an unreadable submission must carry no total and be held for review, got %+v", q)
	}
	if q.MaxTotal != rubric.MaxTotal() {
		t.Errorf("the report should know what it was out of, got %v", q.MaxTotal)
	}

	s := grade.Summarise("cos461-routing", []*grade.Report{graded, q}, 0)
	// The corrupt file must not drag the class mean down: that would measure
	// the platform, not the class.
	if s.Mean != 8 {
		t.Fatalf("the unreadable submission was counted as a zero: mean %.2f, want 8.00", s.Mean)
	}
	if s.Graded != 1 || s.Count != 2 {
		t.Fatalf("expected 1 graded of 2, got %d of %d", s.Graded, s.Count)
	}
	if len(s.Quarantined()) != 1 {
		t.Fatal("the unreadable submission is not reported as needing review")
	}

	// And the run must not exit successfully, so a script does not treat a
	// partial class as a complete one.
	var out bytes.Buffer
	if err := releaseGuard(s, &out); err == nil {
		t.Fatal("a run with a quarantined submission reported success")
	}
	if !strings.Contains(out.String(), "group6") {
		t.Errorf("the quarantined submission is not named in the release guard:\n%s", out.String())
	}
}

func TestASubmissionForNoStudentASIsQuarantinedNotFatal(t *testing.T) {
	dir := t.TempDir()
	goodSubmission(t, dir, "group3")
	goodSubmission(t, dir, "not-a-group")

	subs, bad, err := readSubmissions(dir, classOfEight(t))
	if err != nil {
		t.Fatalf("a submission naming no student AS stopped the run: %v", err)
	}
	if len(subs) != 1 || subs[0].Group != "group3" {
		t.Fatalf("expected group3 to be graded, got %+v", subs)
	}
	if len(bad) != 1 || bad[0].Name != "not-a-group" {
		t.Fatalf("expected not-a-group to be quarantined, got %+v", bad)
	}
	if !strings.Contains(bad[0].Reason, "student AS") {
		t.Errorf("the reason should say why: %q", bad[0].Reason)
	}
}

// The set being ambiguous is a different thing from one submission being bad,
// and must still stop everything: there is no way to know which of two
// submissions for one AS the course meant to mark.
func TestAnAmbiguousSetStillStopsEverything(t *testing.T) {
	dir := t.TempDir()
	goodSubmission(t, dir, "group3")
	goodSubmission(t, dir, "Group3")
	if _, _, err := readSubmissions(dir, classOfEight(t)); err == nil {
		t.Skip("this filesystem is case-insensitive, so the two names are one directory")
	}
}

func TestTheOperatorIsToldBeforeTheRunNotAfterIt(t *testing.T) {
	var out bytes.Buffer
	announceUnreadable(&out, []unreadable{
		{Name: "group6", Reason: "unexpected EOF while reading the archive"},
	})
	s := out.String()
	if !strings.Contains(s, "group6") || !strings.Contains(s, "unexpected EOF") {
		t.Fatalf("the announcement does not say which submission or why:\n%s", s)
	}
	if !strings.Contains(s, "graded normally") {
		t.Errorf("the announcement should make clear the rest of the class is still graded:\n%s", s)
	}
	out.Reset()
	announceUnreadable(&out, nil)
	if out.Len() != 0 {
		t.Errorf("nothing should be printed when every submission is readable: %q", out.String())
	}
}
