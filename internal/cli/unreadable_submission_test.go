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
	}, 7)
	s := out.String()
	if !strings.Contains(s, "group6") || !strings.Contains(s, "unexpected EOF") {
		t.Fatalf("the announcement does not say which submission or why:\n%s", s)
	}
	if !strings.Contains(s, "other 7 are graded normally") {
		t.Errorf("the announcement should make clear the rest of the class is still graded:\n%s", s)
	}
	out.Reset()
	announceUnreadable(&out, nil, 8)

	// When nothing else was handed in, it must not claim the rest is graded.
	out.Reset()
	announceUnreadable(&out, []unreadable{{Name: "group6", Reason: "unexpected EOF"}}, 0)
	if strings.Contains(out.String(), "graded normally") {
		t.Errorf("with nothing else to grade, the announcement still promised to grade it:\n%s",
			out.String())
	}
	out.Reset()
	announceUnreadable(&out, nil, 8)
	if out.Len() != 0 {
		t.Errorf("nothing should be printed when every submission is readable: %q", out.String())
	}
}

// A student who scored full marks was handed a report saying they had not been
// graded, because a second entry in the directory carried their name. Found by
// review round 135; introduced by the fix for finding 129, which added a set of
// names that the ambiguity check never saw.
func TestAGradedSubmissionIsNotOverwrittenByAQuarantinedOne(t *testing.T) {
	dir := t.TempDir()
	goodSubmission(t, dir, "group3")
	// An empty directory of the same name: readable as a name, unreadable as
	// a submission.
	if err := os.MkdirAll(filepath.Join(dir, "group3.tar.gz.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Use the archive form so both resolve to "group3".
	if err := os.WriteFile(filepath.Join(dir, "group3.tar.gz"), []byte("not a gzip"), 0o644); err != nil {
		t.Fatal(err)
	}

	subs, bad, err := readSubmissions(dir, classOfEight(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range subs {
		if strings.EqualFold(s.Group, "group3") {
			t.Fatalf("group3 was graded even though two submissions claim that name; "+
				"the quarantine report for the other one will overwrite the mark: %+v", subs)
		}
	}
	var found int
	for _, u := range bad {
		if strings.EqualFold(u.Name, "group3") {
			found++
			if !strings.Contains(u.Reason, "claim") {
				t.Errorf("the reason should say the name is contested: %q", u.Reason)
			}
		}
	}
	if found != 1 {
		t.Fatalf("one contested name must yield exactly one report, got %d: %+v", found, bad)
	}
}

// Two different students claiming one AS are both withdrawn, and the rest of
// the class is still marked -- one student's mistake is not a hundred students'
// problem.
func TestOneContestedASDoesNotStopTheClass(t *testing.T) {
	subs := []submission{
		{Group: "alice", AS: 3, Dir: "/s/alice"},
		{Group: "bob", AS: 3, Dir: "/s/bob"},
		{Group: "group4", AS: 4, Dir: "/s/group4"},
		{Group: "group5", AS: 5, Dir: "/s/group5"},
	}
	kept, held := withdrawContested(subs, nil)
	if len(kept) != 2 {
		t.Fatalf("the uncontested submissions should still be graded, got %+v", kept)
	}
	for _, s := range kept {
		if s.AS == 3 {
			t.Fatalf("a contested AS was graded anyway: %+v", s)
		}
	}
	if len(held) != 2 {
		t.Fatalf("both claimants should be held, got %+v", held)
	}
	for _, u := range held {
		if !strings.Contains(u.Reason, "AS 3") ||
			!strings.Contains(u.Reason, "alice") || !strings.Contains(u.Reason, "bob") {
			t.Errorf("a held report should name the conflict: %q", u.Reason)
		}
	}
}

func TestAnUncontestedSetIsUntouched(t *testing.T) {
	subs := []submission{
		{Group: "group3", AS: 3}, {Group: "group4", AS: 4}, {Group: "group5", AS: 5},
	}
	kept, held := withdrawContested(subs, []unreadable{{Name: "group6", Reason: "EOF"}})
	if len(kept) != 3 || len(held) != 1 {
		t.Fatalf("an ordinary set was disturbed: kept %+v held %+v", kept, held)
	}
}

func TestAllAttemptsPermitsOnlyDistinctSignedAttemptClaims(t *testing.T) {
	subs := []submission{
		{Group: "group3", AS: 3, Attempt: "benchmark-000", Dir: "/s/one"},
		{Group: "group3", AS: 3, Attempt: "benchmark-001", Dir: "/s/two"},
		{Group: "group4", AS: 4, Dir: "/s/group4"},
	}
	kept, held := withdrawContestedWithAttempts(subs, nil, true)
	if len(kept) != 3 || len(held) != 0 {
		t.Fatalf("distinct signed attempts were not admitted: kept=%+v held=%+v", kept, held)
	}
	if kept[0].Identity() == kept[1].Identity() {
		t.Fatalf("attempt identities collide: %+v", kept)
	}

	subs[1].Attempt = "benchmark-000"
	kept, held = withdrawContestedWithAttempts(subs, nil, true)
	if len(kept) != 1 || len(held) != 1 {
		t.Fatalf("duplicate attempt was not contested: kept=%+v held=%+v", kept, held)
	}
	if !strings.Contains(held[0].Reason, "--all-attempts") {
		t.Fatalf("contest reason does not explain attempt gate: %q", held[0].Reason)
	}

	subs[1].Attempt = ""
	kept, held = withdrawContestedWithAttempts(subs, nil, true)
	if len(kept) != 1 || len(held) != 1 {
		t.Fatalf("missing attempt was not contested: kept=%+v held=%+v", kept, held)
	}
}

func TestAttemptReportsUseCollisionFreeFilesAndCSVIdentity(t *testing.T) {
	dir := t.TempDir()
	s := grade.Summarise("r", []*grade.Report{
		{Submission: "group3", Attempt: "benchmark-000", AS: 3, Total: 10, MaxTotal: 10},
		{Submission: "group3", Attempt: "benchmark-001", AS: 3, Total: 9, MaxTotal: 10},
	}, 0)
	if err := writeReports(dir, s); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		(&grade.Report{Submission: "group3", Attempt: "benchmark-000"}).FileIdentity() + ".json",
		(&grade.Report{Submission: "group3", Attempt: "benchmark-001"}).FileIdentity() + ".json",
		(&grade.Report{Submission: "group3", Attempt: "benchmark-000"}).FileIdentity() + ".txt",
		(&grade.Report{Submission: "group3", Attempt: "benchmark-001"}).FileIdentity() + ".txt",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing collision-free report file %s: %v", name, err)
		}
	}
	csv, err := os.ReadFile(filepath.Join(dir, "summary.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csv), "submission,attempt,as,status") ||
		!strings.Contains(string(csv), "group3,benchmark-000") ||
		!strings.Contains(string(csv), "group3,benchmark-001") {
		t.Fatalf("CSV lost attempt identities:\n%s", csv)
	}
}

func TestTwoReportsForOneNameAreRefusedRatherThanOverwritten(t *testing.T) {
	dir := t.TempDir()
	s := grade.Summarise("r", []*grade.Report{
		{Submission: "group3", AS: 3, Total: 10, MaxTotal: 10},
		{Submission: "group3", AS: 3, MaxTotal: 10, NeedsReview: true, Err: "unreadable"},
	}, 0)
	err := writeReports(dir, s)
	if err == nil {
		t.Fatal("two reports for one student were written, so one mark silently replaced the other")
	}
	if !strings.Contains(err.Error(), "group3") || !strings.Contains(err.Error(), "marked 10.00") {
		t.Errorf("the error should say whose mark was at risk: %v", err)
	}
}

// A withdrawn submission must not be told it was unreadable: it read fine.
func TestAContestedSubmissionIsNotCalledUnreadable(t *testing.T) {
	_, held := withdrawContested([]submission{
		{Group: "group3", AS: 3, Dir: "/s/group3"},
		{Group: "Group3", AS: 3, Dir: "/s/Group3"},
	}, nil)
	if len(held) != 1 {
		t.Fatalf("expected one report, got %+v", held)
	}
	rubric := &grade.Rubric{}
	rubric.Questions = []grade.QuestionSpec{{ID: "q1", Points: 10}}
	reps := quarantineUnreadable(held, rubric, "cos461")
	if strings.Contains(reps[0].Err, "could not be read") {
		t.Errorf("a submission that read perfectly is reported as unreadable: %q", reps[0].Err)
	}
	if strings.Count(reps[0].Err, "was not graded") > 1 {
		t.Errorf("the reason is doubled up: %q", reps[0].Err)
	}
	if !strings.Contains(reps[0].Err, "claim to be") {
		t.Errorf("the reason should say the name is contested: %q", reps[0].Err)
	}
	// And one that really was unreadable still says so.
	reps = quarantineUnreadable([]unreadable{
		{Name: "group6", Reason: "this submission could not be read, so it was not graded: EOF"},
	}, rubric, "cos461")
	if !strings.Contains(reps[0].Err, "could not be read") {
		t.Errorf("an unreadable submission no longer says why: %q", reps[0].Err)
	}
}
