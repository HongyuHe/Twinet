package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestBatchHarnessOptionsUseAttestedCompactSynthetic(t *testing.T) {
	compact := batchHarnessOptions(0, false, false, true, true, "group")
	if !compact.Synthetic || compact.Reduce || compact.Depth != 0 {
		t.Fatalf("default batch options = %#v, want compact synthetic", compact)
	}
	full := batchHarnessOptions(0, false, true, false, false, "group")
	if full.Synthetic || full.Reduce || !full.KeepHosts {
		t.Fatalf("full fallback options = %#v", full)
	}
	legacy := batchHarnessOptions(1, false, false, true, true, "group")
	if legacy.Synthetic {
		t.Fatalf("explicit depth must retain legacy slicing: %#v", legacy)
	}
}

func TestBatchHarnessTypeReportsActualMode(t *testing.T) {
	if got := batchHarnessType(batchOpts{}); got != "full-audit-fallback" {
		t.Fatalf("unattested harness type=%q", got)
	}

	if got := batchHarnessType(batchOpts{compact: true}); got != "compact-synthetic" {
		t.Fatalf("compact harness type=%q", got)
	}
	if got := batchHarnessType(batchOpts{fullHarness: true}); got != "full" {
		t.Fatalf("full harness type=%q", got)
	}
	if got := batchHarnessType(batchOpts{reduce: true}); got != "legacy-reduced" {
		t.Fatalf("reduced harness type=%q", got)
	}
}

func TestBatchAllAttemptsRequiresExplicitOptInFlag(t *testing.T) {
	cmd := newGradeBatchCmd(&Options{})
	flag := cmd.Flags().Lookup("all-attempts")
	if flag == nil || flag.DefValue != "false" {
		t.Fatalf("batch all-attempts flag is not explicit and default-deny: %#v", flag)
	}

}

func TestBatchAllAttemptsRejectsArgvToken(t *testing.T) {
	cmd := newGradeBatchCmd(&Options{})
	cmd.SetArgs([]string{"--all-attempts", "--token", "test-token"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "TWINET_TOKEN") {
		t.Fatalf("release batch accepted argv token: %v", err)
	}
}

func TestBrokenReferenceBaselineCannotBecomeStudentMark(t *testing.T) {
	rep := ungradeableReport(submission{Group: "group3", AS: 3},
		&grade.Rubric{}, "verifying solved reference baseline",
		fmt.Errorf("as4/R solved BGP session is Active"))
	if !rep.NeedsReview || rep.Err == "" || rep.Total != 0 {
		t.Fatalf("broken solved reference produced a student score: %+v", rep)
	}
	if got := rep.Text(); !containsAll(got, "not graded", "reference baseline") {
		t.Fatalf("reference baseline failure was presented as a student mark:\n%s", got)
	}
}

func TestBatchReportCarriesPlanBindings(t *testing.T) {
	original := SourceDigest
	originalGrade := grade.GraderSource
	SourceDigest = attestTestSourceDigest
	grade.GraderSource = attestTestSourceDigest
	t.Cleanup(func() {
		SourceDigest = original
		grade.GraderSource = originalGrade
	})
	top := &model.Topology{
		Hash: "topology-test",
		Lab:  &model.Lab{Images: model.ImagePolicy{LockDigest: "image-lock-test"}},
	}
	rubric := &grade.Rubric{Metadata: grade.RubricMeta{Name: "rubric-test"}}
	rep := &grade.Report{}
	applyBatchReportProvenance(rep, top, rubric)
	if rep.Manifest != top.Hash || rep.ImageLock != top.Lab.Images.LockDigest ||
		rep.RubricHash != compactRubricHash(rubric) || rep.GraderSource != attestTestSourceDigest {
		t.Fatalf("benchmark plan bindings missing from report: %+v", rep)
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
