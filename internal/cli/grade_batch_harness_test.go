package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestBatchHarnessOptionsUseAttestedCompactSynthetic(t *testing.T) {
	compact := batchHarnessOptions(0, false, false, true, false, "group")
	if !compact.Synthetic || compact.Reduce || compact.Depth != 0 || !compact.KeepHosts {
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

func TestHarnessDeployWorkersScaleWithTopology(t *testing.T) {
	for _, test := range []struct {
		devices int
		want    int
	}{
		{devices: 40, want: 8},
		{devices: 320, want: 8},
		{devices: 2020, want: 51},
		{devices: 4000, want: 56},
	} {
		if got := harnessDeployWorkers(test.devices); got != test.want {
			t.Errorf("harnessDeployWorkers(%d) = %d, want %d",
				test.devices, got, test.want)
		}
	}
}

func TestWarmHarnessTimeoutsScaleWithTopology(t *testing.T) {
	if got := warmHarnessBaselineTimeout(40, time.Minute); got != 3*time.Minute {
		t.Fatalf("compact baseline timeout = %s", got)
	}
	if got := warmHarnessBaselineTimeout(2020, 3*time.Minute); got != 10*time.Minute {
		t.Fatalf("scale baseline timeout = %s", got)
	}
	if got := warmHarnessCleanupTimeout(2020); got != 10*time.Minute {
		t.Fatalf("scale cleanup timeout = %s", got)
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

func TestOnlyRepeatedASesUseReusableHarnessPools(t *testing.T) {
	plans := []*batchHarness{
		{index: 0, submission: submission{Group: "g5", AS: 5, Attempt: "a"}},
		{index: 1, submission: submission{Group: "g3", AS: 3, Attempt: "a"}},
		{index: 2, submission: submission{Group: "g7", AS: 7}},
		{index: 3, submission: submission{Group: "g3", AS: 3, Attempt: "b"}},
		{index: 4, submission: submission{Group: "g5", AS: 5, Attempt: "b"}},
	}
	groups, cold := splitBatchHarnesses(plans, true)
	if len(groups) != 2 || groups[0].asn != 3 || groups[1].asn != 5 {
		t.Fatalf("reusable groups = %#v, want AS 3 then AS 5", groups)
	}
	if len(groups[0].plans) != 2 || len(groups[1].plans) != 2 {
		t.Fatalf("reusable group sizes = %d/%d, want 2/2",
			len(groups[0].plans), len(groups[1].plans))
	}
	if len(cold) != 1 || cold[0].submission.AS != 7 {
		t.Fatalf("one-off plans = %#v, want only AS 7", cold)
	}

	groups, cold = splitBatchHarnesses(plans, false)
	if len(groups) != 0 || len(cold) != len(plans) {
		t.Fatalf("reuse-disabled split = %d groups/%d cold, want 0/%d",
			len(groups), len(cold), len(plans))
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
