package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestGradeBenchmarkGenerateCommandIsRegistered(t *testing.T) {
	root := Root()
	gradeCmd, _, err := root.Find([]string{"grade"})
	if err != nil {
		t.Fatal(err)
	}

	found, _, err := gradeCmd.Find([]string{"benchmark", "generate"})
	if err != nil || found == nil || found.Use != "generate" {
		t.Fatalf("benchmark generator command is not registered: %v", err)
	}
	if found.Flags().Lookup("token") != nil {
		t.Fatal("benchmark generator exposes a bearer token through argv")
	}
}

func TestGradeBenchmarkGenerateRequiresExplicitSigningInputs(t *testing.T) {
	cmd := newGradeBenchmarkGenerateCmd(&Options{})
	cmd.SetArgs([]string{"--reference", "reference.tar.gz", "--mutations", "mutations.yaml"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--submission-private-key") {
		t.Fatalf("generator accepted incomplete signing inputs: %v", err)
	}
}

func TestDeterministicSignedBenchmarkGeneration100(t *testing.T) {
	dir := attestTestDir(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeAttestPublicKey(t, filepath.Join(dir, "trusted_signers", "submission.pem"), public)
	t.Setenv("TWINET_PKI", dir)
	top := benchmarkFixtureTopology()
	rubric := benchmarkFixtureRubric()
	suite := benchmarkFixtureSuite(t)
	reference := submission{
		Group: "group-3", AS: 3, Controller: "reference-controller", TakenAt: time.Unix(123, 0).UTC(),
		Files: map[string]string{"ATL": "good\n"}, Scripts: map[string]string{},
	}
	firstDir := filepath.Join(dir, "first")
	secondDir := filepath.Join(dir, "second")
	first, err := generateBenchmarkArtifacts(top, rubric, suite, reference, attestTestSourceDigest,
		attestTestSourceDigest, attestTestSourceDigest, private, 100, firstDir, attestTestSourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateBenchmarkArtifacts(top, rubric, suite, reference, attestTestSourceDigest,
		attestTestSourceDigest, attestTestSourceDigest, private, 100, secondDir, attestTestSourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Archives) != 100 || len(second.Archives) != 100 {
		t.Fatalf("plans contain %d and %d archives, want 100", len(first.Archives), len(second.Archives))
	}
	attempts, held, err := readSubmissionsWithAttempts(firstDir, top, true)
	if err != nil || len(attempts) != 100 || len(held) != 0 {
		t.Fatalf("signed benchmark attempts were not admitted: attempts=%d held=%+v err=%v", len(attempts), held, err)
	}
	finalOnly, contested, err := readSubmissionsWithAttempts(firstDir, top, false)
	if err != nil || len(finalOnly) != 0 || len(contested) != 1 {
		t.Fatalf("ordinary final-submission policy admitted benchmark repeats: final=%+v contested=%+v err=%v", finalOnly, contested, err)
	}
	if first.EquivalenceAuditHash != attestTestSourceDigest {
		t.Fatalf("missing benchmark attestation hash: %+v", first)
	}
	if first.MutationSuiteSHA256 != attestTestSourceDigest ||
		first.ImageLock != top.Lab.Images.LockDigest ||
		first.GraderSource != attestTestSourceDigest {
		t.Fatalf("benchmark plan dropped release bindings: %+v", first)
	}
	firstNames := benchmarkArchiveNames(t, firstDir)
	secondNames := benchmarkArchiveNames(t, secondDir)
	if len(firstNames) != 100 || len(secondNames) != 100 {
		t.Fatalf("archive counts = %d and %d, want 100", len(firstNames), len(secondNames))
	}
	for index, name := range firstNames {
		if name != secondNames[index] {
			t.Fatalf("archive order differs: %v vs %v", firstNames, secondNames)
		}
		left, err := os.ReadFile(filepath.Join(firstDir, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(secondDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(left) != string(right) {
			t.Fatalf("%s is not byte-for-byte deterministic", name)
		}
		sub, err := submissionFromArchive(filepath.Join(firstDir, name), top)
		if err != nil {
			t.Fatalf("%s is not a trusted generated archive: %v", name, err)
		}
		if sub.Attempt == "" || sub.ArchiveSHA256 == "" {
			t.Fatalf("%s has no signed attempt/archive identity: %+v", name, sub)
		}
		if sub.Controller != "reference-controller" {
			t.Fatalf("%s did not preserve reference controller provenance: %q", name, sub.Controller)
		}
		entry, ok := first.Archives[sub.ArchiveSHA256]
		if !ok || entry.Attempt != sub.Attempt || entry.Submission != sub.Group || entry.AS != sub.AS {
			t.Fatalf("%s is absent or mismatched in benchmark plan: %+v", name, entry)
		}
	}
	firstPlan := filepath.Join(dir, "first-plan.json")
	secondPlan := filepath.Join(dir, "second-plan.json")
	if err := writeBenchmarkPlan(firstPlan, first); err != nil {
		t.Fatal(err)
	}
	if err := writeBenchmarkPlan(secondPlan, second); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadFile(firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.ReadFile(secondPlan)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("machine-readable benchmark plans are not deterministic")
	}
	for digest, entry := range first.Archives {
		entry.Attempt = "../tampered"
		first.Archives[digest] = entry
		if err := first.Validate(); err == nil {
			t.Fatal("tampered benchmark attempt identity was accepted")
		}
		break
	}

	failedDir := filepath.Join(dir, "failed-plan-output")
	failed, err := generateBenchmarkArtifacts(top, rubric, suite, reference,
		attestTestSourceDigest, attestTestSourceDigest, attestTestSourceDigest,
		private, 1, failedDir, attestTestSourceDigest)
	if err != nil {
		t.Fatal(err)
	}
	blockedPlan := filepath.Join(dir, "already-exists.json")
	if err := os.WriteFile(blockedPlan, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := finalizeBenchmarkGeneration(failedDir, blockedPlan, failed); err == nil {
		t.Fatal("existing plan did not fail generation finalization")
	}
	if _, err := os.Stat(failedDir); !os.IsNotExist(err) {
		t.Fatalf("plan write failure left generated bundles behind: %v", err)
	}
}

func benchmarkFixtureTopology() *model.Topology {
	return &model.Topology{
		Name: "fixture", Hash: "fixture-topology",
		Lab:  &model.Lab{Images: model.ImagePolicy{LockDigest: "fixture-lock"}},
		ASes: map[int]*model.AS{3: {ASN: 3, Role: model.RoleStudent}},
	}
}

func benchmarkFixtureRubric() *grade.Rubric {
	return &grade.Rubric{Questions: []grade.QuestionSpec{
		{ID: "q1", Points: 1, Checks: []grade.CheckSpec{{Check: "fixture.check"}}},
		{ID: "q2", Points: 1},
	}}
}

func benchmarkFixtureSuite(t *testing.T) *harness.MutationSuite {
	t.Helper()
	suite, err := harness.ParseMutationSuite([]byte(`apiVersion: twinet.dev/v1
kind: CompactMutationSuite
cases:
  - name: wrong
    required: {question_id: q1, check_id: fixture.check, check_index: 0}
    expected_check_status: fail
    transforms:
      - {file: ATL.conf, find: good, replace: bad}
`))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func benchmarkArchiveNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".gz" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}
