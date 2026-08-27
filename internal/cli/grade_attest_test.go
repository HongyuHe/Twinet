package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

const attestTestSourceDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCOSMutationSuiteCoversEveryRubricCheckOccurrence(t *testing.T) {
	rubric, err := grade.LoadRubric(filepath.Join("..", "..", "examples", "cos461", "rubric", "cos461.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	suite, err := harness.LoadMutationSuite(filepath.Join("..", "..", "examples", "cos461", "audit", "mutations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := suite.Validate(compactCoverage(rubric)); err != nil {
		t.Fatalf("COS compact mutation coverage: %v", err)
	}
}

func TestMutationTransformationChangesGenuineSubmissionContent(t *testing.T) {
	sub := submission{Files: map[string]string{"ATL": "router ospf\n"}, Scripts: map[string]string{"ATL": "ip link set lo up\n"}}
	mutation := harness.MutationCase{
		Name: "change", Transforms: []harness.MutationTransform{{File: "ATL.sh", Append: "ip link set lo down"}},
	}
	if err := applyMutationCase(&sub, mutation); err != nil {
		t.Fatal(err)
	}
	if sub.Scripts["ATL"] == "ip link set lo up\n" {
		t.Fatal("mutation left signed submission content unchanged")
	}
}

func TestCOSFixtureTransformsMatchReferenceEquivalentContent(t *testing.T) {
	suite, err := harness.LoadMutationSuite(filepath.Join("..", "..", "examples", "cos461", "audit", "mutations.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]harness.MutationCase{}
	for _, mutation := range suite.Cases {
		byName[mutation.Name] = mutation
	}
	sub := submission{
		Files:   map[string]string{"ATL": "router ospf\n network 3.0.8.0/24 area 0\n"},
		ROAs:    []byte("[\n  {\"prefix\": \"3.0.0.0/8\", \"maxLength\": 8, \"asn\": 3}\n]\n"),
		Scripts: map[string]string{},
	}
	if err := applyMutationCase(&sub, byName["q1_2_ospf_subnets"]); err != nil {
		t.Fatalf("OSPF fixture did not apply to reference-equivalent content: %v", err)
	}
	if strings.Contains(sub.Files["ATL"], "network 3.0.8.0/24 area 0") {
		t.Fatal("OSPF fixture left original network in place")
	}
	if err := applyMutationCase(&sub, byName["q2_6_roa_published"]); err != nil {
		t.Fatalf("ROA fixture did not apply to reference-equivalent content: %v", err)
	}
	if strings.Contains(string(sub.ROAs), "\"prefix\": \"3.0.0.0/8\"") {
		t.Fatal("ROA fixture left original prefix in place")
	}
}

func TestCOSFixtureTransformsProvidedReferenceArchive(t *testing.T) {
	archive := os.Getenv("TWINET_COS_REFERENCE_ARCHIVE")
	if archive == "" {
		t.Skip("set TWINET_COS_REFERENCE_ARCHIVE to validate the release reference bundle")
	}
	suite, err := harness.LoadMutationSuite(filepath.Join("..", "..", "examples", "cos461", "audit", "mutations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	reference := submissionFromArchiveContents(t, archive)
	for _, mutation := range suite.Cases {
		mutation := mutation
		t.Run(mutation.Name, func(t *testing.T) {
			candidate := cloneSubmission(reference)
			if err := applyMutationCase(&candidate, mutation); err != nil {
				t.Fatalf("fixture does not transform the signed reference content: %v", err)
			}
		})
	}
}

func submissionFromArchiveContents(t *testing.T, archive string) submission {
	t.Helper()
	file, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	out := submission{Files: map[string]string{}, Scripts: map[string]string{}}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case header.Name == "roas.json":
			out.ROAs = raw
		case strings.HasSuffix(header.Name, ".conf"):
			out.Files[strings.TrimSuffix(header.Name, ".conf")] = string(raw)
		case strings.HasSuffix(header.Name, ".sh"):
			out.Scripts[strings.TrimSuffix(header.Name, ".sh")] = string(raw)
		}
	}
}

func TestGradeAttestCompactCommandIsRegistered(t *testing.T) {
	root := Root()
	gradeCmd, _, err := root.Find([]string{"grade"})
	if err != nil {
		t.Fatal(err)
	}
	found, _, err := gradeCmd.Find([]string{"attest", "compact"})
	if err != nil || found == nil || found.Use != "attest compact" {
		t.Fatalf("compact attestation command is not registered: %v", err)
	}
	if found.Flags().Lookup("token") != nil {
		t.Fatal("release attestation exposes the bearer token through argv")
	}
}

func TestGradeAttestRequiresExplicitSubmissionPrivateKey(t *testing.T) {
	cmd := newGradeAttestCmd(&Options{})
	cmd.SetArgs([]string{
		"--reference", "reference.tar.gz",
		"--mutations", "mutations.yaml",
		"--private-key", "attestation.pem",
		"--output", "attestation.json",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--submission-private-key") {
		t.Fatalf("missing explicit submission key was accepted: %v", err)
	}
}

func TestAttestationAndSubmissionKeysMustDiffer(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDistinctAttestationKeys(key, key); err == nil {
		t.Fatal("same private key accepted for attestation and mutation bundles")
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureDistinctAttestationKeys(key, other); err != nil {
		t.Fatal(err)
	}
}

func TestAttestationSubmissionKeyMustAlreadyExist(t *testing.T) {
	path := filepath.Join(attestTestDir(t), "missing-submission-key.pem")
	if _, err := loadExistingEd25519PrivateKey(path, "submission"); err == nil {
		t.Fatal("missing submission key was implicitly created")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing submission key path was created: %v", err)
	}
}

func TestAttestedReferenceRequiresProvidedTrustedSigner(t *testing.T) {
	dir := attestTestDir(t)
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeAttestPublicKey(t, filepath.Join(dir, "trusted_signers", "submission.pem"), pub)
	t.Setenv("TWINET_PKI", dir)
	top := &model.Topology{
		Name: "fixture", Hash: "fixture-topology",
		Lab:  &model.Lab{Images: model.ImagePolicy{LockDigest: "fixture-lock"}},
		ASes: map[int]*model.AS{3: {ASN: 3, Role: model.RoleStudent}},
	}
	archive := filepath.Join(dir, "reference.tar.gz")
	sub := submission{
		Group: "group-3", AS: 3, TakenAt: time.Unix(123, 0).UTC(),
		Files: map[string]string{"ATL": "router ospf\n"}, Scripts: map[string]string{},
	}
	if err := writeSignedSubmissionBundle(archive, top, sub, private); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := attestedReferenceSubmission(archive, top, pub); err != nil {
		t.Fatalf("reference signed by the supplied trusted key was rejected: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := attestedReferenceSubmission(archive, top, otherPub); err == nil {
		t.Fatal("reference signed by a different key was accepted")
	}
}

func TestMutationBundleResigningIsDeterministic(t *testing.T) {
	dir := attestTestDir(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	top := &model.Topology{
		Name: "fixture", Hash: "fixture-topology",
		Lab: &model.Lab{Images: model.ImagePolicy{LockDigest: "fixture-lock"}},
	}
	sub := submission{
		Group: "group-3", AS: 3, TakenAt: time.Unix(123, 0).UTC(),
		Files: map[string]string{"ATL": "router ospf\n"}, Scripts: map[string]string{"ATL": "ip link set lo up\n"},
	}
	first := filepath.Join(dir, "first.tar.gz")
	second := filepath.Join(dir, "second.tar.gz")
	if err := writeSignedSubmissionBundle(first, top, sub, key); err != nil {
		t.Fatal(err)
	}
	if err := writeSignedSubmissionBundle(second, top, sub, key); err != nil {
		t.Fatal(err)
	}
	firstRaw, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstRaw) != string(secondRaw) {
		t.Fatal("identical mutation inputs produced different signed bundles")
	}
}

func TestAttestationEvidenceStagingLeavesNoOutputOnFailure(t *testing.T) {
	dir := attestTestDir(t)
	out := filepath.Join(dir, "compact-attestation.json")
	evidence, err := newCompactAttestationEvidence(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.Write("mutation-suite.yaml", []byte("suite"), 0); err != nil {
		t.Fatal(err)
	}
	if err := evidence.Discard(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{out, out + ".evidence", out + ".evidence.staging"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed attestation left output %s: %v", path, err)
		}
	}
}

func TestCompactAttestationSuiteRetainsSignedEvidenceAndFailsWithoutOutput(t *testing.T) {
	dir := attestTestDir(t)
	submissionPublic, submissionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPublic, attestationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeAttestPublicKey(t, filepath.Join(dir, "trusted_signers", "submission.pem"), submissionPublic)
	t.Setenv("TWINET_PKI", dir)

	top := &model.Topology{
		Name: "fixture", Hash: "fixture-topology",
		Lab:  &model.Lab{Images: model.ImagePolicy{LockDigest: "fixture-lock"}},
		ASes: map[int]*model.AS{3: {ASN: 3, Role: model.RoleStudent}},
	}
	rubric := &grade.Rubric{Questions: []grade.QuestionSpec{
		{ID: "q1", Points: 1, Checks: []grade.CheckSpec{{Check: "fixture.check"}}},
		{ID: "q2", Points: 1},
	}}
	suiteRaw := []byte(`apiVersion: twinet.dev/v1
kind: CompactMutationSuite
cases:
  - name: wrong
    required: {question_id: q1, check_id: fixture.check, check_index: 0}
    expected_check_status: fail
    transforms:
      - {file: ATL.conf, find: good, replace: bad}
`)
	suite, err := harness.ParseMutationSuite(suiteRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := suite.Validate(compactCoverage(rubric)); err != nil {
		t.Fatal(err)
	}
	reference := submission{
		Group: "group-3", AS: 3, TakenAt: time.Unix(123, 0).UTC(),
		Files: map[string]string{"ATL": "good\n"}, Scripts: map[string]string{},
	}
	referenceRaw := []byte("genuine-reference-archive")
	referenceDigest := evidenceArtifact("reference", referenceRaw, 0).SHA256
	suiteDigest := evidenceArtifact("suite", suiteRaw, 0).SHA256

	sameKeyOut := filepath.Join(dir, "same-key.json")
	if _, _, err := runCompactAttestationSuite(
		context.Background(), top, rubric, suite, suiteRaw, suiteDigest,
		reference, referenceRaw, referenceDigest, submissionPrivate, submissionPrivate,
		attestTestSourceDigest, sameKeyOut, batchOpts{converge: time.Second},
	); err == nil {
		t.Fatal("same attestation and submission key produced an attestation")
	}
	assertNoAttestationOutput(t, sameKeyOut)

	missingCoverage := *suite
	missingCoverage.Cases = nil
	missingOut := filepath.Join(dir, "missing-coverage.json")
	if _, _, err := runCompactAttestationSuite(
		context.Background(), top, rubric, &missingCoverage, suiteRaw, suiteDigest,
		reference, referenceRaw, referenceDigest, attestationPrivate, submissionPrivate,
		attestTestSourceDigest, missingOut, batchOpts{converge: time.Second},
	); err == nil {
		t.Fatal("missing mutation coverage produced an attestation")
	}
	assertNoAttestationOutput(t, missingOut)

	oldFactory := newCompactAttestRunner
	t.Cleanup(func() { newCompactAttestRunner = oldFactory })
	successRunner := &fakeCompactAttestRunner{}
	factoryCalls := 0
	newCompactAttestRunner = func(context.Context, *model.Topology, *grade.Rubric, batchOpts, int) (compactAttestRunner, error) {
		factoryCalls++
		return successRunner, nil
	}
	out := filepath.Join(dir, "attestation.json")
	attestation, evidenceDir, err := runCompactAttestationSuite(
		context.Background(), top, rubric, suite, suiteRaw, suiteDigest,
		reference, referenceRaw, referenceDigest, attestationPrivate, submissionPrivate,
		attestTestSourceDigest, out, batchOpts{converge: time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 || len(successRunner.runs) != 2 || successRunner.closed != 1 {
		t.Fatalf("suite did not reuse one full/compact runner: factories=%d runs=%d closes=%d",
			factoryCalls, len(successRunner.runs), successRunner.closed)
	}
	if err := attestation.Verify(attestationPublic, top.Hash, compactRubricHash(rubric),
		harness.CompactCompilerContract, attestTestSourceDigest, top.Lab.Images.LockDigest, compactCoverage(rubric)); err != nil {
		t.Fatalf("signed attestation did not verify: %v", err)
	}
	if err := attestation.VerifyEvidence(filepath.Dir(out)); err != nil {
		t.Fatalf("retained report evidence did not verify: %v", err)
	}
	if evidenceDir != out+".evidence" {
		t.Fatalf("evidence directory=%q, want deterministic sibling", evidenceDir)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("attestation permissions=%#o, want 0600", info.Mode().Perm())
	}
	for _, record := range attestation.Audit.Records {
		for _, artifact := range []harness.EvidenceArtifact{
			record.MutationBundle, record.FullReport, record.SyntheticReport,
		} {
			if _, err := os.Stat(filepath.Join(evidenceDir, filepath.FromSlash(artifact.Path))); err != nil {
				t.Fatalf("missing retained %s: %v", artifact.Path, err)
			}
			if artifact.DurationMillis < 0 {
				t.Fatalf("negative timing for %s", artifact.Path)
			}
		}
	}

	failedRunner := &fakeCompactAttestRunner{masked: true}
	newCompactAttestRunner = func(context.Context, *model.Topology, *grade.Rubric, batchOpts, int) (compactAttestRunner, error) {
		return failedRunner, nil
	}
	failedOut := filepath.Join(dir, "masked.json")
	if _, _, err := runCompactAttestationSuite(
		context.Background(), top, rubric, suite, suiteRaw, suiteDigest,
		reference, referenceRaw, referenceDigest, attestationPrivate, submissionPrivate,
		attestTestSourceDigest, failedOut, batchOpts{converge: time.Second},
	); err == nil {
		t.Fatal("masked compact mutation produced an attestation")
	}
	assertRejectedAttestationEvidence(t, failedOut)

	reviewRunner := &fakeCompactAttestRunner{review: true}
	newCompactAttestRunner = func(context.Context, *model.Topology, *grade.Rubric, batchOpts, int) (compactAttestRunner, error) {
		return reviewRunner, nil
	}
	reviewOut := filepath.Join(dir, "review.json")
	if _, _, err := runCompactAttestationSuite(
		context.Background(), top, rubric, suite, suiteRaw, suiteDigest,
		reference, referenceRaw, referenceDigest, attestationPrivate, submissionPrivate,
		attestTestSourceDigest, reviewOut, batchOpts{converge: time.Second},
	); err == nil {
		t.Fatal("infrastructure-review audit produced an attestation")
	}
	assertRejectedAttestationEvidence(t, reviewOut)
}

type fakeCompactAttestRunner struct {
	runs   []string
	closed int
	masked bool
	review bool
}

func (r *fakeCompactAttestRunner) Run(_ context.Context, _ submission, name string) (compactAttestResult, error) {
	r.runs = append(r.runs, name)
	full := fakeAttestReport(name == "reference")
	compact := fakeAttestReport(name == "reference")
	if r.masked && name != "reference" {
		compact = fakeAttestReport(true)
	}
	if r.review && name != "reference" {
		full.NeedsReview = true
		compact.NeedsReview = true
	}
	return compactAttestResult{
		Full: full, Compact: compact, FullDuration: time.Millisecond, CompactDuration: 2 * time.Millisecond,
	}, nil
}

func assertNoAttestationOutput(t *testing.T, out string) {
	t.Helper()
	for _, path := range []string{out, out + ".evidence", out + ".evidence.staging"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed audit left output %s: %v", path, err)
		}
	}
}

func assertRejectedAttestationEvidence(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("rejected audit published a signed attestation %s: %v", out, err)
	}
	if _, err := os.Stat(out + ".evidence.staging"); !os.IsNotExist(err) {
		t.Fatalf("rejected audit left staging output: %v", err)
	}
	failure := filepath.Join(out+".evidence", "audit-failure.json")
	raw, err := os.ReadFile(failure)
	if err != nil {
		t.Fatalf("rejected audit did not retain %s: %v", failure, err)
	}
	var audit harness.AuditResult
	if err := json.Unmarshal(raw, &audit); err != nil {
		t.Fatalf("rejected audit evidence is invalid: %v", err)
	}
	if audit.Equivalent || len(audit.Records) == 0 {
		t.Fatalf("rejected audit evidence does not explain the rejection: %+v", audit)
	}
}

func (r *fakeCompactAttestRunner) Close(context.Context) error {
	r.closed++
	return nil
}

func fakeAttestReport(reference bool) *grade.Report {
	q1Awarded := 0.0
	status := grade.StatusFail
	score := 0.0
	total := 1.0
	if reference {
		q1Awarded = 1
		status = grade.StatusPass
		score = 1
		total = 2
	}
	return &grade.Report{
		Total: total, MaxTotal: 2,
		Questions: []grade.QuestionResult{
			{ID: "q1", Points: 1, Awarded: q1Awarded,
				Results: []grade.Result{{Check: "fixture.check", Status: status, Score: score}}},
			{ID: "q2", Points: 1, Awarded: 1},
		},
	}
}

func TestWarmCompactAttestRunnerReusesBothModeManagers(t *testing.T) {
	full := &fakeAttestWarmManager{report: fakeAttestReport(true)}
	compact := &fakeAttestWarmManager{report: fakeAttestReport(true)}
	runner := &warmCompactAttestRunner{full: full, compact: compact}
	for _, name := range []string{"reference", "wrong"} {
		if _, err := runner.Run(context.Background(), submission{AS: 3}, name); err != nil {
			t.Fatal(err)
		}
	}
	if full.grades != 2 || compact.grades != 2 {
		t.Fatalf("audit cases did not reuse full/compact managers: full=%d compact=%d", full.grades, compact.grades)
	}
	if err := runner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if full.closes != 1 || compact.closes != 1 {
		t.Fatalf("warm managers not closed exactly once: full=%d compact=%d", full.closes, compact.closes)
	}
}

type fakeAttestWarmManager struct {
	report *grade.Report
	grades int
	closes int
}

func (m *fakeAttestWarmManager) grade(context.Context, submission) *grade.Report {
	m.grades++
	return m.report
}

func (m *fakeAttestWarmManager) close(context.Context) error {
	m.closes++
	return nil
}

var attestTestCounter uint64

func attestTestDir(t *testing.T) string {
	t.Helper()
	dir := fmt.Sprintf(".attest-test-%d-%d", os.Getpid(), atomic.AddUint64(&attestTestCounter, 1))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeAttestPublicKey(t *testing.T, path string, public ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}
