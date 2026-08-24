package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

// compactAttestResult retains independent full/compact timings alongside the
// reports that will be sealed into the attestation evidence directory.
type compactAttestResult struct {
	Full            *grade.Report
	Compact         *grade.Report
	FullDuration    time.Duration
	CompactDuration time.Duration
}

// compactAttestRunner owns the full and compact warm substrates for an entire
// suite. A case never creates a new harness: Reset before/after each lease is
// the isolation boundary, while a failed reset or peer undo taints the pool.
type compactAttestRunner interface {
	Run(context.Context, submission, string) (compactAttestResult, error)
	Close(context.Context) error
}

type compactAttestRunnerFactory func(context.Context, *model.Topology, *grade.Rubric,
	batchOpts, int,
) (compactAttestRunner, error)

var newCompactAttestRunner compactAttestRunnerFactory = newWarmCompactAttestRunner

func newGradeAttestCmd(opts *Options) *cobra.Command {
	var (
		rubricPath        string
		reference         string
		suitePath         string
		keyPath           string
		submissionKeyPath string
		outPath           string
		converge          time.Duration
		settle            time.Duration
	)
	attest := &cobra.Command{Use: "attest compact", Short: "Produce a signed compact-harness equivalence attestation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reference == "" || suitePath == "" || keyPath == "" || submissionKeyPath == "" || outPath == "" {
				return fmt.Errorf("--reference, --mutations, --private-key, --submission-private-key, and --output are required")
			}
			source, ok := graderSourceIdentity()
			if !ok {
				return fmt.Errorf("exact full grader source digest is unavailable")
			}
			token, err := tokenFor("")
			if err != nil {
				return fmt.Errorf("compact attestation requires TWINET_TOKEN from the environment or protected credential file: %w", err)
			}
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
			}
			if top.Lab.Images.LockDigest == "" {
				return fmt.Errorf("compact attestation requires a grading/release manifest with a verified image lock")
			}
			if rubricPath == "" {
				rubricPath, err = defaultRubric(top.Lab.Dir)
				if err != nil {
					return err
				}
			}
			rubric, err := grade.LoadRubric(rubricPath)
			if err != nil {
				return err
			}
			if err := rubric.ValidateTopology(top); err != nil {
				return err
			}
			suiteRaw, suiteDigest, err := readSHA256File(suitePath)
			if err != nil {
				return fmt.Errorf("read mutation suite: %w", err)
			}
			suite, err := harness.ParseMutationSuite(suiteRaw)
			if err != nil {
				return fmt.Errorf("load mutation suite: %w", err)
			}
			coverage := compactCoverage(rubric)
			if err := suite.Validate(coverage); err != nil {
				return fmt.Errorf("mutation coverage: %w", err)
			}
			key, err := loadCompactAttestationPrivateKey(keyPath)
			if err != nil {
				return err
			}
			submissionKey, err := loadExistingEd25519PrivateKey(submissionKeyPath, "submission")
			if err != nil {
				return err
			}
			if err := ensureDistinctAttestationKeys(key, submissionKey); err != nil {
				return err
			}
			referenceSubmission, referenceRaw, referenceDigest, err := attestedReferenceSubmission(
				reference, top, submissionKey.Public().(ed25519.PublicKey))
			if err != nil {
				return fmt.Errorf("read signed reference archive: %w", err)
			}
			opts := batchOpts{token: token, keepHosts: true, converge: converge, settle: settle,
				compact: true, auditHash: "attestation-in-progress"}
			attestation, evidenceDir, err := runCompactAttestationSuite(
				cmd.Context(), top, rubric, suite, suiteRaw, suiteDigest,
				referenceSubmission, referenceRaw, referenceDigest,
				key, submissionKey, source, outPath, opts,
			)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
				"attestation": outPath, "evidence": evidenceDir, "hash": attestation.Hash(),
				"cases": len(attestation.Audit.Records),
			})
		}}
	attest.Flags().StringVar(&rubricPath, "rubric", "", "rubric path")
	attest.Flags().StringVar(&reference, "reference", "", "genuine signed reference submission archive")
	attest.Flags().StringVar(&suitePath, "mutations", "", "versioned mutation suite YAML")
	attest.Flags().StringVar(&keyPath, "private-key", "", "0600 Ed25519 private key for attestation signing")
	attest.Flags().StringVar(&submissionKeyPath, "submission-private-key", "", "existing 0600 Ed25519 key used to re-sign mutation bundles")
	attest.Flags().StringVar(&outPath, "output", "", "output signed attestation JSON")
	attest.Flags().DurationVar(&converge, "converge-timeout", 3*time.Minute, "per-case convergence timeout")
	attest.Flags().DurationVar(&settle, "settle", 0, "optional fixed settle duration")
	return attest
}

func runCompactAttestationSuite(ctx context.Context, top *model.Topology, rubric *grade.Rubric,
	suite *harness.MutationSuite, suiteRaw []byte, suiteDigest string,
	referenceSubmission submission, referenceRaw []byte, referenceDigest string,
	attestationKey, submissionKey ed25519.PrivateKey, source, outPath string, opts batchOpts,
) (harness.Attestation, string, error) {
	if top == nil || top.Lab == nil || rubric == nil || suite == nil {
		return harness.Attestation{}, "", fmt.Errorf("attestation suite needs topology, rubric, and mutation suite")
	}
	if top.Lab.Images.LockDigest == "" {
		return harness.Attestation{}, "", fmt.Errorf("attestation suite needs a verified image lock")
	}
	if err := ensureDistinctAttestationKeys(attestationKey, submissionKey); err != nil {
		return harness.Attestation{}, "", err
	}
	coverage := compactCoverage(rubric)
	if err := suite.Validate(coverage); err != nil {
		return harness.Attestation{}, "", fmt.Errorf("mutation coverage: %w", err)
	}
	evidence, err := newCompactAttestationEvidence(outPath)
	if err != nil {
		return harness.Attestation{}, "", err
	}
	published := false
	defer func() {
		if !published {
			_ = evidence.Discard()
		}
	}()
	suiteArtifact, err := evidence.Write("mutation-suite.yaml", suiteRaw, 0)
	if err != nil {
		return harness.Attestation{}, "", err
	}
	if suiteArtifact.SHA256 != suiteDigest {
		return harness.Attestation{}, "", fmt.Errorf("mutation suite evidence digest changed while staging")
	}
	referenceArtifact, err := evidence.Write("mutations/reference.tar.gz", referenceRaw, 0)
	if err != nil {
		return harness.Attestation{}, "", err
	}
	if referenceArtifact.SHA256 != referenceDigest {
		return harness.Attestation{}, "", fmt.Errorf("reference archive evidence digest changed while staging")
	}

	opts.outDir = evidence.StagingDir()
	cases := []harness.AuditCase{{Name: "reference", ExpectedClass: "full"}}
	fixtures := map[string]harness.MutationCase{}
	for _, fixture := range suite.Cases {
		cases = append(cases, harness.AuditCase{
			Name: fixture.Name, Required: fixture.Required,
			ExpectedClass: "partial", ExpectedCheckStatus: fixture.ExpectedCheckStatus,
		})
		fixtures[fixture.Name] = fixture
	}
	mutations := cases[1:]
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].Name < mutations[j].Name })

	runner, err := newCompactAttestRunner(ctx, top, rubric, opts, referenceSubmission.AS)
	if err != nil {
		return harness.Attestation{}, "", fmt.Errorf("create reusable audit harnesses: %w", err)
	}
	runnerClosed := false
	cleanupTimeout := warmHarnessCleanupTimeout(len(top.Devices))
	defer func() {
		if !runnerClosed {
			closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
			defer cancel()
			_ = runner.Close(closeCtx)
		}
	}()

	type caseArtifacts struct {
		mutation harness.EvidenceArtifact
		full     harness.EvidenceArtifact
		compact  harness.EvidenceArtifact
	}
	reports := map[string]compactAttestResult{}
	artifacts := map[string]caseArtifacts{}
	for _, auditCase := range cases {
		sub := cloneSubmission(referenceSubmission)
		mutationArtifact := referenceArtifact
		if auditCase.Name != "reference" {
			if err := applyMutationCase(&sub, fixtures[auditCase.Name]); err != nil {
				return harness.Attestation{}, "", fmt.Errorf("mutation %s: %w", auditCase.Name, err)
			}
			relative := filepath.ToSlash(filepath.Join("mutations", auditCase.Name+".tar.gz"))
			archivePath := evidence.Path(relative)
			if err := writeSignedSubmissionBundle(archivePath, top, sub, submissionKey); err != nil {
				return harness.Attestation{}, "", fmt.Errorf("write mutation %s: %w", auditCase.Name, err)
			}
			mutationArtifact, err = evidence.File(relative, 0)
			if err != nil {
				return harness.Attestation{}, "", fmt.Errorf("digest mutation %s: %w", auditCase.Name, err)
			}
			verified, err := attestedMutationSubmission(archivePath, top, submissionKey.Public().(ed25519.PublicKey))
			if err != nil {
				return harness.Attestation{}, "", fmt.Errorf("verify signed mutation %s: %w", auditCase.Name, err)
			}
			sub = verified
		}
		result, err := runner.Run(ctx, sub, auditCase.Name)
		if err != nil {
			return harness.Attestation{}, "", fmt.Errorf("grade mutation %s: %w", auditCase.Name, err)
		}
		if result.Full == nil || result.Compact == nil {
			return harness.Attestation{}, "", fmt.Errorf("grade mutation %s returned an incomplete report pair", auditCase.Name)
		}
		fullArtifact, err := evidence.Report(auditCase.Name, "full", result.Full, result.FullDuration)
		if err != nil {
			return harness.Attestation{}, "", fmt.Errorf("retain full report for %s: %w", auditCase.Name, err)
		}
		compactArtifact, err := evidence.Report(auditCase.Name, "compact", result.Compact, result.CompactDuration)
		if err != nil {
			return harness.Attestation{}, "", fmt.Errorf("retain compact report for %s: %w", auditCase.Name, err)
		}
		reports[auditCase.Name] = result
		artifacts[auditCase.Name] = caseArtifacts{
			mutation: mutationArtifact, full: fullArtifact, compact: compactArtifact,
		}
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	err = runner.Close(closeCtx)
	cancel()
	runnerClosed = true
	if err != nil {
		return harness.Attestation{}, "", fmt.Errorf("destroy reusable audit harnesses: %w", err)
	}

	fullIdentity := &model.Topology{Name: "full-audit"}
	compactIdentity := &model.Topology{Name: "compact-audit"}
	audit, err := harness.AuditEquivalence(ctx, fullIdentity, compactIdentity, cases,
		func(_ context.Context, candidate *model.Topology, auditCase harness.AuditCase) (harness.AuditScore, error) {
			pair, ok := reports[auditCase.Name]
			if !ok {
				return harness.AuditScore{}, fmt.Errorf("missing retained reports for %s", auditCase.Name)
			}
			if candidate == fullIdentity {
				return reportAuditScore(pair.Full, rubric), nil
			}
			return reportAuditScore(pair.Compact, rubric), nil
		})
	if err != nil {
		return harness.Attestation{}, "", err
	}
	if !audit.Equivalent {
		return harness.Attestation{}, "", fmt.Errorf("compact equivalence audit did not pass")
	}
	for index := range audit.Records {
		recordArtifacts, ok := artifacts[audit.Records[index].Case.Name]
		if !ok {
			return harness.Attestation{}, "", fmt.Errorf("missing retained evidence for %s", audit.Records[index].Case.Name)
		}
		audit.Records[index].MutationBundle = recordArtifacts.mutation
		audit.Records[index].FullReport = recordArtifacts.full
		audit.Records[index].SyntheticReport = recordArtifacts.compact
	}
	attestation := harness.Attestation{
		TopologyHash: top.Hash, RubricHash: compactRubricHash(rubric),
		CompilerVersion: harness.CompactCompilerContract, ControllerVersion: Version, ControllerCommit: Commit,
		GraderSource: source, ImageLock: top.Lab.Images.LockDigest,
		MutationSuiteDigest: suiteDigest, ReferenceBundleDigest: referenceDigest,
		EvidenceDir: evidence.Name(), Coverage: coverage, Audit: audit,
	}
	if err := attestation.Sign(attestationKey); err != nil {
		return harness.Attestation{}, "", err
	}
	if err := evidence.Publish(); err != nil {
		return harness.Attestation{}, "", err
	}
	if err := attestation.VerifyEvidence(filepath.Dir(outPath)); err != nil {
		return harness.Attestation{}, "", fmt.Errorf("verify retained audit evidence: %w", err)
	}
	if err := writeCompactAttestation(outPath, attestation); err != nil {
		return harness.Attestation{}, "", err
	}
	published = true
	return attestation, evidence.FinalDir(), nil
}

func applyMutationCase(sub *submission, mutation harness.MutationCase) error {
	changed := false
	for _, transform := range mutation.Transforms {
		var body *string
		switch {
		case transform.File == "roas.json":
			value := string(sub.ROAs)
			body = &value
		case strings.HasSuffix(transform.File, ".conf"):
			name := strings.TrimSuffix(transform.File, ".conf")
			value, ok := sub.Files[name]
			if !ok {
				return fmt.Errorf("fixture file %s is absent from signed reference", transform.File)
			}
			body = &value
		case strings.HasSuffix(transform.File, ".sh"):
			name := strings.TrimSuffix(transform.File, ".sh")
			value, ok := sub.Scripts[name]
			if !ok {
				return fmt.Errorf("fixture file %s is absent from signed reference", transform.File)
			}
			body = &value
		default:
			return fmt.Errorf("unsupported fixture file %s", transform.File)
		}
		before := *body
		if transform.Find != "" {
			if !strings.Contains(*body, transform.Find) {
				return fmt.Errorf("fixture %s did not find required text in %s", mutation.Name, transform.File)
			}
			*body = strings.Replace(*body, transform.Find, transform.Replace, 1)
		}
		if transform.Append != "" {
			if !strings.HasSuffix(*body, "\n") {
				*body += "\n"
			}
			*body += transform.Append + "\n"
		}
		if *body == before {
			return fmt.Errorf("fixture %s left %s unchanged", mutation.Name, transform.File)
		}
		changed = true
		switch {
		case transform.File == "roas.json":
			sub.ROAs = []byte(*body)
		case strings.HasSuffix(transform.File, ".conf"):
			sub.Files[strings.TrimSuffix(transform.File, ".conf")] = *body
		case strings.HasSuffix(transform.File, ".sh"):
			sub.Scripts[strings.TrimSuffix(transform.File, ".sh")] = *body
		}
	}
	if !changed {
		return fmt.Errorf("fixture %s has no effective state transformation", mutation.Name)
	}
	return nil
}

func cloneSubmission(in submission) submission {
	out := in
	out.Files = map[string]string{}
	for name, body := range in.Files {
		out.Files[name] = body
	}
	out.Scripts = map[string]string{}
	for name, body := range in.Scripts {
		out.Scripts[name] = body
	}
	out.ROAs = append([]byte(nil), in.ROAs...)
	return out
}

type warmCompactAttestRunner struct {
	full    compactAttestWarmManager
	compact compactAttestWarmManager
}

type compactAttestWarmManager interface {
	grade(context.Context, submission) *grade.Report
	close(context.Context) error
}

func newWarmCompactAttestRunner(ctx context.Context, top *model.Topology, rubric *grade.Rubric,
	opts batchOpts, asn int,
) (compactAttestRunner, error) {
	fullOpts := opts
	fullOpts.fullHarness = true
	fullOpts.compact = false
	fullOpts.warmNamespace = "attest-full"
	compactOpts := opts
	compactOpts.fullHarness = false
	compactOpts.compact = true
	compactOpts.warmNamespace = "attest-compact"

	workers := map[int]int{asn: 1}
	fullManager := newWarmBatchManager(top, rubric, fullOpts, workers)
	compactManager := newWarmBatchManager(top, rubric, compactOpts, workers)
	runner := &warmCompactAttestRunner{full: fullManager, compact: compactManager}
	if _, err := fullManager.pool(ctx, asn); err != nil {
		return nil, fmt.Errorf("deploy full warm audit harness: %w", err)
	}
	if _, err := compactManager.pool(ctx, asn); err != nil {
		closeCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), warmHarnessCleanupTimeout(len(top.Devices)),
		)
		defer cancel()
		_ = fullManager.close(closeCtx)
		return nil, fmt.Errorf("deploy compact warm audit harness: %w", err)
	}
	return runner, nil
}

func (r *warmCompactAttestRunner) Run(ctx context.Context, sub submission, _ string) (compactAttestResult, error) {
	started := time.Now()
	full := r.full.grade(ctx, sub)
	fullDuration := time.Since(started)
	started = time.Now()
	compact := r.compact.grade(ctx, sub)
	compactDuration := time.Since(started)
	if full == nil || compact == nil {
		return compactAttestResult{}, fmt.Errorf("warm audit runner produced a nil report")
	}
	return compactAttestResult{
		Full: full, Compact: compact, FullDuration: fullDuration, CompactDuration: compactDuration,
	}, nil
}

func (r *warmCompactAttestRunner) Close(ctx context.Context) error {
	if err := r.full.close(ctx); err != nil {
		_ = r.compact.close(context.WithoutCancel(ctx))
		return fmt.Errorf("close full warm audit harness: %w", err)
	}
	if err := r.compact.close(ctx); err != nil {
		return fmt.Errorf("close compact warm audit harness: %w", err)
	}
	return nil
}

func reportAuditScore(report *grade.Report, rubric *grade.Rubric) harness.AuditScore {
	out := harness.AuditScore{Total: report.Total, MaxTotal: report.MaxTotal,
		NeedsReview: report.NeedsReview || report.Err != "", CheckClasses: map[string]string{},
		QuestionScores: map[string]float64{}, QuestionPoints: map[string]float64{}, CheckScores: map[string]float64{}}
	for _, question := range report.Questions {
		out.QuestionScores[question.ID] = question.Awarded
		out.QuestionPoints[question.ID] = question.Points
		for index, result := range question.Results {
			key := harness.CoverageRequirement{QuestionID: question.ID, CheckID: result.Check, CheckIndex: index}.Key()
			out.CheckClasses[key] = string(result.Status)
			out.CheckScores[key] = result.Score
		}
	}
	return out
}

type compactAttestationEvidence struct {
	finalDir   string
	stagingDir string
	published  bool
	written    map[string]bool
}

func newCompactAttestationEvidence(outPath string) (*compactAttestationEvidence, error) {
	parent := filepath.Dir(outPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	finalDir := outPath + ".evidence"
	stagingDir := finalDir + ".staging"
	for _, path := range []string{outPath, finalDir, stagingDir} {
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("refusing to replace existing attestation artifact %s", path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		return nil, err
	}
	return &compactAttestationEvidence{
		finalDir: finalDir, stagingDir: stagingDir, written: map[string]bool{},
	}, nil
}

func (e *compactAttestationEvidence) Name() string {
	return filepath.Base(e.finalDir)
}

func (e *compactAttestationEvidence) FinalDir() string {
	return e.finalDir
}

func (e *compactAttestationEvidence) StagingDir() string {
	return e.stagingDir
}

func (e *compactAttestationEvidence) Path(relative string) string {
	return filepath.Join(e.stagingDir, filepath.FromSlash(relative))
}

func (e *compactAttestationEvidence) Write(relative string, raw []byte,
	duration time.Duration,
) (harness.EvidenceArtifact, error) {
	if !safeEvidenceRelativePath(relative) {
		return harness.EvidenceArtifact{}, fmt.Errorf("unsafe evidence path %q", relative)
	}
	if e.written[relative] {
		return harness.EvidenceArtifact{}, fmt.Errorf("duplicate evidence path %s", relative)
	}
	path := e.Path(relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return harness.EvidenceArtifact{}, err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return harness.EvidenceArtifact{}, err
	}
	e.written[relative] = true
	return evidenceArtifact(relative, raw, duration), nil
}

func (e *compactAttestationEvidence) File(relative string,
	duration time.Duration,
) (harness.EvidenceArtifact, error) {
	if !safeEvidenceRelativePath(relative) {
		return harness.EvidenceArtifact{}, fmt.Errorf("unsafe evidence path %q", relative)
	}
	if e.written[relative] {
		return harness.EvidenceArtifact{}, fmt.Errorf("duplicate evidence path %s", relative)
	}
	raw, err := os.ReadFile(e.Path(relative))
	if err != nil {
		return harness.EvidenceArtifact{}, err
	}
	e.written[relative] = true
	return evidenceArtifact(relative, raw, duration), nil
}

func (e *compactAttestationEvidence) Report(caseName, mode string, report *grade.Report,
	duration time.Duration,
) (harness.EvidenceArtifact, error) {
	if report == nil {
		return harness.EvidenceArtifact{}, fmt.Errorf("nil %s report for %s", mode, caseName)
	}
	raw, err := report.JSON()
	if err != nil {
		return harness.EvidenceArtifact{}, err
	}
	return e.Write(filepath.ToSlash(filepath.Join("reports", caseName, mode+".json")), raw, duration)
}

func (e *compactAttestationEvidence) Publish() error {
	if e.published {
		return fmt.Errorf("attestation evidence was already published")
	}
	if err := os.Rename(e.stagingDir, e.finalDir); err != nil {
		return err
	}
	e.published = true
	return nil
}

func (e *compactAttestationEvidence) Discard() error {
	if e == nil {
		return nil
	}
	if e.published {
		return os.RemoveAll(e.finalDir)
	}
	return os.RemoveAll(e.stagingDir)
}

func evidenceArtifact(relative string, raw []byte, duration time.Duration) harness.EvidenceArtifact {
	sum := sha256.Sum256(raw)
	return harness.EvidenceArtifact{
		Path: relative, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw)),
		DurationMillis: duration.Milliseconds(),
	}
}

func safeEvidenceRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	return filepath.ToSlash(clean) == value
}

func readSHA256File(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func bundleSignatureFromArchive(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return "", fmt.Errorf("archive has no manifest.json")
			}
			return "", fmt.Errorf("find signed manifest: %w", err)
		}
		if header.Typeflag != tar.TypeReg || header.Name != "manifest.json" {
			continue
		}
		var manifest struct {
			Signature string `json:"signature"`
		}
		if err := json.NewDecoder(tr).Decode(&manifest); err != nil {
			return "", fmt.Errorf("decode signed manifest: %w", err)
		}
		if manifest.Signature == "" {
			return "", fmt.Errorf("archive manifest has no signature")
		}
		return manifest.Signature, nil
	}
}

func verifyArchiveSignedBy(path string, public ed25519.PublicKey) error {
	bundle, _, err := readBundle(path)
	if err != nil {
		return err
	}
	signature, err := bundleSignatureFromArchive(path)
	if err != nil {
		return err
	}
	if !verifyBundle(bundle, signature, public) {
		return fmt.Errorf("archive signature does not match --submission-private-key public key")
	}
	return nil
}

func attestedReferenceSubmission(path string, top *model.Topology,
	public ed25519.PublicKey,
) (submission, []byte, string, error) {
	raw, digest, err := readSHA256File(path)
	if err != nil {
		return submission{}, nil, "", err
	}
	if err := verifyArchiveSignedBy(path, public); err != nil {
		return submission{}, nil, "", err
	}
	sub, err := submissionFromArchive(path, top)
	if err != nil {
		return submission{}, nil, "", err
	}
	_, after, err := readSHA256File(path)
	if err != nil {
		return submission{}, nil, "", err
	}
	if after != digest {
		return submission{}, nil, "", fmt.Errorf("archive changed while signature and topology checks ran")
	}
	return sub, raw, digest, nil
}

func attestedMutationSubmission(path string, top *model.Topology,
	public ed25519.PublicKey,
) (submission, error) {
	if err := verifyArchiveSignedBy(path, public); err != nil {
		return submission{}, err
	}
	return submissionFromArchive(path, top)
}

func loadCompactAttestationPrivateKey(path string) (ed25519.PrivateKey, error) {
	return loadExistingEd25519PrivateKey(path, "attestation")
}

func loadExistingEd25519PrivateKey(path, purpose string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s private key %s must not be group/world readable", purpose, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s private key is not PEM", purpose)
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s private key is not Ed25519", purpose)
	}
	return key, nil
}

func ensureDistinctAttestationKeys(attestation, submission ed25519.PrivateKey) error {
	if bytes.Equal(attestation, submission) {
		return fmt.Errorf("attestation and submission signing keys must be separate")
	}
	return nil
}

func writeCompactAttestation(path string, attestation harness.Attestation) error {
	raw, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to replace existing compact attestation %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	staged := path + ".new"
	file, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(staged) }()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(staged, path)
}

func writeSignedSubmissionBundle(path string, top *model.Topology, sub submission, key ed25519.PrivateKey) error {
	files := map[string][]byte{}
	for name, body := range sub.Files {
		files[name+".conf"] = []byte(body)
	}
	for name, body := range sub.Scripts {
		files[name+".sh"] = []byte(body)
	}
	if len(sub.ROAs) > 0 {
		files["roas.json"] = append([]byte(nil), sub.ROAs...)
	}
	takenAt := sub.TakenAt.UTC()
	if takenAt.IsZero() {
		takenAt = time.Unix(0, 0).UTC()
	}
	controller := sub.Controller
	if controller == "" {
		controller = Version
	}
	bundle := Bundle{Lab: top.Name, AS: sub.AS, Group: sub.Group, Attempt: sub.Attempt, Topology: top.Hash,
		Controller: controller, ImageLock: top.Lab.Images.LockDigest, TakenAt: takenAt, Files: map[string]string{}}
	for name, body := range files {
		sum := sha256.Sum256(body)
		bundle.Files[name] = hex.EncodeToString(sum[:])
	}
	meta, err := bundleJSON(bundle, signBundle(bundle, key))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	if err := writeDeterministicTar(tw, "manifest.json", meta); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeDeterministicTar(tw, name, files[name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeDeterministicTar(tw *tar.Writer, name string, body []byte) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC(),
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}
