package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

const benchmarkPlanSchemaVersion = 1

// BenchmarkPlan binds a release-scale expected-outcome plan to exact archive
// bytes. It deliberately describes expected score classes and designated
// check outcomes, rather than embedding fabricated grade reports.
type BenchmarkPlan struct {
	SchemaVersion          int                           `json:"schema_version"`
	TopologyHash           string                        `json:"topology_hash"`
	RubricHash             string                        `json:"rubric_hash"`
	MutationSuiteSHA256    string                        `json:"mutation_suite_sha256"`
	ImageLock              string                        `json:"image_lock"`
	GraderSource           string                        `json:"grader_source"`
	ReferenceArchiveSHA256 string                        `json:"reference_archive_sha256"`
	EquivalenceAuditHash   string                        `json:"equivalence_audit_hash"`
	Archives               map[string]BenchmarkPlanEntry `json:"archives"`
}

type BenchmarkPlanEntry struct {
	Submission         string                   `json:"submission"`
	Attempt            string                   `json:"attempt"`
	AS                 int                      `json:"as"`
	Variant            string                   `json:"variant"`
	ExpectedTotalClass grade.ScoreClass         `json:"expected_total_class"`
	ExpectedTotal      *float64                 `json:"expected_total,omitempty"`
	ExpectedChecks     []BenchmarkExpectedCheck `json:"expected_checks"`
}

type BenchmarkExpectedCheck struct {
	QuestionID string       `json:"question_id"`
	CheckID    string       `json:"check_id"`
	CheckIndex int          `json:"check_index"`
	Status     grade.Status `json:"status"`
}

func (p BenchmarkPlan) Validate() error {
	if p.SchemaVersion != benchmarkPlanSchemaVersion {
		return fmt.Errorf("benchmark plan schema_version %d, want %d", p.SchemaVersion, benchmarkPlanSchemaVersion)
	}
	if p.TopologyHash == "" || p.RubricHash == "" || p.ImageLock == "" ||
		!benchmarkSHA256(p.MutationSuiteSHA256) || !benchmarkSHA256(p.GraderSource) ||
		!benchmarkSHA256(p.ReferenceArchiveSHA256) {
		return fmt.Errorf("benchmark plan has an invalid topology, rubric, image, suite, source, or reference identity")
	}
	if !benchmarkSHA256(p.EquivalenceAuditHash) {
		return fmt.Errorf("benchmark plan has no valid equivalence audit hash")
	}
	if len(p.Archives) == 0 {
		return fmt.Errorf("benchmark plan has no archives")
	}
	identities := map[string]bool{}
	for digest, entry := range p.Archives {
		if !benchmarkSHA256(digest) || entry.Submission == "" || !validAttempt(entry.Attempt) || entry.AS < 1 {
			return fmt.Errorf("benchmark plan has an invalid archive identity %q", digest)
		}
		identity := strings.ToLower(entry.Submission) + "\x00" + strings.ToLower(entry.Attempt)
		if identities[identity] {
			return fmt.Errorf("benchmark plan repeats submission attempt %s", entry.Submission+"--"+entry.Attempt)
		}
		identities[identity] = true
		switch entry.ExpectedTotalClass {
		case grade.ScoreClassFull, grade.ScoreClassPartial, grade.ScoreClassZero:
		default:
			return fmt.Errorf("%s has invalid expected total class %q", digest, entry.ExpectedTotalClass)
		}
		if entry.ExpectedTotal != nil && *entry.ExpectedTotal < 0 {
			return fmt.Errorf("%s has a negative expected total", digest)
		}
		if len(entry.ExpectedChecks) == 0 {
			return fmt.Errorf("%s has no expected check classes", digest)
		}
		seenChecks := map[string]bool{}
		for _, check := range entry.ExpectedChecks {
			if check.QuestionID == "" || check.CheckID == "" || check.CheckIndex < 0 || check.Status == "" {
				return fmt.Errorf("%s has an incomplete expected check", digest)
			}
			switch check.Status {
			case grade.StatusPass, grade.StatusFail, grade.StatusPartial, grade.StatusSkipped, grade.StatusNotApplicable:
			default:
				return fmt.Errorf("%s has invalid expected check status %q", digest, check.Status)
			}
			key := fmt.Sprintf("%s/%s[%d]", check.QuestionID, check.CheckID, check.CheckIndex)
			if seenChecks[key] {
				return fmt.Errorf("%s repeats expected check %s", digest, key)
			}
			seenChecks[key] = true
		}
	}
	return nil
}

func benchmarkSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func newGradeBenchmarkCmd(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "benchmark",
		Short: "Generate and validate deterministic grading benchmark artifacts",
	}
	cmd.AddCommand(newGradeBenchmarkGenerateCmd(opts))
	return cmd
}

func newGradeBenchmarkGenerateCmd(opts *Options) *cobra.Command {
	var (
		rubricPath           string
		reference            string
		suitePath            string
		submissionKeyPath    string
		outputDir            string
		planPath             string
		count                int
		equivalenceAuditHash string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate deterministic signed benchmark submission archives",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reference == "" || suitePath == "" || submissionKeyPath == "" || outputDir == "" || planPath == "" {
				return fmt.Errorf("--reference, --mutations, --submission-private-key, --output, and --plan are required")
			}
			if count < 1 {
				return fmt.Errorf("--count must be positive")
			}
			if !benchmarkSHA256(equivalenceAuditHash) {
				return fmt.Errorf("--equivalence-audit-hash must be a non-empty SHA-256")
			}
			graderSource, ok := graderSourceIdentity()
			if !ok {
				return fmt.Errorf("exact full grader source digest is unavailable")
			}
			if grade.GraderSource != graderSource {
				return fmt.Errorf("grade report source digest %q does not match controller source digest %q",
					grade.GraderSource, graderSource)
			}
			top, err := loadAndPlace(opts)
			if err != nil {
				return err
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
				return fmt.Errorf("parse mutation suite: %w", err)
			}
			if err := suite.Validate(compactCoverage(rubric)); err != nil {
				return fmt.Errorf("mutation coverage: %w", err)
			}
			key, err := loadExistingEd25519PrivateKey(submissionKeyPath, "submission")
			if err != nil {
				return err
			}
			referenceSubmission, _, referenceDigest, err := attestedReferenceSubmission(
				reference, top, key.Public().(ed25519.PublicKey))
			if err != nil {
				return fmt.Errorf("read signed reference archive: %w", err)
			}
			plan, err := generateBenchmarkArtifacts(top, rubric, suite, referenceSubmission,
				suiteDigest, referenceDigest, graderSource, key, count, outputDir, equivalenceAuditHash)
			if err != nil {
				return err
			}
			if err := finalizeBenchmarkGeneration(outputDir, planPath, plan); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
				"output": outputDir, "plan": planPath, "count": len(plan.Archives),
				"mutation_suite_sha256": suiteDigest,
			})
		},
	}
	cmd.Flags().StringVar(&rubricPath, "rubric", "", "rubric path")
	cmd.Flags().StringVar(&reference, "reference", "", "genuine signed reference submission archive")
	cmd.Flags().StringVar(&suitePath, "mutations", "", "versioned mutation suite YAML")
	cmd.Flags().StringVar(&submissionKeyPath, "submission-private-key", "", "existing 0600 Ed25519 key for benchmark archives")
	cmd.Flags().IntVar(&count, "count", 100, "number of deterministic benchmark archives")
	cmd.Flags().StringVar(&outputDir, "output", "", "new directory for generated tar.gz archives")
	cmd.Flags().StringVar(&planPath, "plan", "", "machine-readable expected-score plan JSON")
	cmd.Flags().StringVar(&equivalenceAuditHash, "equivalence-audit-hash", "",
		"required verified compact attestation SHA-256 expected in every benchmark report")
	return cmd
}

func generateBenchmarkArtifacts(top *model.Topology, rubric *grade.Rubric, suite *harness.MutationSuite,
	reference submission, suiteDigest, referenceDigest, graderSource string,
	key ed25519.PrivateKey, count int,
	outputDir, equivalenceAuditHash string,
) (BenchmarkPlan, error) {
	if top == nil || top.Lab == nil || rubric == nil || suite == nil {
		return BenchmarkPlan{}, fmt.Errorf("benchmark generation needs topology, rubric, and mutation suite")
	}
	if count < 1 {
		return BenchmarkPlan{}, fmt.Errorf("benchmark count must be positive")
	}
	if err := suite.Validate(compactCoverage(rubric)); err != nil {
		return BenchmarkPlan{}, err
	}
	if !benchmarkSHA256(suiteDigest) || !benchmarkSHA256(referenceDigest) ||
		!benchmarkSHA256(graderSource) || !benchmarkSHA256(equivalenceAuditHash) {
		return BenchmarkPlan{}, fmt.Errorf("benchmark generation needs exact suite, reference, source, and attestation SHA-256 values")
	}
	if top.Lab.Images.LockDigest == "" {
		return BenchmarkPlan{}, fmt.Errorf("benchmark generation requires a verified image lock")
	}
	if _, err := os.Stat(outputDir); err == nil {
		return BenchmarkPlan{}, fmt.Errorf("benchmark output directory already exists: %s", outputDir)
	} else if !os.IsNotExist(err) {
		return BenchmarkPlan{}, err
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return BenchmarkPlan{}, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(outputDir)
		}
	}()

	type variant struct {
		name     string
		mutation *harness.MutationCase
	}
	variants := []variant{{name: "reference"}}
	mutations := append([]harness.MutationCase(nil), suite.Cases...)
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].Name < mutations[j].Name })
	for index := range mutations {
		variants = append(variants, variant{name: mutations[index].Name, mutation: &mutations[index]})
	}
	width := len(strconv.Itoa(count - 1))
	if width < 3 {
		width = 3
	}
	plan := BenchmarkPlan{
		SchemaVersion: benchmarkPlanSchemaVersion, TopologyHash: top.Hash,
		RubricHash: compactRubricHash(rubric), MutationSuiteSHA256: suiteDigest,
		ImageLock: top.Lab.Images.LockDigest, GraderSource: graderSource,
		ReferenceArchiveSHA256: referenceDigest,
		EquivalenceAuditHash:   equivalenceAuditHash, Archives: map[string]BenchmarkPlanEntry{},
	}
	for index := 0; index < count; index++ {
		current := variants[index%len(variants)]
		sub := cloneSubmission(reference)
		sub.Attempt = fmt.Sprintf("benchmark-%0*d", width, index)
		if current.mutation != nil {
			if err := applyMutationCase(&sub, *current.mutation); err != nil {
				return BenchmarkPlan{}, fmt.Errorf("apply benchmark mutation %s: %w", current.name, err)
			}
		}
		archivePath := filepath.Join(outputDir, sub.Attempt+".tar.gz")
		if err := writeSignedSubmissionBundle(archivePath, top, sub, key); err != nil {
			return BenchmarkPlan{}, fmt.Errorf("write %s: %w", sub.Attempt, err)
		}
		raw, err := os.ReadFile(archivePath)
		if err != nil {
			return BenchmarkPlan{}, err
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if _, duplicate := plan.Archives[digest]; duplicate {
			return BenchmarkPlan{}, fmt.Errorf("benchmark archive digest collision for %s", sub.Attempt)
		}
		entry := BenchmarkPlanEntry{
			Submission: sub.Group, Attempt: sub.Attempt, AS: sub.AS, Variant: current.name,
			ExpectedTotalClass: grade.ScoreClassFull,
			ExpectedChecks:     benchmarkExpectedChecks(rubric, current.mutation),
		}
		if current.mutation == nil {
			total := rubric.MaxTotal()
			entry.ExpectedTotal = &total
		} else {
			entry.ExpectedTotalClass = grade.ScoreClassPartial
		}
		plan.Archives[digest] = entry
	}
	if err := plan.Validate(); err != nil {
		return BenchmarkPlan{}, err
	}
	ok = true
	return plan, nil
}

func benchmarkExpectedChecks(rubric *grade.Rubric,
	mutation *harness.MutationCase,
) []BenchmarkExpectedCheck {
	if mutation != nil {
		return []BenchmarkExpectedCheck{{
			QuestionID: mutation.Required.QuestionID, CheckID: mutation.Required.CheckID,
			CheckIndex: mutation.Required.CheckIndex, Status: grade.Status(mutation.ExpectedCheckStatus),
		}}
	}
	var out []BenchmarkExpectedCheck
	for _, question := range rubric.Questions {
		for index, check := range question.Checks {
			out = append(out, BenchmarkExpectedCheck{
				QuestionID: question.ID, CheckID: check.Check, CheckIndex: index, Status: grade.StatusPass,
			})
		}
	}
	return out
}

func writeBenchmarkPlan(path string, plan BenchmarkPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to replace existing benchmark plan %s", path)
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
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(staged, path)
}

func finalizeBenchmarkGeneration(outputDir, planPath string, plan BenchmarkPlan) error {
	if err := writeBenchmarkPlan(planPath, plan); err != nil {
		_ = os.RemoveAll(outputDir)
		return err
	}
	return nil
}
