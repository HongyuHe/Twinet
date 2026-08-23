package harness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Attestation is a release-gate artifact proving that compact harness scoring
// matched full harness scoring for the deterministic reference and mutation
// suite. It is keyed to every input capable of changing a mark.
type Attestation struct {
	TopologyHash    string `json:"topology_hash"`
	RubricHash      string `json:"rubric_hash"`
	CompilerVersion string `json:"compiler_version"`
	// ControllerVersion is human-facing release provenance (for example a
	// git-describe tag). It is signed but not used as the validity identity:
	// tags can be added to an unchanged commit after an attestation exists.
	ControllerVersion string `json:"controller_version,omitempty"`
	// ControllerCommit is signed human-facing Git provenance. GraderSource is
	// the validity identity because a source archive may not carry Git data.
	ControllerCommit string `json:"controller_commit,omitempty"`
	// GraderSource is the deterministic source-content digest. It is verified
	// in addition to the stable compiler contract: a grading-code change must
	// never reuse stale equivalence evidence.
	GraderSource          string `json:"grader_source"`
	ImageLock             string `json:"image_lock"`
	MutationSuiteDigest   string `json:"mutation_suite_digest"`
	ReferenceBundleDigest string `json:"reference_bundle_digest"`
	// EvidenceDir is a sibling directory of the signed attestation. It holds
	// the deterministic per-case inputs and reports named by Audit records.
	EvidenceDir string                `json:"evidence_dir"`
	Coverage    []CoverageRequirement `json:"coverage"`
	Audit       AuditResult           `json:"audit"`
	Signature   string                `json:"signature,omitempty"`
}

func (a Attestation) payload() ([]byte, error) {
	a.Signature = ""
	return json.Marshal(a)
}

// Sign attaches an Ed25519 signature to an already-complete audit artifact.
func (a *Attestation) Sign(key ed25519.PrivateKey) error {
	if a == nil {
		return fmt.Errorf("nil compact harness attestation")
	}
	if !a.Audit.Equivalent {
		return fmt.Errorf("cannot sign a non-equivalent compact harness audit")
	}
	if err := a.validateBoundInputs(); err != nil {
		return err
	}
	payload, err := a.payload()
	if err != nil {
		return err
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(key, payload))
	return nil
}

// Verify refuses unsigned, mismatched, or behaviorally incomplete attestations.
func (a Attestation) Verify(pub ed25519.PublicKey, topology, rubric, compiler, graderSource, imageLock string,
	requiredCoverage []CoverageRequirement,
) error {
	if !a.Audit.Equivalent || len(a.Audit.Records) == 0 {
		return fmt.Errorf("compact harness attestation contains no successful audit suite")
	}
	if a.TopologyHash != topology || a.RubricHash != rubric ||
		a.CompilerVersion != compiler || a.GraderSource != graderSource || a.ImageLock != imageLock {
		return fmt.Errorf("compact harness attestation does not match topology/rubric/compiler/image inputs")
	}
	if !validSourceDigest(a.GraderSource) {
		return fmt.Errorf("compact harness attestation has no full exact grader source digest")
	}
	if err := a.validateBoundInputs(); err != nil {
		return err
	}
	if err := verifyCoverage(a.Coverage, requiredCoverage, a.Audit.Records); err != nil {
		return err
	}
	raw, err := hex.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(pub, mustAttestationPayload(a), raw) {
		return fmt.Errorf("compact harness attestation signature is invalid")
	}
	return nil
}

func (a Attestation) validateBoundInputs() error {
	if !validSourceDigest(a.MutationSuiteDigest) {
		return fmt.Errorf("compact harness attestation has no mutation suite digest")
	}
	if !validSourceDigest(a.ReferenceBundleDigest) {
		return fmt.Errorf("compact harness attestation has no reference bundle digest")
	}
	if !safeRelativePath(a.EvidenceDir) {
		return fmt.Errorf("compact harness attestation has an unsafe evidence directory")
	}
	for _, record := range a.Audit.Records {
		for _, artifact := range []EvidenceArtifact{
			record.MutationBundle, record.FullReport, record.SyntheticReport,
		} {
			if err := validateEvidenceArtifact(artifact); err != nil {
				return fmt.Errorf("audit evidence for %q: %w", record.Case.Name, err)
			}
		}
	}
	var reference *AuditRecord
	for index := range a.Audit.Records {
		if a.Audit.Records[index].Case.Name == "reference" {
			reference = &a.Audit.Records[index]
			break
		}
	}
	if reference == nil || reference.MutationBundle.SHA256 != a.ReferenceBundleDigest {
		return fmt.Errorf("compact harness attestation reference bundle is not bound to its audit record")
	}
	return nil
}

func validSourceDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func validateEvidenceArtifact(artifact EvidenceArtifact) error {
	if !safeRelativePath(artifact.Path) {
		return fmt.Errorf("unsafe artifact path %q", artifact.Path)
	}
	if !validSourceDigest(artifact.SHA256) {
		return fmt.Errorf("missing SHA-256 for %s", artifact.Path)
	}
	if artifact.Bytes < 0 || artifact.DurationMillis < 0 {
		return fmt.Errorf("negative artifact metadata for %s", artifact.Path)
	}
	return nil
}

func safeRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	return filepath.ToSlash(clean) == value
}

// VerifyEvidence confirms the artifact bytes retained beside an attestation.
// It is separate from Verify because callers that only inspect a payload may
// not have its sibling evidence directory mounted.
func (a Attestation) VerifyEvidence(parent string) error {
	if err := a.validateBoundInputs(); err != nil {
		return err
	}
	root := filepath.Join(parent, filepath.FromSlash(a.EvidenceDir))
	suite, err := os.ReadFile(filepath.Join(root, "mutation-suite.yaml"))
	if err != nil {
		return fmt.Errorf("read mutation suite evidence: %w", err)
	}
	suiteSum := sha256.Sum256(suite)
	if hex.EncodeToString(suiteSum[:]) != a.MutationSuiteDigest {
		return fmt.Errorf("mutation suite evidence digest mismatch")
	}
	seen := map[string]bool{}
	for _, record := range a.Audit.Records {
		for _, artifact := range []EvidenceArtifact{
			record.MutationBundle, record.FullReport, record.SyntheticReport,
		} {
			if seen[artifact.Path] {
				return fmt.Errorf("audit evidence reuses artifact path %s", artifact.Path)
			}
			seen[artifact.Path] = true
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(artifact.Path)))
			if err != nil {
				return fmt.Errorf("read audit evidence %s: %w", artifact.Path, err)
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != artifact.SHA256 {
				return fmt.Errorf("audit evidence digest mismatch for %s", artifact.Path)
			}
			if int64(len(raw)) != artifact.Bytes {
				return fmt.Errorf("audit evidence size mismatch for %s", artifact.Path)
			}
		}
	}
	return nil
}

func verifyCoverage(attested, required []CoverageRequirement, records []AuditRecord) error {
	want := map[string]bool{}
	for _, item := range required {
		if !item.Valid() || want[item.Key()] {
			return fmt.Errorf("required rubric coverage is invalid or duplicated: %s", item.Key())
		}
		want[item.Key()] = true
	}
	got := map[string]bool{}
	for _, item := range attested {
		if !item.Valid() || got[item.Key()] {
			return fmt.Errorf("attested rubric coverage is invalid or duplicated: %s", item.Key())
		}
		got[item.Key()] = true
	}
	if len(got) != len(want) {
		return fmt.Errorf("attested rubric coverage count %d does not match required %d", len(got), len(want))
	}
	for key := range want {
		if !got[key] {
			return fmt.Errorf("attestation is missing required rubric coverage %s", key)
		}
	}
	seenRecord := map[string]bool{}
	references := 0
	for _, record := range records {
		required := record.Case.Required
		if required.QuestionID == "" && required.CheckID == "" {
			if record.Case.Name != "reference" || record.Case.ExpectedClass != "full" {
				return fmt.Errorf("audit has an invalid non-mutation case %q", record.Case.Name)
			}
			references++
			continue
		}
		if !required.Valid() || !got[required.Key()] || seenRecord[required.Key()] {
			return fmt.Errorf("audit records have missing or duplicate rubric coverage %s", required.Key())
		}
		seenRecord[required.Key()] = true
		if !record.Equal || record.Error != "" {
			return fmt.Errorf("audit record for %s is not equivalent", required.Key())
		}
		if err := validateMutationCoverage(record.Case, record.Full); err != nil {
			return fmt.Errorf("full audit record for %s: %w", required.Key(), err)
		}
		if err := validateMutationCoverage(record.Case, record.Synthetic); err != nil {
			return fmt.Errorf("compact audit record for %s: %w", required.Key(), err)
		}
	}
	for key := range want {
		if !seenRecord[key] {
			return fmt.Errorf("attestation has no mutation record for required coverage %s", key)
		}
	}
	if references != 1 {
		return fmt.Errorf("attestation must contain exactly one reference record, got %d", references)
	}
	return nil
}

func mustAttestationPayload(a Attestation) []byte {
	payload, err := a.payload()
	if err != nil {
		return nil
	}
	return payload
}

// Hash identifies the verified audit record in grading reports.
func (a Attestation) Hash() string {
	payload, err := a.payload()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
