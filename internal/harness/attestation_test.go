package harness

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

var testCoverage = []CoverageRequirement{{QuestionID: "q1.1", CheckID: "l2.vlan_isolation", CheckIndex: 0}}

const sourceA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const sourceB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const artifactDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func evidence(path, digest string) EvidenceArtifact {
	return EvidenceArtifact{Path: path, SHA256: digest}
}

func mutationScore(status string, awarded float64) AuditScore {
	key := testCoverage[0].Key()
	return AuditScore{
		Total: 8, MaxTotal: 10,
		CheckClasses:   map[string]string{key: status},
		QuestionScores: map[string]float64{"q1.1": awarded},
		QuestionPoints: map[string]float64{"q1.1": 1},
		CheckScores:    map[string]float64{key: awarded},
	}
}

func equivalentAudit() AuditResult {
	reference := AuditCase{Name: "reference", ExpectedClass: "full"}
	mutation := AuditCase{
		Name: "wrong-vlan", ExpectedClass: "partial", Required: testCoverage[0], ExpectedCheckStatus: "fail",
	}
	score := mutationScore("fail", 0)
	full := AuditScore{Total: 10, MaxTotal: 10, CheckClasses: map[string]string{}}
	return AuditResult{Equivalent: true, Records: []AuditRecord{
		{
			Case: reference, Full: full, Synthetic: full, Equal: true,
			MutationBundle:  evidence("mutations/reference.tar.gz", sourceB),
			FullReport:      evidence("reports/reference/full.json", artifactDigest),
			SyntheticReport: evidence("reports/reference/compact.json", sourceA),
		},
		{
			Case: mutation, Full: score, Synthetic: score, Equal: true,
			MutationBundle:  evidence("mutations/wrong-vlan.tar.gz", artifactDigest),
			FullReport:      evidence("reports/wrong-vlan/full.json", sourceA),
			SyntheticReport: evidence("reports/wrong-vlan/compact.json", sourceB),
		},
	}}
}

func TestAttestationRejectsMutationMaskedByCompactHarness(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric", CompilerVersion: "compiler", ControllerVersion: "build", GraderSource: sourceA, ImageLock: "lock",
		MutationSuiteDigest: sourceA, ReferenceBundleDigest: sourceB, EvidenceDir: "audit.evidence",
		Coverage: testCoverage,
		Audit: AuditResult{Equivalent: false, Records: []AuditRecord{{
			Case: AuditCase{Name: "wrong-vlan", Required: testCoverage[0], ExpectedCheckStatus: "fail"},
			Full: mutationScore("fail", 0),
			Synthetic: AuditScore{
				Total: 10, MaxTotal: 10,
				CheckClasses:   map[string]string{testCoverage[0].Key(): "pass"},
				QuestionScores: map[string]float64{"q1.1": 1},
				QuestionPoints: map[string]float64{"q1.1": 1},
			},
			Equal: false, Error: "score or check discrimination differs",
		}}},
	}
	if err := attestation.Sign(priv); err == nil {
		t.Fatal("masked wrong-answer mutation was signed as equivalent")
	}
	if err := attestation.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("masked wrong-answer mutation enabled compact grading")
	}
}

func TestAttestationVerifiesOnlyExactCoverageAndInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric", CompilerVersion: "compiler", ControllerVersion: "build", GraderSource: sourceA, ImageLock: "lock",
		MutationSuiteDigest: sourceA, ReferenceBundleDigest: sourceB, EvidenceDir: "audit.evidence",
		Coverage: testCoverage, Audit: equivalentAudit(),
	}
	if err := attestation.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(pub, "other", "rubric", "compiler", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("attestation accepted a different topology")
	}
	if err := attestation.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", nil); err == nil {
		t.Fatal("attestation accepted missing required rubric coverage")
	}
}

func TestAttestationRejectsDuplicateCoverage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(append([]CoverageRequirement{}, testCoverage...), testCoverage[0])
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric", CompilerVersion: "compiler", ControllerVersion: "build", GraderSource: sourceA, ImageLock: "lock",
		MutationSuiteDigest: sourceA, ReferenceBundleDigest: sourceB, EvidenceDir: "audit.evidence",
		Coverage: duplicate, Audit: equivalentAudit(),
	}
	if err := attestation.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("duplicate attested coverage was accepted")
	}
}

func TestAttestationUsesStableCompactContractAndExactBuild(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric",
		CompilerVersion: CompactCompilerContract, ControllerVersion: "v0.5.0-tag-a", ControllerCommit: "abc1234", GraderSource: sourceA,
		ImageLock: "lock", MutationSuiteDigest: sourceA, ReferenceBundleDigest: sourceB,
		EvidenceDir: "audit.evidence", Coverage: testCoverage, Audit: equivalentAudit(),
	}
	if err := attestation.Sign(priv); err != nil {
		t.Fatal(err)
	}
	// A presentation tag may change at the same immutable source digest.
	if err := attestation.Verify(pub, "top", "rubric", CompactCompilerContract, sourceA, "lock", testCoverage); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(pub, "top", "rubric", CompactCompilerContract, sourceB, "lock", testCoverage); err == nil {
		t.Fatal("changed full source identity accepted stale attestation")
	}
	if err := attestation.Verify(pub, "top", "rubric", CompactCompilerContract+"-changed", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("changed compact compiler contract accepted old attestation")
	}
	tampered := attestation
	tampered.ControllerCommit = "def5678"
	if err := tampered.Verify(pub, "top", "rubric", CompactCompilerContract, sourceA, "lock", testCoverage); err == nil {
		t.Fatal("unsigned controller commit provenance was accepted")
	}
}

func TestAttestationBindsSuiteAndReferenceDigests(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric", CompilerVersion: "compiler",
		GraderSource: sourceA, ImageLock: "lock", MutationSuiteDigest: sourceA,
		ReferenceBundleDigest: sourceB, EvidenceDir: "audit.evidence",
		Coverage: testCoverage, Audit: equivalentAudit(),
	}
	if err := attestation.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := attestation.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err != nil {
		t.Fatal(err)
	}
	tamperedSuite := attestation
	tamperedSuite.MutationSuiteDigest = artifactDigest
	if err := tamperedSuite.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("tampered mutation suite digest was accepted")
	}
	tamperedReference := attestation
	tamperedReference.ReferenceBundleDigest = sourceA
	if err := tamperedReference.Verify(pub, "top", "rubric", "compiler", sourceA, "lock", testCoverage); err == nil {
		t.Fatal("tampered reference digest was accepted")
	}
}

func TestAttestationEvidenceDigestDetectsTampering(t *testing.T) {
	parent := attestEvidenceTestDir(t)
	root := filepath.Join(parent, "audit.evidence")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) EvidenceArtifact {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		raw := []byte(body)
		if err := os.WriteFile(full, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return EvidenceArtifact{Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))}
	}
	suite := write("mutation-suite.yaml", "suite")
	reference := write("mutations/reference.tar.gz", "reference")
	referenceFull := write("reports/reference/full.json", "reference-full")
	referenceCompact := write("reports/reference/compact.json", "reference-compact")
	mutation := write("mutations/wrong-vlan.tar.gz", "mutation")
	mutationFull := write("reports/wrong-vlan/full.json", "mutation-full")
	mutationCompact := write("reports/wrong-vlan/compact.json", "mutation-compact")

	audit := equivalentAudit()
	audit.Records[0].MutationBundle = reference
	audit.Records[0].FullReport = referenceFull
	audit.Records[0].SyntheticReport = referenceCompact
	audit.Records[1].MutationBundle = mutation
	audit.Records[1].FullReport = mutationFull
	audit.Records[1].SyntheticReport = mutationCompact
	attestation := Attestation{
		TopologyHash: "top", RubricHash: "rubric", CompilerVersion: "compiler",
		GraderSource: sourceA, ImageLock: "lock", MutationSuiteDigest: suite.SHA256,
		ReferenceBundleDigest: reference.SHA256, EvidenceDir: "audit.evidence",
		Coverage: testCoverage, Audit: audit,
	}
	if err := attestation.VerifyEvidence(parent); err != nil {
		t.Fatalf("retained evidence did not verify: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "reports/wrong-vlan/full.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := attestation.VerifyEvidence(parent); err == nil {
		t.Fatal("tampered report evidence was accepted")
	}
}

var attestEvidenceCounter uint64

func attestEvidenceTestDir(t *testing.T) string {
	t.Helper()
	dir := fmt.Sprintf(".attestation-evidence-%d-%d", os.Getpid(), atomic.AddUint64(&attestEvidenceCounter, 1))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
