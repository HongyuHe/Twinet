package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HongyuHe/twinet/internal/grade"
	"github.com/HongyuHe/twinet/internal/harness"
	"github.com/HongyuHe/twinet/internal/model"
)

// compactEligibility fail-closes: a development lab without a verified image
// lock or a release attestation uses the complete isolated harness rather than
// presenting an unproven compact mark as a normal grade.
func compactEligibility(top *model.Topology, rubric *grade.Rubric, attestationPath, keyPath string) (bool, string, string) {
	source, ok := graderSourceIdentity()
	if !ok {
		return false, "", "exact full grader source digest is unavailable"
	}
	if top == nil || top.Lab == nil || top.Lab.Images.LockDigest == "" {
		return false, "", "grading-mode image lock is unavailable"
	}
	if attestationPath == "" || keyPath == "" {
		return false, "", "signed compact attestation and public key are required"
	}
	raw, err := os.ReadFile(attestationPath)
	if err != nil {
		return false, "", fmt.Sprintf("read compact attestation: %v", err)
	}
	var attestation harness.Attestation
	if err := json.Unmarshal(raw, &attestation); err != nil {
		return false, "", fmt.Sprintf("parse compact attestation: %v", err)
	}
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return false, "", fmt.Sprintf("read compact attestation key: %v", err)
	}
	pub, err := parsePublicKey(keyRaw)
	if err != nil {
		return false, "", fmt.Sprintf("parse compact attestation key: %v", err)
	}
	rubricHash := compactRubricHash(rubric)
	if err := attestation.Verify(pub, top.Hash, rubricHash, harness.CompactCompilerContract,
		source, top.Lab.Images.LockDigest, compactCoverage(rubric)); err != nil {
		return false, "", err.Error()
	}
	if err := attestation.VerifyEvidence(filepath.Dir(attestationPath)); err != nil {
		return false, "", err.Error()
	}
	return true, attestation.Hash(), ""
}

func compactCoverage(rubric *grade.Rubric) []harness.CoverageRequirement {
	if rubric == nil {
		return nil
	}
	var out []harness.CoverageRequirement
	for _, question := range rubric.Questions {
		for index, check := range question.Checks {
			out = append(out, harness.CoverageRequirement{
				QuestionID: question.ID, CheckID: check.Check, CheckIndex: index,
			})
		}
	}
	return out
}

func graderSourceIdentity() (string, bool) {
	if len(SourceDigest) != 64 {
		return "", false
	}
	for _, ch := range SourceDigest {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return "", false
		}
	}
	return SourceDigest, true
}

func compactRubricHash(rubric *grade.Rubric) string {
	if rubric == nil {
		return ""
	}
	raw, err := json.Marshal(rubric)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
