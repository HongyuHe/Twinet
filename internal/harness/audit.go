package harness

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// AuditCase is one reference or deliberately wrong submission used to prove a
// compact harness has the same discrimination as a full harness.
type AuditCase struct {
	Name                string              `json:"name"`
	ExpectedClass       string              `json:"expected_class"`
	Required            CoverageRequirement `json:"required,omitempty"`
	ExpectedCheckStatus string              `json:"expected_check_status,omitempty"`
}

// CoverageRequirement identifies one rubric assertion, including repeated
// uses of the same registered check within a question.
type CoverageRequirement struct {
	QuestionID string `yaml:"question_id" json:"question_id"`
	CheckID    string `yaml:"check_id" json:"check_id"`
	CheckIndex int    `yaml:"check_index" json:"check_index"`
}

func (c CoverageRequirement) Key() string {
	return fmt.Sprintf("%s/%s[%d]", c.QuestionID, c.CheckID, c.CheckIndex)
}

func (c CoverageRequirement) Valid() bool {
	return c.QuestionID != "" && c.CheckID != "" && c.CheckIndex >= 0
}

// AuditScore is deliberately independent of the grade package so harness
// planning does not import grading. CheckClasses normally contains pass/fail
// class per rubric check; a total alone would let two opposite deductions look
// equivalent.
type AuditScore struct {
	Total        float64           `json:"total"`
	MaxTotal     float64           `json:"max_total"`
	NeedsReview  bool              `json:"needs_review"`
	CheckClasses map[string]string `json:"check_classes"`
	// QuestionScores/Points and CheckScores are keyed by question ID and
	// CoverageRequirement.Key respectively. They prove the designated
	// mutation actually lost the intended mark, not merely some unrelated
	// point elsewhere in the rubric.
	QuestionScores map[string]float64 `json:"question_scores,omitempty"`
	QuestionPoints map[string]float64 `json:"question_points,omitempty"`
	CheckScores    map[string]float64 `json:"check_scores,omitempty"`
}

// AuditRunner grades one fixture in one topology. Production callers use the
// ordinary isolated grade path; test callers can supply a deterministic fake.
type AuditRunner func(context.Context, *model.Topology, AuditCase) (AuditScore, error)

// AuditRecord is machine-readable evidence for one full/compact comparison.
type AuditRecord struct {
	Case            AuditCase        `json:"case"`
	Full            AuditScore       `json:"full"`
	Synthetic       AuditScore       `json:"synthetic"`
	MutationBundle  EvidenceArtifact `json:"mutation_bundle"`
	FullReport      EvidenceArtifact `json:"full_report"`
	SyntheticReport EvidenceArtifact `json:"compact_report"`
	Equal           bool             `json:"equal"`
	Error           string           `json:"error,omitempty"`
}

// EvidenceArtifact is a deterministic, signed pointer to one audit input or
// report retained beside an attestation. Paths are relative to
// Attestation.EvidenceDir; the digest makes later tampering detectable.
type EvidenceArtifact struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Bytes          int64  `json:"bytes"`
	DurationMillis int64  `json:"duration_millis,omitempty"`
}

// AuditResult is an auditable gate, not a best-effort warning. A synthetic
// harness may be used for marks only when every record is equal and neither
// side required human review.
type AuditResult struct {
	Equivalent bool          `json:"equivalent"`
	Records    []AuditRecord `json:"records"`
}

// AuditEquivalence compares a compact synthetic harness to its complete
// counterpart for every reference and wrong-answer fixture. It is strict by
// design: an infrastructure review flag or a missing check classification is
// not evidence of equivalence.
func AuditEquivalence(ctx context.Context, full, synthetic *model.Topology,
	cases []AuditCase, run AuditRunner,
) (AuditResult, error) {
	if full == nil || synthetic == nil {
		return AuditResult{}, fmt.Errorf("harness equivalence needs full and synthetic topologies")
	}
	if run == nil {
		return AuditResult{}, fmt.Errorf("harness equivalence needs an audit runner")
	}
	ordered := append([]AuditCase(nil), cases...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	result := AuditResult{Equivalent: len(ordered) > 0}
	covered := map[string]bool{}
	for _, fixture := range ordered {
		if fixture.Required.QuestionID != "" || fixture.Required.CheckID != "" {
			if !fixture.Required.Valid() {
				return AuditResult{}, fmt.Errorf("audit case %q has incomplete rubric coverage", fixture.Name)
			}
			if covered[fixture.Required.Key()] {
				return AuditResult{}, fmt.Errorf("audit cases duplicate rubric coverage %s", fixture.Required.Key())
			}
			covered[fixture.Required.Key()] = true
		}
		fullScore, fullErr := run(ctx, full, fixture)
		syntheticScore, syntheticErr := run(ctx, synthetic, fixture)
		record := AuditRecord{Case: fixture, Full: fullScore, Synthetic: syntheticScore}
		switch {
		case fullErr != nil:
			record.Error = "full harness: " + fullErr.Error()
		case syntheticErr != nil:
			record.Error = "synthetic harness: " + syntheticErr.Error()
		default:
			record.Equal = sameAuditScore(fullScore, syntheticScore)
			if !record.Equal {
				record.Error = "score or check discrimination differs"
			}
			if fixture.ExpectedClass != "" &&
				(auditScoreClass(fullScore) != fixture.ExpectedClass ||
					auditScoreClass(syntheticScore) != fixture.ExpectedClass) {
				record.Error = fmt.Sprintf("expected score class %q, got full=%q synthetic=%q",
					fixture.ExpectedClass, auditScoreClass(fullScore), auditScoreClass(syntheticScore))
			}
			if err := validateMutationCoverage(fixture, fullScore); err != nil {
				record.Error = "full harness: " + err.Error()
			}
			if err := validateMutationCoverage(fixture, syntheticScore); err != nil {
				record.Error = "compact harness: " + err.Error()
			}
		}
		if record.Error != "" || !record.Equal || fullScore.NeedsReview || syntheticScore.NeedsReview {
			result.Equivalent = false
			if record.Error == "" {
				record.Error = "one harness produced an infrastructure review flag"
			}
		}
		result.Records = append(result.Records, record)
	}
	return result, nil
}

func validateMutationCoverage(fixture AuditCase, score AuditScore) error {
	if fixture.Required.QuestionID == "" && fixture.Required.CheckID == "" {
		return nil // reference case
	}
	if score.NeedsReview {
		return fmt.Errorf("mutation requires review rather than a defensible verdict")
	}
	key := fixture.Required.Key()
	questionScore, gotScore := score.QuestionScores[fixture.Required.QuestionID]
	questionPoints, gotPoints := score.QuestionPoints[fixture.Required.QuestionID]
	if !gotScore || !gotPoints || questionScore >= questionPoints-0.000001 {
		return fmt.Errorf("question %s did not lose marks", fixture.Required.QuestionID)
	}
	status, ok := score.CheckClasses[key]
	if !ok || status == "pass" {
		return fmt.Errorf("designated check %s still passes", key)
	}
	if fixture.ExpectedCheckStatus != "" && status != fixture.ExpectedCheckStatus {
		return fmt.Errorf("designated check %s is %s, want %s", key, status, fixture.ExpectedCheckStatus)
	}
	return nil
}

func auditScoreClass(score AuditScore) string {
	if score.NeedsReview {
		return "review"
	}
	switch {
	case score.MaxTotal <= 0 || score.Total <= 0:
		return "zero"
	case math.Abs(score.Total-score.MaxTotal) <= 0.000001:
		return "full"
	default:
		return "partial"
	}
}

func sameAuditScore(a, b AuditScore) bool {
	if a.NeedsReview != b.NeedsReview ||
		math.Abs(a.Total-b.Total) > 0.000001 ||
		math.Abs(a.MaxTotal-b.MaxTotal) > 0.000001 ||
		len(a.CheckClasses) != len(b.CheckClasses) {
		return false
	}
	for check, class := range a.CheckClasses {
		if b.CheckClasses[check] != class {
			return false
		}
	}
	if len(a.QuestionScores) != len(b.QuestionScores) || len(a.CheckScores) != len(b.CheckScores) {
		return false
	}
	for id, score := range a.QuestionScores {
		if math.Abs(score-b.QuestionScores[id]) > 0.000001 {
			return false
		}
	}
	for id, score := range a.CheckScores {
		if math.Abs(score-b.CheckScores[id]) > 0.000001 {
			return false
		}
	}
	return true
}
