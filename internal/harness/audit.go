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
	Name          string `json:"name"`
	ExpectedClass string `json:"expected_class"`
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
}

// AuditRunner grades one fixture in one topology. Production callers use the
// ordinary isolated grade path; test callers can supply a deterministic fake.
type AuditRunner func(context.Context, *model.Topology, AuditCase) (AuditScore, error)

// AuditRecord is machine-readable evidence for one full/compact comparison.
type AuditRecord struct {
	Case      AuditCase  `json:"case"`
	Full      AuditScore `json:"full"`
	Synthetic AuditScore `json:"synthetic"`
	Equal     bool       `json:"equal"`
	Error     string     `json:"error,omitempty"`
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
	for _, fixture := range ordered {
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
	return true
}
