package harness

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestAuditEquivalenceRejectsMutationWhenDesignatedCheckPasses(t *testing.T) {
	coverage := CoverageRequirement{QuestionID: "q1.3", CheckID: "ospf.ecmp_paths", CheckIndex: 1}
	score := AuditScore{
		Total: 9, MaxTotal: 10,
		CheckClasses:   map[string]string{coverage.Key(): "pass"},
		QuestionScores: map[string]float64{"q1.3": 0},
		QuestionPoints: map[string]float64{"q1.3": 1},
		CheckScores:    map[string]float64{coverage.Key(): 1},
	}
	result, err := AuditEquivalence(context.Background(), &model.Topology{Name: "full"},
		&model.Topology{Name: "compact"}, []AuditCase{{
			Name: "wrong-ecmp", Required: coverage, ExpectedCheckStatus: "fail",
		}}, func(context.Context, *model.Topology, AuditCase) (AuditScore, error) {
			return score, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if result.Equivalent || result.Records[0].Error == "" {
		t.Fatalf("designated passing check was accepted as mutation coverage: %#v", result)
	}
}
