package grade

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A dependency on a question graded later is not a dependency.
//
// Dependencies are resolved as the questions are graded, in declaration order,
// so when the dependent question is reached the one it depends on has no mark
// yet -- and the rule that an unmet dependency stops a question from being
// graded reads a missing mark as "met". A rubric could therefore say "isolation
// is only worth marks once traffic flows", be told it was valid, and award the
// isolation mark to a network where nothing works at all, which is the exact
// failure depends_on exists to prevent.
func TestADependencyOnALaterQuestionIsRefused(t *testing.T) {
	r := &Rubric{
		APIVersion: "twinet.dev/v1", Kind: "Rubric",
		Metadata: RubricMeta{Name: "backwards"},
		Questions: []QuestionSpec{
			{ID: "q1", Title: "first", Points: 1, DependsOn: []string{"q2"},
				Checks: []CheckSpec{{Check: "ospf.full_adjacency", Weight: 1}}},
			{ID: "q2", Title: "second", Points: 1,
				Checks: []CheckSpec{{Check: "bgp.ibgp_full_mesh", Weight: 1}}},
		},
	}
	err := r.Validate()
	if err == nil {
		t.Fatal("a rubric whose dependency can never apply was accepted")
	}
	if !strings.Contains(err.Error(), "graded after it") {
		t.Errorf("the error does not explain the problem: %v", err)
	}

	// And the same rubric with the questions the right way round is fine.
	r.Questions[0], r.Questions[1] = r.Questions[1], r.Questions[0]
	r.Questions[1].DependsOn = []string{r.Questions[0].ID}
	r.Questions[0].DependsOn = nil
	if err := r.Validate(); err != nil {
		t.Errorf("a rubric whose dependency does apply was refused: %v", err)
	}
}

// A question that depends on itself never runs.
func TestASelfDependencyIsRefused(t *testing.T) {
	r := &Rubric{
		APIVersion: "twinet.dev/v1", Kind: "Rubric",
		Metadata: RubricMeta{Name: "selfish"},
		Questions: []QuestionSpec{
			{ID: "q1", Title: "only", Points: 1, DependsOn: []string{"q1"},
				Checks: []CheckSpec{{Check: "ospf.full_adjacency", Weight: 1}}},
		},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("a question that depends on itself was accepted")
	}
}

func TestRubricInteriorCompatibilityIsAnAuthorError(t *testing.T) {
	top := &model.Topology{
		Name: "shape-test",
		ASes: map[int]*model.AS{
			1: {ASN: 1, InteriorKind: model.InteriorClos},
			2: {ASN: 2}, // legacy means explicit
		},
	}
	r := &Rubric{
		Metadata: RubricMeta{Name: "clos-only",
			SupportedInteriorKinds: []model.InteriorKind{model.InteriorClos}},
	}
	err := r.ValidateTopology(top)
	if err == nil {
		t.Fatal("a Clos-only rubric was accepted for an explicit AS")
	}
	if !strings.Contains(err.Error(), "author error") || !strings.Contains(err.Error(), "explicit") {
		t.Errorf("compatibility error does not identify authoring mismatch: %v", err)
	}
	if _, ok := err.(*RubricCompatibilityError); !ok {
		t.Errorf("compatibility error has type %T, want *RubricCompatibilityError", err)
	}

	r.Metadata.SupportedInteriorKinds = []model.InteriorKind{
		model.InteriorClos, model.InteriorExplicit,
	}
	if err := r.ValidateTopology(top); err != nil {
		t.Errorf("a rubric supporting both shapes was refused: %v", err)
	}
	r.Metadata.SupportedInteriorKinds = nil
	if err := r.ValidateTopology(top); err != nil {
		t.Errorf("an unconstrained legacy rubric was refused: %v", err)
	}
}

func TestRubricRejectsUnknownOrDuplicateInteriorKinds(t *testing.T) {
	base := func(kinds []model.InteriorKind) *Rubric {
		return &Rubric{
			APIVersion: "twinet.dev/v1", Kind: "Rubric",
			Metadata: RubricMeta{Name: "shape", SupportedInteriorKinds: kinds},
			Questions: []QuestionSpec{{ID: "q", Points: 1,
				Checks: []CheckSpec{{Check: "ospf.full_adjacency", Weight: 1}}}},
		}
	}
	if err := base([]model.InteriorKind{"not-a-shape"}).Validate(); err == nil {
		t.Error("rubric accepted an unknown interior kind")
	}
	if err := base([]model.InteriorKind{model.InteriorClos, model.InteriorClos}).Validate(); err == nil {
		t.Error("rubric accepted a duplicate interior kind")
	}
}

func TestClosFixtureRubricLoads(t *testing.T) {
	r, err := LoadRubric("../../examples/clos/rubric/clos.yaml")
	if err != nil {
		t.Fatalf("Clos fixture rubric does not validate: %v", err)
	}
	if len(r.Metadata.SupportedInteriorKinds) != 1 ||
		r.Metadata.SupportedInteriorKinds[0] != model.InteriorClos {
		t.Errorf("fixture supported interiors = %v, want [clos]", r.Metadata.SupportedInteriorKinds)
	}
}
