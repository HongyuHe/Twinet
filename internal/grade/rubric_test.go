package grade

import (
	"strings"
	"testing"
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
