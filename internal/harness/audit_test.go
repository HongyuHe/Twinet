package harness

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestAuditEquivalenceRequiresEveryScoreClassToMatch(t *testing.T) {
	full := &model.Topology{Name: "full"}
	synthetic := &model.Topology{Name: "synthetic"}
	cases := []AuditCase{
		{Name: "reference", ExpectedClass: "full"},
		{Name: "wrong-rpki", ExpectedClass: "partial"},
	}
	run := func(_ context.Context, top *model.Topology, fixture AuditCase) (AuditScore, error) {
		score := AuditScore{Total: 10, MaxTotal: 10, CheckClasses: map[string]string{"rpki": "pass"}}
		if fixture.Name == "wrong-rpki" {
			score.Total = 9
			score.CheckClasses["rpki"] = "fail"
		}
		if top.Name == "synthetic" && fixture.Name == "wrong-rpki" {
			// A matching total alone would not prove the same discriminator:
			// this deliberately changes the check class and must fail audit.
			score.CheckClasses["rpki"] = "partial"
		}
		return score, nil
	}
	result, err := AuditEquivalence(context.Background(), full, synthetic, cases, run)
	if err != nil {
		t.Fatal(err)
	}
	if result.Equivalent || len(result.Records) != 2 || result.Records[1].Equal {
		t.Fatalf("audit accepted different wrong-answer discrimination: %#v", result)
	}
}

func TestAuditEquivalenceAcceptsMatchingReferenceAndMutations(t *testing.T) {
	run := func(_ context.Context, _ *model.Topology, fixture AuditCase) (AuditScore, error) {
		score := AuditScore{Total: 10, MaxTotal: 10, CheckClasses: map[string]string{"bgp": "pass"}}
		if fixture.Name == "wrong-bgp" {
			score.Total, score.CheckClasses["bgp"] = 8, "fail"
		}
		return score, nil
	}
	result, err := AuditEquivalence(context.Background(), &model.Topology{Name: "full"},
		&model.Topology{Name: "synthetic"}, []AuditCase{{Name: "wrong-bgp"}, {Name: "reference"}}, run)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Equivalent || result.Records[0].Case.Name != "reference" {
		t.Fatalf("matching audit rejected or lost deterministic order: %#v", result)
	}
}
