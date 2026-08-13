package svc

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// ReachInvalid was declared as "the orange cell students chase" and produced by
// nothing, so the matrix could only ever say up or down -- and a network
// reachable over a path that gives somebody free transit looked exactly like a
// correct one.
func TestAPathThatGivesSomebodyFreeTransitIsNotJustReachable(t *testing.T) {
	// 1 is a provider of 3 and of 4; 3 and 4 are peers; 9 is a customer of 4.
	top := &model.Topology{ASes: map[int]*model.AS{
		1: {ASN: 1}, 3: {ASN: 3}, 4: {ASN: 4}, 9: {ASN: 9},
	}}
	rel := map[int]map[int]model.Relationship{
		3: {1: model.RelProvider, 4: model.RelPeer},
		4: {1: model.RelProvider, 3: model.RelPeer, 9: model.RelCustomer},
		1: {3: model.RelCustomer, 4: model.RelCustomer},
		9: {4: model.RelProvider},
	}
	relationshipMapForTest = rel
	defer func() { relationshipMapForTest = nil }()

	cases := []struct {
		name string
		from int
		path []int
		bad  bool
	}{
		{"up to a provider and down to its customer", 3, []int{1, 4}, false},
		{"across a peering and down to a customer", 3, []int{4, 9}, false},
		{"across a peering and then up to a provider", 3, []int{4, 1}, true},
		{"up to a provider and across its peering", 9, []int{4, 3}, false},
		{"across two peerings", 9, []int{4, 3, 4}, true},
		{"prepends are not hops", 3, []int{1, 1, 1, 4}, false},
	}
	for _, c := range cases {
		why := violatesRelationships(top, c.from, c.path)
		if c.bad && why == "" {
			t.Errorf("%s: reported as a correct path, so the matrix shows it green and "+
				"the transit nobody is paying for is invisible", c.name)
		}
		if !c.bad && why != "" {
			t.Errorf("%s: reported as a violation (%s), which would mark a correct "+
				"network orange", c.name, why)
		}
	}
}
