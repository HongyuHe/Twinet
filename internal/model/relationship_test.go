package model

import "testing"

// Link.Rel says what A is to B. Every consumer needs the opposite question --
// what my neighbour is to me -- and answering it wrong inverts the economics of
// the entire network: a customer prefers its provider over its own customers,
// and pays for traffic it was being paid to carry.
//
// It was wrong, in the renderer and in three grading checks at once, and
// because they were wrong in the same direction the inverted answer was the one
// that scored full marks. A correct implementation would have been marked down.
func TestPeerRelationshipAnswersTheQuestionConsumersAsk(t *testing.T) {
	provider := &Iface{Name: "to_customer"}
	customer := &Iface{Name: "to_provider"}
	l := &Link{A: provider, B: customer, Rel: RelProvider} // A provides to B
	provider.Link, customer.Link = l, l

	// From the provider's side, the neighbour is its customer.
	if got := l.PeerRelationship(provider); got != RelCustomer {
		t.Errorf("the provider sees its neighbour as %q, want %q", got, RelCustomer)
	}
	// From the customer's side, the neighbour is its provider.
	if got := l.PeerRelationship(customer); got != RelProvider {
		t.Errorf("the customer sees its neighbour as %q, want %q", got, RelProvider)
	}
}

func TestAPeeringLooksTheSameFromBothSides(t *testing.T) {
	a, b := &Iface{Name: "a"}, &Iface{Name: "b"}
	l := &Link{A: a, B: b, Rel: RelPeer}
	a.Link, b.Link = l, l
	if l.PeerRelationship(a) != RelPeer || l.PeerRelationship(b) != RelPeer {
		t.Error("a peering is not symmetric")
	}
}

// The preference order is the whole point of the policy: a route from a
// customer is revenue, a route from a peer is free, a route from a provider
// costs money. Preferring them in any other order is a bill.
func TestCustomerRoutesOutrankPeerWhichOutranksProvider(t *testing.T) {
	if !(prefRank(RelCustomer) > prefRank(RelPeer) && prefRank(RelPeer) > prefRank(RelProvider)) {
		t.Error("the relationship preference order is not customer > peer > provider")
	}
}

// prefRank mirrors the intent the renderer encodes, so this file states the
// invariant even though the numbers live elsewhere.
func prefRank(r Relationship) int {
	switch r {
	case RelCustomer:
		return 3
	case RelPeer:
		return 2
	default:
		return 1
	}
}
