package grade

import "testing"

// The IXP question asks a member to refuse the routes whose path crosses its
// own region. It does not say how. The check used to look for `match as-path`
// in the inbound route-map and nothing else, so a member that refused exactly
// the same routes with a prefix-list was told "nothing filters arrivals" and
// lost half the mark while its table was indistinguishable from the reference
// answer's.
//
// What decides it now is the table: if the exchange offered in-region routes
// and none of them arrived, something refused them.

func TestTheExchangeOffersAreCountedByPath(t *testing.T) {
	inRegion := map[int]bool{4: true, 5: true}
	offered := map[string]string{
		"1.0.0.0/8":  "1",
		"2.0.0.0/8":  "2",
		"4.0.0.0/8":  "4",
		"5.0.0.0/8":  "5",
		"11.0.0.0/8": "2 11",
		"12.0.0.0/8": "4 12", // relayed by an in-region member
	}
	if got := countInRegionOffers(offered, inRegion); got != 3 {
		t.Fatalf("in-region offers = %d, want 3 (4.0.0.0/8, 5.0.0.0/8, and the one relayed via AS 4)", got)
	}
}

func TestAnExchangeWithNoInRegionOffersProvesNothing(t *testing.T) {
	// Every member of this exchange is outside our region. An empty set of
	// wrongly-admitted routes is then the lab's doing, not the submission's,
	// so the table cannot stand in for a filter the member never wrote.
	inRegion := map[int]bool{4: true, 5: true}
	offered := map[string]string{
		"1.0.0.0/8": "1",
		"2.0.0.0/8": "2",
	}
	if got := countInRegionOffers(offered, inRegion); got != 0 {
		t.Fatalf("in-region offers = %d, want 0", got)
	}
}

func TestAnASIsNotInItsOwnRegionForThisPurpose(t *testing.T) {
	// A path that crosses nobody in the region is out-of-region however long
	// it is, and a member's own number appearing in a path it is being offered
	// must not make the route count against it.
	inRegion := map[int]bool{}
	offered := map[string]string{"9.0.0.0/8": "1 2 3 9"}
	if got := countInRegionOffers(offered, inRegion); got != 0 {
		t.Fatalf("in-region offers = %d, want 0 when the region has no other student system", got)
	}
}

func TestAPathThatIsNotNumbersIsNotAnInRegionOffer(t *testing.T) {
	// AS_SET and confederation notation appear in paths as bracketed or
	// braced text. Nothing there should be read as an in-region system.
	inRegion := map[int]bool{4: true}
	offered := map[string]string{
		"6.0.0.0/8": "{4,7}",
		"7.0.0.0/8": "i",
		"8.0.0.0/8": "",
	}
	if got := countInRegionOffers(offered, inRegion); got != 0 {
		t.Fatalf("in-region offers = %d, want 0", got)
	}
}
