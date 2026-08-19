package grade

import (
	"net/netip"
	"testing"
)

func TestKernelHopsReadsAMultipathRoute(t *testing.T) {
	out := "3.153.0.1 nhid 57 proto ospf metric 20 \n" +
		"\tnexthop via 3.0.8.1 dev port_PHY weight 1 \n" +
		"\tnexthop via 3.0.10.1 dev port_BOS weight 1 \n"
	got := hopNames(kernelHops(out))
	if len(got) != 2 || !got["port_PHY"] || !got["port_BOS"] {
		t.Fatalf("a route with two next hops should name both links, got %v", got)
	}
}

func TestKernelHopsReadsASingleRoute(t *testing.T) {
	out := "3.153.0.1 nhid 49 via 3.0.5.2 dev port_BOS proto ospf metric 20 \n"
	got := hopNames(kernelHops(out))
	if len(got) != 1 || !got["port_BOS"] {
		t.Fatalf("a route with one next hop should name one link, got %v", got)
	}
}

func TestKernelHopsReadsARouteWithNoInterface(t *testing.T) {
	got := hopNames(kernelHops("10.0.0.0/8 via 10.1.1.1 \n"))
	if len(got) != 1 || !got["10.1.1.1"] {
		t.Fatalf("a route naming no interface should fall back to the address, got %v", got)
	}
}

func TestKernelHopsReadsNothingFromAnEmptyTable(t *testing.T) {
	if got := kernelHops("\n\n"); len(got) != 0 {
		t.Fatalf("an empty table has no next hops, got %v", got)
	}
}

func TestPathRoutersLeavesOutTheDestination(t *testing.T) {
	got := pathRouters([][]string{
		{"ATL", "BOS"},
		{"ATL", "PHY", "NYC", "BOS"},
	})
	want := map[string]bool{"ATL": true, "PHY": true, "NYC": true}
	if len(got) != len(want) {
		t.Fatalf("every router a path passes through and no more, got %v", got)
	}
	for _, r := range got {
		if !want[r] {
			t.Fatalf("%s is the destination or not on a path, got %v", r, got)
		}
	}
	// Stable order, so the router reported first does not move between runs.
	if got[0] != "ATL" || got[1] != "NYC" || got[2] != "PHY" {
		t.Fatalf("the routers should come back sorted, got %v", got)
	}
}

func TestARuleNamingNoDestinationGovernsEveryone(t *testing.T) {
	dst := netip.MustParseAddr("3.153.0.1")
	if !mayCarry(ipRule{from: "all", table: "100"}, dst) {
		t.Fatal("a rule that names no destination governs all of it")
	}
	if !mayCarry(ipRule{to: "all", table: "100"}, dst) {
		t.Fatal("\"to all\" is the same as naming no destination")
	}
}

func TestARuleForAnotherDestinationIsLeftAlone(t *testing.T) {
	dst := netip.MustParseAddr("3.153.0.1")
	if mayCarry(ipRule{to: "4.0.0.0/8", table: "100"}, dst) {
		t.Fatal("a rule for another network says nothing about this destination")
	}
	if mayCarry(ipRule{to: "3.153.0.2", table: "100"}, dst) {
		t.Fatal("a rule for another host says nothing about this destination")
	}
}

func TestARuleCoveringTheDestinationIsPickedUp(t *testing.T) {
	dst := netip.MustParseAddr("3.153.0.1")
	for _, to := range []string{"3.153.0.1", "3.153.0.1/32", "3.0.0.0/8", "0.0.0.0/0"} {
		if !mayCarry(ipRule{to: to, table: "100"}, dst) {
			t.Fatalf("a rule for %s covers %s", to, dst)
		}
	}
}

func TestADestinationThatCannotBeReadIsNotAssumedHarmless(t *testing.T) {
	dst := netip.MustParseAddr("3.153.0.1")
	if !mayCarry(ipRule{to: "not-an-address", table: "100"}, dst) {
		t.Fatal("a destination that cannot be read is not a reason to conclude " +
			"the rule does not apply")
	}
}

func TestTwoReadingsOfTheSameLinksAgree(t *testing.T) {
	main := hopNames(kernelHops("3.153.0.1 nhid 57 proto ospf metric 20 \n" +
		"\tnexthop via 3.0.8.1 dev port_PHY weight 1 \n" +
		"\tnexthop via 3.0.10.1 dev port_BOS weight 1 \n"))
	// A rule pointing at a table that holds the same route changes nothing,
	// whatever order the kernel prints it in.
	same := hopNames(kernelHops("3.153.0.1 proto static \n" +
		"\tnexthop via 3.0.10.1 dev port_BOS weight 1 \n" +
		"\tnexthop via 3.0.8.1 dev port_PHY weight 1 \n"))
	if !sameHops(main, same) {
		t.Fatal("the same links read twice should compare equal")
	}
	pinned := hopNames(kernelHops("3.153.0.1 via 3.0.10.1 dev port_BOS \n"))
	if sameHops(main, pinned) {
		t.Fatal("one of the two links is not both of them")
	}
	if sameHops(main, hopNames(nil)) {
		t.Fatal("no links at all is not the same as two")
	}
}
