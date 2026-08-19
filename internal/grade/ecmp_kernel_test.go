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

func TestKernelRoutesSeparatesEntries(t *testing.T) {
	// A route added by hand with the daemon's own protocol label sits beside
	// the daemon's route, with the lower metric, and wins.
	out := "3.153.0.1 via 3.0.10.1 dev port_BOS proto ospf \n" +
		"3.153.0.1 nhid 57 proto ospf metric 20 \n" +
		"\tnexthop via 3.0.8.1 dev port_PHY weight 1 \n" +
		"\tnexthop via 3.0.10.1 dev port_BOS weight 1 \n"
	routes := kernelRoutes(out)
	if len(routes) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(routes), routes)
	}
	if len(routes[0].hops) != 1 || routes[0].metric != 0 {
		t.Fatalf("first entry: want 1 hop at metric 0, got %+v", routes[0])
	}
	if len(routes[1].hops) != 2 || routes[1].metric != 20 {
		t.Fatalf("second entry: want 2 hops at metric 20, got %+v", routes[1])
	}
	win, ok := forwarding(routes, netip.MustParseAddr("3.153.0.1"))
	if !ok {
		t.Fatal("no forwarding entry")
	}
	if got := hopNames(win.hops); !sameHops(got, map[string]bool{"port_BOS": true}) {
		t.Fatalf("the lower metric decides; got %v", got)
	}
}

func TestForwardingPrefersLongestPrefix(t *testing.T) {
	out := "default via 3.0.1.1 dev port_A \n" +
		"3.153.0.0/24 via 3.0.2.1 dev port_B \n" +
		"3.153.0.1 via 3.0.3.1 dev port_C metric 100 \n"
	win, ok := forwarding(kernelRoutes(out), netip.MustParseAddr("3.153.0.1"))
	if !ok {
		t.Fatal("no forwarding entry")
	}
	if got := hopNames(win.hops); !sameHops(got, map[string]bool{"port_C": true}) {
		t.Fatalf("a higher metric on a longer prefix still wins; got %v", got)
	}
	// And a destination the host route does not cover falls to the /24.
	win, _ = forwarding(kernelRoutes(out), netip.MustParseAddr("3.153.0.9"))
	if got := hopNames(win.hops); !sameHops(got, map[string]bool{"port_B": true}) {
		t.Fatalf("want the covering prefix; got %v", got)
	}
	// And one neither covers falls to the default.
	win, _ = forwarding(kernelRoutes(out), netip.MustParseAddr("9.9.9.9"))
	if got := hopNames(win.hops); !sameHops(got, map[string]bool{"port_A": true}) {
		t.Fatalf("want the default route; got %v", got)
	}
}

func TestForwardingReportsDiscardingRoutes(t *testing.T) {
	for _, kind := range []string{"blackhole", "unreachable", "prohibit"} {
		win, ok := forwarding(kernelRoutes(kind+" 3.153.0.1 \n"),
			netip.MustParseAddr("3.153.0.1"))
		if !ok {
			t.Fatalf("%s: no forwarding entry", kind)
		}
		if win.kind != kind {
			t.Fatalf("%s: read as %q", kind, win.kind)
		}
	}
	// A plain unicast route is not one of them, spelled either way.
	win, _ := forwarding(kernelRoutes("unicast 3.153.0.1 via 3.0.1.1 dev port_A \n"),
		netip.MustParseAddr("3.153.0.1"))
	if win.kind != "" || len(win.hops) != 1 {
		t.Fatalf("explicit unicast misread: %+v", win)
	}
}

func TestForwardingIgnoresUncoveredEntries(t *testing.T) {
	// `ip route show to match` returns only covering routes, but a table read
	// in full must not have an unrelated entry mistaken for the answer.
	out := "3.100.0.0/24 via 3.0.9.1 dev port_Z \n"
	if _, ok := forwarding(kernelRoutes(out), netip.MustParseAddr("3.153.0.1")); ok {
		t.Fatal("an entry that does not cover the destination decided the route")
	}
}
