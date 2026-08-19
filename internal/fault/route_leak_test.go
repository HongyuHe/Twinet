package fault

import "testing"

// Verbatim from as3/SFO on the cos461 lab while bgp_blackhole_route_leak was
// injected: the router originates 7.0.0.0/8 and discards it.
const leakBGPOriginated = `BGP routing table entry for 7.0.0.0/8, version 16
Paths: (3 available, best #2, table default)
  Advertised to non peer-group peers:
  3.151.0.1 3.152.0.1 3.153.0.1 179.3.7.2 179.3.9.2
  4 7
    3.153.0.1 (metric 25) from 3.153.0.1 (3.153.0.1)
      Origin IGP, localpref 200, valid, internal, rpki validation-state: valid
      Community: 1:20
      Last update: Wed Aug 19 18:53:50 2026
  Local
    0.0.0.0 from 0.0.0.0 (3.157.0.1)
      Origin IGP, metric 0, weight 32768, valid, sourced, local, best (Weight), rpki validation-state: invalid
      Last update: Wed Aug 19 18:51:06 2026
  7 7 7 7
    179.3.7.2 from 179.3.7.2 (7.151.0.1)
      Origin IGP, metric 0, localpref 250, valid, external, rpki validation-state: valid
      Last update: Wed Aug 19 18:53:48 2026
`

// The same table after `no network 7.0.0.0/8`: the prefix is still present,
// learned from neighbours, but this router no longer sources it.
const leakBGPLearnedOnly = `BGP routing table entry for 7.0.0.0/8, version 18
Paths: (2 available, best #2, table default)
  4 7
    3.153.0.1 (metric 25) from 3.153.0.1 (3.153.0.1)
      Origin IGP, localpref 200, valid, internal, rpki validation-state: valid
      Last update: Wed Aug 19 18:55:10 2026
  7 7 7 7
    179.3.7.2 from 179.3.7.2 (7.151.0.1)
      Origin IGP, metric 0, localpref 250, valid, external, best (Local Pref), rpki validation-state: valid
      Last update: Wed Aug 19 18:55:08 2026
`

const leakRouteBlackhole = `Routing entry for 7.0.0.0/8
  Known via "static", distance 1, metric 0, best
  Last update 00:00:00 ago
  * unreachable (blackhole), weight 1
`

// FRR's answer once the discard route is removed.
const leakRouteAbsent = "% Network not in table\n"

// The reviewer's mutation: withdraw the announcement, leave the discard route.
// The lab then lost every packet to the prefix, so this has to keep reading as
// still in effect -- and has to say which half survived.
func TestLeakWithAnnouncementWithdrawnIsStillInEffect(t *testing.T) {
	discarding := blackholeFor(leakRouteBlackhole, "7.0.0.0/8")
	originating := locallyOriginated(leakBGPLearnedOnly)
	if !discarding {
		t.Fatal("the discard route is present and was not seen")
	}
	if originating {
		t.Fatal("the prefix is only learned here, but it was read as locally originated")
	}
	if !discarding && !originating {
		t.Fatal("half-undone leak reported as no longer in effect")
	}
	got := leakObserved("7.0.0.0/8", discarding, originating)
	for _, want := range []string{"no longer originated", "still dropped"} {
		if !contains(got, want) {
			t.Errorf("evidence %q does not mention %q", got, want)
		}
	}
}

// The mirror mutation: remove the discard route, leave the announcement. The
// router still advertises a prefix it does not own and has no route for what
// arrives, so this is not a clean lab either.
func TestLeakWithDiscardRemovedIsStillInEffect(t *testing.T) {
	discarding := blackholeFor(leakRouteAbsent, "7.0.0.0/8")
	originating := locallyOriginated(leakBGPOriginated)
	if discarding {
		t.Fatal("there is no discard route, but one was reported")
	}
	if !originating {
		t.Fatal("the router originates the prefix and it was not seen")
	}
	got := leakObserved("7.0.0.0/8", discarding, originating)
	if !contains(got, "still originates") {
		t.Errorf("evidence %q does not say the announcement survived", got)
	}
}

func TestLeakFullyInjectedAndFullyResolved(t *testing.T) {
	if !blackholeFor(leakRouteBlackhole, "7.0.0.0/8") || !locallyOriginated(leakBGPOriginated) {
		t.Fatal("a fully injected leak was not recognised")
	}
	if blackholeFor(leakRouteAbsent, "7.0.0.0/8") || locallyOriginated(leakBGPLearnedOnly) {
		t.Fatal("a fully resolved leak still reads as present")
	}
	got := leakObserved("7.0.0.0/8", false, false)
	if !contains(got, "neither") {
		t.Errorf("evidence %q should say neither half is present", got)
	}
}

// `show ip route` answers about whatever entry covers the prefix asked for, so
// a discard route for a different network must not be credited to this fault.
func TestBlackholeIsScopedToTheRecordedPrefix(t *testing.T) {
	other := `Routing entry for 7.0.0.0/16
  Known via "static", distance 1, metric 0, best
  * unreachable (blackhole), weight 1
`
	if blackholeFor(other, "7.0.0.0/8") {
		t.Fatal("a blackhole for 7.0.0.0/16 was credited to the fault on 7.0.0.0/8")
	}
	if !blackholeFor(other, "7.0.0.0/16") {
		t.Fatal("the entry for the prefix asked about was not recognised")
	}
}
