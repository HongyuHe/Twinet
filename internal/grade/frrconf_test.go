package grade

import (
	"strings"
	"testing"
)

// A route-map that is written but never attached to a neighbour changes
// nothing the network can observe. Awarding a mark for it credits a student
// with behaviour their router does not have, and the mark is indistinguishable
// from a correct answer, so nobody finds out.
func TestAPolicyIsOnlyCountedWhereItIsApplied(t *testing.T) {
	const cfg = `router bgp 5
 neighbor 180.5.0.2 remote-as 180
 neighbor 180.5.0.2 route-map IXP-OUT out
 neighbor 180.5.0.2 route-map IXP-IN in
exit
route-map IXP-OUT permit 10
 set community 180:6 180:7
exit
route-map ORPHAN permit 10
 set community 180:99
exit
route-map IXP-IN deny 5
 match as-path IN-REGION
exit
`
	f := parseFRR(cfg)
	if got := f.mapFor("180.5.0.2", "out"); got != "IXP-OUT" {
		t.Errorf("outbound map = %q, want IXP-OUT", got)
	}
	out := f.appliedBody("180.5.0.2", "out")
	if !contains(out, "180:6") {
		t.Errorf("the applied outbound policy did not include its community: %q", out)
	}
	if contains(out, "180:99") {
		t.Error("a route-map that is not attached to the neighbour was counted as applied")
	}
	if !contains(f.appliedBody("180.5.0.2", "in"), "match as-path") {
		t.Error("the applied inbound policy did not include its AS-path filter")
	}
}

// FRR keeps only the last route-map per neighbour and direction. A parser that
// remembered the first would report a policy the router is not using.
func TestOnlyTheLastBindingCounts(t *testing.T) {
	const cfg = `router bgp 5
 neighbor 1.1.1.1 route-map FIRST in
 neighbor 1.1.1.1 route-map SECOND in
exit
route-map FIRST permit 10
 set local-preference 50
exit
route-map SECOND permit 10
 set local-preference 250
exit
`
	f := parseFRR(cfg)
	if got := f.mapFor("1.1.1.1", "in"); got != "SECOND" {
		t.Errorf("inbound map = %q, want SECOND: FRR replaces the earlier binding", got)
	}
	if !contains(f.appliedBody("1.1.1.1", "in"), "250") {
		t.Error("the body of the map the router actually uses was not returned")
	}
}

// Every container carries the kernel's own sit0 with no endpoints. Counting it
// as a 6in4 tunnel awards the mark before the student begins the exercise.
func TestTheKernelsOwnSitDeviceIsNotATunnel(t *testing.T) {
	const bare = "sit0: ipv6/ip remote any local any ttl 64 nopmtudisc 6rd-prefix 2002::/16\n"
	if got := configuredTunnels(bare); len(got) != 0 {
		t.Errorf("sit0 was accepted as the student's tunnel: %q", got)
	}
	const built = bare + "tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64 6rd-prefix 2002::/16\n"
	if got := configuredTunnels(built); len(got) != 1 || got[0] != "tun6" {
		t.Errorf("a configured tunnel was not recognised: %q", got)
	}
}

// A device may carry more than one tunnel, and a student debugging their
// answer routinely leaves an experiment behind. The kernel lists them in its
// own order, so judging only the first meant a correct tunnel could be marked
// wrong on an abandoned tunnel's endpoints.
func TestALeftoverTunnelDoesNotHideTheRealOne(t *testing.T) {
	const both = "sit0: ipv6/ip remote any local any ttl 64\n" +
		"bad_tun: ipv6/ip remote 3.0.10.2 local 3.0.10.1 ttl 64\n" +
		"tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64\n"
	got := configuredTunnels(both)
	if len(got) != 2 || got[0] != "bad_tun" || got[1] != "tun6" {
		t.Fatalf("both tunnels should be offered for judging, got %q", got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// The reference solution binds its exchange policy to the route server, which
// is on the shared fabric rather than on the far end of the member's own link.
// A check that looked at the far end was looking at a switch port, found no
// neighbour there, and failed a configuration that was correct.
//
// This is the shape of the configuration the reference produces; the parser
// must find the policy through the route server's address.
func TestTheReferenceExchangePolicyIsFound(t *testing.T) {
	const cfg = `router bgp 5
 neighbor 180.140.0.140 remote-as 140
 address-family ipv4 unicast
  neighbor 180.140.0.140 route-map IMPORT-IXP-140 in
  neighbor 180.140.0.140 route-map EXPORT-IXP-140 out
 exit-address-family
exit
route-map IMPORT-IXP-140 deny 10
 match as-path IXP-140-REGION
exit
route-map EXPORT-IXP-140 permit 10
 set community 140:6 140:7
exit
`
	f := parseFRR(cfg)
	const rs = "180.140.0.140"
	if !f.hasNeighbor(rs) {
		t.Fatal("the route server was not recognised as a neighbour")
	}
	if !contains(f.appliedBody(rs, "out"), "140:6") {
		t.Error("the exchange communities were not found in the policy applied towards the route server")
	}
	if !contains(f.appliedBody(rs, "in"), "match as-path") {
		t.Error("the in-region filter was not found in the policy applied from the route server")
	}
}

// The question asks for IPv6 over IPv4 -- protocol 41, printed by iproute2 as
// "ipv6/ip". A GRE tunnel between the same two addresses carries the same
// traffic and moves the same counters, so accepting any tunnel with two
// endpoints awarded the mark for a different answer to a different question.
func TestOnlyA6in4TunnelCounts(t *testing.T) {
	const gre = "sit0: ipv6/ip remote any local any ttl 64\n" +
		"tun6: gre/ip remote 3.153.0.1 local 3.156.0.1 ttl 64\n"
	if got := configuredTunnels(gre); len(got) != 0 {
		t.Errorf("a GRE tunnel was accepted as the answer to the 6in4 question (got %q)", got)
	}

	const sit = "sit0: ipv6/ip remote any local any ttl 64\n" +
		"tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64 6rd-prefix 2002::/16\n"
	if got := configuredTunnels(sit); len(got) != 1 || got[0] != "tun6" {
		t.Errorf("a correct 6in4 tunnel was not recognised (got %q)", got)
	}
}

// A tunnel's line is found by its whole name. A substring search for "tun6:"
// also matches "xtun6:", so an experiment left behind and listed first
// supplied the endpoints of the tunnel actually being judged.
func TestATunnelIsJudgedOnItsOwnLine(t *testing.T) {
	const out = "sit0: ipv6/ip remote any local any ttl 64\n" +
		"xtun6: ipv6/ip remote 3.0.10.2 local 3.0.10.1 ttl 64\n" +
		"tun6: ipv6/ip remote 3.156.0.1 local 3.153.0.1 ttl 64\n"
	got := tunnelLine(out, "tun6")
	if !strings.HasPrefix(got, "tun6:") {
		t.Fatalf("the wrong tunnel's line was returned: %q", got)
	}
	if strings.Contains(got, "3.0.10.1") {
		t.Fatalf("the leftover tunnel's endpoints were read as tun6's: %q", got)
	}
}

// And a name that describes no line is not a tunnel whose endpoints are right.
func TestATunnelWithNoLineIsNotAccepted(t *testing.T) {
	if got := tunnelLine("sit0: ipv6/ip remote any local any\n", "tun6"); got != "" {
		t.Fatalf("a line was invented for a tunnel that is not there: %q", got)
	}
}
