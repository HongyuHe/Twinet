package grade

import "testing"

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
	if got := configuredTunnel(bare); got != "" {
		t.Errorf("sit0 was accepted as the student's tunnel: %q", got)
	}
	const built = bare + "tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64 6rd-prefix 2002::/16\n"
	if got := configuredTunnel(built); got != "tun6" {
		t.Errorf("a configured tunnel was not recognised: %q", got)
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
