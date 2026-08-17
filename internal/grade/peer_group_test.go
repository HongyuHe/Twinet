package grade

import (
	"reflect"
	"testing"
)

// The configuration BOS ran when a peer-group carried a correct policy and the
// session overrode it with one that filters nothing. FRR applied the
// session's, which is what a live check of the local-preference it sets
// confirmed; the grader read the group's and awarded full marks.
const groupOverrideCfg = `router bgp 3
 bgp router-id 3.153.0.1
 neighbor 3.151.0.1 remote-as 3
 neighbor 3.151.0.1 update-source lo
 neighbor PEERS peer-group
 neighbor PEERS remote-as 4
 neighbor 179.3.4.2 peer-group PEERS
 !
 address-family ipv4 unicast
  network 3.0.0.0/8
  neighbor 3.151.0.1 next-hop-self
  neighbor PEERS route-map LP-PEER in
  neighbor PEERS route-map EXPORT-PEER out
  neighbor 179.3.4.2 route-map WIDE-OPEN in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!
route-map LP-PEER permit 20
 set local-preference 200
exit
!
route-map WIDE-OPEN permit 20
 set local-preference 200
exit
!`

// A peer-group is a template. Nothing peers with it, so grading it as a session
// reads a policy that governs whichever members do not override it -- and says
// nothing about the ones that do.
func TestAPeerGroupIsNotASession(t *testing.T) {
	f := parseFRR(groupOverrideCfg)
	got := f.externalNeighbours()
	if !reflect.DeepEqual(got, []string{"179.3.4.2"}) {
		t.Fatalf("external sessions: got %v, want [179.3.4.2]; a peer-group is a template, "+
			"and a session that inherits its remote AS is still a session", got)
	}
	if f.hasNeighbor("PEERS") {
		t.Error("the peer-group PEERS was reported as a configured neighbour")
	}
}

// The session's own binding is the one the router runs.
func TestASessionsOwnPolicyOverridesItsGroups(t *testing.T) {
	f := parseFRR(groupOverrideCfg)
	if got := f.mapFor("179.3.4.2", "in"); got != "WIDE-OPEN" {
		t.Fatalf("inbound policy: got %q, want WIDE-OPEN; the group's LP-PEER is overridden "+
			"on this session and never runs on it", got)
	}
	if denyMatches(f.appliedBody("179.3.4.2", "in"), "rpki invalid") {
		t.Error("the session was credited with rejecting invalid origins, but the policy it " +
			"runs has no such clause")
	}
}

// An override is per direction: a session that states its own inbound policy
// still takes the group's outbound one.
func TestOverridingOneDirectionKeepsTheOther(t *testing.T) {
	f := parseFRR(groupOverrideCfg)
	if got := f.mapFor("179.3.4.2", "out"); got != "EXPORT-PEER" {
		t.Fatalf("outbound policy: got %q, want the group's EXPORT-PEER", got)
	}
}

// Binding a policy once on a group and pointing the sessions at it is how this
// is done in practice. It was marked as having no policy at all.
func TestASessionInheritsItsGroupsPolicy(t *testing.T) {
	const cfg = `router bgp 3
 neighbor PEERS peer-group
 neighbor 179.3.4.2 remote-as 4
 neighbor 179.3.4.2 peer-group PEERS
 !
 address-family ipv4 unicast
  neighbor PEERS route-map LP-PEER in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!`
	f := parseFRR(cfg)
	if got := f.mapFor("179.3.4.2", "in"); got != "LP-PEER" {
		t.Fatalf("inbound policy: got %q, want the inherited LP-PEER", got)
	}
	if !denyMatches(f.appliedBody("179.3.4.2", "in"), "rpki invalid") {
		t.Error("a correct policy applied through a peer-group was not counted")
	}
	if got := f.externalNeighbours(); !reflect.DeepEqual(got, []string{"179.3.4.2"}) {
		t.Errorf("external sessions: got %v, want [179.3.4.2]", got)
	}
}

// A session states its own remote AS, and it is internal; the group says
// otherwise. The router uses the session's.
func TestASessionsOwnRemoteASWins(t *testing.T) {
	const cfg = `router bgp 3
 neighbor PEERS peer-group
 neighbor PEERS remote-as 4
 neighbor 3.151.0.1 peer-group PEERS
 neighbor 3.151.0.1 remote-as 3
exit
!`
	f := parseFRR(cfg)
	if got := f.externalNeighbours(); len(got) != 0 {
		t.Fatalf("external sessions: got %v, want none; this session is iBGP whatever its "+
			"group says", got)
	}
}

// A group is a group even where the configuration names it before declaring it.
func TestAGroupNamedBeforeItIsDeclaredIsStillAGroup(t *testing.T) {
	const cfg = `router bgp 3
 neighbor 179.3.4.2 peer-group PEERS
 neighbor PEERS remote-as 4
exit
!`
	f := parseFRR(cfg)
	if got := f.externalNeighbours(); !reflect.DeepEqual(got, []string{"179.3.4.2"}) {
		t.Fatalf("external sessions: got %v, want [179.3.4.2]", got)
	}
}

// A binding governs the address family it was written in. FRR prints IPv6
// after IPv4, so keeping only the last one read made an IPv6 policy stand for
// the IPv4 session -- a route-map the router never runs on the routes in
// question.
func TestAPolicyBoundInAnotherFamilyIsNotThisFamilysPolicy(t *testing.T) {
	const cfg = `router bgp 3
 neighbor 179.3.4.2 remote-as 4
 !
 address-family ipv4 unicast
  neighbor 179.3.4.2 route-map WIDE-OPEN in
 exit-address-family
 address-family ipv6 unicast
  neighbor 179.3.4.2 route-map LP-PEER in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!
route-map WIDE-OPEN permit 20
 set local-preference 200
exit
!`
	f := parseFRR(cfg)
	if got := f.mapFor("179.3.4.2", "in"); got != "WIDE-OPEN" {
		t.Fatalf("IPv4 inbound policy: got %q, want WIDE-OPEN; LP-PEER is bound in the IPv6 "+
			"family and does not run on IPv4 routes", got)
	}
	if got := f.mapForAF("179.3.4.2", "ipv6 unicast", "in"); got != "LP-PEER" {
		t.Errorf("IPv6 inbound policy: got %q, want LP-PEER", got)
	}
}

// A binding outside any address-family block is an IPv4 unicast binding, and
// the family resets when the block ends.
func TestABindingOutsideAnyFamilyIsIPv4Unicast(t *testing.T) {
	const cfg = `router bgp 3
 neighbor 179.3.4.2 remote-as 4
 neighbor 179.3.4.2 route-map LP-PEER in
 !
 address-family ipv6 unicast
 exit-address-family
 neighbor 179.3.5.2 remote-as 5
 neighbor 179.3.5.2 route-map LP-PEER in
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!`
	f := parseFRR(cfg)
	for _, addr := range []string{"179.3.4.2", "179.3.5.2"} {
		if got := f.mapFor(addr, "in"); got != "LP-PEER" {
			t.Errorf("%s inbound policy: got %q, want LP-PEER", addr, got)
		}
	}
}

// Every member of a guarded group is guarded, and one that opts out is not.
func TestEveryMemberOfAGroupIsJudgedSeparately(t *testing.T) {
	const cfg = `router bgp 3
 neighbor PEERS peer-group
 neighbor PEERS remote-as 4
 neighbor 179.3.4.2 peer-group PEERS
 neighbor 179.3.6.2 peer-group PEERS
 !
 address-family ipv4 unicast
  neighbor PEERS route-map LP-PEER in
  neighbor 179.3.6.2 route-map WIDE-OPEN in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!
route-map WIDE-OPEN permit 20
 set local-preference 200
exit
!`
	f := parseFRR(cfg)
	want := []string{"179.3.4.2", "179.3.6.2"}
	if got := f.externalNeighbours(); !reflect.DeepEqual(got, want) {
		t.Fatalf("external sessions: got %v, want %v", got, want)
	}
	if !denyMatches(f.appliedBody("179.3.4.2", "in"), "rpki invalid") {
		t.Error("the member that inherits the group's policy was not credited with it")
	}
	if denyMatches(f.appliedBody("179.3.6.2", "in"), "rpki invalid") {
		t.Error("the member that overrode the group's policy was credited with it anyway")
	}
}

// A group carrying no remote AS, whose members state their own, still passes
// its policy down.
func TestAPolicyOnlyGroupStillAppliesToItsMembers(t *testing.T) {
	const cfg = `router bgp 3
 neighbor RPKI-GUARD peer-group
 neighbor 179.3.4.2 remote-as 4
 neighbor 179.3.4.2 peer-group RPKI-GUARD
 neighbor 179.3.6.2 remote-as 6
 neighbor 179.3.6.2 peer-group RPKI-GUARD
 !
 address-family ipv4 unicast
  neighbor RPKI-GUARD route-map LP-PEER in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!`
	f := parseFRR(cfg)
	want := []string{"179.3.4.2", "179.3.6.2"}
	if got := f.externalNeighbours(); !reflect.DeepEqual(got, want) {
		t.Fatalf("external sessions: got %v, want %v", got, want)
	}
	for _, addr := range want {
		if !denyMatches(f.appliedBody(addr, "in"), "rpki invalid") {
			t.Errorf("%s was not credited with the policy it inherits", addr)
		}
	}
}

// A session belonging to no group behaves exactly as it did before.
func TestASessionWithNoGroupIsUnaffected(t *testing.T) {
	const cfg = `router bgp 3
 neighbor 179.3.4.2 remote-as 4
 !
 address-family ipv4 unicast
  neighbor 179.3.4.2 route-map LP-PEER in
 exit-address-family
exit
!
route-map LP-PEER deny 5
 match rpki invalid
exit
!`
	f := parseFRR(cfg)
	if got := f.mapFor("179.3.4.2", "in"); got != "LP-PEER" {
		t.Fatalf("inbound policy: got %q, want LP-PEER", got)
	}
	if !f.hasNeighbor("179.3.4.2") {
		t.Error("a plain neighbour was not reported as configured")
	}
}
