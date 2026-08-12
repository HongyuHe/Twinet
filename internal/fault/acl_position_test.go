package fault

import "testing"

// `iptables -D <chain> <spec>` deletes the *first* rule matching the
// specification. The injected rule is appended, so on a device that already had
// an identical rule, deleting by specification removes the student's and leaves
// ours -- and the rule counts still match afterwards, so nothing notices.
//
// The listing is parsed and the last matching position removed instead.
func TestTheInjectedRuleIsFoundByPositionNotBySpecification(t *testing.T) {
	const listing = `-P INPUT ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j DROP
-A INPUT -p tcp -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j DROP
`
	got := lastMatchingPosition(listing, "INPUT", specTokens("-p icmp -m icmp --icmp-type 8"))
	if got != 3 {
		t.Errorf("the injected rule was located at position %d, not 3. Removing the "+
			"first match would delete the rule the student wrote and leave the "+
			"injected one behind, with the counts still adding up", got)
	}
}

func TestARuleThatIsNotThereHasNoPosition(t *testing.T) {
	const listing = `-P INPUT ACCEPT
-A INPUT -p tcp -j ACCEPT
`
	if got := lastMatchingPosition(listing, "INPUT", specTokens("-p icmp")); got != 0 {
		t.Errorf("a chain with no matching rule reported position %d", got)
	}
}

func TestASpecificationIsReducedToWhatAListingShows(t *testing.T) {
	got := specTokens("-p icmp -m icmp --icmp-type 8 -s 10.0.0.1")
	want := map[string]bool{"icmp": true, "10.0.0.1": true}
	if len(got) != len(want) {
		t.Fatalf("reduced to %v, want the protocol and the address only", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("%q is an option flag or its argument, which a listing does not show "+
				"in that form, so matching on it would never find the rule", g)
		}
	}
}

// The human listing renders the protocol as a number -- an OSPF rule appears as
// "89", not "ospf" -- so matching a specification against it failed for every
// rule named by protocol, and the fault could not be removed at all. That is
// how three OSPF faults were left live on a lab.
func TestARuleNamedByProtocolIsFound(t *testing.T) {
	const listing = `-P INPUT ACCEPT
-A INPUT -p ospf -j DROP
`
	if got := lastMatchingPosition(listing, "INPUT", specTokens("-p ospf")); got != 1 {
		t.Errorf("an OSPF drop rule was located at position %d, not 1; the fault that "+
			"installed it could not be undone", got)
	}
}

// The port is part of what makes a rule that rule. Without it, "-p udp --dport
// 53" matched any UDP drop rule, and removing "the last one" could remove a
// rule this injection never added.
func TestAPortIsPartOfTheRuleIdentity(t *testing.T) {
	const listing = `-P INPUT ACCEPT
-A INPUT -p udp -m udp --dport 123 -j DROP
-A INPUT -p udp -m udp --dport 53 -j DROP
`
	got := lastMatchingPosition(listing, "INPUT", specTokens("-p udp --dport 53"))
	if got != 2 {
		t.Errorf("the DNS rule was located at position %d, not 2; resolving would have "+
			"removed the rule for port 123 instead", got)
	}
}

// Every learned BGP path prints "Local host: <addr>, Local port: 179", so
// looking for the word "Local" anywhere was true whenever the prefix was in
// the table at all. For a hijack of a real neighbour's prefix that is always,
// and the fault could then never be resolved: its own verification insisted it
// was still present after the configuration had been removed.
func TestALearnedPathIsNotMistakenForALocalOrigin(t *testing.T) {
	const learned = `BGP routing table entry for 3.0.0.0/8, version 62
Paths: (2 available, best #1, table default)
  3
    179.3.5.1 from 179.3.5.1 (3.151.0.1)
      Origin IGP, metric 0, localpref 250, valid, external, best
      Last update: Wed Aug 12 07:00:00 2026
      Local host: 179.3.5.2, Local port: 179
`
	if locallyOriginated(learned) {
		t.Error("a prefix learned from a neighbour was read as one this router originates, " +
			"so the hijack fault could never be resolved")
	}

	const originated = `BGP routing table entry for 3.0.0.0/8, version 63
Paths: (1 available, best #1, table default)
  Local
    0.0.0.0 from 0.0.0.0 (5.152.0.1)
      Origin IGP, metric 0, weight 32768, valid, sourced, local, best
`
	if !locallyOriginated(originated) {
		t.Error("a prefix this router originates was not recognised, so the hijack would " +
			"report that it had not taken effect")
	}
}
