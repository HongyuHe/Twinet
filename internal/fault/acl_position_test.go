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
