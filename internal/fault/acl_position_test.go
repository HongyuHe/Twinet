package fault

import "testing"

// `iptables -D <chain> <spec>` deletes the *first* rule matching the
// specification. The injected rule is appended, so on a device that already had
// an identical rule, deleting by specification removes the student's and leaves
// ours -- and the rule counts still match afterwards, so nothing notices.
//
// The listing is parsed and the last matching position removed instead.
func TestTheInjectedRuleIsFoundByPositionNotBySpecification(t *testing.T) {
	const listing = `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       icmp --  0.0.0.0/0            0.0.0.0/0            icmptype 8
2    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0
3    DROP       icmp --  0.0.0.0/0            0.0.0.0/0            icmptype 8
`
	got := lastMatchingPosition(listing, specTokens("-p icmp -m icmp --icmp-type 8"))
	if got != 3 {
		t.Errorf("the injected rule was located at position %d, not 3. Removing the "+
			"first match would delete the rule the student wrote and leave the "+
			"injected one behind, with the counts still adding up", got)
	}
}

func TestARuleThatIsNotThereHasNoPosition(t *testing.T) {
	const listing = `Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0
`
	if got := lastMatchingPosition(listing, specTokens("-p icmp")); got != 0 {
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
