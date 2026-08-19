package grade

import "testing"

// FRR prints the validator's table with the address and the prefix length in
// separate columns. Looking for a slash matched nothing, so every system
// appeared to have published no ROA and the not-found check quietly became a
// test that this AS holds a route to every other one -- a different question,
// failing for reasons that had nothing to do with over-filtering.
func TestTheValidatorTableIsParsedAsFRRPrintsIt(t *testing.T) {
	const table = `RPKI/RTR prefix table
Prefix                                   Prefix Length  Origin-AS
6.0.0.0                                      8 -   8   6
10.128.0.0                                   9 -   9   2
2001:db8::                                  32 -  32   7
not a row
`
	got := parseROATable(table)
	if !got["6.0.0.0/8"] {
		t.Errorf("6.0.0.0/8 was not recognised as covered by a ROA; parsed %v", got)
	}
	if !got["10.128.0.0/9"] {
		t.Errorf("10.128.0.0/9 was not recognised; parsed %v", got)
	}
	if len(got) != 2 {
		t.Errorf("parsed %d entries from two IPv4 rows: %v", len(got), got)
	}
}

// "remote-as 10" contains "remote-as 1", so in AS 1 every neighbour in AS 10,
// 100 or 140 was classified as internal -- and a check that requires every
// external session to be guarded then skipped exactly the sessions that matter.
func TestARemoteASIsComparedAsAWholeNumber(t *testing.T) {
	if !hasRemoteAS("remote-as 1", 1) {
		t.Error("a neighbour in AS 1 was not recognised as being in AS 1")
	}
	if hasRemoteAS("remote-as 10", 1) {
		t.Error("a neighbour in AS 10 was treated as internal to AS 1, so its session " +
			"would be skipped by every check that looks at external sessions")
	}
	if hasRemoteAS("remote-as 140", 14) {
		t.Error("a neighbour in AS 140 was treated as internal to AS 14")
	}
	if !hasRemoteAS("peer-group X\nremote-as 140", 140) {
		t.Error("a neighbour in AS 140 was not recognised across multiple lines")
	}
}

// Route-maps are evaluated in sequence order, first match wins, and a clause
// with no match statements matches everything. Asking only whether some deny
// clause mentioned the condition made an accept-all policy score the marks for
// filtering.
func TestAnUnreachableDenyIsNotProtection(t *testing.T) {
	acceptAll := "route-map RPKI-IN permit 10" + "\n" +
		"route-map RPKI-IN deny 20" + "\n" +
		" match rpki invalid" + "\n"
	if denyMatches(acceptAll, "rpki invalid") {
		t.Error("a permit clause that matches everything, followed by an unreachable deny, " +
			"was counted as filtering invalid origins")
	}

	real := "route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n" +
		"route-map RPKI-IN permit 10" + "\n"
	if !denyMatches(real, "rpki invalid") {
		t.Error("a deny clause reached before any permit was not recognised")
	}

	outOfOrder := "route-map RPKI-IN permit 20" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n"
	if !denyMatches(outOfOrder, "rpki invalid") {
		t.Error("the clauses were judged in the order they were written rather than in " +
			"sequence order, which is the order the router uses")
	}

	permitted := "route-map RPKI-IN permit 5" + "\n" +
		" match rpki invalid" + "\n"
	if denyMatches(permitted, "rpki invalid") {
		t.Error("a clause that permits invalid origins was counted as denying them")
	}
}

// A clause is reached only if every one of its match statements holds, so a
// permit clause asking for a validation state cannot be the way a route in a
// different state gets in -- whatever else it also asks for. Reading this as
// "every match must select on the state" failed a correct submission whose
// permit clause set local-preference for valid routes on a prefix list.
func TestAPermitThatCannotMatchTheDeniedStateIsNotAWayIn(t *testing.T) {
	withPrefixList := "route-map RPKI-IN permit 3" + "\n" +
		" match ip address prefix-list ALL-ROUTES" + "\n" +
		" match rpki valid" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n" +
		"route-map RPKI-IN permit 20" + "\n"
	if !denyMatches(withPrefixList, "rpki invalid") {
		t.Error("a permit clause that no invalid route can match was treated as letting " +
			"invalid routes through, failing a submission that rejects them")
	}

	// The same clause, written with the validation state first.
	stateFirst := "route-map RPKI-IN permit 3" + "\n" +
		" match rpki valid" + "\n" +
		" match community 1:30" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n"
	if !denyMatches(stateFirst, "rpki invalid") {
		t.Error("the verdict depended on the order the match statements were written in")
	}

	notfound := "route-map RPKI-IN permit 3" + "\n" +
		" match rpki notfound" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n"
	if !denyMatches(notfound, "rpki invalid") {
		t.Error("a permit clause selecting a third validation state was treated as a way in")
	}
}

// The reason the preceding-permit rule exists in the first place: a clause
// resting on anything the configuration cannot decide can be true of an
// invalid route, so it still hides the deny behind it.
func TestAPermitThatCouldMatchTheDeniedStateStillHidesTheDeny(t *testing.T) {
	prefixOnly := "route-map RPKI-IN permit 3" + "\n" +
		" match ip address prefix-list ALL-BUT-THE-TESTED-ONE" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n"
	if denyMatches(prefixOnly, "rpki invalid") {
		t.Error("a permit clause an invalid route can match was counted as harmless")
	}

	// Permitting the very state the deny behind it names.
	sameState := "route-map RPKI-IN permit 3" + "\n" +
		" match rpki invalid" + "\n" +
		" match ip address prefix-list SOME" + "\n" +
		"route-map RPKI-IN deny 5" + "\n" +
		" match rpki invalid" + "\n"
	if denyMatches(sameState, "rpki invalid") {
		t.Error("a clause that permits invalid origins on a prefix list was counted as " +
			"denying them")
	}
}
