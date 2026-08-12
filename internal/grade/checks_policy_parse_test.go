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
