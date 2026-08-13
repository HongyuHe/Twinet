package grade

import "testing"

// FRR's status field is not just "*>". With origin validation on it puts the
// validation code first, so the line reads "I*> 10.128.0.0/9" -- and this was
// matched with a "*>" prefix test, on the output of `show bgp ipv4 unicast rpki
// invalid`, where every line carries a validation code by construction.
//
// So the one thing the check existed to notice, an invalid route still being
// chosen, was the one thing it could never match. It passed on every
// submission, including ones with no validation configured at all. Measured on
// a live cluster: 64 routers were carrying the lab's hijack while the check
// reported a clean table.
func TestASelectedInvalidRouteIsRecognised(t *testing.T) {
	chosen := []string{
		"I*> 10.128.0.0/9     179.2.6.1                     100      0 2 1 i",
		"*> 10.128.0.0/9      179.2.6.1                     100      0 2 1 i",
		"N*>i10.128.0.0/9     6.151.0.1               0    100      0 1 1 1 1 i",
	}
	for _, line := range chosen {
		if !selectedRoute(line) {
			t.Errorf("a chosen route was not recognised, so the check reports a clean "+
				"table on a router that is carrying the hijack:\n  %s", line)
		}
	}
	notChosen := []string{
		"   Network          Next Hop            Metric LocPrf Weight Path",
		"I   10.128.0.0/9     179.2.6.1                     100      0 2 1 i",
		"Displayed 1 routes and 20 total paths",
		"BGP table version is 18, local router ID is 6.152.0.1, vrf id 0",
	}
	for _, line := range notChosen {
		if selectedRoute(line) {
			t.Errorf("a line that is not a chosen route was counted as one, which fails "+
				"a submission for the grader's own output:\n  %s", line)
		}
	}
}
