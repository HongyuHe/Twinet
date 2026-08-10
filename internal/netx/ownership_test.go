package netx

import "testing"

// Two labs on one node derive their VXLAN identifiers independently, so nothing
// stops them landing on the same 24-bit value. Without an owner recorded on the
// device the second lab silently joins the first one's tunnel, and cleaning up
// either deletes the other's fabric. Both failures look like impossible routing
// rather than like an error, which is why ownership is recorded explicitly.
func TestOverlayOwnershipRoundTrips(t *testing.T) {
	cases := []string{"cos461", "cos461-g3-attempt2", "a"}
	for _, lab := range cases {
		if got := ownerFromAlias(ownerAlias(lab)); got != lab {
			t.Errorf("ownerFromAlias(ownerAlias(%q)) = %q", lab, got)
		}
	}
	// An interface Twinet did not create, or one from before ownership was
	// recorded, must read as unowned rather than as belonging to some lab.
	for _, alias := range []string{"", "something-else", "twinet", "vxlan100"} {
		if got := ownerFromAlias(alias); got != "" {
			t.Errorf("alias %q was read as owned by %q", alias, got)
		}
	}
}
