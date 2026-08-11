package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// The leak detector read only the "nexthops" array, which `show ip bgp` uses.
// This check runs over advertised routes, where FRR writes a scalar "nextHop" --
// so every advertisement had an unknown source, no leak could be attributed,
// and an autonomous system giving the entire internet free transit passed the
// question about not doing that.
func TestALeakedRouteIsAttributedToItsSource(t *testing.T) {
	relOf := map[string]model.Relationship{
		"179.1.3.1": model.RelProvider,
		"179.3.4.2": model.RelPeer,
		"179.3.9.2": model.RelCustomer,
	}
	relOfASN := map[int]model.Relationship{1: model.RelProvider, 4: model.RelPeer, 9: model.RelCustomer}

	cases := []struct {
		name string
		e    bgpRoute
		want model.Relationship
	}{
		{"scalar nextHop, the advertised-routes form",
			bgpRoute{NextHop: "179.3.4.2"}, model.RelPeer},
		{"nexthops array, the show-ip-bgp form",
			bgpRoute{Nexthops: []struct {
				IP string `json:"ip"`
			}{{IP: "179.1.3.1"}}}, model.RelProvider},
		{"next hop rewritten, but the path still names the source",
			bgpRoute{NextHop: "10.0.0.1", Path: "4 200 300"}, model.RelPeer},
		{"our own route has no external source",
			bgpRoute{NextHop: "0.0.0.0", Path: ""}, model.Relationship("")},
	}
	for _, c := range cases {
		if got := sourceRelationship(c.e, relOf, relOfASN); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A route learned from a peer and advertised to another peer is the leak the
// question is about. One learned from a customer is not.
func TestOnlyCustomerRoutesMayBeRelayed(t *testing.T) {
	relOfASN := map[int]model.Relationship{4: model.RelPeer, 9: model.RelCustomer}
	relOf := map[string]model.Relationship{}

	leak := bgpRoute{Path: "4 200"}
	if got := sourceRelationship(leak, relOf, relOfASN); got != model.RelPeer {
		t.Fatalf("a peer's route was attributed to %q", got)
	}
	fine := bgpRoute{Path: "9 500"}
	if got := sourceRelationship(fine, relOf, relOfASN); got != model.RelCustomer {
		t.Fatalf("a customer's route was attributed to %q", got)
	}
}
