package grade

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FRR's BGP JSON output is not one shape but several, and the differences are
// silent: an unknown key simply decodes to nothing.
//
//	show ip bgp json
//	  {"routes": {"1.0.0.0/8": [ {..., "nexthops":[{"ip":"179.0.13.1"}]} ]}}
//
//	show ip bgp neighbors X advertised-routes json
//	  {"advertisedRoutes": {"1.0.0.0/8": {..., "nextHop":"0.0.0.0"}}}
//
// The top-level key differs, the value is an array in one case and a bare
// object in the other, and the next hop is a list in one and a string in the
// other. Decoding one into the other yields an empty map and no error, which
// turned two policy checks into unconditional passes.
//
// These types therefore accept every shape explicitly and normalise it, and
// TestDecodeRealFRROutput pins the behaviour against captured output from the
// FRR version the platform ships.

// bgpRoute is one path for one prefix, normalised across output shapes.
type bgpRoute struct {
	Valid     bool   `json:"valid"`
	BestPath  bool   `json:"bestpath"`
	Best      bool   `json:"best"`
	LocalPref int    `json:"locPrf"`
	Origin    string `json:"origin"`
	Path      string `json:"path"`
	PeerID    string `json:"peerId"`
	Network   string `json:"network"`

	// Nexthops is the `show ip bgp` form.
	Nexthops []struct {
		IP string `json:"ip"`
	} `json:"nexthops"`
	// NextHop is the `advertised-routes` form.
	NextHop string `json:"nextHop"`
	// PathFrom is "internal" for a route another router of this AS advertised,
	// and "external" for one learned over an eBGP session directly. It is what
	// tells a next-hop-self fault from a normal connected next hop.
	PathFrom string `json:"pathFrom"`

	Community *struct {
		String string `json:"string"`
	} `json:"community"`
}

// IsBest reports whether this path was selected, across both spellings.
func (r bgpRoute) IsBest() bool { return r.BestPath || r.Best }

// NextHops returns every next-hop address, from whichever field carried them.
func (r bgpRoute) NextHops() []string {
	out := make([]string, 0, len(r.Nexthops)+1)
	for _, n := range r.Nexthops {
		if n.IP != "" {
			out = append(out, n.IP)
		}
	}
	if r.NextHop != "" {
		out = append(out, r.NextHop)
	}
	return out
}

// PathLen returns the number of AS numbers in the path.
func (r bgpRoute) PathLen() int { return len(strings.Fields(r.Path)) }

// Originated reports whether this AS injected the route itself.
//
// Two independent signs, either of which is decisive. FRR gives a path it
// injected no peer at all -- `peerId` reads "(unspec)" -- and nothing a
// route-map can set changes that, because there is no session to name. And an
// empty AS path anywhere inside the AS means the same thing from the other
// side: a route learned over eBGP always carries at least the neighbour's ASN,
// so an empty path on an iBGP-learned copy can only have started here.
//
// The empty path alone was the whole test, and it is not enough. Injecting a
// prefix with `network X route-map M` where M prepends an ASN produces a
// locally sourced route with a non-empty path, which read as somebody else's
// route passing through: a reviewer announced 203.0.113.0/24 that way, AS 3
// advertised it to its customers, and the check that exists to catch exactly
// that gave full marks.
func (r bgpRoute) Originated() bool {
	return r.PeerID == unspecifiedPeer || strings.TrimSpace(r.Path) == ""
}

// unspecifiedPeer is what FRR prints for a path with no session behind it.
const unspecifiedPeer = "(unspec)"

// routeSet is a prefix-to-paths map that accepts both an array of paths and a
// single bare path object for each prefix.
type routeSet map[string][]bgpRoute

// UnmarshalJSON normalises whichever shape FRR used.
func (rs *routeSet) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make(routeSet, len(raw))
	for prefix, v := range raw {
		trimmed := strings.TrimLeft(string(v), " \t\r\n")
		if strings.HasPrefix(trimmed, "[") {
			var arr []bgpRoute
			if err := json.Unmarshal(v, &arr); err != nil {
				return fmt.Errorf("prefix %s: %w", prefix, err)
			}
			out[prefix] = arr
			continue
		}
		var one bgpRoute
		if err := json.Unmarshal(v, &one); err != nil {
			return fmt.Errorf("prefix %s: %w", prefix, err)
		}
		out[prefix] = []bgpRoute{one}
	}
	*rs = out
	return nil
}

// bgpRouteJSON covers every BGP table document the checks read.
type bgpRouteJSON struct {
	Routes           routeSet `json:"routes"`
	AdvertisedRoutes routeSet `json:"advertisedRoutes"`
	ReceivedRoutes   routeSet `json:"receivedRoutes"`
	TotalPrefix      int      `json:"totalPrefixCounter"`
	LocalAS          int      `json:"localAS"`

	// FRR answers a query about a neighbour it does not have with
	// {"warning":"No such neighbor in this view/vrf"} and exit status 0. That
	// is a finding about the student -- they did not configure the session --
	// and not an unreadable document, which is a fault in the grader.
	Warning string `json:"warning"`
}

// NoSuchNeighbour reports whether FRR answered that the neighbour asked about
// does not exist.
func (b bgpRouteJSON) NoSuchNeighbour() bool {
	return strings.Contains(strings.ToLower(b.Warning), "no such neighbor")
}

// Table returns the populated route map, whichever key FRR used.
func (b bgpRouteJSON) Table() routeSet {
	switch {
	case len(b.Routes) > 0:
		return b.Routes
	case len(b.AdvertisedRoutes) > 0:
		return b.AdvertisedRoutes
	case len(b.ReceivedRoutes) > 0:
		return b.ReceivedRoutes
	}
	return nil
}

// Decoded reports whether the document contained a recognisable table at all.
//
// A check must be able to tell "the neighbour was advertised nothing" from "the
// output was not understood": the first is a finding about the student, the
// second is a fault in the grader that must never silently cost marks.
func (b bgpRouteJSON) Decoded() bool {
	return b.Routes != nil || b.AdvertisedRoutes != nil || b.ReceivedRoutes != nil
}
