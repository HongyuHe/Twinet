package grade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file registers the checks that grade the inter-domain half of the
// assignment: iBGP, eBGP, business relationships, exchange policy and RPKI.

func init() {
	Register(&Check{
		Name:     "bgp.ibgp_full_mesh",
		Describe: "a BGP session exists between every pair of routers, sourced from loopbacks",
		Run:      checkIBGPFullMesh,
	})
	Register(&Check{
		Name:     "bgp.ebgp_established",
		Describe: "every external BGP session with a neighbour is established",
		Run:      checkEBGPEstablished,
	})
	Register(&Check{
		Name:     "bgp.own_prefix_only",
		Describe: "the AS originates exactly its own prefix and nothing else",
		Run:      checkOwnPrefix,
	})
	Register(&Check{
		Name:     "policy.gao_rexford",
		Describe: "routes from a customer are preferred over a peer's, and a peer's over a provider's",
		Run:      checkGaoRexford,
	})
	Register(&Check{
		Name:     "policy.no_transit_for_peers",
		Describe: "routes learned from a peer or provider are not re-exported to a peer or provider",
		Run:      checkNoTransit,
	})
	Register(&Check{
		Name:     "config.no_forbidden_ospf",
		Describe: "inter-AS subnets are kept out of OSPF, as the assignment requires",
		Run:      checkNoForbiddenOSPF,
	})
}

// bgpSummaryJSON is the shape of `show ip bgp summary json`.
type bgpSummaryJSON struct {
	IPv4Unicast struct {
		RouterID string `json:"routerId"`
		AS       int    `json:"as"`
		Peers    map[string]struct {
			RemoteAs      int    `json:"remoteAs"`
			State         string `json:"state"`
			PfxRcd        int    `json:"pfxRcd"`
			PfxSnt        int    `json:"pfxSnt"`
			PeerUptimeMs  int64  `json:"peerUptimeMsec"`
			ConnectionsEs int    `json:"connectionsEstablished"`
		} `json:"peers"`
	} `json:"ipv4Unicast"`
}

// summary fetches a router's BGP summary, tolerating a router with no BGP.
func bgpSummary(ctx context.Context, env *Env, router string) (bgpSummaryJSON, error) {
	var out bgpSummaryJSON
	err := env.VtyshJSON(ctx, router, "show ip bgp summary json", &out)
	return out, err
}

func checkIBGPFullMesh(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) < 2 {
		return Errored("bgp.ibgp_full_mesh", fmt.Errorf("AS %d has %d routers", env.AS, len(routers)))
	}
	// The expected peer address of each router is its loopback: the assignment
	// is explicit that iBGP must be sourced from loopbacks so a session does
	// not drop when one physical interface goes down.
	loopback := map[string]string{}
	for _, r := range routers {
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			loopback[r.Name] = addrOf(lo.Addr4)
		}
	}

	want := len(routers) * (len(routers) - 1)
	established := 0
	var problems []string

	for _, r := range routers {
		sum, err := bgpSummary(ctx, env, r.Name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for _, other := range routers {
			if other == r {
				continue
			}
			addr := loopback[other.Name]
			if addr == "" {
				continue
			}
			p, ok := sum.IPv4Unicast.Peers[addr]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s has no session with %s (%s)", r.Name, other.Name, addr))
			case p.RemoteAs != env.AS:
				problems = append(problems, fmt.Sprintf("%s -> %s is configured as AS %d, not %d",
					r.Name, other.Name, p.RemoteAs, env.AS))
			case !strings.EqualFold(p.State, "Established"):
				problems = append(problems, fmt.Sprintf("%s -> %s is %s", r.Name, other.Name, p.State))
			default:
				established++
			}
		}
	}

	if established == want && len(problems) == 0 {
		return Pass("bgp.ibgp_full_mesh", Evidence{
			Observed: fmt.Sprintf("%d of %d iBGP sessions established", established, want)})
	}
	sort.Strings(problems)
	return Partial("bgp.ibgp_full_mesh", ratio(established, want), Evidence{
		Expected: fmt.Sprintf("%d iBGP sessions on loopbacks", want),
		Observed: fmt.Sprintf("%d established", established),
		Detail:   strings.Join(problems, "\n"),
		Hint:     "peer with each router's loopback and set update-source lo on both ends",
		Command:  "show ip bgp summary json",
	})
}

func checkEBGPEstablished(ctx context.Context, env *Env) Result {
	// The model knows exactly which external sessions should exist.
	type want struct {
		router, peerAddr string
		peerAS           int
	}
	var wanted []want
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Role != model.RoleInterAS && i.Role != model.RoleIXPLink {
				continue
			}
			if i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			wanted = append(wanted, want{r.Name, addrOf(i.Peer.Addr4), i.Peer.Device.ASN})
		}
	}
	if len(wanted) == 0 {
		return Errored("bgp.ebgp_established", fmt.Errorf("AS %d has no external links in the lab", env.AS))
	}

	byRouter := map[string]bgpSummaryJSON{}
	up := 0
	var problems []string
	for _, w := range wanted {
		sum, ok := byRouter[w.router]
		if !ok {
			var err error
			sum, err = bgpSummary(ctx, env, w.router)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", w.router, err))
				continue
			}
			byRouter[w.router] = sum
		}
		p, ok := sum.IPv4Unicast.Peers[w.peerAddr]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s has no session with AS %d at %s",
				w.router, w.peerAS, w.peerAddr))
		case !strings.EqualFold(p.State, "Established"):
			problems = append(problems, fmt.Sprintf("%s -> AS %d (%s) is %s",
				w.router, w.peerAS, w.peerAddr, p.State))
		default:
			up++
		}
	}

	if up == len(wanted) {
		return Pass("bgp.ebgp_established", Evidence{
			Observed: fmt.Sprintf("all %d eBGP sessions established", up)})
	}
	sort.Strings(problems)
	return Partial("bgp.ebgp_established", ratio(up, len(wanted)), Evidence{
		Expected: fmt.Sprintf("%d eBGP sessions", len(wanted)),
		Observed: fmt.Sprintf("%d established", up),
		Detail:   strings.Join(problems, "\n"),
		Hint:     "agree the addresses with your neighbour, and remember next-hop-self",
		Command:  "show ip bgp summary json",
	})
}

func bgpTable(ctx context.Context, env *Env, router string) (bgpRouteJSON, error) {
	var out bgpRouteJSON
	err := env.VtyshJSON(ctx, router, "show ip bgp json", &out)
	return out, err
}

func checkOwnPrefix(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || as.Block == "" {
		return Errored("bgp.own_prefix_only", fmt.Errorf("AS %d has no prefix in the plan", env.AS))
	}
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("bgp.own_prefix_only", fmt.Errorf("AS %d has no routers", env.AS))
	}
	tbl, err := bgpTable(ctx, env, routers[0].Name)
	if err != nil {
		return Errored("bgp.own_prefix_only", err)
	}

	originated := map[string]bool{}
	for prefix, entries := range tbl.Table() {
		for _, e := range entries {
			// An empty AS path on a locally injected route means we originate it.
			if strings.TrimSpace(e.Path) == "" {
				originated[prefix] = true
			}
		}
	}

	hasOwn := originated[as.Block]
	var extra []string
	for p := range originated {
		if p != as.Block {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)

	switch {
	case hasOwn && len(extra) == 0:
		return Pass("bgp.own_prefix_only", Evidence{Observed: "originates " + as.Block})
	case !hasOwn:
		return Fail("bgp.own_prefix_only", Evidence{
			Expected: as.Block, Observed: "not originated",
			Detail:  fmt.Sprintf("%s does not appear as a locally originated route", as.Block),
			Hint:    "advertise your /8 with `network " + as.Block + "` under the IPv4 address family",
			Command: "show ip bgp json",
		})
	default:
		return Partial("bgp.own_prefix_only", 0.5, Evidence{
			Expected: "only " + as.Block,
			Observed: fmt.Sprintf("also originates %s", strings.Join(extra, ", ")),
			Detail:   "advertising address space that is not yours is what the hijack exercise is about",
			Command:  "show ip bgp json",
		})
	}
}

// checkGaoRexford verifies the local-preference ordering that implements the
// business relationships: customer over peer over provider.
//
// It reads the ordering out of the routing table rather than pattern-matching
// the configuration, so any correct implementation passes and a configuration
// that merely looks right does not.
func checkGaoRexford(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("policy.gao_rexford", fmt.Errorf("AS %d has no routers", env.AS))
	}

	// Which neighbour address corresponds to which relationship, from the model.
	relOf := map[string]model.Relationship{}
	for _, r := range routers {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			// What the neighbour is to us. Derived in one place, because the
			// same two lines written out here, in the renderer and in the
			// other checks were all inverted in the same direction -- so the
			// wrong answer was self-consistent and scored full marks.
			rel := i.Link.PeerRelationship(i)
			relOf[addrOf(i.Peer.Addr4)] = rel
		}
	}
	if len(relOf) == 0 {
		return Errored("policy.gao_rexford", fmt.Errorf("AS %d has no external neighbours", env.AS))
	}

	// Observe the local preference applied to routes from each relationship.
	prefs := map[model.Relationship][]int{}
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for _, entries := range tbl.Table() {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					if rel, ok := relOf[nh.IP]; ok {
						prefs[rel] = append(prefs[rel], e.LocalPref)
					}
				}
			}
		}
	}

	median := func(rel model.Relationship) (int, bool) {
		v := prefs[rel]
		if len(v) == 0 {
			return 0, false
		}
		sort.Ints(v)
		return v[len(v)/2], true
	}
	cust, hasCust := median(model.RelCustomer)
	peer, hasPeer := median(model.RelPeer)
	prov, hasProv := median(model.RelProvider)

	var detail strings.Builder
	fmt.Fprintf(&detail, "observed local preference: customer=%s peer=%s provider=%s\n",
		orNone(cust, hasCust), orNone(peer, hasPeer), orNone(prov, hasProv))

	checks, passed := 0, 0
	if hasCust && hasPeer {
		checks++
		if cust > peer {
			passed++
		} else {
			fmt.Fprintf(&detail, "a customer's routes (%d) must be preferred over a peer's (%d)\n", cust, peer)
		}
	}
	if hasPeer && hasProv {
		checks++
		if peer > prov {
			passed++
		} else {
			fmt.Fprintf(&detail, "a peer's routes (%d) must be preferred over a provider's (%d)\n", peer, prov)
		}
	}
	if hasCust && hasProv {
		checks++
		if cust > prov {
			passed++
		} else {
			fmt.Fprintf(&detail, "a customer's routes (%d) must be preferred over a provider's (%d)\n", cust, prov)
		}
	}
	// Every relationship this AS actually has must be represented.
	//
	// Only the classes that happened to be visible were compared, so an AS
	// whose provider routes had all been filtered away was marked on
	// customer-versus-peer alone and passed -- the ordering it was asked about
	// was never observed. What relationships exist is in the topology, so it
	// does not have to be inferred from what survived.
	var absent []string
	for rel, present := range map[model.Relationship]bool{
		model.RelCustomer: hasCust, model.RelPeer: hasPeer, model.RelProvider: hasProv,
	} {
		if present {
			continue
		}
		for _, r := range relOf {
			if r == rel {
				absent = append(absent, string(rel))
				break
			}
		}
	}
	if len(absent) > 0 {
		sort.Strings(absent)
		return Partial("policy.gao_rexford", ratio(passed, maxInt(checks, 1))*0.5, Evidence{
			Expected: "customer routes preferred over peers', and peers' over providers'",
			Observed: fmt.Sprintf("this AS has %s neighbour(s), but no route from them is in "+
				"its table, so the ordering they are part of could not be observed",
				strings.Join(absent, " and ")),
			Detail: detail.String(),
			Hint: "a relationship whose routes are all filtered away cannot be shown to be " +
				"ranked correctly; accept them and rank them",
			Command: "show ip bgp json",
		})
	}
	if checks == 0 {
		return Errored("policy.gao_rexford",
			fmt.Errorf("no routes were learned from enough distinct relationships to compare"))
	}
	if passed == checks {
		return Pass("policy.gao_rexford", Evidence{
			Observed: strings.TrimSpace(detail.String())})
	}
	return Partial("policy.gao_rexford", ratio(passed, checks), Evidence{
		Expected: "local preference customer > peer > provider",
		Observed: fmt.Sprintf("%d of %d orderings correct", passed, checks),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "set local-preference on import, per relationship, with a route-map",
		Command:  "show ip bgp json",
	})
}

// checkNoTransit verifies the export half of the business relationships: a
// route learned from a peer or a provider must not be handed to another peer or
// provider, or the AS is providing free transit.
func checkNoTransit(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	relOf := map[string]model.Relationship{}
	relOfASN := map[int]model.Relationship{}
	for _, r := range routers {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			// What the neighbour is to us. Derived in one place, because the
			// same two lines written out here, in the renderer and in the
			// other checks were all inverted in the same direction -- so the
			// wrong answer was self-consistent and scored full marks.
			rel := i.Link.PeerRelationship(i)
			relOf[addrOf(i.Peer.Addr4)] = rel
			if i.Peer.Device != nil {
				relOfASN[i.Peer.Device.ASN] = rel
			}
		}
	}

	// What this AS is supposed to be announcing about itself.
	own := ""
	if as, ok := env.Topology.ASes[env.AS]; ok {
		own = as.Block
	}
	announced := 0

	// For each non-customer neighbour, look at what we advertise to them.
	var leaks []string
	var silent []string
	var unreadable []string
	checked := 0
	for _, r := range routers {
		for addr, rel := range relOf {
			if rel == model.RelCustomer {
				continue // a customer may receive everything
			}
			adv, err := advertisedRoutes(ctx, env, r.Name, addr)
			if err != nil {
				// The session may simply not exist yet, which is a student
				// finding; an unreadable document is ours, and is recorded so
				// it cannot masquerade as a pass.
				unreadable = append(unreadable, err.Error())
				continue
			}
			checked++
			sawOwn := false
			for prefix, entries := range adv.Table() {
				if own != "" && prefix == own {
					announced++
					sawOwn = true
				}
				for _, e := range entries {
					// A route we originate has an empty path and may go anywhere.
					if strings.TrimSpace(e.Path) == "" {
						continue
					}
					// Otherwise it came from someone: if it came from a peer or
					// provider, exporting it here is a leak.
					src := sourceRelationship(e, relOf, relOfASN)
					if src == model.RelPeer || src == model.RelProvider {
						leaks = append(leaks, fmt.Sprintf(
							"%s advertises %s (learned from a %s, path %q) to a %s at %s",
							r.Name, prefix, src, strings.TrimSpace(e.Path), rel, addr))
					}
				}
			}
			if !sawOwn {
				silent = append(silent, fmt.Sprintf("%s advertises nothing of its own to the %s at %s",
					r.Name, rel, addr))
			}
		}
	}
	if checked == 0 {
		sort.Strings(unreadable)
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"no neighbour's advertised routes could be read, so nothing could be assessed: %s",
			strings.Join(truncate(unreadable, 3), "; ")))
	}
	// Advertising nothing is not the same as advertising correctly.
	//
	// This check counted leaks and passed when it found none, so a deny-all
	// export policy scored full marks: no advertisements, therefore no leaked
	// advertisements. That is a badly wrong answer -- the AS is invisible to
	// the internet -- receiving the same mark as a correct Gao-Rexford export.
	// The question is what may cross the session, and a session carrying
	// nothing has not answered it.
	if announced == 0 {
		return Fail("policy.no_transit_for_peers", Evidence{
			Expected: "your own prefix advertised to peers and providers, and nothing learned from them",
			Observed: fmt.Sprintf("nothing at all is advertised to any of the %d non-customer neighbours", checked),
			Hint: "an export policy that denies everything leaks nothing, but it also means " +
				"nobody outside your AS can reach you",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	// Reaching one neighbour is not reaching the internet.
	//
	// This counted advertisements in total, so a policy that announced the
	// prefix to a single provider and denied every other peer and provider
	// passed with full marks -- an AS almost nobody can reach, marked the same
	// as one that is correctly connected. Each session is now asked separately.
	if len(silent) > 0 && len(leaks) == 0 {
		sort.Strings(silent)
		return Partial("policy.no_transit_for_peers", 0.5, Evidence{
			Expected: "your own prefix advertised to every peer and provider, and nothing learned from them",
			Observed: fmt.Sprintf("nothing leaks, but %d of %d non-customer sessions carry "+
				"nothing of your own", len(silent), checked),
			Detail: strings.Join(truncate(silent, 5), "\n"),
			Hint: "an export policy that denies everything leaks nothing, but the networks " +
				"behind those sessions cannot reach you at all",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	if len(leaks) == 0 {
		return Pass("policy.no_transit_for_peers", Evidence{
			Observed: fmt.Sprintf("no leaks across %d neighbour views; own prefix advertised to all of them",
				checked)})
	}
	sort.Strings(leaks)
	if len(leaks) > 12 {
		leaks = append(leaks[:12], fmt.Sprintf("... and %d more", len(leaks)-12))
	}
	return Fail("policy.no_transit_for_peers", Evidence{
		Expected: "only your own and your customers' routes go to peers and providers",
		Observed: fmt.Sprintf("%d leaked advertisement(s)", len(leaks)),
		Detail:   strings.Join(leaks, "\n"),
		Hint:     "tag routes with a community on import and match it when exporting",
		Command:  "show ip bgp neighbors <addr> advertised-routes json",
	})
}

// sourceRelationship infers which neighbour a route was learned from.
//
// Both spellings of the next hop are read. FRR uses a "nexthops" array for
// `show ip bgp` and a scalar "nextHop" for advertised routes, and this check
// runs over the latter -- so reading only the array meant every advertisement
// had an unknown source, no leak could ever be attributed, and a network
// providing free transit to the entire internet passed the question about not
// doing that.
func sourceRelationship(e bgpRoute, relOf map[string]model.Relationship,
	relOfASN map[int]model.Relationship) model.Relationship {
	for _, nh := range e.Nexthops {
		if rel, ok := relOf[nh.IP]; ok {
			return rel
		}
	}
	if e.NextHop != "" {
		if rel, ok := relOf[e.NextHop]; ok {
			return rel
		}
	}
	// The AS path is the fallback, and for this question the better signal:
	// an advertisement whose path begins with a neighbour is a route learned
	// from that neighbour, whatever the next hop was rewritten to.
	if f := strings.Fields(strings.TrimSpace(e.Path)); len(f) > 0 {
		var asn int
		if _, err := fmt.Sscanf(f[0], "%d", &asn); err == nil {
			if rel, ok := relOfASN[asn]; ok {
				return rel
			}
		}
	}
	return ""
}

func checkNoForbiddenOSPF(ctx context.Context, env *Env) Result {
	// Every router, or none: this check concludes from what it does not find,
	// so a router it could not read is a router whose forbidden statements it
	// would also not have found.
	cfgs, err := runningConfigs(ctx, env)
	if err != nil {
		return Fail("config.no_forbidden_ospf", Evidence{
			Expected: "every router's configuration readable, with no 179.x or 180.x under router ospf",
			Observed: "some configurations could not be read",
			Detail:   err.Error(),
			Hint:     "make sure FRR is running on every router before submitting",
			Command:  "show running-config",
		})
	}
	var found []string
	for _, r := range env.Routers() {
		out := cfgs[r.Name]
		inOSPF := false
		for _, line := range strings.Split(out, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "router ospf") {
				inOSPF = true
				continue
			}
			if inOSPF && (t == "exit" || t == "!") {
				inOSPF = false
				continue
			}
			if !inOSPF || !strings.HasPrefix(t, "network ") {
				continue
			}
			// The assignment is explicit that the inter-AS ranges must not be
			// in OSPF: advertising them internally breaks eBGP next-hop
			// resolution in confusing ways.
			if strings.HasPrefix(t, "network 179.") || strings.HasPrefix(t, "network 180.") {
				found = append(found, fmt.Sprintf("%s: %s", r.Name, t))
			}
		}
	}
	if len(found) == 0 {
		return Pass("config.no_forbidden_ospf", Evidence{
			Observed: "no inter-AS subnets are advertised in OSPF"})
	}
	sort.Strings(found)
	return Fail("config.no_forbidden_ospf", Evidence{
		Expected: "no 179.x or 180.x networks under router ospf",
		Observed: fmt.Sprintf("%d such statement(s)", len(found)),
		Detail:   strings.Join(found, "\n"),
		Hint:     "external subnets belong to BGP, not to your interior routing protocol",
		Command:  "show running-config",
	})
}

func addrOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

func orNone(v int, ok bool) string {
	if !ok {
		return "none"
	}
	return fmt.Sprint(v)
}

// jsonUnmarshalLoose decodes JSON, tolerating the leading noise some vtysh
// versions emit before the document.
func jsonUnmarshalLoose(s string, out any) error {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if s == "" {
		return fmt.Errorf("empty output")
	}
	return json.Unmarshal([]byte(s), out)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
