package grade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
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
			wanted = append(wanted, want{r.Name, env.PeerAddr(ctx, i), i.Peer.Device.ASN})
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
	// Every router, and what each of them actually sends.
	//
	// This read the table of routers[0] alone. A system originating somebody
	// else's address space on one router and hiding it from the first with an
	// outbound route-map kept the whole mark: the prefix was in the neighbour's
	// table and in the originating router's advertisements, and the grader
	// looked at neither. Which router happens to be first is an accident of the
	// template's ordering, and no property of a system is a property of one of
	// its routers.
	originated := map[string]bool{}
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			return Errored("bgp.own_prefix_only", err)
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				// An empty AS path on a locally injected route means we
				// originate it.
				if strings.TrimSpace(e.Path) == "" {
					originated[prefix] = true
				}
			}
		}
	}

	// And what leaves the system, which is what the neighbours see and what the
	// question is really about. A prefix originated and withheld is a mistake;
	// a prefix advertised is a claim on somebody's address space.
	advertised := map[string]string{}
	for _, sess := range externalSessions(ctx, env) {
		adv, err := advertisedRoutes(ctx, env, sess.Router, sess.Addr)
		if err != nil {
			if errors.Is(err, errNoSuchNeighbour) {
				continue
			}
			return Errored("bgp.own_prefix_only", fmt.Errorf(
				"%s: what it advertises to %s could not be read, so whether this system "+
					"announces address space that is not its own cannot be decided: %w",
				sess.Router, sess.Addr, err))
		}
		for prefix, entries := range adv.Table() {
			for _, e := range entries {
				if strings.TrimSpace(e.Path) != "" {
					continue // somebody else's route, passing through
				}
				originated[prefix] = true
				if prefix != as.Block {
					advertised[prefix] = fmt.Sprintf("%s advertises it to %s",
						sess.Router, sess.Addr)
				}
			}
		}
	}

	hasOwn := originated[as.Block]
	var extra []string
	for p := range originated {
		if p == as.Block {
			continue
		}
		if where, ok := advertised[p]; ok {
			extra = append(extra, fmt.Sprintf("%s (%s)", p, where))
			continue
		}
		extra = append(extra, p)
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

	// Which neighbour address corresponds to which relationship.
	//
	// Taken from externalSessions rather than rebuilt here, because rebuilding
	// it here left the exchange out: a session with a route server is not a
	// point-to-point inter-AS link, so every peer reached across an IXP was
	// invisible to this check. An AS whose only peers are exchange members --
	// which is most of them, and all of the ones the assignment cares about --
	// was marked on customer-versus-provider alone.
	relOf := map[string]model.Relationship{}
	for _, sess := range externalSessions(ctx, env) {
		relOf[sess.Addr] = sess.Rel
	}
	if len(relOf) == 0 {
		return Errored("policy.gao_rexford", fmt.Errorf("AS %d has no external neighbours", env.AS))
	}

	// Every route, not a summary of them.
	//
	// This used to compare the median local preference of each relationship,
	// which is a statement about most routes and about no particular one: an AS
	// that set local-preference 200 on nine customer prefixes and left the
	// tenth at the default passed, and so did one that ranked a whole peer
	// correctly on average while preferring one of its routes over a
	// customer's. Gao-Rexford is a rule about every route, so every route is
	// where it is checked -- the worst customer route must still beat the best
	// peer route, and the worst peer route the best provider route.
	type observed struct {
		pref   int
		prefix string
		via    string
		router string
	}
	seen := map[model.Relationship][]observed{}
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					rel, ok := relOf[nh.IP]
					if !ok {
						continue
					}
					seen[rel] = append(seen[rel], observed{e.LocalPref, prefix, nh.IP, r.Name})
				}
			}
		}
	}

	worst := func(rel model.Relationship) (observed, bool) {
		v := seen[rel]
		if len(v) == 0 {
			return observed{}, false
		}
		out := v[0]
		for _, o := range v[1:] {
			if o.pref < out.pref {
				out = o
			}
		}
		return out, true
	}
	best := func(rel model.Relationship) (observed, bool) {
		v := seen[rel]
		if len(v) == 0 {
			return observed{}, false
		}
		out := v[0]
		for _, o := range v[1:] {
			if o.pref > out.pref {
				out = o
			}
		}
		return out, true
	}

	custLo, hasCust := worst(model.RelCustomer)
	peerLo, hasPeer := worst(model.RelPeer)
	provLo, hasProv := worst(model.RelProvider)
	custHi, _ := best(model.RelCustomer)
	peerHi, _ := best(model.RelPeer)
	provHi, _ := best(model.RelProvider)

	span := func(lo, hi observed, ok bool, n int) string {
		if !ok {
			return "none"
		}
		if lo.pref == hi.pref {
			return fmt.Sprintf("%d (%d route(s))", lo.pref, n)
		}
		return fmt.Sprintf("%d..%d (%d route(s))", lo.pref, hi.pref, n)
	}
	var detail strings.Builder
	fmt.Fprintf(&detail, "observed local preference: customer=%s peer=%s provider=%s\n",
		span(custLo, custHi, hasCust, len(seen[model.RelCustomer])),
		span(peerLo, peerHi, hasPeer, len(seen[model.RelPeer])),
		span(provLo, provHi, hasProv, len(seen[model.RelProvider])))

	checks, passed := 0, 0
	compare := func(hiRel, loRel model.Relationship, hiOK, loOK bool,
		hiWorst, loBest observed) {

		if !hiOK || !loOK {
			return
		}
		checks++
		if hiWorst.pref > loBest.pref {
			passed++
			return
		}
		fmt.Fprintf(&detail,
			"every route from a %s must be preferred over every route from a %s, but "+
				"%s carries local preference %d on %s (via %s) while %s carries %d on %s (via %s)\n",
			hiRel, loRel,
			hiWorst.router, hiWorst.pref, hiWorst.prefix, hiWorst.via,
			loBest.router, loBest.pref, loBest.prefix, loBest.via)
	}
	compare(model.RelCustomer, model.RelPeer, hasCust, hasPeer, custLo, peerHi)
	compare(model.RelPeer, model.RelProvider, hasPeer, hasProv, peerLo, provHi)
	compare(model.RelCustomer, model.RelProvider, hasCust, hasProv, custLo, provHi)

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
		Expected: "local preference customer > peer > provider, for every route",
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
	relOf := map[string]model.Relationship{}
	relOfASN := map[int]model.Relationship{}
	// What each neighbour is to us. Derived in one place, because the same two
	// lines written out here, in the renderer and in the other checks were all
	// inverted in the same direction -- so the wrong answer was self-consistent
	// and scored full marks. The exchange is included: its members are peers.
	for _, s := range externalSessions(ctx, env) {
		relOf[s.Addr] = s.Rel
		if s.ASN != 0 {
			relOfASN[s.ASN] = s.Rel
		}
	}

	// What this AS is supposed to be announcing about itself.
	own := ""
	if as, ok := env.Topology.ASes[env.AS]; ok {
		own = as.Block
	}
	announced := 0

	// Each router is asked about its own sessions, and only its own.
	//
	// Every router used to be asked about every inter-AS address in the AS, so
	// most reads came back "no such neighbour" -- one router does not hold
	// another's session -- and landed in the same bucket as a read that failed
	// because the router could not be reached. Both were dropped, so a session
	// that could not be assessed cost nothing, and an AS whose routers were
	// mostly unreadable passed on the strength of the one that answered.
	type session struct {
		router string
		addr   string
		rel    model.Relationship
	}
	var sessions []session
	for _, s := range externalSessions(ctx, env) {
		if s.Rel == model.RelCustomer {
			continue // a customer may receive everything
		}
		sessions = append(sessions, session{s.Router, s.Addr, s.Rel})
	}

	// What this AS learned from its customers and selected. Gao-Rexford's
	// export rule has two halves -- advertise your own prefixes and your
	// customers' to everybody, and nothing else to a peer or a provider -- and
	// only the second half was ever checked. An AS that accepted its customer's
	// routes, used them, and told nobody else about them scored full marks
	// while leaving that customer unreachable from the rest of the internet,
	// which is the single most consequential thing a transit AS can get wrong.
	custPrefixes := map[string]string{}
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if !e.IsBest() {
					continue
				}
				for _, nh := range e.Nexthops {
					if relOf[nh.IP] == model.RelCustomer {
						custPrefixes[prefix] = fmt.Sprintf("learned from a customer at %s", nh.IP)
					}
				}
			}
		}
	}

	// For each non-customer neighbour, look at what we advertise to them.
	var leaks []string
	var withheld []string
	var silent []string
	var unreadable []string
	checked := 0
	for _, sess := range sessions {
		name, addr, rel := sess.router, sess.addr, sess.rel
		adv, err := advertisedRoutes(ctx, env, name, addr)
		if err != nil {
			if errors.Is(err, errNoSuchNeighbour) {
				// The student did not configure the session. That is a
				// finding about them, and it is assessed: nothing of ours
				// crosses a session that does not exist.
				checked++
				silent = append(silent, fmt.Sprintf(
					"%s has no BGP session with the %s at %s, so nothing of yours reaches it",
					name, rel, addr))
				continue
			}
			// An unreadable document is ours, and is recorded so it cannot
			// masquerade as a pass.
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
				src := sourceRelationship(e, env.AS, relOf, relOfASN)
				if src == model.RelPeer || src == model.RelProvider {
					leaks = append(leaks, fmt.Sprintf(
						"%s advertises %s (learned from a %s, path %q) to a %s at %s",
						name, prefix, src, strings.TrimSpace(e.Path), rel, addr))
				}
			}
		}
		if !sawOwn {
			silent = append(silent, fmt.Sprintf("%s advertises nothing of its own to the %s at %s",
				name, rel, addr))
		}
		// The other half of the export rule.
		//
		// A customer's routes must reach the rest of the internet through you;
		// that is what they are paying for. Withholding them is not a safe
		// error, it is the transit service not being provided.
		for prefix, why := range custPrefixes {
			if _, ok := adv.Table()[prefix]; ok {
				continue
			}
			// A route whose own next hop is this neighbour is not withheld
			// from them, it is simply not sent back where it came from.
			withheld = append(withheld, fmt.Sprintf(
				"%s does not advertise %s (%s) to the %s at %s",
				name, prefix, why, rel, addr))
		}
	}
	// A session that could not be read has not been assessed, and a check that
	// reports "no leaks" while some of the sessions it is about were never read
	// is reporting on a question it did not finish asking.
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"%d of %d non-customer session(s) could not be read, so no verdict covers them: %s",
			len(unreadable), len(sessions), strings.Join(truncate(unreadable, 3), "; ")))
	}
	if checked == 0 {
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"this AS has no session with a peer or a provider, so the question of what "+
				"may cross one cannot be assessed"))
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
	if len(leaks) == 0 && len(withheld) > 0 {
		sort.Strings(withheld)
		return Partial("policy.no_transit_for_peers", 0.5, Evidence{
			Expected: "your own and your customers' prefixes advertised to every peer and " +
				"provider, and nothing learned from one",
			Observed: fmt.Sprintf("nothing leaks, but %d customer route advertisement(s) are "+
				"missing", len(withheld)),
			Detail: strings.Join(truncate(withheld, 5), "\n"),
			Hint: "a customer pays you to carry their prefixes to the rest of the internet; " +
				"an export policy that sends only your own leaves them unreachable",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	if len(leaks) == 0 {
		return Pass("policy.no_transit_for_peers", Evidence{
			Observed: fmt.Sprintf("no leaks across %d neighbour views; own and customer "+
				"prefixes advertised to all of them", checked)})
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
func sourceRelationship(e bgpRoute, selfAS int, relOf map[string]model.Relationship,
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
	//
	// Our own prepends are skipped first. The traffic-engineering question
	// asks for `set as-path prepend <own> <own> <own>` towards a slow
	// neighbour, so an advertisement leaving this AS reads "3 3 3 9" -- and
	// reading only the first element found *ourselves*, which is in no
	// relationship map, so the route's origin was unknown and a leak of a
	// provider's route through a prepended session went unnoticed.
	f := strings.Fields(strings.TrimSpace(e.Path))
	for len(f) > 0 && f[0] == strconv.Itoa(selfAS) {
		f = f[1:]
	}
	if len(f) > 0 {
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
	external := externalRangesOf(ctx, env)
	if len(external.nets) == 0 {
		// Which networks are forbidden is not a matter of opinion, but it is a
		// matter of knowing what this system's sessions are. Not knowing means
		// not concluding: passing here would award the mark for a rule that
		// was applied to nothing.
		return Errored("config.no_forbidden_ospf", fmt.Errorf(
			"this system has no external session the grader can see, so which networks "+
				"must stay out of its interior routing cannot be decided"))
	}
	cfgs, err := runningConfigs(ctx, env)
	if err != nil {
		return Fail("config.no_forbidden_ospf", Evidence{
			Expected: "every router's configuration readable, with no inter-AS network under router ospf",
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
			//
			// Which ranges those are is read off the sessions this system
			// actually has, not from the two prefixes the manifest happens to
			// plan. A group that agreed a different peering range with their
			// neighbour -- which the assignment lets them do -- could put it
			// in OSPF and pass, while the rule exists precisely to stop that.
			if external.matches(strings.TrimPrefix(t, "network ")) {
				found = append(found, fmt.Sprintf("%s: %s", r.Name, t))
			}
		}
	}

	// And what OSPF is actually carrying, which is the question.
	//
	// Reading `network` statements finds one way of putting a prefix into OSPF
	// and misses every other. `redistribute connected` under `router ospf` puts
	// every inter-AS subnet into the interior with no network statement
	// anywhere, and this check passed a system doing exactly that while the
	// peering networks appeared as OSPF routes on every other router of the
	// system. The configuration is the intent; the routing table is the fact.
	for _, r := range env.Routers() {
		var routes map[string][]struct {
			Protocol string `json:"protocol"`
			Selected bool   `json:"selected"`
			Nexthops []struct {
				InterfaceName string `json:"interfaceName"`
			} `json:"nexthops"`
		}
		if err := env.VtyshJSON(ctx, r.Name, "show ip route ospf json", &routes); err != nil {
			// An empty table is not an error, and FRR prints nothing at all
			// for it; anything else is.
			if s, verr := env.Vtysh(ctx, r.Name, "show ip route ospf json"); verr == nil &&
				strings.TrimSpace(s) == "" {
				continue
			}
			return Errored("config.no_forbidden_ospf", fmt.Errorf(
				"%s: its OSPF routes could not be read, so whether the inter-AS ranges are "+
					"in its interior routing cannot be decided: %w", r.Name, err))
		}
		for prefix, entries := range routes {
			if !external.matches(prefix) {
				continue
			}
			for _, e := range entries {
				if e.Protocol != "ospf" {
					continue
				}
				found = append(found, fmt.Sprintf(
					"%s carries %s as an OSPF route", r.Name, prefix))
				break
			}
		}
	}

	if len(found) == 0 {
		return Pass("config.no_forbidden_ospf", Evidence{
			Observed: "no inter-AS subnet is advertised in OSPF or carried as an OSPF route"})
	}
	sort.Strings(found)
	return Fail("config.no_forbidden_ospf", Evidence{
		Expected: "no inter-AS network in the interior routing protocol, however it got there",
		Observed: fmt.Sprintf("%d finding(s)", len(found)),
		Detail:   strings.Join(truncate(found, 8), "\n"),
		Hint: "external subnets belong to BGP, not to your interior routing protocol; " +
			"`redistribute connected` puts them there as surely as a network statement does",
		Command: "show running-config; show ip route ospf",
	})
}

// peerPlannedAddr is the address the manifest gave the far end of a link.
func peerPlannedAddr(i *model.Iface) string {
	if i.Peer == nil {
		return ""
	}
	return i.Peer.Addr4
}

// externalRanges are the networks this system's external sessions are on.
type externalRanges struct{ nets []netip.Prefix }

// externalRangesOf reads them off the sessions rather than off the plan.
func externalRangesOf(ctx context.Context, env *Env) externalRanges {
	var out externalRanges
	seen := map[string]bool{}
	addrs := []string{}
	for _, s := range externalSessions(ctx, env) {
		addrs = append(addrs, s.Addr)
	}
	// The planned ranges as well as the ones in use.
	//
	// Reading only what is live would make the rule apply to nothing on a
	// system whose sessions are all down -- which is the state a submission
	// that put the inter-AS range into OSPF is quite likely to be in.
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS {
				continue
			}
			// Both ends of the planned link. The plan is the right source
			// here, and only here: this is about which networks are external,
			// which the manifest defines, rather than about which address a
			// group chose to peer on, which only the device knows.
			for _, planned := range []string{i.Addr4, peerPlannedAddr(i)} {
				if p, err := netip.ParsePrefix(planned); err == nil {
					addrs = append(addrs, p.Addr().String())
				}
			}
		}
	}
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		// The neighbour's address with the local prefix length; the exact
		// length matters less than the network, and any statement covering the
		// neighbour's address is the one the rule is about.
		for _, bits := range []int{24, 30, 31, 29, 28} {
			p := netip.PrefixFrom(a, bits).Masked()
			if !seen[p.String()] {
				seen[p.String()] = true
				out.nets = append(out.nets, p)
			}
		}
	}
	return out
}

// matches reports whether an OSPF network statement covers a session's network.
func (e externalRanges) matches(stmt string) bool {
	f := strings.Fields(stmt)
	if len(f) == 0 {
		return false
	}
	p, err := netip.ParsePrefix(f[0])
	if err != nil {
		return false
	}
	p = p.Masked()
	for _, n := range e.nets {
		if p.Contains(n.Addr()) || n.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func addrOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
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

// externalSession is one BGP session this AS has with somebody outside it.
type externalSession struct {
	Router string
	Addr   string
	Rel    model.Relationship
	ASN    int
}

// externalSessions lists every session with a neighbour outside this AS,
// including the one with an exchange's route server.
//
// The exchange used to be missing from every policy check, because a member's
// interface onto an exchange sits on a shared segment and the checks skipped
// anything that was not a point-to-point inter-AS link. So the question those
// checks exist to ask -- what may cross a session to somebody who is not a
// customer -- was never asked about the exchange, which is exactly where
// leaking a provider's route is the classic mistake and where the assignment
// spends a whole question. A submission that leaked everything to the exchange
// scored full marks for no transit.
func externalSessions(ctx context.Context, env *Env) []externalSession {
	var out []externalSession
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil {
				continue
			}
			switch {
			case i.Role == model.RoleIXPLink:
				// At an exchange the session is with the route server, and the
				// members behind it are peers by definition: only this AS's own
				// and its customers' routes may cross it.
				addr, asn := routeServerOn(env.Topology, i)
				if addr == "" {
					continue
				}
				out = append(out, externalSession{r.Name, addr, model.RelPeer, asn})
			case i.Link.InterAS && i.Peer != nil && i.Peer.Addr4 != "":
				rel := i.Link.PeerRelationship(i)
				asn := 0
				if i.Peer.Device != nil {
					asn = i.Peer.Device.ASN
				}
				out = append(out, externalSession{r.Name, env.PeerAddr(ctx, i), rel, asn})
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Router != out[b].Router {
			return out[a].Router < out[b].Router
		}
		return out[a].Addr < out[b].Addr
	})
	return out
}
