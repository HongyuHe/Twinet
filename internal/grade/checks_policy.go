package grade

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file registers the remaining course checks: 6in4 tunnels, exchange
// community policy, traffic engineering and RPKI.

func init() {
	Register(&Check{
		Name:     "tunnel.sixin4",
		Describe: "IPv6 traffic between the two datacentres traverses a 6in4 tunnel",
		Run:      checkSixIn4,
	})
	Register(&Check{
		Name:     "policy.ixp_communities",
		Describe: "announcements are relayed through the exchange only where intended",
		Run:      checkIXPCommunities,
	})
	Register(&Check{
		Name:     "policy.traffic_engineering",
		Describe: "the high-delay provider and customer are made less attractive, without filtering",
		Run:      checkTrafficEngineering,
	})
	Register(&Check{
		Name:     "rpki.invalid_rejected",
		Describe: "a route whose origin is RPKI-invalid is not selected",
		Run:      checkRPKIInvalidRejected,
	})
	Register(&Check{
		Name:     "rpki.notfound_preserved",
		Describe: "routes with no ROA are still usable, so filtering has not gone too far",
		Run:      checkRPKINotFoundPreserved,
	})
}

// checkSixIn4 verifies both that IPv6 works between the datacentres and that it
// actually goes through a tunnel.
//
// Testing reachability alone would pass a student who configured native IPv6
// routing, which is not what the question asks for; testing only for a tunnel
// device would pass one who built a tunnel that does not carry traffic.
func checkSixIn4(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("tunnel.sixin4", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// Find the two gateway routers and one host in each datacentre.
	gateways := map[string]*model.Device{}
	for _, r := range as.Routers {
		if r.L2Gateway != "" {
			gateways[r.L2Gateway] = r
		}
	}
	if len(gateways) < 2 {
		return Errored("tunnel.sixin4", fmt.Errorf("expected two L2 gateways, found %d", len(gateways)))
	}
	hosts := map[string]*model.Device{}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost && d.L2Domain != "" {
			if _, have := hosts[d.L2Domain]; !have {
				hosts[d.L2Domain] = d
			}
		}
	}

	domains := make([]string, 0, len(gateways))
	for d := range gateways {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	// A configured tunnel must exist on both gateways.
	//
	// Every container carries the kernel's own sit0, so a substring test for
	// "sit" is true before the student has done anything at all. Only a device
	// with both endpoints set counts.
	var missing []string
	tunnels := map[string]string{}
	for _, d := range domains {
		gw := gateways[d]
		out, err := env.Probe(ctx, gw.ID, []string{"sh", "-c", "ip -d tunnel show 2>/dev/null"})
		if err != nil {
			return Errored("tunnel.sixin4", err)
		}
		if name := configuredTunnel(out.Stdout); name != "" {
			tunnels[d] = name
		} else {
			missing = append(missing, fmt.Sprintf("%s has no configured 6in4 tunnel "+
				"(the kernel's own sit0 does not count: it has no endpoints)", gw.Name))
		}
	}

	// And IPv6 must actually get across *through the tunnel*.
	//
	// Native IPv6 routing between the datacentres also makes the ping succeed,
	// and it is not what the question asks for. The tunnel's own counters
	// settle it: if they do not move, the packets went some other way.
	var reach string
	reachable, throughTunnel := false, false
	if len(domains) >= 2 {
		src, sok := hosts[domains[0]]
		dst, dok := hosts[domains[1]]
		gw := gateways[domains[0]]
		switch {
		case !sok || !dok:
			reach = "could not find a host in each datacentre"
		default:
			addr := firstAddr6(dst)
			if addr == "" {
				reach = fmt.Sprintf("%s has no IPv6 address configured", dst.Name)
				break
			}
			// Each gateway resolves its own datacentre's host before anything
			// is measured, and the result of that is discarded.
			//
			// This is not politeness, it is necessary. Measured on this
			// cluster: after the datacentre is reconfigured -- which is what
			// installing a solution does -- the gateway records the host as
			// FAILED, and traffic arriving through the tunnel never clears it.
			// Twenty seconds of forwarded pings left the entry FAILED; a
			// single ping originated by the gateway itself made it REACHABLE
			// and every forwarded packet then went through. So a correct
			// answer scored zero or full marks depending on whether anything
			// had happened to originate a packet from the right router in the
			// preceding few minutes.
			//
			// Neighbour cache state is not part of the student's answer. This
			// removes it from the measurement in the same spirit as waiting
			// for BGP to converge, and it cannot manufacture a pass: the
			// tunnel's own counters must still move and the end-to-end ping
			// from the far datacentre must still succeed.
			for _, d := range domains {
				gw, h := gateways[d], hosts[d]
				if gw == nil || h == nil {
					continue
				}
				if a := firstAddr6(h); a != "" {
					_, _ = env.Probe(ctx, gw.ID, []string{"ping6", "-c", "2", "-W", "3", a})
				}
			}

			// Reachability across the tunnel is waited for, not sampled once.
			//
			// The first packet has to wait for neighbour discovery, and the
			// solicitation itself crosses the tunnel and comes back. If the
			// tunnel was rebuilt moments earlier -- which is exactly what
			// installing a solution does -- the path is not ready the instant
			// the check asks. Graded immediately after a redeploy a correct
			// answer scored zero; graded a minute later the same configuration
			// scored full marks. Every other check in this rubric waits for the
			// control plane to settle, and this one is no different: the
			// difference between "not configured" and "not yet" is the whole
			// question.
			var before, after int
			deadline := time.Now().Add(45 * time.Second)
			for {
				before = tunnelTx(ctx, env, gw.ID, tunnels[domains[0]])
				res, err := env.Probe(ctx, src.ID,
					[]string{"ping6", "-c", "3", "-W", "5", "-i", "0.3", addr})
				after = tunnelTx(ctx, env, gw.ID, tunnels[domains[0]])
				if err == nil && res.ExitCode == 0 {
					reachable = true
					break
				}
				if time.Now().After(deadline) {
					reach = fmt.Sprintf("%s could not reach %s at %s over IPv6 in %s",
						src.Name, dst.Name, addr, 45*time.Second)
					break
				}
				select {
				case <-ctx.Done():
					reach = "the grading run was cancelled while waiting for IPv6 to come up"
				case <-time.After(3 * time.Second):
					continue
				}
				break
			}
			if reachable && tunnels[domains[0]] != "" && after > before {
				throughTunnel = true
			} else if reachable && tunnels[domains[0]] != "" {
				reach = fmt.Sprintf("IPv6 reaches %s, but %s carried no packets during the test, "+
					"so the traffic is being routed natively rather than encapsulated",
					dst.Name, tunnels[domains[0]])
			}
		}
	}

	switch {
	case len(missing) == 0 && reachable && throughTunnel:
		return Pass("tunnel.sixin4", Evidence{
			Observed: fmt.Sprintf("IPv6 crosses between %s and %s through %s, which carried the packets",
				domains[0], domains[1], tunnels[domains[0]])})
	case reachable:
		return Partial("tunnel.sixin4", 0.5, Evidence{
			Expected: "IPv6 carried over a 6in4 tunnel",
			Observed: "IPv6 works, but not through a tunnel",
			Detail:   strings.TrimSpace(strings.Join(append(missing, reach), "\n")),
			Hint:     "the question asks for encapsulation, not native IPv6 routing",
		})
	default:
		detail := strings.Join(append(missing, reach), "\n")
		return Fail("tunnel.sixin4", Evidence{
			Expected: "IPv6 reachability between the datacentres over 6in4",
			Observed: "not reachable",
			Detail:   strings.TrimSpace(detail),
			Hint:     "create the tunnel with `ip tunnel add ... mode sit` at both ends, using the loopbacks",
		})
	}
}

// checkIXPCommunities verifies the community-gated relay policy at an exchange.
//
// The exchange only relays an announcement carrying the community N:X, so a
// correct answer both tags its own announcements for out-of-region members and
// refuses announcements arriving from in-region members.
func checkIXPCommunities(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("policy.ixp_communities", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// Find the exchange this AS is attached to, its number, and the address
	// the exchange's route server is reached at. The peer address matters:
	// the mark is for a policy the route server actually sees, not for one
	// written in the configuration and never attached to anything.
	ixp := 0
	var ixpRouter *model.Device
	ixpPeer := ""
	for _, r := range as.Routers {
		for _, i := range r.Ifaces {
			if i.Role == model.RoleIXPLink && i.Peer != nil {
				if addr, asn := routeServerOn(env.Topology, i); addr != "" {
					ixp, ixpRouter, ixpPeer = asn, r, addr
				}
			}
		}
	}
	if ixp == 0 || ixpRouter == nil {
		return Errored("policy.ixp_communities", fmt.Errorf("AS %d is not attached to an exchange", env.AS))
	}

	out, err := env.Vtysh(ctx, ixpRouter.Name, "show running-config")
	if err != nil {
		return Errored("policy.ixp_communities", err)
	}
	cfg := parseFRR(out)
	if !cfg.hasNeighbor(ixpPeer) {
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("a session with the exchange's route server at %s", ixpPeer),
			Observed: "no such neighbour is configured",
			Hint:     "the exchange relays announcements only between its own members",
			Command:  "show running-config",
		})
	}

	// (i) Communities must be set on what leaves towards the route server.
	// A "set community" anywhere else changes nothing the exchange can see.
	outbound := cfg.appliedBody(ixpPeer, "out")
	prefix := strconv.Itoa(ixp) + ":"
	var tagged []string
	for _, line := range strings.Split(outbound, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "set community") {
			continue
		}
		for _, f := range strings.Fields(t) {
			if strings.HasPrefix(f, prefix) {
				tagged = append(tagged, f)
			}
		}
	}
	sort.Strings(tagged)
	tagged = uniq(tagged)

	// (ii) The in-region filter must be applied to what arrives from the
	// route server, and must actually match on AS path.
	inbound := cfg.appliedBody(ixpPeer, "in")
	filters := strings.Contains(inbound, "match as-path")

	unapplied := ""
	if len(tagged) == 0 && strings.Contains(out, "set community "+prefix) {
		unapplied = fmt.Sprintf("a route-map sets %s<member> but it is not applied outbound to %s", prefix, ixpPeer)
	} else if !filters && strings.Contains(out, "match as-path") {
		unapplied = fmt.Sprintf("an AS-path filter exists but is not applied inbound from %s", ixpPeer)
	}

	switch {
	case len(tagged) > 0 && filters:
		return Pass("policy.ixp_communities", Evidence{
			Observed: fmt.Sprintf("tags %d exchange communities towards %s and filters arrivals on AS path",
				len(tagged), ixpPeer),
			Detail: strings.Join(tagged, " "),
		})
	case len(tagged) > 0:
		return Partial("policy.ixp_communities", 0.5, Evidence{
			Expected: "communities set for out-of-region members, and in-region announcements refused",
			Observed: fmt.Sprintf("communities set (%s) but no AS-path filter is applied inbound from %s",
				strings.Join(tagged, " "), ixpPeer),
			Hint:    "part (ii) asks you to deny announcements whose path contains an in-region AS",
			Detail:  unapplied,
			Command: "show running-config",
		})
	default:
		obs := "none set on the session with the route server"
		if unapplied != "" {
			obs = unapplied
		}
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("community values of the form %s<member>, set outbound towards %s", prefix, ixpPeer),
			Observed: obs,
			Hint: fmt.Sprintf("the exchange relays an announcement to member X only if it carries %s%s",
				prefix, "X"),
			Command: "show running-config",
		})
	}
}

// checkTrafficEngineering verifies the answer to the "one of your links is
// slow" question: prefer the fast neighbour outbound, make the slow one less
// attractive inbound, and do it *without* filtering anything.
func checkTrafficEngineering(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("policy.traffic_engineering", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// The model knows which links are slow: the delay is in the topology.
	type nb struct {
		router string
		addr   string
		asn    int
		rel    model.Relationship
		delay  string
		slow   bool
	}
	var neighbours []nb
	var maxDelay float64
	for _, r := range as.Routers {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			// What the neighbour is to us. Derived in one place, because the
			// same two lines written out here, in the renderer and in the
			// other checks were all inverted in the same direction -- so the
			// wrong answer was self-consistent and scored full marks.
			rel := i.Link.PeerRelationship(i)
			d := parseMillis(i.Link.Props.Delay)
			if d > maxDelay {
				maxDelay = d
			}
			neighbours = append(neighbours, nb{r.Name, addrOf(i.Peer.Addr4), i.Peer.Device.ASN, rel, i.Link.Props.Delay, false})
		}
	}
	if len(neighbours) < 2 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("AS %d has %d external neighbours", env.AS, len(neighbours)))
	}
	for i := range neighbours {
		neighbours[i].slow = parseMillis(neighbours[i].delay) >= maxDelay && maxDelay > 0
	}

	var slow, fast []nb
	for _, n := range neighbours {
		if n.slow {
			slow = append(slow, n)
		} else {
			fast = append(fast, n)
		}
	}
	if len(slow) == 0 || len(fast) == 0 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("the lab has no delay difference between neighbours to discover"))
	}

	var detail strings.Builder
	detail.WriteString("slow neighbours: ")
	for _, n := range slow {
		fmt.Fprintf(&detail, "AS%d via %s (%s) ", n.asn, n.router, n.delay)
	}
	detail.WriteString("\n")

	checks, passed := 0, 0

	// Outbound: within a relationship class, the fast neighbour's routes must
	// carry a higher local preference than the slow one's.
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		sp := medianLocalPref(ctx, env, s.addr)
		fp := medianLocalPref(ctx, env, f.addr)
		if fp > sp {
			passed++
		} else {
			fmt.Fprintf(&detail,
				"outbound: routes from the fast %s (AS%d, local preference %d) should be preferred over the slow one (AS%d, %d)\n",
				rel, f.asn, fp, s.asn, sp)
		}
	}

	// Inbound: the announcement of our own prefix sent to the slow neighbour
	// should carry a longer AS path than the one sent to the fast neighbour of
	// the same relationship class, so other networks find that route less
	// attractive.
	own := as.Block
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		sLen, sAdv := advertisedOwnPrefix(ctx, env, s.router, s.addr, own)
		fLen, fAdv := advertisedOwnPrefix(ctx, env, f.router, f.addr, own)

		// Filtering is explicitly forbidden here: the slow neighbour must still
		// be able to reach us directly, as a backup.
		if !sAdv {
			fmt.Fprintf(&detail,
				"inbound: %s is not advertised to the slow AS%d at all; the question forbids blocking it\n",
				own, s.asn)
			continue
		}
		if !fAdv {
			fmt.Fprintf(&detail, "inbound: %s is not advertised to AS%d\n", own, f.asn)
			continue
		}
		if sLen > fLen {
			passed++
		} else {
			fmt.Fprintf(&detail,
				"inbound: the path advertised to the slow AS%d is %d long, no longer than the %d sent to AS%d; prepend to make it less attractive\n",
				s.asn, sLen, fLen, f.asn)
		}
	}

	// Nothing may be *additionally* filtered toward the slow neighbour. This is
	// compared against the fast neighbour of the same class rather than by
	// counting deny clauses: the business-relationship policy of the previous
	// question legitimately denies plenty, and conflating the two would punish
	// a correct answer.
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		sSet := advertisedPrefixes(ctx, env, s.router, s.addr)
		fSet := advertisedPrefixes(ctx, env, f.router, f.addr)
		var withheld []string
		for p := range fSet {
			if !sSet[p] {
				withheld = append(withheld, p)
			}
		}
		if len(withheld) == 0 {
			passed++
		} else {
			sort.Strings(withheld)
			fmt.Fprintf(&detail,
				"inbound: %d prefix(es) advertised to AS%d are withheld from the slow AS%d (%s); the question forbids denying advertisements\n",
				len(withheld), f.asn, s.asn, strings.Join(truncate(withheld, 3), ", "))
		}
	}

	if checks == 0 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("no slow and fast neighbour of the same relationship class to compare"))
	}
	if passed == checks {
		return Pass("policy.traffic_engineering", Evidence{
			Observed: strings.TrimSpace(detail.String())})
	}
	return Partial("policy.traffic_engineering", ratio(passed, checks), Evidence{
		Expected: "prefer the fast neighbour outbound, prepend toward the slow one inbound, deny nothing",
		Observed: fmt.Sprintf("%d of %d correct", passed, checks),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "local preference controls where your traffic leaves; AS-path length is what other networks see",
	})
}

// advertisedOwnPrefix returns the AS-path length of our own prefix as
// advertised to a neighbour, and whether it is advertised at all.
func advertisedOwnPrefix(ctx context.Context, env *Env, router, peer, own string) (int, bool) {
	adv, err := advertisedRoutes(ctx, env, router, peer)
	if err != nil {
		return 0, false
	}
	entries, ok := adv.Table()[own]
	if !ok || len(entries) == 0 {
		return 0, false
	}
	longest := 0
	for _, e := range entries {
		if n := len(strings.Fields(e.Path)); n > longest {
			longest = n
		}
	}
	return longest, true
}

// advertisedPrefixes returns the set of prefixes advertised to a neighbour.
func advertisedPrefixes(ctx context.Context, env *Env, router, peer string) map[string]bool {
	out := map[string]bool{}
	adv, err := advertisedRoutes(ctx, env, router, peer)
	if err != nil {
		return out
	}
	for p := range adv.Table() {
		out[p] = true
	}
	return out
}

func advertisedRoutes(ctx context.Context, env *Env, router, peer string) (bgpRouteJSON, error) {
	var adv bgpRouteJSON
	out, err := env.Vtysh(ctx, router,
		fmt.Sprintf("show ip bgp neighbors %s advertised-routes json", peer))
	if err != nil {
		return adv, err
	}
	if err := jsonUnmarshalLoose(out, &adv); err != nil {
		return adv, fmt.Errorf("%s: could not read what is advertised to %s: %w", router, peer, err)
	}
	if !adv.Decoded() {
		// An unrecognised document must never pass for an empty table: that is
		// exactly how a policy check silently became an unconditional pass.
		return adv, fmt.Errorf("%s: the advertised-routes output for %s was not recognised", router, peer)
	}
	return adv, nil
}

func medianLocalPref(ctx context.Context, env *Env, peer string) int {
	var prefs []int
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for _, entries := range tbl.Table() {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					if nh.IP == peer {
						prefs = append(prefs, e.LocalPref)
					}
				}
			}
		}
	}
	if len(prefs) == 0 {
		return 0
	}
	sort.Ints(prefs)
	return prefs[len(prefs)/2]
}

// checkRPKIInvalidRejected verifies that a route whose origin is RPKI-invalid
// does not win.
func checkRPKIInvalidRejected(ctx context.Context, env *Env) Result {
	configured, detail := rpkiConfigured(ctx, env)
	if !configured {
		return Fail("rpki.invalid_rejected", Evidence{
			Expected: "an RPKI cache configured and route-maps matching validation state",
			Observed: "no RPKI configuration found",
			Detail:   detail,
			Hint:     "point your routers at the validator and match `rpki invalid` in an import route-map",
			Command:  "show running-config",
		})
	}

	// Look for a route-map that acts on the invalid state.
	rejects := false
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
		low := strings.ToLower(out)
		if strings.Contains(low, "match rpki invalid") {
			rejects = true
			break
		}
	}
	if !rejects {
		return Partial("rpki.invalid_rejected", 0.4, Evidence{
			Expected: "invalid-origin routes rejected",
			Observed: "an RPKI cache is configured but nothing matches the invalid state",
			Detail:   detail,
			Hint:     "add a route-map clause that denies routes matching `rpki invalid`",
		})
	}

	// An empty invalid table is exactly what an unreachable validator produces:
	// with no ROAs, every route is "notfound" and nothing is ever invalid. So
	// "no invalid route is selected" on its own is not evidence of anything.
	// Validation must be shown to be running before its silence means anything.
	live, liveDetail := rpkiValidating(ctx, env)
	if !live {
		return Partial("rpki.invalid_rejected", 0.5, Evidence{
			Expected: "a validator session that is up, with ROAs received and applied to the BGP table",
			Observed: liveDetail,
			Detail:   detail,
			Hint: "the route-maps are right, but nothing is validating: with no ROAs every route is " +
				"`notfound`, so no route can be invalid and the policy never fires",
			Command: "show rpki cache-connection",
		})
	}

	// And confirm no invalid route is actually selected. A router whose table
	// could not be read is not evidence that it selects nothing.
	var selected, unread []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show bgp ipv4 unicast rpki invalid")
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "*>") {
				selected = append(selected, strings.TrimSpace(r.Name+": "+line))
			}
		}
	}
	if len(unread) > 0 {
		return Partial("rpki.invalid_rejected", 0.6, Evidence{
			Expected: "no invalid route selected on any router",
			Observed: fmt.Sprintf("%d router(s) could not be asked", len(unread)),
			Detail:   strings.Join(unread, "\n"),
			Hint:     "an unanswered router is not a router with a clean table",
			Command:  "show bgp ipv4 unicast rpki invalid",
		})
	}
	if len(selected) == 0 {
		return Pass("rpki.invalid_rejected", Evidence{
			Observed: "validation is live and no RPKI-invalid route is selected",
			Detail:   liveDetail + "\n" + detail})
	}
	return Partial("rpki.invalid_rejected", 0.6, Evidence{
		Expected: "no invalid route selected",
		Observed: fmt.Sprintf("%d invalid route(s) still chosen", len(selected)),
		Detail:   strings.Join(truncate(selected, 5), "\n"),
	})
}

// checkRPKINotFoundPreserved guards against over-filtering: a student who
// rejects everything without a ROA would break connectivity to every AS that
// has not yet issued one, which the assignment explicitly forbids.
func checkRPKINotFoundPreserved(ctx context.Context, env *Env) Result {
	if configured, detail := rpkiConfigured(ctx, env); !configured {
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "RPKI configured without over-filtering",
			Observed: "no RPKI configuration found",
			Detail:   detail,
		})
	}
	var denies []string
	cfgs, err := runningConfigs(ctx, env)
	if err != nil {
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "every router's configuration readable, with no clause denying not-found routes",
			Observed: "some configurations could not be read",
			Detail:   err.Error(),
			Hint:     "make sure FRR is running on every router before submitting",
			Command:  "show running-config",
		})
	}
	for _, r := range env.Routers() {
		out := cfgs[r.Name]
		lines := strings.Split(out, "\n")
		for i, line := range lines {
			if !strings.Contains(strings.ToLower(line), "match rpki notfound") {
				continue
			}
			// Walk back to the enclosing route-map clause to see whether this
			// match sits under a deny.
			for j := i; j >= 0 && j > i-8; j-- {
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "route-map ") {
					if strings.Contains(t, " deny ") {
						denies = append(denies, fmt.Sprintf("%s: %s", r.Name, t))
					}
					break
				}
			}
		}
	}
	if len(denies) == 0 {
		return Pass("rpki.notfound_preserved", Evidence{
			Observed: "routes without a ROA are still accepted"})
	}
	sort.Strings(denies)
	return Fail("rpki.notfound_preserved", Evidence{
		Expected: "not-found routes remain usable",
		Observed: fmt.Sprintf("%d route-map(s) deny them", len(denies)),
		Detail:   strings.Join(denies, "\n"),
		Hint:     "most of the Internet has no ROA; rejecting not-found would cut you off from it",
	})
}

// rpkiConfigured reports whether any router has an RPKI cache configured.
func rpkiConfigured(ctx context.Context, env *Env) (bool, string) {
	var found []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "rpki cache ") {
				found = append(found, r.Name+": "+t)
			}
		}
	}
	if len(found) == 0 {
		return false, "no `rpki cache` statement on any router"
	}
	sort.Strings(found)
	return true, strings.Join(found, "\n")
}

func firstAddr6(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Addr6 != "" {
			if j := strings.IndexByte(i.Addr6, '/'); j > 0 {
				return i.Addr6[:j]
			}
			return i.Addr6
		}
	}
	return ""
}

func parseMillis(s string) float64 {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "ms"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		return v
	case strings.HasSuffix(s, "s"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		return v * 1000
	}
	return 0
}

func uniq(in []string) []string {
	out := in[:0]
	var prev string
	for i, s := range in {
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

// rpkiValidating reports whether origin validation is actually operating, as
// opposed to merely being configured.
//
// Three things have to hold, and each has been seen to fail on its own: the
// session to the validator is established, ROAs have arrived, and the BGP table
// reflects them. A cache that FRR never connected to leaves all three of the
// per-state tables empty, which reads identically to a network in which every
// route is legitimate.
func rpkiValidating(ctx context.Context, env *Env) (bool, string) {
	var connected, withROAs, validated []string
	for _, r := range env.Routers() {
		if out, err := env.Vtysh(ctx, r.Name, "show rpki cache-connection"); err == nil &&
			strings.Contains(strings.ToLower(out), "connected") {
			connected = append(connected, r.Name)
		}
		if out, err := env.Vtysh(ctx, r.Name, "show rpki prefix-table"); err == nil {
			if n := countROAs(out); n > 0 {
				withROAs = append(withROAs, fmt.Sprintf("%s: %d ROAs", r.Name, n))
			}
		}
		if out, err := env.Vtysh(ctx, r.Name, "show bgp ipv4 unicast rpki valid"); err == nil &&
			strings.Contains(out, "V") && strings.Contains(out, "Displayed") {
			validated = append(validated, r.Name)
		}
	}
	sort.Strings(connected)
	sort.Strings(withROAs)
	switch {
	case len(connected) == 0:
		return false, "no router has an established session with a validator"
	case len(withROAs) == 0:
		return false, fmt.Sprintf("%d router(s) reached a validator but received no ROAs", len(connected))
	case len(validated) == 0:
		return false, fmt.Sprintf("ROAs were received (%s) but no route carries a validation state",
			strings.Join(truncate(withROAs, 3), ", "))
	}
	return true, fmt.Sprintf("%d router(s) connected to a validator, %s, %d with validated routes",
		len(connected), strings.Join(truncate(withROAs, 3), ", "), len(validated))
}

// countROAs counts prefix entries in `show rpki prefix-table` output.
func countROAs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// "6.0.0.0   8 -   8   6": address, length, "-", maxlen, origin AS.
		if len(f) >= 5 && strings.Count(f[0], ".") == 3 {
			n++
		}
	}
	return n
}

// configuredTunnel returns the name of a 6in4 tunnel with both endpoints set.
//
// `ip -d tunnel show` always lists the kernel's sit0 with "remote any local
// any"; it is not the student's work and matching it awards the mark before
// the exercise is begun.
func configuredTunnel(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "remote ") || !strings.Contains(line, "local ") {
			continue
		}
		name := strings.TrimSuffix(strings.Fields(line)[0], ":")
		if name == "sit0" || name == "" {
			continue
		}
		if fieldAfter(line, "remote") == "any" || fieldAfter(line, "local") == "any" {
			continue
		}
		return name
	}
	return ""
}

// tunnelTx reads a tunnel's transmitted packet count.
func tunnelTx(ctx context.Context, env *Env, device, iface string) int {
	if iface == "" {
		return -1
	}
	res, err := env.Probe(ctx, device, []string{"sh", "-c",
		"cat /sys/class/net/" + iface + "/statistics/tx_packets 2>/dev/null"})
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return -1
	}
	return n
}

// fieldAfter returns the token following a keyword on a line.
func fieldAfter(line, key string) string {
	f := strings.Fields(line)
	for i, x := range f {
		if x == key && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}
