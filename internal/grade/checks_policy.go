package grade

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

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

	// A tunnel device must exist on both gateways.
	var missing []string
	for _, d := range domains {
		gw := gateways[d]
		out, err := env.Exec(ctx, gw.ID, []string{"ip", "-o", "link", "show"})
		if err != nil {
			return Errored("tunnel.sixin4", err)
		}
		if !strings.Contains(out.Stdout, "sit") && !strings.Contains(out.Stdout, "ip6tnl") {
			missing = append(missing, fmt.Sprintf("%s has no 6in4 (sit) tunnel device", gw.Name))
		}
	}

	// And IPv6 must actually get across.
	var reach string
	reachable := false
	if len(domains) >= 2 {
		src, sok := hosts[domains[0]]
		dst, dok := hosts[domains[1]]
		if sok && dok {
			addr := firstAddr6(dst)
			if addr == "" {
				reach = fmt.Sprintf("%s has no IPv6 address configured", dst.Name)
			} else {
				res, err := env.Exec(ctx, src.ID,
					[]string{"ping6", "-c", "2", "-W", "2", "-i", "0.3", addr})
				if err == nil && res.ExitCode == 0 {
					reachable = true
				} else {
					reach = fmt.Sprintf("%s cannot reach %s at %s over IPv6", src.Name, dst.Name, addr)
				}
			}
		} else {
			reach = "could not find a host in each datacentre"
		}
	}

	switch {
	case len(missing) == 0 && reachable:
		return Pass("tunnel.sixin4", Evidence{
			Observed: fmt.Sprintf("IPv6 crosses between %s and %s through a 6in4 tunnel",
				domains[0], domains[1])})
	case reachable:
		return Partial("tunnel.sixin4", 0.5, Evidence{
			Expected: "IPv6 carried over a 6in4 tunnel",
			Observed: "IPv6 works, but no tunnel device was found",
			Detail:   strings.Join(missing, "\n"),
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

	// Find the exchange this AS is attached to, and its number.
	ixp := 0
	var ixpRouter *model.Device
	for _, r := range as.Routers {
		for _, i := range r.Ifaces {
			if i.Role == model.RoleIXPLink && i.Peer != nil {
				ixp = i.Peer.Device.ASN
				ixpRouter = r
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

	// Look for community values of the form <ixp>:<member> being set.
	prefix := strconv.Itoa(ixp) + ":"
	var tagged []string
	for _, line := range strings.Split(out, "\n") {
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

	// And for an import policy that rejects in-region announcements.
	filters := strings.Contains(out, "as-path access-list") ||
		strings.Contains(out, "bgp as-path access-list") ||
		strings.Contains(out, "match as-path")

	switch {
	case len(tagged) > 0 && filters:
		return Pass("policy.ixp_communities", Evidence{
			Observed: fmt.Sprintf("tags %d exchange communities and filters on AS path", len(tagged)),
			Detail:   strings.Join(tagged, " "),
		})
	case len(tagged) > 0:
		return Partial("policy.ixp_communities", 0.5, Evidence{
			Expected: "communities set for out-of-region members, and in-region announcements refused",
			Observed: fmt.Sprintf("communities set (%s) but no AS-path filter found", strings.Join(tagged, " ")),
			Hint:     "part (ii) asks you to deny announcements whose path contains an in-region AS",
			Command:  "show running-config",
		})
	default:
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("community values of the form %s<member>", prefix),
			Observed: "none set",
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
			rel := i.Link.Rel
			if i.Link.B == i {
				rel = rel.Inverse()
			}
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
	entries, ok := adv.Routes[own]
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
	for p := range adv.Routes {
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
	return adv, jsonUnmarshalLoose(out, &adv)
}

func medianLocalPref(ctx context.Context, env *Env, peer string) int {
	var prefs []int
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for _, entries := range tbl.Routes {
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

	// And confirm no invalid route is actually selected.
	var selected []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show bgp ipv4 unicast rpki invalid")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "*>") {
				selected = append(selected, strings.TrimSpace(r.Name+": "+line))
			}
		}
	}
	if len(selected) == 0 {
		return Pass("rpki.invalid_rejected", Evidence{
			Observed: "no RPKI-invalid route is selected", Detail: detail})
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
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
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
