package grade

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Checks for the advanced-networks course: a BGP-free core and BGP/MPLS L3VPN.
//
// The exercise asks the student to carry two customers' traffic across a
// backbone whose interior routers hold no BGP state at all, and to keep the two
// customers apart. Each of those is a separate claim, and each is checked by
// observing the network rather than by reading the configuration that was
// supposed to produce it -- a distinction that cost this project a good deal of
// time elsewhere and is not repeated here.

func init() {
	Register(&Check{
		Name:     "mpls.bgp_free_core",
		Describe: "the core routers hold no BGP state, and the edges do not peer with them",
		Run:      checkBGPFreeCore,
	})
	Register(&Check{
		Name:     "mpls.ldp_adjacencies",
		Describe: "every interior link has an operational LDP session, and labels are installed",
		Run:      checkLDPAdjacencies,
	})
	Register(&Check{
		Name:     "vpn.site_reachability",
		Describe: "the sites of one customer can reach each other across the provider",
		Run:      checkVPNReachability,
	})
	Register(&Check{
		Name:     "vpn.label_switched",
		Describe: "the customer's remote sites are reached over a two-label path, not by plain routing",
		Run:      checkVPNLabelSwitched,
	})
	Register(&Check{
		Name:     "vpn.isolation",
		Describe: "one customer cannot reach another, whatever addresses they use",
		Run:      checkVPNIsolation,
	})
}

// checkBGPFreeCore asserts the point of the exercise.
//
// A core router that runs BGP will carry the customer routes perfectly well, so
// reachability alone cannot tell a correct answer from one that has simply put
// BGP everywhere. The absence is the answer, so the absence is what is checked
// -- on the core routers themselves and in the edges' neighbour lists, because
// a core router with a BGP process nobody peers with is a different mistake
// from one that is in the mesh.
func checkBGPFreeCore(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("mpls.bgp_free_core", fmt.Errorf("AS %d is not in this lab", env.AS))
	}
	core := coreRouters(as)
	if len(core) == 0 {
		return Errored("mpls.bgp_free_core",
			fmt.Errorf("AS %d declares no core routers, so there is nothing to check; "+
				"set mpls.core in the manifest", env.AS))
	}

	var bad []string
	for _, d := range core {
		out, err := env.Vtysh(ctx, d.Name, "show bgp summary")
		if err != nil {
			return Errored("mpls.bgp_free_core", err)
		}
		// FRR says "BGP instance not found" when no process exists at all,
		// which is the state being asked for.
		//
		// Requiring the word "Neighbor" as well was the mistake: FRR prints a
		// neighbour table only when there are neighbours, so a core router with
		// `router bgp 1` configured and no peers matched neither string and was
		// reported as holding no BGP state. It holds a BGP instance, a routing
		// information base and an identifier, and one line of configuration
		// away from holding the whole table -- which is the thing the exercise
		// says a core router must not do.
		if !strings.Contains(out, "instance not found") {
			bad = append(bad, fmt.Sprintf("%s has a BGP instance", d.Name))
			continue
		}
		// And the configuration, because an instance that exists but has not
		// been read by this command would be missed by it.
		cfg, err := env.Vtysh(ctx, d.Name, "show running-config")
		if err != nil {
			return Errored("mpls.bgp_free_core", err)
		}
		for _, line := range strings.Split(cfg, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "router bgp") {
				bad = append(bad, fmt.Sprintf("%s is configured with %s",
					d.Name, strings.TrimSpace(line)))
				break
			}
		}
	}
	// And no edge may name a core router as a neighbour: a session configured
	// towards a router with no BGP sits idle and is easy to miss.
	coreAddrs := map[string]string{}
	for _, d := range core {
		if lo, ok := d.IfaceByName("lo"); ok && lo.Addr4 != "" {
			coreAddrs[addrOnly(lo.Addr4)] = d.Name
		}
	}
	for _, d := range as.Routers {
		if isCore(as, d.Name) {
			continue
		}
		out, err := env.Vtysh(ctx, d.Name, "show bgp summary")
		if err != nil {
			continue
		}
		for addr, name := range coreAddrs {
			if strings.Contains(out, addr) {
				bad = append(bad, fmt.Sprintf("%s peers with the core router %s", d.Name, name))
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		return Fail("mpls.bgp_free_core", Evidence{
			Expected: "the core carries traffic on labels alone, with no BGP anywhere in it",
			Observed: strings.Join(bad, "; "),
			Command:  "vtysh -c 'show bgp summary'",
		})
	}
	return Pass("mpls.bgp_free_core", Evidence{
		Expected: "no BGP on the core",
		Observed: fmt.Sprintf("%d core router(s) hold no BGP state", len(core)),
	})
}

// checkLDPAdjacencies confirms label distribution reached the forwarding table.
//
// An operational LDP session is not the claim. A router can hold every session
// and still install nothing, and a router can install labels the kernel then
// refuses to act on. Both were real failures here. So the session and the
// installed label table are checked together.
func checkLDPAdjacencies(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("mpls.ldp_adjacencies", fmt.Errorf("AS %d is not in this lab", env.AS))
	}
	var problems []string
	checked := 0
	for _, d := range as.Routers {
		want := interiorPeers(as, d)
		if len(want) == 0 {
			continue
		}
		checked++
		out, err := env.Vtysh(ctx, d.Name, "show mpls ldp neighbor")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		// Where the adjacency was discovered, not merely that a session
		// exists.
		//
		// LDP will happily bring up a *targeted* session between two
		// loopbacks, routed over whatever path the IGP offers. That is a
		// session with the right peer at the right address, and the check
		// accepted it -- so a submission could take LDP off the interior link
		// entirely, replace it with a targeted session, and keep full marks
		// for label distribution across a link that distributes no labels.
		// A link adjacency is discovered by hellos on the interface itself,
		// and says so.
		disc, err := env.Vtysh(ctx, d.Name, "show mpls ldp discovery")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		links := ldpLinkAdjacencies(disc)
		for _, p := range want {
			if !strings.Contains(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s has no LDP session with %s", d.Name, p.name))
				continue
			}
			if !operationalWith(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s's LDP session with %s is not operational",
					d.Name, p.name))
			}
			if id, ok := links[p.iface]; !ok {
				problems = append(problems, fmt.Sprintf(
					"%s has no link LDP adjacency on %s, the interface facing %s: a targeted "+
						"session is not label distribution across that link",
					d.Name, p.iface, p.name))
			} else if id != p.addr {
				problems = append(problems, fmt.Sprintf(
					"%s's link adjacency on %s is with %s, not %s", d.Name, p.iface, id, p.name))
			}
		}
		// Labels must reach the kernel, not merely be negotiated. A table that
		// cannot be read is the grader's failure, not the student's: silently
		// reading the missing output as "labels are present" once let a router
		// that installed nothing pass, so the read is required to succeed.
		tbl, err := env.Vtysh(ctx, d.Name, "show mpls table")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		if !strings.Contains(tbl, "LDP") {
			problems = append(problems, fmt.Sprintf(
				"%s has negotiated labels but installed none, so it forwards nothing on them", d.Name))
		}
	}
	if checked == 0 {
		return Errored("mpls.ldp_adjacencies",
			fmt.Errorf("no router in AS %d has an interior link, so there is nothing to check", env.AS))
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		return Fail("mpls.ldp_adjacencies", Evidence{
			Expected: "an operational LDP session on every interior link, with labels installed",
			Observed: strings.Join(problems, "; "),
			Command:  "vtysh -c 'show mpls ldp neighbor'; vtysh -c 'show mpls table'",
		})
	}
	return Pass("mpls.ldp_adjacencies", Evidence{
		Expected: "label distribution across the interior",
		Observed: fmt.Sprintf("%d router(s) have every interior session operational with labels installed", checked),
	})
}

// checkVPNReachability asks whether each customer's sites can reach each other.
//
// It pings between hosts of the same customer, from one site to another. That
// is the only claim the exercise makes that a student can be sure of: the
// branches run ordinary eBGP and know nothing about MPLS, so if two sites of a
// bank can reach each other it is because the provider carried them.
func checkVPNReachability(ctx context.Context, env *Env) Result {
	groups, err := customerGroups(env)
	if err != nil {
		return Errored("vpn.site_reachability", err)
	}
	// What each site received, before and after.
	//
	// A ping proves that something answered, not that the customer's site did.
	// The provider is the system being marked and every packet crosses it: a
	// DNAT rule on each edge, answering the far site's address locally while
	// the real traffic is dropped, left every probe succeeding and the mark
	// untouched. The customer's hosts are not the provider's to configure, and
	// the kernel's count of echo requests delivered to them is not something a
	// rule on the way can arrange.
	var allSites []sitePoint
	for _, sites := range groups {
		allSites = append(allSites, sites...)
	}
	before := receivedEchoesAt(ctx, env, allSites)

	var problems []string
	tried := 0
	sentTo := map[string]int{}
	for name, sites := range groups {
		if len(sites) < 2 {
			continue
		}
		for i := 0; i < len(sites); i++ {
			for j := i + 1; j < len(sites); j++ {
				// Both directions: a VPN that carries a customer one way but
				// not back is still broken, and a single-direction probe would
				// report it as working.
				for _, d := range directed(sites[i], sites[j]) {
					tried++
					sentTo[d.to.host]++
					reached, err := env.reaches(ctx, d.from.host, d.to.addr)
					if err != nil {
						return Errored("vpn.site_reachability", err)
					}
					if !reached {
						problems = append(problems, fmt.Sprintf(
							"%s cannot reach %s (%s), both sites of %s",
							d.from.host, d.to.host, d.to.addr, name))
					}
				}
			}
		}
	}
	after := receivedEchoesAt(ctx, env, allSites)
	for _, site := range allSites {
		if sentTo[site.host] == 0 {
			continue
		}
		b, okB := before[site.host]
		a, okA := after[site.host]
		if !okB || !okA {
			continue // the counter could not be read; the probe stands alone
		}
		if a <= b {
			problems = append(problems, fmt.Sprintf(
				"%s answered %d probe(s) it never received, so something on the way is "+
					"replying for it", site.host, sentTo[site.host]))
		}
	}
	if tried == 0 {
		return Errored("vpn.site_reachability",
			fmt.Errorf("no customer in this lab has two sites, so there is nothing to check"))
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		return Fail("vpn.site_reachability", Evidence{
			Expected: "each customer's sites reach each other across the provider",
			Observed: strings.Join(problems, "; "),
			Command:  "ping",
		})
	}
	return Pass("vpn.site_reachability", Evidence{
		Expected: "each customer's sites reach each other",
		Observed: fmt.Sprintf("%d site pair(s) reachable, and every site received the traffic "+
			"addressed to it", tried),
	})
}

// receivedEchoesAt reads each site host's count of ICMP echo requests the
// kernel delivered to it.
func receivedEchoesAt(ctx context.Context, env *Env, sites []sitePoint) map[string]int {
	out := map[string]int{}
	seen := map[string]bool{}
	for _, s := range sites {
		if seen[s.host] {
			continue
		}
		seen[s.host] = true
		res, err := env.Probe(ctx, s.host, []string{"cat", "/proc/net/snmp"})
		if err != nil || res.ExitCode != 0 {
			continue
		}
		if n, ok := icmpInEchos(res.Stdout); ok {
			out[s.host] = n
		}
	}
	return out
}

// checkVPNIsolation asks whether the customers are kept apart.
//
// This is the half that a working VPN does not imply. A provider that simply
// put every customer in one table would pass the reachability check completely
// and fail this one, and it is the mistake the exercise is designed to provoke.
func checkVPNIsolation(ctx context.Context, env *Env) Result {
	groups, err := customerGroups(env)
	if err != nil {
		return Errored("vpn.isolation", err)
	}
	if len(groups) < 2 {
		return Errored("vpn.isolation",
			fmt.Errorf("this lab has fewer than two customers, so isolation cannot be tested"))
	}
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	// Isolation is only worth anything over a VPN that actually carries
	// traffic. "The ping was blocked" is equally true of a network where
	// nothing works at all, so certifying isolation without first seeing one
	// customer's own sites reach each other would award full marks to a dead
	// network -- the very failure this exercise is built to provoke, recorded
	// as a success. The rubric also makes this question depend on reachability;
	// this is the same guarantee at the level of the check, so it holds when
	// the check is run on its own.
	carried, intraPairs := 0, 0
	for _, sites := range groups {
		for i := 0; i < len(sites); i++ {
			for j := i + 1; j < len(sites); j++ {
				for _, d := range directed(sites[i], sites[j]) {
					intraPairs++
					reached, err := env.reaches(ctx, d.from.host, d.to.addr)
					if err != nil {
						return Errored("vpn.isolation", err)
					}
					if reached {
						carried++
					}
				}
			}
		}
	}
	if intraPairs > 0 && carried == 0 {
		return Fail("vpn.isolation", Evidence{
			Expected: "a working VPN whose sites reach each other, so that isolating it means something",
			Observed: "no customer's own sites can reach each other at all",
			Detail: "every isolation probe here is blocked because nothing is reachable, not because " +
				"the tables are kept apart, and a dead network must not earn the isolation marks; " +
				"get vpn.site_reachability passing first",
			Command: "ping",
		})
	}

	// Every site of one customer must fail to reach every site of another, in
	// both directions: a table that leaks from only one branch, or only on the
	// return path, is still a leak, and the first-site, one-direction probe
	// this replaced walked straight past it.
	var leaks []string
	tried := 0
	for x := 0; x < len(names); x++ {
		for y := x + 1; y < len(names); y++ {
			for _, a := range groups[names[x]] {
				for _, b := range groups[names[y]] {
					for _, d := range directed(a, b) {
						tried++
						reached, err := env.reaches(ctx, d.from.host, d.to.addr)
						if err != nil {
							return Errored("vpn.isolation", err)
						}
						if reached {
							leaks = append(leaks, fmt.Sprintf(
								"%s reached %s (%s): %s and %s are sharing a routing table",
								d.from.host, d.to.host, d.to.addr, names[x], names[y]))
						}
					}
				}
			}
		}
	}
	// And the tables themselves, because a probe that needs a reply cannot see
	// a leak that only goes one way.
	//
	// Importing another customer's route target on one edge puts their
	// prefixes in this customer's table. Traffic then flows into the other
	// bank's network, and nothing comes back, because their table has no route
	// to here -- so every ping is lost and a check built on ping reports
	// perfect isolation. One bank able to inject packets into another's
	// network is precisely the failure the mechanism exists to prevent, and it
	// scored full marks. Found by the advanced course's own discrimination
	// suite, which is what that suite is for.
	routeLeaks, err := crossCustomerRoutes(ctx, env, groups, names)
	if err != nil {
		return Errored("vpn.isolation", err)
	}
	leaks = append(leaks, routeLeaks...)

	if len(leaks) > 0 {
		sort.Strings(leaks)
		return Fail("vpn.isolation", Evidence{
			Expected: "customers cannot reach one another, and cannot see one another's routes",
			Observed: strings.Join(truncate(leaks, 6), "; "),
			Command:  "ping; show ip route vrf <table> <prefix>",
		})
	}
	return Pass("vpn.isolation", Evidence{
		Expected: "customers are kept apart, over a VPN that carries their traffic",
		Observed: fmt.Sprintf("%d directed site pair(s) across %d customer(s) mutually "+
			"unreachable, and no customer's table holds another's prefixes",
			tried, len(names)),
	})
}

// anyCustomerTrafficArrives reports whether at least one customer's site can
// reach another of its own sites.
//
// It is deliberately a low bar: this is not the reachability question, which is
// marked separately and in full. It is the precondition for asking *how*
// traffic is carried, and a VPN across which nothing at all passes cannot
// answer it.
func anyCustomerTrafficArrives(ctx context.Context, env *Env) (bool, error) {
	groups, err := customerGroups(env)
	if err != nil {
		return false, err
	}
	tried := 0
	for _, sites := range groups {
		for i := 0; i < len(sites); i++ {
			for j := 0; j < len(sites); j++ {
				if i == j {
					continue
				}
				tried++
				ok, err := env.reaches(ctx, sites[i].host, sites[j].addr)
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
		}
	}
	if tried == 0 {
		return false, fmt.Errorf("no customer in this lab has two sites, so there is no " +
			"traffic between them to carry")
	}
	return false, nil
}

// crossCustomerRoutes reports every place one customer's routing table holds a
// route to another customer's addresses.
//
// This is the control-plane half of isolation, and it is not redundant with the
// probes above: a leak in one direction delivers packets and receives no reply,
// which is indistinguishable from isolation to anything that pings.
//
// A route counts as a leak when it covers another customer's site and does not
// cover any of this customer's own. That last clause is what keeps a default
// route -- which covers everybody, is not customer-specific, and is present in
// every correct submission here -- from being read as a total leak, without
// resorting to a list of prefixes to forgive.
func crossCustomerRoutes(ctx context.Context, env *Env, groups map[string][]sitePoint,
	names []string) ([]string, error) {
	holders, err := vrfHolders(env)
	if err != nil {
		return nil, err
	}
	addrs := map[string][]netip.Addr{}
	for name, sites := range groups {
		for _, s := range sites {
			if a, perr := netip.ParseAddr(s.addr); perr == nil {
				addrs[name] = append(addrs[name], a)
			}
		}
	}
	covers := func(p netip.Prefix, who string) bool {
		for _, a := range addrs[who] {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	var leaks []string
	for _, mine := range names {
		for _, router := range holders[mine] {
			var doc map[string]any
			cmd := fmt.Sprintf("show ip route vrf %s json", mine)
			if err := env.VtyshJSON(ctx, router, cmd, &doc); err != nil {
				// Unreadable is not empty. A verdict of "no leaks" drawn from a
				// table nobody managed to read is the failure this file exists
				// to avoid.
				return nil, fmt.Errorf("%s: table %s could not be read (%w), so what is in "+
					"it cannot be part of a verdict", router, mine, err)
			}
			for prefix := range doc {
				p, perr := netip.ParsePrefix(prefix)
				if perr != nil || covers(p, mine) {
					continue
				}
				for _, theirs := range names {
					if theirs == mine || !covers(p, theirs) {
						continue
					}
					leaks = append(leaks, fmt.Sprintf(
						"%s holds a route to %s in table %s, and those addresses belong to "+
							"%s: the tables are not separate", router, prefix, mine, theirs))
				}
			}
		}
	}
	sort.Strings(leaks)
	return leaks, nil
}

// vrfHolders lists, for each routing table, the provider edges that hold it.
func vrfHolders(env *Env) (map[string][]string, error) {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil, fmt.Errorf("AS %d is not in this lab", env.AS)
	}
	out := map[string][]string{}
	for _, d := range as.Routers {
		seen := map[string]bool{}
		for _, i := range d.Ifaces {
			if i.VRF == "" || seen[i.VRF] {
				continue
			}
			seen[i.VRF] = true
			out[i.VRF] = append(out[i.VRF], d.Name)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out, nil
}

// ---------------------------------------------------------------------------

type sitePoint struct {
	host string // device ID of a host at this site
	addr string // an address reachable at this site
}

// customerGroups collects the customers of the provider under test and the
// sites of each, keyed by the routing table that carries them.
//
// The table is what defines a customer here: two sites belong to the same
// customer exactly when the provider puts them in the same table, which is the
// property the exercise is about. Grouping by anything else -- a name, an AS
// number range -- would let a lab be built where the check and the exercise
// disagree about who is whose.
func customerGroups(env *Env) (map[string][]sitePoint, error) {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil, fmt.Errorf("AS %d is not in this lab", env.AS)
	}
	if len(as.VRFs) == 0 {
		return nil, fmt.Errorf("AS %d declares no routing tables, so it carries no VPN customers", env.AS)
	}

	groups := map[string][]sitePoint{}
	for _, d := range as.Routers {
		for _, i := range d.Ifaces {
			if i.VRF == "" || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			// The site is the AS on the far side of a table-bound port. Its
			// host is what gets pinged, because a host proves the data plane
			// end to end and a router interface only proves the last hop.
			peerAS := i.Peer.Device.ASN
			if h := hostIn(env.Topology, peerAS); h != nil {
				if addr := siteAddr(h); addr != "" {
					groups[i.VRF] = append(groups[i.VRF], sitePoint{host: h.ID, addr: addr})
				}
			}
		}
	}
	for k := range groups {
		sort.Slice(groups[k], func(a, b int) bool { return groups[k][a].host < groups[k][b].host })
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no customer site could be resolved; the tables exist but no "+
			"interface is bound to one in AS %d", env.AS)
	}
	return groups, nil
}

func coreRouters(as *model.AS) []*model.Device {
	var out []*model.Device
	for _, d := range as.Routers {
		if isCore(as, d.Name) {
			out = append(out, d)
		}
	}
	return out
}

func isCore(as *model.AS, name string) bool { return as.InCore(name) }

type ldpPeer struct{ name, addr, iface string }

// interiorPeers lists the routers this one shares an interior link with, by the
// address LDP identifies them with.
func interiorPeers(as *model.AS, d *model.Device) []ldpPeer {
	var out []ldpPeer
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Link.InterAS || i.Peer == nil || i.Peer.Device == nil {
			continue
		}
		p := i.Peer.Device
		if p.ASN != as.ASN || p.Kind != model.KindRouter {
			continue
		}
		if lo, ok := p.IfaceByName("lo"); ok && lo.Addr4 != "" {
			out = append(out, ldpPeer{name: p.Name, addr: addrOnly(lo.Addr4), iface: i.Name})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

// ldpLinkAdjacencies maps each interface with a *link* LDP adjacency to the
// peer discovered on it.
//
// `show mpls ldp discovery` names the kind in its Type column: "Link" for
// hellos heard on an interface, "Targeted" for a session set up to an address
// over whatever path the IGP has. Only the first is an adjacency on that link.
func ldpLinkAdjacencies(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// "ipv4 1.152.0.1 Link port_R2 15"
		if len(f) < 4 || f[0] == "AF" {
			continue
		}
		if !strings.EqualFold(f[2], "Link") {
			continue
		}
		res[f[3]] = f[1]
	}
	return res
}

// operationalWith reports whether the line mentioning an address says the
// session is up. Presence alone is not enough: a session in any other state is
// listed too, and treating that as success is how a check passes on a network
// that is not working.
func operationalWith(out, addr string) bool {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, addr) {
			return strings.Contains(ln, "OPERATIONAL")
		}
	}
	return false
}

func hostIn(top *model.Topology, asn int) *model.Device {
	as, ok := top.ASes[asn]
	if !ok {
		return nil
	}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost {
			return d
		}
	}
	return nil
}

// siteAddr is the address a customer site answers on: the first address that
// is not the loopback, because pinging a loopback proves the control plane
// found the route and says nothing about whether traffic crosses.
func siteAddr(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Name == "lo" || i.Addr4 == "" {
			continue
		}
		return addrOnly(i.Addr4)
	}
	return ""
}

func addrOnly(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// directedPair is one ordered probe: from a site, to a site's address.
type directedPair struct{ from, to sitePoint }

// directed returns both orderings of a site pair.
//
// A VPN can carry a customer one way but not back, and a leak can appear in one
// direction only, so probing a single ordering reports either as its opposite.
func directed(a, b sitePoint) [2]directedPair {
	return [2]directedPair{{from: a, to: b}, {from: b, to: a}}
}

// reaches reports whether a device can reach an address, keeping a path that is
// blocked distinct from a probe that never ran.
//
// The distinction decides a mark, and in opposite directions on the two VPN
// questions: a probe that could not execute looks like an unreachable site to
// the reachability check and like a correctly blocked one to the isolation
// check, so the same transport outage would cost marks on the first and award
// them on the second. Going through Probe records the transport failure with
// the machinery tracker, so it surfaces as an un-gradeable question rather than
// either verdict being invented from it.
//
// Three echoes, because a single loss on a shaped link would otherwise read as
// a routing failure and cost a student marks for the network's timing; ping
// exits zero if any one of them is answered.
func (e *Env) reaches(ctx context.Context, deviceID, addr string) (bool, error) {
	res, err := e.Probe(ctx, deviceID, []string{"ping", "-c", "3", "-W", "2", addr})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// checkVPNLabelSwitched asks how the customer's traffic is carried, not merely
// whether it arrives.
//
// Reachability between two sites of one customer is the exercise's own test,
// and it is satisfiable without doing the exercise: a provider that put every
// customer prefix in the global table and let plain iBGP carry it would pass,
// and so would one that wrote static routes. Neither is a VPN, and the
// distinction is the entire subject of the assignment.
//
// So this reads what the forwarding table actually says. A prefix belonging to
// a remote site must be installed in that customer's own routing table, learned
// by BGP, and resolved through a stack of two labels: the transport label that
// gets the packet across the interior, and the VPN label that tells the far
// edge which customer it belongs to. A static route has no labels; a route in
// the global table is not in the VRF; and a single label is a backbone path
// with no VPN on it.
func checkVPNLabelSwitched(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || len(as.VRFs) == 0 {
		return Errored("vpn.label_switched",
			fmt.Errorf("AS %d declares no routing tables, so it carries no VPN customers", env.AS))
	}
	// Which prefixes belong to which customer, and which edges serve them.
	type edge struct {
		router string
		vrf    string
		remote []string // prefixes of the customer's other sites
	}
	var edges []edge
	for _, d := range as.Routers {
		byVRF := map[string]bool{}
		for _, i := range d.Ifaces {
			if i.VRF == "" || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			byVRF[i.VRF] = true
		}
		for vrf := range byVRF {
			// Every site of this customer that is not behind this edge.
			mine := map[int]bool{}
			for _, i := range d.Ifaces {
				if i.VRF == vrf && i.Peer != nil && i.Peer.Device != nil {
					mine[i.Peer.Device.ASN] = true
				}
			}
			var remote []string
			for _, other := range as.Routers {
				if other.Name == d.Name {
					continue
				}
				for _, i := range other.Ifaces {
					if i.VRF != vrf || i.Peer == nil || i.Peer.Device == nil {
						continue
					}
					peer := i.Peer.Device.ASN
					if mine[peer] {
						continue
					}
					if b := blockOf(env.Topology, peer); b != "" {
						remote = append(remote, b)
					}
				}
			}
			sort.Strings(remote)
			if len(remote) > 0 {
				edges = append(edges, edge{d.Name, vrf, remote})
			}
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].router != edges[j].router {
			return edges[i].router < edges[j].router
		}
		return edges[i].vrf < edges[j].vrf
	})
	if len(edges) == 0 {
		return Errored("vpn.label_switched",
			fmt.Errorf("no customer in this lab has a site behind another edge, so there is "+
				"nothing for a VPN to carry"))
	}

	var problems []string
	checked, labelled := 0, 0
	for _, e := range edges {
		for _, prefix := range e.remote {
			checked++
			var doc map[string][]struct {
				Protocol string `json:"protocol"`
				Selected bool   `json:"selected"`
				Nexthops []struct {
					IP     string `json:"ip"`
					FIB    bool   `json:"fib"`
					Labels []int  `json:"labels"`
				} `json:"nexthops"`
			}
			cmd := fmt.Sprintf("show ip route vrf %s %s json", e.vrf, prefix)
			if err := env.VtyshJSON(ctx, e.router, cmd, &doc); err != nil {
				problems = append(problems, fmt.Sprintf(
					"%s: %s is not in %s at all", e.router, prefix, e.vrf))
				continue
			}
			entries, ok := doc[prefix]
			if !ok || len(entries) == 0 {
				problems = append(problems, fmt.Sprintf(
					"%s: %s is not in %s", e.router, prefix, e.vrf))
				continue
			}
			best := entries[0]
			for _, x := range entries {
				if x.Selected {
					best = x
				}
			}
			if best.Protocol != "bgp" {
				problems = append(problems, fmt.Sprintf(
					"%s carries %s in %s as a %s route; a VPN route is learned by BGP",
					e.router, prefix, e.vrf, best.Protocol))
				continue
			}
			// The stack, in the entry the kernel is actually using.
			stack := 0
			for _, nh := range best.Nexthops {
				if !nh.FIB {
					continue
				}
				if len(nh.Labels) > stack {
					stack = len(nh.Labels)
				}
			}
			switch {
			case stack >= 2:
				labelled++
			case stack == 1:
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s with one label; a VPN route needs two -- a transport "+
						"label across the interior and a VPN label the far edge reads",
					e.router, prefix, e.vrf))
			default:
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s with no label at all, so it is not being carried "+
						"over the label-switched backbone", e.router, prefix, e.vrf))
			}
		}
	}
	// And the labels have to be carrying something.
	//
	// Everything above reads the forwarding table, which is the only place
	// that can distinguish a two-label VPN path from a static route or a leak
	// into the global table -- and it says nothing about whether a packet gets
	// through. Dropping EtherType 0x8847 on the interior links leaves every
	// label stack installed and every labelled packet discarded, and this
	// awarded full marks for a mechanism that carried nothing. The question is
	// how the customer's traffic is carried; if none of it is, there is
	// nothing to answer it about.
	carried, err := anyCustomerTrafficArrives(ctx, env)
	if err != nil {
		return Errored("vpn.label_switched", err)
	}
	if !carried {
		return Errored("vpn.label_switched", fmt.Errorf(
			"no customer's traffic reaches its other site at all, so how it would have been "+
				"carried cannot be assessed; the label stacks are installed and nothing "+
				"crosses them"))
	}

	sort.Strings(problems)
	if len(problems) == 0 {
		return Pass("vpn.label_switched", Evidence{
			Expected: "each customer's remote sites reached over a two-label path",
			Observed: fmt.Sprintf("%d remote prefix(es) across %d edge/table pair(s) resolve "+
				"through a transport label and a VPN label", labelled, len(edges)),
			Command: "show ip route vrf <table> <prefix> json",
		})
	}
	return Partial("vpn.label_switched", ratio(labelled, maxInt(checked, 1)), Evidence{
		Expected: "each customer's remote sites reached over a two-label path",
		Observed: fmt.Sprintf("%d of %d remote prefix(es) are label-switched", labelled, checked),
		Detail:   strings.Join(truncate(problems, 6), "\n"),
		Hint: "the customer's routes must be carried as VPNv4 between the edges and resolved " +
			"through the interior's LDP labels; reachability alone can be achieved without a VPN",
		Command: "show ip route vrf <table> <prefix> json; show bgp ipv4 vpn",
	})
}

// blockOf is the address block an AS was allocated, which is what its sites
// advertise.
func blockOf(top *model.Topology, asn int) string {
	if as, ok := top.ASes[asn]; ok {
		return as.Block
	}
	return ""
}
