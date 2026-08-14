package grade

import (
	"context"
	"fmt"
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
		for _, p := range want {
			if !strings.Contains(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s has no LDP session with %s", d.Name, p.name))
				continue
			}
			if !operationalWith(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s's LDP session with %s is not operational",
					d.Name, p.name))
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
	var problems []string
	tried := 0
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
		Observed: fmt.Sprintf("%d site pair(s) reachable", tried),
	})
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
	if len(leaks) > 0 {
		sort.Strings(leaks)
		return Fail("vpn.isolation", Evidence{
			Expected: "customers cannot reach one another",
			Observed: strings.Join(leaks, "; "),
			Command:  "ping",
		})
	}
	return Pass("vpn.isolation", Evidence{
		Expected: "customers are kept apart, over a VPN that carries their traffic",
		Observed: fmt.Sprintf("%d directed site pair(s) across %d customer(s) mutually unreachable",
			tried, len(names)),
	})
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

type ldpPeer struct{ name, addr string }

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
			out = append(out, ldpPeer{name: p.Name, addr: addrOnly(lo.Addr4)})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
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
