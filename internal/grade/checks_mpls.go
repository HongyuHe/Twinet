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
		if !strings.Contains(out, "instance not found") && strings.Contains(out, "Neighbor") {
			bad = append(bad, fmt.Sprintf("%s runs BGP", d.Name))
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
		// Labels must reach the kernel, not merely be negotiated.
		tbl, err := env.Vtysh(ctx, d.Name, "show mpls table")
		if err == nil && !strings.Contains(tbl, "LDP") {
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
				tried++
				a, b := sites[i], sites[j]
				if !env.pings(ctx, a.host, b.addr) {
					problems = append(problems, fmt.Sprintf(
						"%s cannot reach %s (%s), both sites of %s", a.host, b.host, b.addr, name))
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

	var leaks []string
	tried := 0
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			a, b := groups[names[i]][0], groups[names[j]][0]
			tried++
			if env.pings(ctx, a.host, b.addr) {
				leaks = append(leaks, fmt.Sprintf(
					"%s reached %s (%s): %s and %s are sharing a routing table",
					a.host, b.host, b.addr, names[i], names[j]))
			}
		}
	}
	if len(leaks) > 0 {
		return Fail("vpn.isolation", Evidence{
			Expected: "customers cannot reach one another",
			Observed: strings.Join(leaks, "; "),
			Command:  "ping",
		})
	}
	return Pass("vpn.isolation", Evidence{
		Expected: "customers are kept apart",
		Observed: fmt.Sprintf("%d customer pair(s) mutually unreachable", tried),
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

// pings reports whether a device can reach an address.
//
// Several attempts, because a single loss on a shaped link would otherwise be
// read as a routing failure and cost a student marks for the network's timing.
func (e *Env) pings(ctx context.Context, device, addr string) bool {
	res, err := e.Exec(ctx, device, []string{"ping", "-c", "3", "-W", "2", addr})
	if err != nil {
		return false
	}
	return res.ExitCode == 0
}
