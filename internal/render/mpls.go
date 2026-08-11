package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Label switching and virtual routing, which the advanced-networks course is
// built on.
//
// The exercise is a provider that carries several customers' private networks
// across one backbone. Two things make that possible, and neither has any
// equivalent in the introductory course:
//
//   - A BGP-free core. The routers in the middle hold no BGP routes at all;
//     they forward on labels distributed by LDP. That is what lets a backbone
//     scale: the interior does not have to hold a copy of the internet.
//   - Virtual routing tables. Each customer's routes live in their own table,
//     so two customers can both use 192.168.0.0/16 without either seeing the
//     other, and route targets decide precisely which sites may reach which.
//
// Both are rendered from the same declaration the grader reads, so a check
// cannot disagree with the configuration about what was asked for.

// renderMPLS emits the LDP configuration for one router.
//
// LDP runs on the interior interfaces only. Running it towards a customer or a
// peer would offer them labels for the provider's internal prefixes, which is
// both pointless and a leak of the backbone's structure.
func renderMPLS(as *model.AS, d *model.Device) string {
	if !as.MPLS.Enabled {
		return ""
	}
	lo, hasLo := d.IfaceByName("lo")
	if !hasLo || lo.Addr4 == "" {
		return ""
	}
	var ifaces []string
	for _, i := range d.Ifaces {
		if i.Role == model.RoleIntraAS {
			ifaces = append(ifaces, i.Name)
		}
	}
	if len(ifaces) == 0 {
		return ""
	}
	sort.Strings(ifaces)

	var b strings.Builder
	b.WriteString("mpls ldp\n")
	fmt.Fprintf(&b, " router-id %s\n", addrOf(lo.Addr4))
	b.WriteString(" address-family ipv4\n")
	// The transport address must be the loopback, not an interface address.
	// LDP sessions are between loopbacks so that a session survives any single
	// interior link failing; anchoring them to an interface address means the
	// session goes down with the cable, which is exactly the failure the design
	// is meant to ride out.
	fmt.Fprintf(&b, "  discovery transport-address %s\n", addrOf(lo.Addr4))
	for _, n := range ifaces {
		fmt.Fprintf(&b, "  interface %s\n", n)
	}
	b.WriteString("  exit-address-family\n")
	b.WriteString("exit\n!\n")
	return b.String()
}

// vrfsOn returns the virtual routing tables this router actually terminates,
// in name order.
//
// Only the routers with an interface in a table configure it. Configuring every
// table on every router would make the core hold customer routes, which is the
// one thing a BGP-free core is defined by not doing.
func vrfsOn(as *model.AS, d *model.Device) []string {
	seen := map[string]bool{}
	for _, i := range d.Ifaces {
		if i.VRF != "" && as.VRFs[i.VRF] != nil {
			seen[i.VRF] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// renderVRFBGP emits one `router bgp N vrf X` block per virtual routing table
// the router terminates.
//
// The route distinguisher makes two customers' identical prefixes distinct in
// the provider's table. The route targets decide which tables may import each
// other's routes -- and therefore which sites can reach which, which is the
// answer to the exercise's isolation question.
func renderVRFBGP(as *model.AS, d *model.Device) string {
	names := vrfsOn(as, d)
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range names {
		v := as.VRFs[n]
		fmt.Fprintf(&b, "router bgp %d vrf %s\n", as.ASN, n)
		b.WriteString(" no bgp ebgp-requires-policy\n")
		// The customer's own session lives inside their table, not the
		// provider's. A neighbour statement in the default instance would put
		// the customer's routes in the provider's table, where they would
		// collide with every other customer using the same private space --
		// which is precisely what the exercise asks the student to prevent.
		peers := vrfPeers(d, n)
		for _, p := range peers {
			fmt.Fprintf(&b, " neighbor %s remote-as %d\n", p.addr, p.asn)
		}
		b.WriteString(" address-family ipv4 unicast\n")
		for _, p := range peers {
			fmt.Fprintf(&b, "  neighbor %s activate\n", p.addr)
		}
		// The customer-facing interfaces are in this table, so their subnets
		// are the routes to carry. Redistributing connected is what puts them
		// into the VPN; without it the table is advertised as empty and every
		// site reaches nothing, with no error anywhere.
		b.WriteString("  redistribute connected\n")
		b.WriteString("  label vpn export auto\n")
		fmt.Fprintf(&b, "  rd vpn export %s\n", routeDistinguisher(d, n, v))
		if len(v.Export) > 0 {
			fmt.Fprintf(&b, "  rt vpn export %s\n", strings.Join(v.Export, " "))
		}
		if len(v.Import) > 0 {
			fmt.Fprintf(&b, "  rt vpn import %s\n", strings.Join(v.Import, " "))
		}
		b.WriteString("  export vpn\n")
		b.WriteString("  import vpn\n")
		b.WriteString("  exit-address-family\n")
		b.WriteString("exit\n!\n")
	}
	return b.String()
}

// vrfPeer is one external neighbour reached through a virtual routing table.
type vrfPeer struct {
	addr string
	asn  int
}

// vrfPeers returns the external neighbours whose interface is in a given table.
func vrfPeers(d *model.Device, vrf string) []vrfPeer {
	var out []vrfPeer
	for _, i := range d.Ifaces {
		if i.VRF != vrf || i.Peer == nil || i.Peer.Addr4 == "" || i.Peer.Device == nil {
			continue
		}
		out = append(out, vrfPeer{addr: addrOf(i.Peer.Addr4), asn: i.Peer.Device.ASN})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].addr < out[b].addr })
	return out
}

// vpnAddressFamily activates the VPN address family towards the internal
// neighbours, so labelled customer routes are carried between the edges.
//
// It is emitted only where the router has a table to carry. A core router
// activating it would receive customer routes it has no business holding.
func vpnAddressFamily(as *model.AS, d *model.Device, peers []string) string {
	if len(as.VRFs) == 0 || len(vrfsOn(as, d)) == 0 || len(peers) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(" address-family ipv4 vpn\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "  neighbor %s activate\n", p)
	}
	b.WriteString(" exit-address-family\n")
	return b.String()
}

// edgePeers returns the loopbacks of the routers this one exchanges VPN routes
// with: the other edges, not the core.
//
// A core router by definition runs no BGP, so a session towards one would never
// come up, and the configuration would describe a network that cannot work.
func edgePeers(as *model.AS, d *model.Device) []string {
	var out []string
	for _, r := range as.Routers {
		if r == d || as.InCore(r.Name) {
			continue
		}
		if len(vrfsOn(as, r)) == 0 {
			continue
		}
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			out = append(out, addrOf(lo.Addr4))
		}
	}
	sort.Strings(out)
	return out
}

// routeDistinguisher returns the value that makes this router's copy of a
// customer's routes distinct from every other router's.
//
// It must differ per provider edge, not merely per customer. The distinguisher
// is part of the key a VPN route is stored under, so two edges advertising a
// customer's prefixes under one value are advertising the same key with
// different contents: the receiving router keeps one and discards the other,
// and one of the customer's sites simply disappears from the other's routing
// table. There is no error; the site is just unreachable.
//
// That is what happened here with a single value written in the manifest. Both
// edges of a bank used 1:101, and neither learned the other's routes while both
// learned the other bank's perfectly well -- a failure that looks like a policy
// mistake and is not one.
//
// The derived form is the canonical one: the router's own loopback, which is
// unique in the autonomous system by construction, and the table number, which
// is unique within the router. An explicit value in the manifest overrides it,
// for course material that publishes specific distinguishers -- but then it is
// the author's job to keep them distinct, and validation says so.
func routeDistinguisher(d *model.Device, name string, v *model.VRFSpec) string {
	if v.RD != "" {
		return v.RD
	}
	// The autonomous system number and a value encoding both the table and the
	// router. The other canonical form, <loopback>:<table>, is accepted by
	// vtysh interactively and silently discarded when the same line is read
	// from the configuration file at startup -- so the router comes up with no
	// distinguisher at all, exports nothing, and the customer's other site
	// simply is not there. Nothing logs it. This form survives a restart,
	// which is the only form that is any use.
	id := d.RouterID
	if id == 0 {
		id = 1
	}
	return fmt.Sprintf("%d:%d", d.ASN, v.Table*1000+id)
}
