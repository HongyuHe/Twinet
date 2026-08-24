package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// RouteServer renders an internet exchange's route server.
//
// An exchange is a shared fabric, so the route server's peers are not the
// devices at the other end of its cable — that is a switch — but every member
// on the same segment. Discovering peers by walking directly addressed
// interfaces, as an ordinary router does, therefore finds nobody, and the
// exchange silently carries no routes at all. Membership has to be derived from
// the segment.
//
// The policy is the one the assignment is built around: the exchange relays an
// announcement to member X only when it carries the community <IXP>:X. That is
// what makes question 2.4 a real exercise rather than a formality.
func RouteServer(top *model.Topology, d *model.Device) (RouterConfig, error) {
	as, ok := top.ASes[d.ASN]
	if !ok {
		return RouterConfig{}, fmt.Errorf("%s belongs to unknown AS %d", d.ID, d.ASN)
	}
	members := ExchangeMembers(top, as.ASN)
	if len(members) == 0 {
		return RouterConfig{}, fmt.Errorf("exchange %d has no members", as.ASN)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "frr version 10.0\nfrr defaults traditional\nhostname %s\n", d.Name)
	b.WriteString("service integrated-vtysh-config\n!\n")

	// The fabric-facing interface.
	for _, i := range d.Ifaces {
		if i.Addr4 == "" {
			continue
		}
		fmt.Fprintf(&b, "interface %s\n ip address %s\nexit\n!\n", i.Name, i.Addr4)
	}

	fmt.Fprintf(&b, "router bgp %d\n", as.ASN)
	if lo, ok := d.IfaceByName("fabric"); ok && lo.Addr4 != "" {
		fmt.Fprintf(&b, " bgp router-id %s\n", addrOf(lo.Addr4))
	}
	b.WriteString(" no bgp ebgp-requires-policy\n")
	b.WriteString(" no bgp network import-check\n")
	// A route server does not insert itself into the path, and does not rewrite
	// the next hop: members must reach each other directly across the fabric.
	b.WriteString(" bgp cluster-id 0.0.0.1\n")

	for _, m := range members {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", m.Addr, m.ASN)
		fmt.Fprintf(&b, " neighbor %s description AS%d\n", m.Addr, m.ASN)
		// Members are frequently unconfigured for days at the start of a
		// project, so the exchange must tolerate a session that never comes up
		// without hammering it.
		fmt.Fprintf(&b, " neighbor %s timers connect 30\n", m.Addr)
	}

	b.WriteString(" address-family ipv4 unicast\n")
	for _, m := range members {
		fmt.Fprintf(&b, "  neighbor %s activate\n", m.Addr)
		fmt.Fprintf(&b, "  neighbor %s route-server-client\n", m.Addr)
		fmt.Fprintf(&b, "  neighbor %s route-map RS-IN-%d in\n", m.Addr, m.ASN)
		fmt.Fprintf(&b, "  neighbor %s route-map RS-OUT-%d out\n", m.Addr, m.ASN)
		// Sending the community through is essential: it is the signal the
		// export policy of every other member matches on.
		fmt.Fprintf(&b, "  neighbor %s send-community\n", m.Addr)
	}
	b.WriteString(" exit-address-family\nexit\n!\n")

	// Import keeps the announcement as it is; the decision is made on export.
	for _, m := range members {
		fmt.Fprintf(&b, "route-map RS-IN-%d permit 10\nexit\n!\n", m.ASN)
	}
	// Export to member X only when the announcement carries <IXP>:X.
	for _, m := range members {
		fmt.Fprintf(&b, "bgp community-list standard RELAY-%d permit %d:%d\n", m.ASN, as.ASN, m.ASN)
		fmt.Fprintf(&b, "route-map RS-OUT-%d permit 10\n match community RELAY-%d\nexit\n",
			m.ASN, m.ASN)
		fmt.Fprintf(&b, "route-map RS-OUT-%d deny 20\nexit\n!\n", m.ASN)
	}

	return RouterConfig{Platform: b.String()}, nil
}

// Member is one participant of an exchange.
type Member struct {
	ASN  int
	Addr string
	Dev  *model.Device
}

// ExchangeMembers lists the members attached to an exchange's fabric.
func ExchangeMembers(top *model.Topology, ixp int) []Member {
	segment := fmt.Sprintf("ixp%d", ixp)
	seen := map[string]bool{}
	var out []Member
	for _, l := range top.Links {
		if l.Segment != segment {
			continue
		}
		for _, i := range []*model.Iface{l.A, l.B} {
			if i == nil || i.Addr4 == "" || i.Device.ASN == ixp {
				continue
			}
			addr := addrOf(i.Addr4)
			if seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, Member{ASN: i.Device.ASN, Addr: addr, Dev: i.Device})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ASN < out[b].ASN })
	return out
}

// IsRouteServer reports whether a device is an exchange's route server.
func IsRouteServer(top *model.Topology, d *model.Device) bool {
	if !d.IsRouter() {
		return false
	}
	as, ok := top.ASes[d.ASN]
	return ok && as.Role == model.RoleIXP
}
