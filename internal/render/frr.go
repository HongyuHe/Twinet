// Package render produces the configuration that is pushed into devices.
//
// It renders two distinct things for every device:
//
//   - the *platform* configuration, which Twinet applies: service interfaces,
//     the OVS bridge that must exist before a student can configure VLANs on
//     it, the FRR daemons file, and everything belonging to staff-run ASes; and
//   - the *expected* configuration, the reference answer for what a correct
//     student would add. Twinet never applies it during a normal deploy, but
//     `twinet solve` does, and the grader compares against it.
//
// Keeping both in one place is what stops the platform, the assignment text and
// the grader from drifting apart, which is precisely what happened in the
// legacy platform where the addressing plan was restated in four places.
package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// FRRDaemons is the /etc/frr/daemons file. Only the daemons the courses need
// are enabled: every extra daemon is a process in every one of a thousand
// containers.
const FRRDaemons = `zebra=yes
bgpd=yes
ospfd=yes
ospf6d=yes
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd=yes
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no

zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
ospf6d_options=" -A ::1"
ldpd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"

frr_profile="traditional"
vtysh_enable=yes
zebra_enable=yes
`

// RouterConfig is the rendered FRR configuration for one router, split by who
// owns each part.
type RouterConfig struct {
	// Platform is applied on every deploy.
	Platform string
	// Expected is the reference solution, applied only by `twinet solve`.
	Expected string
}

// Router renders the FRR configuration for a router.
func Router(top *model.Topology, d *model.Device) (RouterConfig, error) {
	if !d.IsRouter() {
		return RouterConfig{}, fmt.Errorf("%s is not a router", d.ID)
	}
	as, ok := top.ASes[d.ASN]
	if !ok {
		return RouterConfig{}, fmt.Errorf("%s belongs to unknown AS %d", d.ID, d.ASN)
	}

	var plat, exp strings.Builder
	header := func(b *strings.Builder) {
		fmt.Fprintf(b, "frr version 10.0\nfrr defaults traditional\nhostname %s\n", d.Name)
		b.WriteString("no ipv6 forwarding\nservice integrated-vtysh-config\n!\n")
	}
	header(&plat)
	header(&exp)

	// Interfaces.
	for _, i := range d.Ifaces {
		b := &exp
		if i.Owner == model.OwnerPlatform {
			b = &plat
		}
		if i.Addr4 == "" && i.Addr6 == "" {
			continue
		}
		fmt.Fprintf(b, "interface %s\n", i.Name)
		if i.Addr4 != "" {
			fmt.Fprintf(b, " ip address %s\n", i.Addr4)
		}
		if i.Addr6 != "" {
			fmt.Fprintf(b, " ipv6 address %s\n", i.Addr6)
		}
		if c := ospfCost(i); c > 0 {
			fmt.Fprintf(b, " ip ospf cost %d\n", c)
		}
		b.WriteString("exit\n!\n")
	}

	// OSPF: every intra-AS subnet plus the service subnets, which the
	// assignment explicitly requires students to advertise.
	ospf := renderOSPF(d)
	bgp := renderBGP(top, as, d)
	if isPlatformOwned(as) {
		plat.WriteString(ospf)
		plat.WriteString(bgp)
	} else {
		exp.WriteString(ospf)
		exp.WriteString(bgp)
	}

	return RouterConfig{Platform: plat.String(), Expected: exp.String()}, nil
}

func isPlatformOwned(as *model.AS) bool { return as.Role != model.RoleStudent }

// ospfCost returns a non-default OSPF cost for an interface, or zero.
//
// The COS-461 load-balancing question asks students to choose weights so that
// traffic between two routers splits over exactly three paths. The reference
// solution therefore needs costs, and they belong with the topology rather than
// in a grader constant.
func ospfCost(i *model.Iface) int { return 0 }

func renderOSPF(d *model.Device) string {
	var nets []string
	var b strings.Builder
	for _, i := range d.Ifaces {
		switch i.Role {
		case model.RoleInterAS, model.RoleIXPLink:
			// The assignment is explicit: inter-AS subnets must not be in OSPF.
			continue
		}
		if i.Addr4 == "" {
			continue
		}
		net, err := networkOf(i.Addr4)
		if err != nil {
			continue
		}
		nets = append(nets, net)
	}
	if len(nets) == 0 {
		return ""
	}
	sort.Strings(nets)
	fmt.Fprintf(&b, "router ospf\n ospf router-id %s\n", routerID(d))
	for _, n := range dedupStrings(nets) {
		fmt.Fprintf(&b, " network %s area 0\n", n)
	}
	b.WriteString("exit\n!\n")
	return b.String()
}

func renderBGP(top *model.Topology, as *model.AS, d *model.Device) string {
	var b strings.Builder
	lo, hasLo := d.IfaceByName("lo")
	fmt.Fprintf(&b, "router bgp %d\n", as.ASN)
	if hasLo && lo.Addr4 != "" {
		fmt.Fprintf(&b, " bgp router-id %s\n", addrOf(lo.Addr4))
	}
	b.WriteString(" no bgp ebgp-requires-policy\n")
	b.WriteString(" no bgp network import-check\n")

	// iBGP full mesh on loopbacks.
	var peers []string
	for _, r := range as.Routers {
		if r == d {
			continue
		}
		rlo, ok := r.IfaceByName("lo")
		if !ok || rlo.Addr4 == "" {
			continue
		}
		peers = append(peers, addrOf(rlo.Addr4))
	}
	sort.Strings(peers)
	for _, p := range peers {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", p, as.ASN)
		fmt.Fprintf(&b, " neighbor %s update-source lo\n", p)
	}

	// eBGP sessions.
	type ext struct {
		addr string
		asn  int
		rel  model.Relationship
	}
	var exts []ext
	for _, i := range d.Ifaces {
		if i.Role != model.RoleInterAS && i.Role != model.RoleIXPLink {
			continue
		}
		if i.Peer == nil || i.Peer.Addr4 == "" {
			continue
		}
		rel := model.RelPeer
		if i.Link != nil {
			rel = i.Link.Rel
			if i.Link.B == i {
				rel = rel.Inverse()
			}
		}
		exts = append(exts, ext{addr: addrOf(i.Peer.Addr4), asn: i.Peer.Device.ASN, rel: rel})
	}
	sort.Slice(exts, func(x, y int) bool { return exts[x].addr < exts[y].addr })
	for _, x := range exts {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", x.addr, x.asn)
	}

	b.WriteString(" address-family ipv4 unicast\n")
	fmt.Fprintf(&b, "  network %s\n", as.Block)
	for _, p := range peers {
		fmt.Fprintf(&b, "  neighbor %s activate\n", p)
		fmt.Fprintf(&b, "  neighbor %s next-hop-self\n", p)
	}
	for _, x := range exts {
		fmt.Fprintf(&b, "  neighbor %s activate\n", x.addr)
		fmt.Fprintf(&b, "  neighbor %s route-map LP-%s in\n", x.addr, strings.ToUpper(string(x.rel)))
		fmt.Fprintf(&b, "  neighbor %s route-map EXPORT-%s out\n", x.addr, strings.ToUpper(string(x.rel)))
	}
	b.WriteString(" exit-address-family\nexit\n!\n")

	if len(exts) > 0 {
		b.WriteString(gaoRexfordPolicy())
	}
	return b.String()
}

// gaoRexfordPolicy renders the business-relationship policy the courses teach:
// prefer customer over peer over provider, and export a customer's routes to
// everyone but a peer's or provider's routes only to customers.
func gaoRexfordPolicy() string {
	return `bgp community-list standard CUSTOMER permit 1:10
bgp community-list standard PEER permit 1:20
bgp community-list standard PROVIDER permit 1:30
!
route-map LP-CUSTOMER permit 10
 set local-preference 300
 set community 1:10
exit
route-map LP-PEER permit 10
 set local-preference 200
 set community 1:20
exit
route-map LP-PROVIDER permit 10
 set local-preference 100
 set community 1:30
exit
!
route-map EXPORT-CUSTOMER permit 10
exit
route-map EXPORT-PEER deny 10
 match community PEER
exit
route-map EXPORT-PEER deny 20
 match community PROVIDER
exit
route-map EXPORT-PEER permit 30
exit
route-map EXPORT-PROVIDER deny 10
 match community PEER
exit
route-map EXPORT-PROVIDER deny 20
 match community PROVIDER
exit
route-map EXPORT-PROVIDER permit 30
exit
!
`
}

func routerID(d *model.Device) string {
	if lo, ok := d.IfaceByName("lo"); ok && lo.Addr4 != "" {
		return addrOf(lo.Addr4)
	}
	return fmt.Sprintf("0.0.0.%d", d.RouterID)
}

func addrOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

func networkOf(cidr string) (string, error) {
	i := strings.IndexByte(cidr, '/')
	if i < 0 {
		return "", fmt.Errorf("%q has no prefix length", cidr)
	}
	host := cidr[:i]
	bits := cidr[i:]
	octets := strings.Split(host, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("%q is not IPv4", cidr)
	}
	// Only /24 and shorter appear in these plans; masking the last octet is
	// correct for /24 and the callers never produce anything longer.
	switch bits {
	case "/24":
		return strings.Join(octets[:3], ".") + ".0" + bits, nil
	case "/16":
		return strings.Join(octets[:2], ".") + ".0.0" + bits, nil
	case "/8":
		return octets[0] + ".0.0.0" + bits, nil
	default:
		return host + bits, nil
	}
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
