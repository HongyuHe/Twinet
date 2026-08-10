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
	"github.com/HongyuHe/twinet/internal/svc"
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
# The RPKI module is loaded here rather than left to the exercise: it is a
# build-time capability of the daemon, not something a student can configure.
# Without it the rpki commands do not exist, and a student following the
# assignment exactly would be told their syntax is wrong.
bgpd_options="   -A 127.0.0.1 -M rpki"
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
	// An exchange's route server peers with every member of its fabric, not
	// with whatever is at the end of its cable, so it needs its own renderer.
	if as.Role == model.RoleIXP {
		return RouteServer(top, d)
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

// ospfCost returns the OSPF cost the reference solution puts on an interface.
//
// The load-balancing question asks students to choose weights so that traffic
// between two named routers splits over exactly three paths and no others. The
// reference answer therefore needs real costs, and they are derived from the
// topology rather than hard-coded, so changing the map does not silently
// invalidate the reference.
func ospfCost(i *model.Iface) int {
	if i.Link == nil {
		return 0
	}
	return ecmpCost(i)
}

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
	var exts []ext
	for _, i := range d.Ifaces {
		if i.Role != model.RoleInterAS && i.Role != model.RoleIXPLink {
			continue
		}
		// An exchange is modelled as a real fabric switch, so the interface's
		// peer is a switch port with no address of its own. The session is with
		// the route server on the same segment, and looking only at the direct
		// peer meant the reference solution never peered with the exchange at
		// all -- it scored zero on its own IXP question and nothing said why.
		peerAddr, peerASN := "", 0
		if i.Role == model.RoleIXPLink {
			peerAddr, peerASN = routeServerOn(top, i)
		} else if i.Peer != nil {
			peerAddr, peerASN = addrOf(i.Peer.Addr4), i.Peer.Device.ASN
		}
		if peerAddr == "" {
			continue
		}
		rel := model.RelPeer
		if i.Link != nil {
			rel = i.Link.Rel
			if i.Link.B == i {
				rel = rel.Inverse()
			}
		}
		exts = append(exts, ext{
			addr: peerAddr, asn: peerASN, rel: rel,
			ixp:  i.Role == model.RoleIXPLink,
			slow: parseDelayMS(i.Link) >= 25,
		})
	}
	sort.Slice(exts, func(x, y int) bool { return exts[x].addr < exts[y].addr })
	for _, x := range exts {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", x.addr, x.asn)
	}

	hasRPKI := svc.RPKIAddrFor(top, as.ASN) != ""
	slowRels := map[model.Relationship]bool{}

	b.WriteString(" address-family ipv4 unicast\n")
	if as.Role != model.RoleIXP {
		fmt.Fprintf(&b, "  network %s\n", as.Block)
	}
	for _, p := range peers {
		fmt.Fprintf(&b, "  neighbor %s activate\n", p)
		fmt.Fprintf(&b, "  neighbor %s next-hop-self\n", p)
	}
	for _, x := range exts {
		fmt.Fprintf(&b, "  neighbor %s activate\n", x.addr)
		out := "EXPORT-" + strings.ToUpper(string(x.rel))
		in := "LP-" + strings.ToUpper(string(x.rel))
		if x.slow && !x.ixp {
			// The slow neighbour stays reachable -- the question forbids
			// filtering it away, because it is the backup -- but is made
			// unattractive in both directions: less preferred for traffic we
			// send, and a longer path for traffic others send us.
			in = fmt.Sprintf("LP-SLOW-%s", strings.ToUpper(string(x.rel)))
			out = fmt.Sprintf("EXPORT-SLOW-%s", strings.ToUpper(string(x.rel)))
			slowRels[x.rel] = true
		}
		if x.ixp {
			// At an exchange the export policy also tags the announcement for
			// the members that should receive it, and the import policy
			// refuses announcements that have already been through the region.
			out = fmt.Sprintf("EXPORT-IXP-%d", x.asn)
			in = fmt.Sprintf("IMPORT-IXP-%d", x.asn)
		}
		if hasRPKI {
			// Origin validation runs before the relationship policy, so an
			// invalid announcement is gone before it can win on local
			// preference. Ordering these the other way round would let a
			// hijacked prefix be preferred and then rejected, which works by
			// accident and fails as soon as the policy changes.
			fmt.Fprintf(&b, "  neighbor %s route-map RPKI-IN in\n", x.addr)
		}
		fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", x.addr, in)
		fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", x.addr, out)
	}
	b.WriteString(" exit-address-family\nexit\n!\n")

	if len(exts) > 0 {
		b.WriteString(gaoRexfordPolicy())
		b.WriteString(slowLinkPolicy(as, slowRels))
		b.WriteString(ixpPolicy(top, as, exts))
		b.WriteString(rpkiPolicy(top, as))
	}
	return b.String()
}

// ext is one external BGP neighbour of a router.
type ext struct {
	addr string
	asn  int
	rel  model.Relationship
	ixp  bool
	// slow marks a deliberately high-delay neighbour, which the traffic
	// engineering exercise asks a student to make less attractive in both
	// directions without filtering it away entirely.
	slow bool
}

// parseDelayMS reads a link's one-way delay in milliseconds.
func parseDelayMS(l *model.Link) float64 {
	if l == nil || l.Props.Delay == "" {
		return 0
	}
	var v float64
	unit := strings.TrimLeft(l.Props.Delay, "0123456789.")
	if _, err := fmt.Sscanf(strings.TrimSuffix(l.Props.Delay, unit), "%f", &v); err != nil {
		return 0
	}
	switch unit {
	case "s":
		return v * 1000
	case "us":
		return v / 1000
	default:
		return v
	}
}

// slowLinkPolicy renders the traffic-engineering answer: prefer the fast
// neighbour of a class, and make ourselves less attractive over the slow one.
//
// Both halves are needed and neither may be filtering. Lowering local
// preference only steers what we send; prepending only steers what others send
// us; and denying the announcement outright would remove the backup path the
// question requires to remain.
func slowLinkPolicy(as *model.AS, rels map[model.Relationship]bool) string {
	if len(rels) == 0 {
		return ""
	}
	ordered := []model.Relationship{model.RelCustomer, model.RelPeer, model.RelProvider}
	base := map[model.Relationship]int{
		model.RelCustomer: 300, model.RelPeer: 200, model.RelProvider: 100,
	}
	var b strings.Builder
	for _, rel := range ordered {
		if !rels[rel] {
			continue
		}
		up := strings.ToUpper(string(rel))
		fmt.Fprintf(&b, "route-map LP-SLOW-%s permit 10\n set local-preference %d\n set community 1:%d\nexit\n",
			up, base[rel]-50, communityFor(rel))
		// The export mirrors the fast neighbour of the same class exactly, and
		// adds only the prepend. Anything else is filtering: withholding a
		// prefix from the slow neighbour that the fast one receives removes
		// the backup path the question requires to remain, and the difference
		// is invisible unless the two are compared side by side.
		if rel != model.RelCustomer {
			fmt.Fprintf(&b, "route-map EXPORT-SLOW-%s deny 10\n match community PEER\nexit\n", up)
			fmt.Fprintf(&b, "route-map EXPORT-SLOW-%s deny 20\n match community PROVIDER\nexit\n", up)
		}
		fmt.Fprintf(&b, "route-map EXPORT-SLOW-%s permit 30\n set as-path prepend %d %d %d\nexit\n!\n",
			up, as.ASN, as.ASN, as.ASN)
	}
	return b.String()
}

func communityFor(rel model.Relationship) int {
	switch rel {
	case model.RelCustomer:
		return 10
	case model.RelPeer:
		return 20
	default:
		return 30
	}
}

// ixpPolicy renders the community-gated relay policy an exchange uses.
//
// The exchange relays an announcement to member X only if it carries the
// community <ixp>:X, so the sender chooses who sees it. The import side refuses
// anything whose path has already been through another member of the same
// region, which is what stops the exchange being used as transit between two of
// its own members.
func ixpPolicy(top *model.Topology, as *model.AS, exts []ext) string {
	var b strings.Builder
	for _, x := range exts {
		if !x.ixp {
			continue
		}
		ixp := top.ASes[x.asn]
		if ixp == nil {
			continue
		}

		// The exchange relays an announcement to member X only if it carries
		// <ixp>:X, so an announcement is tagged for every other member: that
		// is what being at an exchange is for.
		//
		// An earlier version tagged only members outside our own region, on
		// the theory that in-region members reach us directly. Every member of
		// this exchange happens to share our region, so the set was empty, no
		// community was ever set, and the reference solution scored zero on
		// its own question -- while looking entirely reasonable in the source.
		var others, sameRegion []int
		for _, asn := range top.SortedASNs() {
			peer := top.ASes[asn]
			if peer == nil || asn == as.ASN || peer.Role == model.RoleIXP {
				continue
			}
			if !attachedTo(top, asn, x.asn) {
				continue
			}
			others = append(others, asn)
			if peer.Region == as.Region && peer.Role == model.RoleStudent {
				sameRegion = append(sameRegion, asn)
			}
		}

		if len(sameRegion) > 0 {
			fmt.Fprintf(&b, "bgp as-path access-list IXP-%d-REGION permit _(%s)_\n",
				x.asn, joinASNs(sameRegion, "|"))
			fmt.Fprintf(&b, "!\nroute-map IMPORT-IXP-%d deny 10\n match as-path IXP-%d-REGION\nexit\n",
				x.asn, x.asn)
			fmt.Fprintf(&b, "route-map IMPORT-IXP-%d permit 20\n set local-preference 200\n set community %d:%d\nexit\n!\n",
				x.asn, 1, 20)
		} else {
			fmt.Fprintf(&b, "route-map IMPORT-IXP-%d permit 10\n set local-preference 200\n set community %d:%d\nexit\n!\n",
				x.asn, 1, 20)
		}

		// Tag our own announcement for each member that should receive it.
		tags := make([]string, 0, len(others))
		for _, m := range others {
			tags = append(tags, fmt.Sprintf("%d:%d", x.asn, m))
		}
		// A peer's or a provider's routes are never relayed onward: doing so
		// would offer the exchange free transit through us.
		fmt.Fprintf(&b, "route-map EXPORT-IXP-%d deny 10\n match community PEER\nexit\n", x.asn)
		fmt.Fprintf(&b, "route-map EXPORT-IXP-%d deny 20\n match community PROVIDER\nexit\n", x.asn)
		fmt.Fprintf(&b, "route-map EXPORT-IXP-%d permit 30\n", x.asn)
		if len(tags) > 0 {
			fmt.Fprintf(&b, " set community %s\n", strings.Join(tags, " "))
		}
		b.WriteString("exit\n!\n")
	}
	return b.String()
}

// rpkiPolicy renders origin validation against the lab's own trust anchor.
//
// Invalid routes are refused and not-found routes are kept. The second half
// matters as much as the first: a router that accepts only what is explicitly
// valid would black-hole most of the real internet, and a check that tested
// only for rejection would award full marks for exactly that mistake.
func rpkiPolicy(top *model.Topology, as *model.AS) string {
	addr := svc.RPKIAddrFor(top, as.ASN)
	if addr == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("rpki\n")
	// FRR 10 spells this without a transport keyword. The version that
	// takes "tcp" is newer, and using it here fails as an unknown command --
	// which a student would read as their own syntax error.
	fmt.Fprintf(&b, " rpki cache %s 3323 preference 1\n", addr)
	b.WriteString(" rpki polling_period 30\nexit\n!\n")
	b.WriteString(`route-map RPKI-IN deny 5
 match rpki invalid
exit
route-map RPKI-IN permit 10
 match rpki notfound
 set local-preference 90
exit
route-map RPKI-IN permit 20
exit
!
`)
	return b.String()
}

// routeServerOn finds the exchange's route server on the segment an interface
// is attached to.
func routeServerOn(top *model.Topology, i *model.Iface) (string, int) {
	if i.Link == nil {
		return "", 0
	}
	seg := i.Link.Segment
	for _, l := range top.Links {
		if l.Segment == "" || l.Segment != seg {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			if side == nil || side.Device == nil || side.Addr4 == "" {
				continue
			}
			as := top.ASes[side.Device.ASN]
			if as == nil || as.Role != model.RoleIXP {
				continue
			}
			return addrOf(side.Addr4), side.Device.ASN
		}
	}
	return "", 0
}

// attachedTo reports whether an AS has a link into a given exchange.
func attachedTo(top *model.Topology, asn, ixp int) bool {
	as := top.ASes[asn]
	if as == nil {
		return false
	}
	for _, d := range as.Devices {
		for _, i := range d.Ifaces {
			if i.Role == model.RoleIXPLink && i.Peer != nil && i.Peer.Device.ASN == ixp {
				return true
			}
		}
	}
	return false
}

func joinASNs(asns []int, sep string) string {
	parts := make([]string, len(asns))
	for i, a := range asns {
		parts[i] = fmt.Sprint(a)
	}
	return strings.Join(parts, sep)
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
