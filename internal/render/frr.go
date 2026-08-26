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
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/svc"
)

// EnabledDaemons is the set of routing processes FRR is told to start, read
// out of the daemons file rather than listed a second time here. A deployment
// checks for exactly these, so enabling a daemon and forgetting to check for it
// is not something that can happen.
func EnabledDaemons() []string { return daemonsIn(FRRDaemons) }

// DaemonsFor returns the daemons file for a device: the base set, plus pimd
// where the AS declares the multicast exercise.
//
// Per AS rather than everywhere. pimd is another process in every one of a
// thousand containers, and a lab that is not about multicast should not pay for
// it; but a lab that is about multicast cannot be configured at all without it,
// and the exercise used to be undeployable for exactly that reason -- the
// daemon was off, so `ip pim` was rejected on every router and there was
// nothing to grade.
func DaemonsFor(as *model.AS) string {
	out := FRRDaemons
	if as == nil {
		return out
	}
	if as.Multicast.Enabled {
		out = strings.ReplaceAll(out, "pimd=no", "pimd=yes")
	}
	if as.MPLS.Enabled {
		out = strings.ReplaceAll(out, "ldpd=no", "ldpd=yes")
	}
	return out
}

// EnabledDaemonsFor is EnabledDaemons for one AS.
func EnabledDaemonsFor(as *model.AS) []string { return daemonsIn(DaemonsFor(as)) }

func daemonsIn(file string) []string {
	var out []string
	for _, line := range strings.Split(file, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		// The settings that are not daemons -- zebra_enable, vtysh_enable --
		// are the ones with an underscore in the key.
		if !ok || value != "yes" || strings.Contains(name, "_") {
			continue
		}
		// Single-quoted into a shell command by the caller, so a name that
		// could close the quote must not get that far. Nothing in the file
		// looks like this today; the check is here so that editing the file
		// cannot quietly turn into a shell injection.
		if strings.ContainsAny(name, "'\\ \t$`\"") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// FRRDaemons is the /etc/frr/daemons file. Only the daemons the courses need
// are enabled: every extra daemon is a process in every one of a thousand
// containers.
const FRRDaemons = `zebra=yes
bgpd=yes
ospfd=yes
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd=no
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
		b.WriteString("service integrated-vtysh-config\n!\n")
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
		if i.VRF != "" {
			fmt.Fprintf(b, "interface %s vrf %s\n", i.Name, i.VRF)
		} else {
			fmt.Fprintf(b, "interface %s\n", i.Name)
		}
		if i.Addr4 != "" {
			fmt.Fprintf(b, " ip address %s\n", i.Addr4)
		}
		if i.Addr6 != "" {
			fmt.Fprintf(b, " ipv6 address %s\n", i.Addr6)
		}
		if c := ospfCost(i); c > 0 {
			fmt.Fprintf(b, " ip ospf cost %d\n", c)
		}
		if usesPointToPointOSPF(i) {
			// A BMv2 segment is physically two veth cables and logically one
			// point-to-point programmable path. Leaving OSPF in broadcast mode
			// elects two DROthers and leaves the adjacency 2-Way, so loopback
			// reachability and iBGP never converge despite a healthy data
			// plane.
			b.WriteString(" ip ospf network point-to-point\n")
		}
		b.WriteString("exit\n!\n")
	}

	// OSPF: every intra-AS subnet plus the service subnets, which the
	// assignment explicitly requires students to advertise.
	ospf := renderOSPF(d)
	// A router declared part of a BGP-free core runs no BGP at all. That is
	// the property the advanced exercise is about, so rendering a session on
	// one would make the reference solution contradict the question.
	bgp := ""
	if !as.InCore(d.Name) {
		bgp = renderBGP(top, as, d)
	}
	mpls := renderMPLS(as, d)
	vrfBGP := renderVRFBGP(as, d)
	mcast := renderMulticast(as, d)
	// Per domain, not per AS.
	//
	// This was one decision for the whole router: either the AS was a staff one
	// and Twinet configured everything, or it was a student one and Twinet
	// configured nothing. A course that wants the interior given and the
	// exterior assigned -- which is what the advanced labs are -- could declare
	// exactly that in the manifest, and got a lab where the students were
	// handed neither.
	into := func(domain, text string) {
		if text == "" {
			return
		}
		if as.Provides(domain) {
			plat.WriteString(text)
			return
		}
		exp.WriteString(text)
	}
	into(model.DomainOSPF, ospf)
	into(model.DomainBGP, bgp)
	into(model.DomainMPLS, mpls)
	into(model.DomainBGP, vrfBGP)
	into(model.DomainMulticast, mcast)

	return RouterConfig{Platform: plat.String(), Expected: exp.String()}, nil
}

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

func usesPointToPointOSPF(i *model.Iface) bool {
	if i == nil || i.Link == nil || i.Peer == nil || i.Peer.Device == nil {
		return false
	}
	if i.Peer.Device.Kind == model.KindP4 {
		return i.Link.Segment != ""
	}
	return i.Role == model.RoleIntraAS && i.Link.Kind == model.LinkVeth &&
		i.Link.Segment == "" && i.Peer.Device.Kind == model.KindRouter
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
	// A core router runs no BGP, so nothing peers with it. Leaving it in the
	// mesh would leave every edge with a session that can never come up, and
	// "the core is BGP-free" would be contradicted by every other router's
	// configuration.
	if len(as.MPLS.Core) > 0 {
		var kept []string
		for _, r := range as.Routers {
			if as.InCore(r.Name) {
				continue
			}
			if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" && addrOf(lo.Addr4) != "" {
				for _, p := range peers {
					if p == addrOf(lo.Addr4) {
						kept = append(kept, p)
					}
				}
			}
		}
		peers = kept
	}
	for _, p := range peers {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", p, as.ASN)
		fmt.Fprintf(&b, " neighbor %s update-source lo\n", p)
		if len(as.VRFs) > 0 {
			// The next hop for a VPN route must be this router's own loopback,
			// or the receiving edge resolves it to an interior address the
			// core does not advertise into BGP -- and the route is accepted,
			// installed, and unusable.
			fmt.Fprintf(&b, " neighbor %s next-hop-self\n", p)
		}
	}

	// eBGP sessions.
	var exts []ext
	for _, i := range d.Ifaces {
		if i.Role != model.RoleInterAS && i.Role != model.RoleIXPLink {
			continue
		}
		// A neighbour reached through a virtual routing table belongs to that
		// table's BGP instance and to no other. Peering with it here as well
		// would put the customer's routes into the provider's global table,
		// where they collide with every other customer using the same private
		// address space -- which is the exact failure the tables exist to
		// prevent, arrived at by configuring the session twice.
		if i.VRF != "" {
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
		// What the neighbour is to us, which is what the import and export
		// policies are named after.
		rel := model.RelPeer
		if i.Link != nil {
			rel = i.Link.PeerRelationship(i)
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
		if x.ixp {
			// A route server is transparent: it relays a member's
			// announcement without putting its own AS in front of the path.
			// FRR checks by default that the first AS of an eBGP update is
			// the peer's, and silently treats every route from the exchange
			// as a withdrawal -- "incorrect first AS (must be 140)" in the
			// log, no notification, no session reset, and nothing in the
			// table. Every member of every exchange in this lab accepted
			// exactly nothing through it, for as long as the lab has
			// existed, while the question about exchange policy scored full
			// marks because refusing everything refuses the in-region routes
			// too.
			fmt.Fprintf(&b, " no neighbor %s enforce-first-as\n", x.addr)
		}
	}

	hasRPKI := svc.RPKIAddrFor(top, as.ASN) != ""
	slowRels := map[model.Relationship]bool{}

	b.WriteString(" address-family ipv4 unicast\n")
	if as.Role != model.RoleIXP {
		fmt.Fprintf(&b, "  network %s\n", as.Block)
	}
	// The deliberate hijack the RPKI exercise is about.
	//
	// The manifest declares a ROA held by one AS for a prefix inside another's
	// space. That is only half of an invalid announcement: without anybody
	// announcing the prefix, no route in the lab was ever RPKI-invalid, so the
	// question "do you reject invalid announcements?" could not be answered by
	// looking at any router, and every submission passed it for having written
	// a route-map. A staff AS other than the ROA holder announces it, so the
	// invalid route exists for every student and no student can withdraw it.
	if hijacker, prefix := svc.HijackOrigin(top); hijacker == as.ASN && prefix != "" {
		fmt.Fprintf(&b, "  network %s\n", prefix)
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
		// One inbound route-map per neighbour. FRR keeps only the last such
		// statement, so emitting origin validation as a second map silently
		// replaced the relationship policy -- or, depending on order, silently
		// discarded the validation. Both halves must live in the same map, and
		// they do: rpkiClauses is folded into every inbound map below.
		fmt.Fprintf(&b, "  neighbor %s route-map %s in\n", x.addr, in)
		fmt.Fprintf(&b, "  neighbor %s route-map %s out\n", x.addr, out)
	}
	b.WriteString(" exit-address-family\n")
	b.WriteString(vpnAddressFamily(as, d, edgePeers(as, d)))
	b.WriteString("exit\n!\n")

	if len(exts) > 0 {
		b.WriteString(gaoRexfordPolicy(hasRPKI))
		b.WriteString(slowLinkPolicy(as, slowRels, hasRPKI))
		b.WriteString(ixpPolicy(top, as, exts, hasRPKI))
		b.WriteString(rpkiCache(top, as))
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
func slowLinkPolicy(as *model.AS, rels map[model.Relationship]bool, rpki bool) string {
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
		b.WriteString(inboundMap("LP-SLOW-"+up, rel, base[rel]-slowLinkPenalty, rpki))
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
func ixpPolicy(top *model.Topology, as *model.AS, exts []ext, rpki bool) string {
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

		name := fmt.Sprintf("IMPORT-IXP-%d", x.asn)
		if rpki {
			fmt.Fprintf(&b, "route-map %s deny 3\n match rpki invalid\nexit\n", name)
		}
		if len(sameRegion) > 0 {
			// Two terms, because one of them cannot match what an exchange
			// mostly carries. `_X_` requires a separator on each side, so it
			// matches a path that crosses AS X on the way to somewhere else
			// and not a path that *is* AS X -- which is exactly what a member
			// announcing its own prefix at an exchange sends. Measured: of
			// nineteen paths, `_(4|5|6|7|8)_` matched two and `^(4|5|6|7|8)$`
			// matched five, and the five were the ones the filter exists to
			// refuse.
			fmt.Fprintf(&b, "bgp as-path access-list IXP-%d-REGION permit _(%s)_\n",
				x.asn, joinASNs(sameRegion, "|"))
			fmt.Fprintf(&b, "bgp as-path access-list IXP-%d-REGION permit ^(%s)$\n",
				x.asn, joinASNs(sameRegion, "|"))
			fmt.Fprintf(&b, "!\nroute-map %s deny 10\n match as-path IXP-%d-REGION\nexit\n", name, x.asn)
		}
		if rpki {
			fmt.Fprintf(&b, "route-map %s permit 15\n match rpki notfound\n set local-preference 150\n set community 1:20\nexit\n", name)
		}
		fmt.Fprintf(&b, "route-map %s permit 20\n set local-preference 200\n set community 1:20\nexit\n!\n", name)

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
func rpkiCache(top *model.Topology, as *model.AS) string {
	// An AS that was never attached to the validator keeps the legacy
	// contract: do not infer RPKI merely because another AS has a replica.
	// Once it has its declared local address, the remaining configured
	// addresses are deterministic failover caches.
	if svc.RPKIAddrFor(top, as.ASN) == "" {
		return ""
	}
	addrs := svc.ServiceAddressesFor(top, "builtin.rpki", as.ASN)
	var b strings.Builder
	b.WriteString("rpki\n")
	// FRR 10 spells this without a transport keyword. The version that
	// takes "tcp" is newer, and using it here fails as an unknown command --
	// which a student would read as their own syntax error.
	for index, addr := range addrs {
		fmt.Fprintf(&b, " rpki cache %s 3323 preference %d\n", addr, index+1)
	}
	// A short retry interval matters more than it looks. The validator lives
	// behind the routing the deployment is still installing, so a router that
	// configures its cache first finds it unreachable -- and without a retry
	// it stays disconnected, silently, with every route becoming not-found and
	// origin validation quietly doing nothing. Only the router the validator
	// happens to be cabled to would work, which is precisely the arrangement
	// that looks correct in a spot check.
	b.WriteString(" rpki polling_period 30\n rpki retry_interval 15\n rpki expire_interval 600\nexit\n!\n")
	return b.String()
}

// hasRPKICache reports whether a router is configured with a validator.
//
// The condition is shared with the renderer rather than restated, because the
// two drifting apart is how a router ends up waiting for a session it was
// never given -- or, worse, being given one nothing ever checks.
func hasRPKICache(top *model.Topology, d *model.Device) bool {
	if !validatesOrigins(top, d) {
		return false
	}
	// The cache is FRR configuration and the readiness script is FRR's CLI.
	// A provider that does not declare origin validation has neither, and
	// running the script there put a vtysh loop inside a container that has no
	// vtysh -- ignored, so it merely wasted an exec per deployment and left an
	// FRR command in a BIRD device's history.
	provider, err := nos.Resolve(d)
	return err == nil && provider.Capabilities().Supports(nos.FeatureRPKI)
}

// validatesOrigins reports whether a router is in a position to care about
// origin validation at all: the lab runs a validator its AS can reach, and the
// router holds a session with somebody outside the AS.
//
// It is deliberately separate from hasRPKICache. Publishing a ROA is an
// exchange with the trust anchor over HTTP and has nothing to do with which
// routing daemon the router runs; refusing to publish because the daemon has
// no RTR client would lose the mark for publishing on a system that published
// correctly.
func validatesOrigins(top *model.Topology, d *model.Device) bool {
	if _, ok := top.ASes[d.ASN]; !ok || svc.RPKIAddrFor(top, d.ASN) == "" {
		return false
	}
	for _, i := range d.Ifaces {
		if i.Role == model.RoleInterAS || i.Role == model.RoleIXPLink {
			return true
		}
	}
	return false
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
func gaoRexfordPolicy(rpki bool) string {
	var b strings.Builder
	b.WriteString(`bgp community-list standard CUSTOMER permit 1:10
bgp community-list standard PEER permit 1:20
bgp community-list standard PROVIDER permit 1:30
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
`)
	// The inbound maps carry both the relationship policy and, where the lab
	// has a validator, origin validation. They cannot be separate maps: FRR
	// allows one inbound route-map per neighbour and keeps the last, so a
	// second one silently replaces the first -- which is exactly what happened
	// here, leaving every router configured to validate and none of them doing
	// it, with the running configuration looking correct at a glance.
	for _, rel := range []model.Relationship{model.RelCustomer, model.RelPeer, model.RelProvider} {
		b.WriteString(inboundMap("LP-"+strings.ToUpper(string(rel)), rel, localPrefFor(rel), rpki))
	}
	return b.String()
}

// localPrefFor is the preference a relationship earns: customer over peer over
// provider, which is what makes the money flow the right way.
func localPrefFor(rel model.Relationship) int {
	switch rel {
	case model.RelCustomer:
		return 300
	case model.RelPeer:
		return 200
	default:
		return 100
	}
}

// inboundMap renders one inbound route-map, optionally validating origins.
//
// Invalid routes are refused and routes with no ROA are kept at a lower
// preference. The second half matters as much as the first: a router that
// accepted only what is explicitly valid would black-hole most of the real
// internet, and a check testing only for rejection would award full marks for
// exactly that mistake.
// notFoundPenalty is how much a route with no ROA is deprioritised, and
// slowLinkPenalty how much a route across a deliberately slow link is. They
// must differ, or the two policies cancel: see inboundMap.
const (
	notFoundPenalty = 25
	slowLinkPenalty = 50
)

func inboundMap(name string, rel model.Relationship, pref int, rpki bool) string {
	var b strings.Builder
	if rpki {
		fmt.Fprintf(&b, "route-map %s deny 5\n match rpki invalid\nexit\n", name)
		// The not-found penalty is smaller than the slow-link one.
		//
		// Both were 50, and the two collided: the system this lab deliberately
		// leaves without a ROA is somebody's *fast* customer, so its routes
		// arrived at 300-50 while the slow customer's arrived at 300-50 as
		// well, and the reference solution stopped preferring the fast
		// neighbour it had just been configured to prefer. Keeping the
		// penalties different keeps the two answers independent, which is what
		// the two questions are.
		fmt.Fprintf(&b, "route-map %s permit 10\n match rpki notfound\n set local-preference %d\n set community 1:%d\nexit\n",
			name, pref-notFoundPenalty, communityFor(rel))
	}
	fmt.Fprintf(&b, "route-map %s permit 20\n set local-preference %d\n set community 1:%d\nexit\n!\n",
		name, pref, communityFor(rel))
	return b.String()
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

// renderMulticast is the reference answer to the advanced course's PIM
// exercise: multicast on every interface, IGMP where the hosts are, and one
// rendezvous point for the declared group range.
//
// Written from the AS's declaration rather than from a fixture, so the figure
// in the exercise, the reference solution and the grader all come from one
// statement. The interface stanzas are emitted separately from the ones the
// addressing produced because FRR merges repeated `interface` blocks, and
// keeping them apart is what lets the addressing be handed out while the
// multicast configuration is left for the student.
func renderMulticast(as *model.AS, d *model.Device) string {
	if as == nil || !as.Multicast.Enabled || !d.IsRouter() {
		return ""
	}
	var b strings.Builder
	for _, i := range d.Ifaces {
		if i.Name == "" {
			continue
		}
		fmt.Fprintf(&b, "interface %s\n ip pim\n", i.Name)
		// IGMP belongs on the interfaces hosts are behind and nowhere else:
		// the routers do not join groups, they route between the hosts that
		// do, and the exercise says so explicitly.
		if facesHosts(i) {
			b.WriteString(" ip igmp\n")
		}
		b.WriteString("exit\n!\n")
	}
	rp := as.Multicast.RP
	groups := as.Multicast.Groups
	if rp != "" && groups != "" {
		// The rendezvous point is addressed by its loopback, so it survives an
		// interface going down while another path to it is still up. That is
		// the reason the exercise gives, and it is the reason here.
		if addr := loopbackAddrOf(as, rp); addr != "" {
			fmt.Fprintf(&b, "ip pim rp %s %s\n!\n", addr, groups)
		}
	}
	return b.String()
}

// facesHosts reports whether an interface has hosts behind it: a host link, or
// a layer-2 access or trunk port into a segment the hosts are on.
func facesHosts(i *model.Iface) bool {
	switch i.Role {
	case model.RoleHostLink, model.RoleL2Access, model.RoleL2Trunk:
		return true
	}
	return false
}

// loopbackAddrOf returns the bare loopback address of a named router.
func loopbackAddrOf(as *model.AS, router string) string {
	for _, r := range as.Routers {
		if r.Name != router {
			continue
		}
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			if i := strings.IndexByte(lo.Addr4, '/'); i > 0 {
				return lo.Addr4[:i]
			}
			return lo.Addr4
		}
	}
	return ""
}
