package expand

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"

	"github.com/HongyuHe/twinet/internal/alloc"
)

// ifaceNameMax is IFNAMSIZ-1: the kernel's limit on an interface name.
const ifaceNameMax = 15

var ifaceNameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// verify checks the invariants that must hold of any expanded topology.
//
// These are checked here, after expansion, rather than in manifest validation,
// because most of them are properties of *generated* names and addresses that
// do not exist until templates are instantiated. Catching them here means an
// author sees "these two links would collide" instead of watching a deployment
// fail on the 71st link with a netlink error about a file already existing,
// which is exactly what happened before this check existed.
func (e *expander) verify() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// Interface names: unique per device, within the kernel's length limit,
	// and made of characters the kernel accepts.
	for _, d := range e.top.SortedDevices() {
		seen := map[string]bool{}
		for _, i := range d.Ifaces {
			if seen[i.Name] {
				add("device %s has two interfaces named %q", d.ID, i.Name)
			}
			seen[i.Name] = true
			if len(i.Name) > ifaceNameMax {
				add("device %s: interface name %q is %d bytes, over the kernel's %d byte limit",
					d.ID, i.Name, len(i.Name), ifaceNameMax)
			}
			if !ifaceNameOK.MatchString(i.Name) {
				add("device %s: interface name %q contains characters the kernel rejects", d.ID, i.Name)
			}
		}
	}

	// Device and container identities must be unique.
	containers := map[string]string{}
	for _, d := range e.top.SortedDevices() {
		if prev, dup := containers[d.Container]; dup {
			add("devices %s and %s would both be container %q", prev, d.ID, d.Container)
		}
		containers[d.Container] = d.ID
	}

	// Links must be complete and must not loop back on themselves.
	for _, l := range e.top.Links {
		if l.A == nil || l.B == nil {
			add("link %s is missing an endpoint", l.ID)
			continue
		}
		if l.A.Device == l.B.Device {
			add("link %s connects device %s to itself", l.ID, l.A.Device.ID)
		}
	}

	// Addressing: every generated prefix must be valid, and no two links may
	// claim overlapping space. The legacy platform had no such check, so an
	// overlap only ever showed up as a network that behaved strangely.
	reg := ipam.NewRegistry()
	for _, asn := range e.top.SortedASNs() {
		as := e.top.ASes[asn]
		if as.Block == "" {
			continue
		}
		p, err := netip.ParsePrefix(as.Block)
		if err != nil {
			add("AS %d: as_block %q is not a prefix: %v", asn, as.Block, err)
			continue
		}
		scope := fmt.Sprintf("as%d", asn)
		reg.Exempt(p.Masked(), scope)
		reg.Claim(p, fmt.Sprintf("AS %d aggregate", asn), ipam.FieldASBlock, scope)
	}
	// Links in a shared segment intentionally share one subnet, so they are
	// claimed once, by segment, rather than once per cable.
	segments := map[string]string{}
	for _, l := range e.top.Links {
		if l.Subnet == "" {
			continue
		}
		p, err := netip.ParsePrefix(l.Subnet)
		if err != nil {
			add("link %s: subnet %q is not a prefix: %v", l.ID, l.Subnet, err)
			continue
		}
		if l.Segment != "" {
			if prev, seen := segments[l.Segment]; seen {
				if prev != l.Subnet {
					add("segment %s has conflicting subnets %s and %s", l.Segment, prev, l.Subnet)
				}
				continue
			}
			segments[l.Segment] = l.Subnet
			reg.Claim(p, "segment "+l.Segment, subnetField(l), linkScope(l))
			continue
		}
		reg.Claim(p, "link "+l.ID, subnetField(l), linkScope(l))
	}
	for _, c := range reg.Conflicts() {
		add("%s", c.String())
	}

	// Within a shared segment every participant must have a distinct address.
	segAddrs := map[string]map[string]string{}
	for _, l := range e.top.Links {
		if l.Segment == "" {
			continue
		}
		for _, i := range []*model.Iface{l.A, l.B} {
			if i == nil || i.Addr4 == "" {
				continue
			}
			if segAddrs[l.Segment] == nil {
				segAddrs[l.Segment] = map[string]string{}
			}
			owner := i.Device.ID + ":" + i.Name
			if prev, dup := segAddrs[l.Segment][i.Addr4]; dup && prev != owner {
				add("segment %s: %s and %s both claim %s", l.Segment, prev, owner, i.Addr4)
			}
			segAddrs[l.Segment][i.Addr4] = owner
		}
	}

	// Every interface address must be inside its link's subnet, or the two
	// ends of a cable are on different networks and nothing will ever work.
	for _, l := range e.top.Links {
		if l.Subnet == "" {
			continue
		}
		sub, err := netip.ParsePrefix(l.Subnet)
		if err != nil {
			continue
		}
		for _, i := range []*model.Iface{l.A, l.B} {
			if i == nil {
				continue
			}
			// A link with a subnet whose endpoint has no address is not a
			// link anybody can use, and it is what an allocation failure
			// looks like from here: the error was turned into an empty
			// string, and every check downstream skips empty strings.
			//
			// The clearest case is a /32 written as a point-to-point subnet.
			// There is no room in it for two hosts, both allocations fail,
			// both addresses come out empty, the lab validates, and the two
			// routers are deployed with nothing configured on the interface
			// that joins them.
			// A switch port is L2 and carries no address by design, which is
			// what an exchange fabric is made of.
			if i.Addr4 == "" {
				if i.Device.Kind != model.KindSwitch {
					add("device %s interface %s: no address could be allocated from the "+
						"link subnet %s; there is not enough room in it for the interfaces "+
						"it has to number",
						i.Device.ID, i.Name, l.Subnet)
				}
				continue
			}
			a, err := netip.ParsePrefix(i.Addr4)
			if err != nil {
				add("device %s interface %s: %q is not addr/len", i.Device.ID, i.Name, i.Addr4)
				continue
			}
			if !sub.Contains(a.Addr()) {
				add("device %s interface %s: %s is outside the link subnet %s",
					i.Device.ID, i.Name, i.Addr4, l.Subnet)
			}
		}
	}

	// Router IDs must be unique within an AS: the addressing plan indexes on
	// them, so a duplicate silently aliases two routers' loopbacks.
	for _, asn := range e.top.SortedASNs() {
		byID := map[int][]string{}
		for _, r := range e.top.ASes[asn].Routers {
			byID[r.RouterID] = append(byID[r.RouterID], r.Name)
		}
		for id, names := range byID {
			if len(names) > 1 {
				sort.Strings(names)
				add("AS %d: router id %d is shared by %s", asn, id, strings.Join(names, " and "))
			}
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("the expanded topology is not valid:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

func subnetField(l *model.Link) string {
	if l.AddressingField != "" {
		return l.AddressingField
	}
	switch {
	case l.InterAS:
		return ipam.FieldInterAS
	case l.Kind == model.LinkService:
		return "svc"
	default:
		return ipam.FieldRouterRouter
	}
}

// uniquifyIfaceNames resolves the one collision the naming scheme cannot avoid:
// two links between the same pair of devices, which happens when a reduced
// staff-run AS carries every external port on a single router.
//
// Names are disambiguated in link-content order so the result is stable
// regardless of the order the manifest happens to list the parallel links in.
func (e *expander) uniquifyIfaceNames() {
	for _, d := range e.top.SortedDevices() {
		byName := map[string][]*model.Iface{}
		for _, i := range d.Ifaces {
			byName[i.Name] = append(byName[i.Name], i)
		}
		for name, group := range byName {
			if len(group) < 2 {
				continue
			}
			// SliceStable, not Slice: two genuinely interchangeable parallel
			// links (identical endpoints, names and addresses) produce equal
			// keys, and a stable sort leaves them in the order they were built
			// so the suffixing is deterministic. Their addresses are identical
			// anyway, so which one keeps the bare name is unobservable.
			sort.SliceStable(group, func(a, b int) bool {
				return linkIdentityKey(group[a]) < linkIdentityKey(group[b])
			})
			for n, i := range group[1:] {
				suffix := fmt.Sprintf("_%d", n+2)
				base := name
				if len(base)+len(suffix) > ifaceNameMax {
					base = base[:ifaceNameMax-len(suffix)]
				}
				i.Name = base + suffix
			}
		}
	}
	e.reidentifyLinks()
}

// reidentifyLinks recomputes every link's identity from the interface names it
// ended up with.
//
// A link's identity is built from the two names it joins, and it was built
// when the link was created -- before the names were made unique. Two parallel
// links between the same pair of devices therefore started life with the same
// name on each side, took the same identity, and kept it after the names were
// separated. Everything downstream is derived from that identity: the tunnel
// number a cross-node link is carried in, the ownership tag, and the address
// each end gets.
//
// Two links sharing a tunnel number is not a cosmetic clash. The two links
// become one broadcast domain, so a router sees its neighbour's traffic on the
// wrong interface, and the second link's addresses land on a segment that
// already has them. Nothing reports it; the lab simply behaves as though a
// cable had been plugged into the wrong socket.
//
// Recomputing here rather than deferring identity until after uniquification
// keeps the identity in one place: it is always "the two names this link
// joins", and this is the point at which those names stop changing.
func (e *expander) reidentifyLinks() {
	for _, l := range e.top.Links {
		if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		l.ID = model.MakeLinkID(l.A.Device.ID, l.A.Name, l.B.Device.ID, l.B.Name)
		l.A.MAC = alloc.MAC(e.lab.Metadata.Name, l.A.Device.ID, l.A.Name)
		l.B.MAC = alloc.MAC(e.lab.Metadata.Name, l.B.Device.ID, l.B.Name)
	}
}

// linkIdentityKey orders two interfaces that share a name on one device by the
// content of the links they terminate, not by an identity those links have not
// been given yet.
//
// uniquifyIfaceNames runs before reidentifyLinks, so two parallel links between
// the same pair of devices still carry the same link ID at this point -- the ID
// is derived from the interface names, and the names are what we are about to
// make unique. Ordering the collision by that ID therefore orders it by an
// already-tied key, and the tie fell to whichever link the manifest listed
// first. Swapping two parallel links in the source then swapped which interface
// kept the bare name and which was suffixed, and with it the address each one
// was left holding -- so a student's saved submission, which records those
// addresses, silently stopped matching the lab it was taken from.
//
// The key is built from the link's own distinguishing content: both endpoints'
// device, declared interface name, declared address and VRF, plus the declared
// subnets and segment. It is assembled canonically -- the two endpoints are
// sorted -- so it does not depend on which end the manifest called A. Two links
// that differ in any of this sort the same way under every manifest ordering;
// two that differ in none are genuinely interchangeable and their identical
// addresses make the outcome the same whichever is suffixed.
func linkIdentityKey(i *model.Iface) string {
	l := i.Link
	if l == nil {
		return "iface\x00" + i.Name
	}
	ends := []string{endpointIdentity(l.A), endpointIdentity(l.B)}
	sort.Strings(ends)
	return strings.Join(append(ends, l.Subnet, l.SubnetV6, l.Segment), "\x00")
}

// endpointIdentity is the distinguishing content of one end of a link: where it
// lands and what it was declared to carry.
func endpointIdentity(i *model.Iface) string {
	if i == nil {
		return ""
	}
	dev := ""
	if i.Device != nil {
		dev = i.Device.ID
	}
	return strings.Join([]string{dev, i.Name, i.Addr4, i.Addr6, i.VRF}, "\x1f")
}

// linkScope names the autonomous system a link's subnet belongs to, or "" when
// it belongs to no single one.
//
// The case that matters is a link between two different systems: its addresses
// are part of neither side's aggregate, so no aggregate should excuse an
// overlap with it. A link from a system to a lab-global service is a different
// thing despite also joining two ASNs -- the service has no address space of
// its own and is numbered out of the system it attaches to, by design.
func linkScope(l *model.Link) string {
	if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
		return ""
	}
	a, b := l.A.Device.ASN, l.B.Device.ASN
	switch {
	case a != 0 && b != 0 && a != b:
		return ""
	case a != 0:
		return fmt.Sprintf("as%d", a)
	case b != 0:
		return fmt.Sprintf("as%d", b)
	default:
		return ""
	}
}
