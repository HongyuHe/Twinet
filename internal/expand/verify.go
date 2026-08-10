package expand

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
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
		reg.Exempt(p.Masked())
		reg.Claim(p, fmt.Sprintf("AS %d aggregate", asn), ipam.FieldASBlock)
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
			reg.Claim(p, "segment "+l.Segment, subnetField(l))
			continue
		}
		reg.Claim(p, "link "+l.ID, subnetField(l))
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
			if i == nil || i.Addr4 == "" {
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
// Names are disambiguated in link-identity order so the result is stable
// regardless of the order the manifest happens to list peerings in.
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
			sort.Slice(group, func(a, b int) bool {
				return linkKeyOf(group[a]) < linkKeyOf(group[b])
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
}

func linkKeyOf(i *model.Iface) string {
	if i.Link != nil {
		return i.Link.ID
	}
	return i.Name
}
