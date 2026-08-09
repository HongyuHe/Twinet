package manifest

import (
	"fmt"
	"net/netip"
	"regexp"

	"gopkg.in/yaml.v3"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
)

// ifaceNameMax is IFNAMSIZ-1. Exceeding it makes link creation fail at deploy
// time with an opaque netlink error, so we catch it at author time.
const ifaceNameMax = 15

var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Validate checks a loaded manifest thoroughly and returns every problem it
// finds, rather than stopping at the first.
func (l *Loaded) Validate() *Diagnostics {
	d := &l.Diags
	lab := l.Lab
	file := l.Files["lab"]

	l.validateHeader(d, file)
	l.validateAddressing(d, file)
	l.validateTemplates(d)
	l.validateASes(d, file)
	l.validatePeerings(d, file)
	l.validateServices(d, file)
	l.validatePlacement(d, file)
	l.validateAccess(d, file)
	_ = lab
	return d
}

func (l *Loaded) validateHeader(d *Diagnostics, file string) {
	lab := l.Lab
	root := l.Nodes[file]
	if lab.APIVersion != model.APIVersion {
		d.AddHint(file, "apiVersion", nodeAt(root, "apiVersion"),
			fmt.Sprintf("unsupported apiVersion %q", lab.APIVersion),
			"this build understands "+model.APIVersion)
	}
	if lab.Kind != model.KindLab {
		d.Addf(file, "kind", nodeAt(root, "kind"), "kind must be %q, got %q", model.KindLab, lab.Kind)
	}
	if lab.Metadata.Name == "" {
		d.Add(file, "metadata.name", "lab name is required; it namespaces every container and VXLAN identifier", nodeAt(root, "metadata"))
	} else if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`).MatchString(lab.Metadata.Name) {
		d.AddHint(file, "metadata.name", nodeAt(root, "metadata.name"),
			fmt.Sprintf("lab name %q must be lowercase alphanumeric with dashes", lab.Metadata.Name),
			"the name becomes part of container names, which Docker restricts")
	}
}

func (l *Loaded) validateAddressing(d *Diagnostics, file string) {
	root := l.Nodes[file]
	a := l.Lab.Addressing
	required := map[string]string{
		"as_block":        a.ASBlock,
		"router_loopback": a.RouterLoopback,
		"router_router":   a.RouterRouter,
		"router_host":     a.RouterHost,
		"inter_as":        a.InterAS,
	}
	for _, name := range sortedMapKeys(required) {
		if strings.TrimSpace(required[name]) == "" {
			d.Addf(file, "addressing."+name, nodeAt(root, "addressing"),
				"addressing.%s is required", name)
		}
	}
	exprs := map[string]string{
		ipam.FieldASBlock: a.ASBlock, ipam.FieldASBlockV6: a.ASBlockV6,
		ipam.FieldRouterLoopback: a.RouterLoopback, ipam.FieldRouterLoopbackV6: a.RouterLoopbackV6,
		ipam.FieldRouterRouter: a.RouterRouter, ipam.FieldRouterHost: a.RouterHost,
		ipam.FieldL2Domain: a.L2Domain, ipam.FieldL2DomainV6: a.L2DomainV6, ipam.FieldL2VLAN: a.L2VLAN, ipam.FieldL2VLANV6: a.L2VLANV6,
		ipam.FieldInterAS: a.InterAS, ipam.FieldIXPPeering: a.IXPPeering,
	}
	for name, expr := range a.Services {
		exprs["svc_"+name] = expr
	}
	if _, err := ipam.Compile(exprs); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			d.Add(file, "addressing", line, nodeAt(root, "addressing"))
		}
	}
}

func (l *Loaded) validateTemplates(d *Diagnostics) {
	for _, name := range l.Lab.SortedTemplateNames() {
		tpl := l.Lab.Templates[name]
		file := l.Files["template:"+name]
		if file == "" {
			file = l.Files["lab"]
		}
		root := l.Nodes[file]

		if len(tpl.Routers) == 0 {
			d.Add(file, "routers", "template declares no routers", nodeAt(root, "routers"))
		}

		// Router IDs must be unique: the addressing plan indexes on them, so a
		// duplicate silently aliases two routers' loopbacks and host subnets.
		byID := map[int][]string{}
		for _, rn := range sortedMapKeys(tpl.Routers) {
			r := tpl.Routers[rn]
			byID[r.ID] = append(byID[r.ID], rn)
			if r.ID <= 0 {
				d.Addf(file, "routers."+rn+".id", nodeAt(root, "routers."+rn),
					"router %s: id must be a positive integer", rn)
			}
			if len(rn) > ifaceNameMax-len("port_") {
				d.AddHint(file, "routers."+rn, nodeAt(root, "routers."+rn),
					fmt.Sprintf("router name %q is too long", rn),
					fmt.Sprintf("interface names are derived as port_<name> and must fit %d bytes", ifaceNameMax))
			}
		}
		for _, id := range sortedIntSlice(byID) {
			if names := byID[id]; len(names) > 1 {
				sort.Strings(names)
				d.AddHint(file, "routers", nodeAt(root, "routers"),
					fmt.Sprintf("router id %d is used by %s", id, strings.Join(names, " and ")),
					"router ids index the addressing plan, so duplicates alias loopbacks and host subnets")
			}
		}

		for i, il := range tpl.InternalLinks {
			path := fmt.Sprintf("internal_links[%d]", i)
			if _, ok := tpl.Routers[il.A]; !ok {
				d.Addf(file, path+".a", nodeAt(root, path), "unknown router %q", il.A)
			}
			if _, ok := tpl.Routers[il.B]; !ok {
				d.Addf(file, path+".b", nodeAt(root, path), "unknown router %q", il.B)
			}
			if il.A == il.B {
				d.Addf(file, path, nodeAt(root, path), "router %q cannot link to itself", il.A)
			}
			validateLinkProps(d, file, path, nodeAt(root, path), il.LinkProps)
		}

		for _, pn := range sortedMapKeys(tpl.ExternalPorts) {
			ep := tpl.ExternalPorts[pn]
			if _, ok := tpl.Routers[ep.Router]; !ok {
				d.Addf(file, "external_ports."+pn+".router", nodeAt(root, "external_ports."+pn),
					"unknown router %q", ep.Router)
			}
		}

		l2IDs := map[int]string{}
		for _, dn := range sortedMapKeys(tpl.L2Domains) {
			dom := tpl.L2Domains[dn]
			path := "l2_domains." + dn
			if prev, dup := l2IDs[dom.ID]; dup {
				d.Addf(file, path+".id", nodeAt(root, path), "l2 domain id %d already used by %q", dom.ID, prev)
			}
			l2IDs[dom.ID] = dn
			if _, ok := tpl.Routers[dom.Gateway]; !ok {
				d.Addf(file, path+".gateway", nodeAt(root, path), "gateway %q is not a router", dom.Gateway)
			}
			if len(dom.Switches) == 0 {
				d.Add(file, path+".switches", "l2 domain declares no switches", nodeAt(root, path))
			}
			for _, sn := range sortedMapKeys(dom.Switches) {
				if mac := dom.Switches[sn].MAC; mac != "" && !validMAC(mac) {
					d.Addf(file, path+".switches."+sn+".mac", nodeAt(root, path),
						"switch %s: %q is not a valid MAC address", sn, mac)
				}
			}
			for i, sl := range dom.SwitchLinks {
				p := fmt.Sprintf("%s.switch_links[%d]", path, i)
				if _, ok := dom.Switches[sl.A]; !ok {
					d.Addf(file, p+".a", nodeAt(root, p), "unknown switch %q", sl.A)
				}
				if _, ok := dom.Switches[sl.B]; !ok {
					d.Addf(file, p+".b", nodeAt(root, p), "unknown switch %q", sl.B)
				}
			}
			for _, hn := range sortedMapKeys(dom.Hosts) {
				h := dom.Hosts[hn]
				p := path + ".hosts." + hn
				if _, ok := dom.Switches[h.Switch]; !ok {
					d.AddHint(file, p+".switch", nodeAt(root, p),
						fmt.Sprintf("host %s references unknown switch %q", hn, h.Switch),
						"declared switches: "+strings.Join(sortedMapKeys(dom.Switches), ", "))
				}
				if len(dom.VLANs) > 0 {
					if _, ok := dom.VLANs[h.VLAN]; !ok {
						d.AddHint(file, p+".vlan", nodeAt(root, p),
							fmt.Sprintf("host %s uses VLAN %d which is not declared", hn, h.VLAN),
							"declared VLANs: "+joinInts(sortedIntKeysOf(dom.VLANs)))
					}
				}
				if h.VLAN < 1 || h.VLAN > 4094 {
					d.Addf(file, p+".vlan", nodeAt(root, p), "VLAN %d is out of the 1-4094 range", h.VLAN)
				}
				validateLinkProps(d, file, p, nodeAt(root, p), h.LinkProps)
			}
		}

		// Gateway sub-interface names must fit; e.g. ATL-L2.10 is 9 bytes.
		for _, dn := range sortedMapKeys(tpl.L2Domains) {
			dom := tpl.L2Domains[dn]
			for _, v := range sortedIntKeysOf(dom.VLANs) {
				n := fmt.Sprintf("%s-L2.%d", dom.Gateway, v)
				if len(n) > ifaceNameMax {
					d.Addf(file, "l2_domains."+dn, nodeAt(root, "l2_domains."+dn),
						"generated sub-interface name %q is %d bytes, exceeding the %d byte kernel limit",
						n, len(n), ifaceNameMax)
				}
			}
		}
	}
}

func (l *Loaded) validateASes(d *Diagnostics, file string) {
	root := l.Nodes[file]
	if len(l.Lab.AutonomousSystems) == 0 {
		d.Add(file, "autonomous_systems", "no autonomous systems declared", nodeAt(root, "autonomous_systems"))
		return
	}
	seen := map[int]int{} // asn -> group index
	for gi, g := range l.Lab.AutonomousSystems {
		path := fmt.Sprintf("autonomous_systems[%d]", gi)
		node := nodeAt(root, path)
		if len(g.Range) > 0 && len(g.List) > 0 {
			d.Add(file, path, "specify either 'range' or 'list', not both", node)
		}
		if len(g.Range) > 0 && len(g.Range) != 2 {
			d.Addf(file, path+".range", node, "range must be [first, last], got %d element(s)", len(g.Range))
		}
		if len(g.Range) == 2 && g.Range[0] > g.Range[1] {
			d.Addf(file, path+".range", node, "range [%d, %d] is empty", g.Range[0], g.Range[1])
		}
		asns := g.ASNs()
		if len(asns) == 0 {
			d.Add(file, path, "declares no autonomous systems", node)
		}
		spec := g.ASSpec.Merge(l.Lab.ASDefaults)
		if spec.Template == "" {
			d.AddHint(file, path+".template", node, "no template specified",
				"set as_defaults.template or this group's template")
		} else if _, ok := l.Lab.Templates[spec.Template]; !ok {
			d.AddHint(file, path+".template", node,
				fmt.Sprintf("template %q not found", spec.Template),
				"available templates: "+strings.Join(l.Lab.SortedTemplateNames(), ", "))
		}
		if spec.Role != "" && !spec.Role.Valid() {
			d.Addf(file, path+".role", node, "unknown role %q (student, staff, ixp)", spec.Role)
		}
		for _, asn := range asns {
			if asn <= 0 || asn > 4_294_967_294 {
				d.Addf(file, path, node, "AS number %d is out of range", asn)
			}
			if prev, dup := seen[asn]; dup {
				d.Addf(file, path, node, "AS %d is already declared by autonomous_systems[%d]", asn, prev)
			}
			seen[asn] = gi
		}
	}
}

func (l *Loaded) validatePeerings(d *Diagnostics, file string) {
	root := l.Nodes[file]
	declared := map[int]bool{}
	for _, g := range l.Lab.AutonomousSystems {
		for _, a := range g.ASNs() {
			declared[a] = true
		}
	}
	check := func(path string, links []model.PeeringLink) {
		keys := map[string]int{}
		for i, p := range links {
			pp := fmt.Sprintf("%s[%d]", path, i)
			node := nodeAt(root, pp)
			if !declared[p.A] {
				d.Addf(file, pp+".a", node, "AS %d is not declared in autonomous_systems", p.A)
			}
			if !declared[p.B] {
				d.Addf(file, pp+".b", node, "AS %d is not declared in autonomous_systems", p.B)
			}
			if p.A == p.B {
				d.Addf(file, pp, node, "AS %d cannot peer with itself", p.A)
			}
			if p.Rel != "" && !p.Rel.Valid() {
				d.Addf(file, pp+".rel", node, "unknown relationship %q (provider, customer, peer)", p.Rel)
			}
			if p.Subnet != "" {
				if _, err := netip.ParsePrefix(p.Subnet); err != nil {
					d.Addf(file, pp+".subnet", node, "%q is not a CIDR prefix", p.Subnet)
				}
			}
			validateLinkProps(d, file, pp, node, p.LinkProps)
			if prev, dup := keys[p.Key()]; dup && path == "peerings.links" {
				d.Addf(file, pp, node, "duplicate peering; already declared at %s[%d]", path, prev)
			}
			keys[p.Key()] = i
		}
	}
	check("peerings.links", l.Lab.Peerings.Links)
	check("peerings.overrides", l.Lab.Peerings.Overrides)

	if g := l.Lab.Peerings.Generator; g != nil {
		node := nodeAt(root, "peerings.generator")
		if g.Kind != "tiered-internet" {
			d.Addf(file, "peerings.generator.kind", node,
				"unknown generator %q (supported: tiered-internet)", g.Kind)
		}
		inTier := map[int]int{}
		for ti, tier := range g.Tiers {
			if len(tier) == 0 {
				d.Addf(file, fmt.Sprintf("peerings.generator.tiers[%d]", ti), node, "tier is empty")
			}
			for _, a := range tier {
				if !declared[a] {
					d.Addf(file, fmt.Sprintf("peerings.generator.tiers[%d]", ti), node,
						"AS %d is not declared in autonomous_systems", a)
				}
				if prev, dup := inTier[a]; dup {
					d.Addf(file, fmt.Sprintf("peerings.generator.tiers[%d]", ti), node,
						"AS %d already appears in tier %d", a, prev)
				}
				inTier[a] = ti
			}
		}
		for _, x := range g.IXPs {
			if !declared[x] {
				d.Addf(file, "peerings.generator.ixps", node, "IXP AS %d is not declared", x)
			}
		}
	}
}

func (l *Loaded) validateServices(d *Diagnostics, file string) {
	root := l.Nodes[file]
	known := map[string]bool{
		"builtin.dns": true, "builtin.matrix": true, "builtin.measurement": true,
		"builtin.web": true, "builtin.wireguard": true, "builtin.krill": true,
		"builtin.routinator": true, "container": true,
	}
	for _, name := range sortedMapKeys(l.Lab.Services) {
		s := l.Lab.Services[name]
		path := "services." + name
		node := nodeAt(root, path)
		if !known[s.Kind] {
			d.AddHint(file, path+".kind", node,
				fmt.Sprintf("unknown service kind %q", s.Kind),
				"known kinds: "+strings.Join(sortedMapKeys(known), ", "))
		}
		if s.Attach != nil {
			if s.Attach.Router == "" {
				d.Add(file, path+".attach.router", "attach.router is required", node)
			}
			if s.Attach.Iface == "" {
				d.Add(file, path+".attach.iface", "attach.iface is required", node)
			} else if len(s.Attach.Iface) > ifaceNameMax || !ifaceNameRe.MatchString(s.Attach.Iface) {
				d.Addf(file, path+".attach.iface", node,
					"interface name %q must match %s and fit %d bytes",
					s.Attach.Iface, ifaceNameRe, ifaceNameMax)
			}
			tplName := s.Attach.Template
			if tplName != "" {
				tpl, ok := l.Lab.Templates[tplName]
				if !ok {
					d.Addf(file, path+".attach.template", node, "template %q not found", tplName)
				} else if _, ok := tpl.Routers[s.Attach.Router]; !ok && s.Attach.Router != "" {
					d.Addf(file, path+".attach.router", node,
						"template %q has no router %q", tplName, s.Attach.Router)
				}
			}
			// A per-AS service needs an addressing entry to derive its subnets.
			if _, ok := l.Lab.Addressing.Services[name]; !ok {
				d.AddHint(file, path, node,
					fmt.Sprintf("service %q is attached per-AS but addressing.services.%s is not defined", name, name),
					"add an entry under addressing.services so each AS gets a subnet for it")
			}
		}
	}
}

func (l *Loaded) validatePlacement(d *Diagnostics, file string) {
	root := l.Nodes[file]
	p := l.Lab.Placement
	switch p.Strategy {
	case "", "pack-by-as", "spread-by-as", "single-node":
	default:
		d.Addf(file, "placement.strategy", nodeAt(root, "placement"),
			"unknown strategy %q (pack-by-as, spread-by-as, single-node)", p.Strategy)
	}
	names := map[string]bool{}
	fronts := 0
	for i, n := range p.Nodes {
		path := fmt.Sprintf("placement.nodes[%d]", i)
		node := nodeAt(root, path)
		if n.Name == "" {
			d.Add(file, path+".name", "node name is required", node)
		}
		if names[n.Name] {
			d.Addf(file, path+".name", node, "duplicate node %q", n.Name)
		}
		names[n.Name] = true
		if n.Front {
			fronts++
		}
		if n.UnderlayIP != "" {
			if _, err := netip.ParseAddr(n.UnderlayIP); err != nil {
				d.Addf(file, path+".underlay_ip", node, "%q is not an IP address", n.UnderlayIP)
			}
		} else if len(p.Nodes) > 1 {
			d.AddHint(file, path+".underlay_ip", node,
				fmt.Sprintf("node %q has no underlay_ip", n.Name),
				"cross-node links need a VTEP source address on each node")
		}
	}
	if fronts > 1 {
		d.Add(file, "placement.nodes", "more than one node is marked front", nodeAt(root, "placement.nodes"))
	}
	if p.Strategy == "single-node" && len(p.Nodes) > 1 {
		d.Warn(file, "placement", "strategy is single-node but several nodes are declared; only the front node will be used", nodeAt(root, "placement"))
	}
	for i, pin := range p.Pin {
		path := fmt.Sprintf("placement.pin[%d]", i)
		if !names[pin.Node] {
			d.Addf(file, path+".node", nodeAt(root, path), "unknown node %q", pin.Node)
		}
	}
	for name := range p.Reserve {
		if !names[name] {
			d.Addf(file, "placement.reserve."+name, nodeAt(root, "placement.reserve"), "unknown node %q", name)
		}
	}
}

func (l *Loaded) validateAccess(d *Diagnostics, file string) {
	root := l.Nodes[file]
	a := l.Lab.Access
	switch a.Mode {
	case "", "gateway", "none":
	default:
		d.Addf(file, "access.mode", nodeAt(root, "access"), "unknown access mode %q (gateway, none)", a.Mode)
	}
	if a.Node != "" {
		if _, ok := l.Lab.NodeByName(a.Node); !ok {
			d.Addf(file, "access.node", nodeAt(root, "access"), "unknown node %q", a.Node)
		}
	}
	if lp := a.LegacyPorts; lp != nil && lp.Enabled {
		maxASN := 0
		for _, g := range l.Lab.AutonomousSystems {
			for _, n := range g.ASNs() {
				if n > maxASN {
					maxASN = n
				}
			}
		}
		if lp.Base+maxASN > 65535 {
			d.Addf(file, "access.legacy_ports.base", nodeAt(root, "access.legacy_ports"),
				"base %d plus the largest AS number %d exceeds the 65535 port range", lp.Base, maxASN)
		}
	}
}

// validateLinkProps checks tc-facing values early, because a malformed rate or
// delay only surfaces as an obscure netlink failure at deploy time.
func validateLinkProps(d *Diagnostics, file, path string, node *yaml.Node, p model.LinkProps) {
	if p.Bandwidth != "" && !rateRe.MatchString(p.Bandwidth) {
		d.AddHint(file, path+".bandwidth", node,
			fmt.Sprintf("%q is not a tc rate", p.Bandwidth),
			"examples: 1mbit, 10mbit, 100kbit, 1gbit")
	}
	if p.Delay != "" && !timeRe.MatchString(p.Delay) {
		d.AddHint(file, path+".delay", node,
			fmt.Sprintf("%q is not a tc time", p.Delay),
			"examples: 1ms, 2.5ms, 25ms, 1s")
	}
	if p.Queue != "" && !timeRe.MatchString(p.Queue) {
		d.AddHint(file, path+".queue", node,
			fmt.Sprintf("%q is not a tc time", p.Queue), "examples: 50ms, 100ms")
	}
	if p.Loss != "" && !lossRe.MatchString(p.Loss) {
		d.AddHint(file, path+".loss", node,
			fmt.Sprintf("%q is not a loss percentage", p.Loss), "examples: 0.1%, 5%")
	}
	if p.MTU != nil && (*p.MTU < 576 || *p.MTU > 65535) {
		d.Addf(file, path+".mtu", node, "MTU %d is outside the 576-65535 range", *p.MTU)
	}
}

var (
	rateRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(bit|kbit|mbit|gbit|tbit|bps|kbps|mbps|gbps|tbps)$`)
	timeRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(s|ms|us)$`)
	lossRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?%$`)
)

func validMAC(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		for _, c := range p {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeysOf[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedIntSlice[V any](m map[int]V) []int { return sortedIntKeysOf(m) }

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}
