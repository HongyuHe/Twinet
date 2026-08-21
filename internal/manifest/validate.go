package manifest

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/nos"
	"github.com/HongyuHe/twinet/internal/runtime"
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
	l.validateNOS(d)
	l.validateASes(d, file)
	l.validatePeerings(d, file)
	l.validateServices(d, file)
	l.validateBehaviours(d, file)
	l.validateEgress(d, file)
	l.validateResources(d, file)
	l.validatePlacement(d, file)
	l.validateStatePolicy(d, file)
	l.validateAccess(d, file)
	_ = lab
	return d
}

// validateNOS resolves every router's inherited NOS declaration before a
// deployment can pull or mutate anything. A provider capability mismatch is an
// author/infrastructure error, not an empty route table that later looks like
// a student's mistake.
func (l *Loaded) validateNOS(d *Diagnostics) {
	for _, templateName := range l.Lab.SortedTemplateNames() {
		tpl := l.Lab.Templates[templateName]
		if tpl == nil {
			continue
		}
		file := l.Files["template:"+templateName]
		if file == "" {
			file = l.Files["lab"]
		}
		root := l.Nodes[file]
		routers, err := tpl.EffectiveRouterSpecs()
		if err != nil {
			// validateTemplates reports the interior error with a better
			// source location. NOS validation cannot infer generated devices.
			continue
		}
		for _, routerName := range sortedMapKeys(routers) {
			spec := routers[routerName]
			if spec == nil {
				continue
			}
			defaults := spec.DeviceDefaults.Merge(l.Lab.Kinds[model.KindRouter]).Merge(l.Lab.Defaults)
			name := defaults.NOS
			if name == "" {
				name = model.DefaultNOS
			}
			provider, ok := nos.Lookup(name)
			path := "routers." + routerName + ".nos"
			node := nodeAt(root, path)
			device := fmt.Sprintf("template %q router %q", templateName, routerName)
			if !ok {
				d.AddHint(file, path, node,
					fmt.Sprintf("device %s declares unknown NOS %q", device, name),
					"registered NOS implementations: "+strings.Join(nos.Names(), ", "))
				continue
			}
			for _, feature := range nos.RequiredFeatures(l.Lab, tpl, routerName) {
				if provider.Capabilities().Supports(feature) {
					continue
				}
				d.AddHint(file, path, node,
					fmt.Sprintf("device %s uses NOS %q, which does not support feature %q",
						device, provider.Name(), feature),
					"select a NOS that declares the feature or remove the unsupported topology request")
			}
		}
	}

	// The current submission format is an FRR configuration file. Accepting a
	// student-owned BIRD router would silently load that syntax nowhere and
	// grade an empty control plane. BIRD is therefore intentionally limited to
	// staff/reference routers until submissions carry provider-specific typed
	// configuration.
	for groupIndex, group := range l.Lab.AutonomousSystems {
		spec := group.Merge(l.Lab.ASDefaults)
		if spec.Role != "" && spec.Role != model.RoleStudent {
			continue
		}
		tpl := l.Lab.Templates[spec.Template]
		if tpl == nil {
			continue
		}
		routers, err := tpl.EffectiveRouterSpecs()
		if err != nil {
			continue
		}
		for _, asn := range group.ASNs() {
			for _, routerName := range sortedMapKeys(routers) {
				router := routers[routerName]
				if router == nil {
					continue
				}
				defaults := router.DeviceDefaults.Merge(l.Lab.Kinds[model.KindRouter]).Merge(l.Lab.Defaults)
				if strings.EqualFold(defaults.NOS, "bird") {
					d.AddHint(l.Files["lab"], fmt.Sprintf("autonomous_systems[%d]", groupIndex),
						nodeAt(l.Nodes[l.Files["lab"]], fmt.Sprintf("autonomous_systems[%d]", groupIndex)),
						fmt.Sprintf("device as%d/%s uses NOS %q in a student-owned AS", asn, routerName, defaults.NOS),
						"student submissions currently carry FRR commands; use BIRD only for staff/reference routers")
				}
			}
		}
	}
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
		ipam.FieldRouterRouter: a.RouterRouter, ipam.FieldRouterRouterRole: a.RouterRouterRole,
		ipam.FieldRouterHost: a.RouterHost,
		ipam.FieldL2Domain:   a.L2Domain, ipam.FieldL2DomainV6: a.L2DomainV6, ipam.FieldL2VLAN: a.L2VLAN, ipam.FieldL2VLANV6: a.L2VLANV6,
		ipam.FieldInterAS: a.InterAS, ipam.FieldIXPPeering: a.IXPPeering,
	}
	for name, expr := range a.Services {
		exprs["svc_"+name] = expr
	}
	plan, err := ipam.Compile(exprs)
	if err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			d.Add(file, "addressing", line, nodeAt(root, "addressing"))
		}
		return
	}
	// Compiling only proves the expression is a well-formed Go template. It
	// says nothing about whether the string it produces is an address.
	//
	// `inter_as: "this is not a prefix"` compiled cleanly and validated
	// cleanly, and the mistake surfaced much later as an addressing plan that
	// could not be built -- by which point the message names an internal
	// field rather than the line the author wrote. Evaluating each expression
	// once, against representative values, turns that into a diagnostic
	// pointing at the manifest.
	for _, name := range sortedMapKeys(exprs) {
		if strings.TrimSpace(exprs[name]) == "" {
			continue
		}
		out, err := plan.Eval(name, sampleCtx)
		if err != nil {
			d.AddHint(file, "addressing."+name, nodeAt(root, "addressing"),
				fmt.Sprintf("addressing.%s could not be evaluated: %v", name, err),
				"the bindings available are .AS .PeerAS .RouterID .PeerID .LinkIndex "+
					".Role .PeerRole .RoleIndex .PeerRoleIndex .RoleLinkIndex .LinkClass "+
					".L2ID .VLAN .VLANIndex .IXP .Low .High .Host .Name .Region")
			continue
		}
		if _, perr := netip.ParsePrefix(out); perr != nil {
			d.AddHint(file, "addressing."+name, nodeAt(root, "addressing"),
				fmt.Sprintf("addressing.%s produced %q, which is not an address and prefix length",
					name, out),
				"every addressing expression must render something like 10.0.1.0/24")
		}
	}
}

// sampleCtx is a representative binding used to prove an addressing expression
// renders an address at all. The values are arbitrary but plausible; what
// matters is that every field is non-zero, so an expression that uses one
// cannot appear to work by rendering an empty string.
var sampleCtx = ipam.Ctx{
	AS: 1, PeerAS: 2, RouterID: 1, PeerID: 2, LinkIndex: 0,
	L2ID: 0, VLAN: 10, VLANIndex: 0, IXP: 100,
	Low: 1, High: 2, Host: 1, Name: "sample", Region: "0",
	Role: "spine", PeerRole: "leaf", RoleIndex: 1, PeerRoleIndex: 2,
	RoleLinkIndex: 3, LinkClass: "spine-leaf",
}

func (l *Loaded) validateTemplates(d *Diagnostics) {
	for _, name := range l.Lab.SortedTemplateNames() {
		tpl := l.Lab.Templates[name]
		file := l.Files["template:"+name]
		if file == "" {
			file = l.Files["lab"]
		}
		root := l.Nodes[file]

		if err := tpl.ValidateInterior(); err != nil {
			for _, problem := range strings.Split(err.Error(), "\n") {
				d.Add(file, "interior", problem, nodeAt(root, "interior"))
			}
		}
		if tpl.Interior != nil && tpl.EffectiveInteriorKind() != model.InteriorExplicit {
			validateLinkProps(d, file, "interior", nodeAt(root, "interior"), tpl.Interior.LinkProps)
		}
		routers, routerErr := tpl.EffectiveRouterSpecs()
		if routerErr != nil {
			d.Addf(file, "interior", nodeAt(root, "interior"), "cannot generate routers: %v", routerErr)
			routers = tpl.Routers
		}
		if len(routers) == 0 {
			d.Add(file, "routers", "template declares no routers", nodeAt(root, "routers"))
		}
		l.validateProvisioning(d, file, root, name, tpl)

		// Router IDs must be unique: the addressing plan indexes on them, so a
		// duplicate silently aliases two routers' loopbacks and host subnets.
		byID := map[int][]string{}
		for _, rn := range sortedMapKeys(routers) {
			r := routers[rn]
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

		for i, il := range tpl.EffectiveInternalLinks() {
			path := fmt.Sprintf("internal_links[%d]", i)
			if _, ok := routers[il.A]; !ok {
				d.Addf(file, path+".a", nodeAt(root, path), "unknown router %q", il.A)
			}
			if _, ok := routers[il.B]; !ok {
				d.Addf(file, path+".b", nodeAt(root, path), "unknown router %q", il.B)
			}
			if il.A == il.B {
				d.Addf(file, path, nodeAt(root, path), "router %q cannot link to itself", il.A)
			}
			validateLinkProps(d, file, path, nodeAt(root, path), il.LinkProps)
		}

		for _, pn := range sortedMapKeys(tpl.ExternalPorts) {
			ep := tpl.ExternalPorts[pn]
			if _, ok := routers[ep.Router]; !ok {
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
			if _, ok := routers[dom.Gateway]; !ok {
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
		spec := g.Merge(l.Lab.ASDefaults)
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
		if !model.Generators.Has(model.GeneratorInterAS, g.Kind) {
			d.Addf(file, "peerings.generator.kind", node,
				"unknown generator %q (supported: %s)", g.Kind,
				strings.Join(model.Generators.Kinds(model.GeneratorInterAS), ", "))
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

// validateBehaviours refuses a behaviour that cannot be carried out.
//
// `behaviours:` validated and did nothing at all for the whole life of the
// project: it appeared in the schema, was documented as the replacement for the
// legacy platform's hijack.sh, and no code read it. The COS-461 RPKI question
// is built on one, so the exercise had a permanent invalid announcement in
// place of an event that could be started and stopped.
func (l *Loaded) validateBehaviours(d *Diagnostics, file string) {
	root := l.Nodes[file]
	for _, name := range sortedMapKeys(l.Lab.Behaviours) {
		b := l.Lab.Behaviours[name]
		path := "behaviours." + name
		node := nodeAt(root, path)
		if _, ok := model.BehaviourFault(b.Kind); !ok {
			d.AddHint(file, path+".kind", node,
				fmt.Sprintf("no implementation for behaviour kind %q", b.Kind),
				"known kinds: "+strings.Join(model.BehaviourKinds(), ", "))
		}
		if b.Params["by"] == "" {
			d.AddHint(file, path+".params", node,
				"this behaviour does not say which AS performs it",
				"set params.by to the AS number; a hijack with no hijacker cannot be started")
		}
		if b.Victims == nil && b.Prefix == "" {
			d.Add(file, path, "this behaviour names neither victims nor a prefix", node)
		}
		switch b.Start {
		case "", "manual", "deploy":
		default:
			d.AddHint(file, path+".start", node,
				fmt.Sprintf("unknown start condition %q", b.Start),
				"`start` may be manual (the default) or deploy")
		}
	}
}

func (l *Loaded) validateServices(d *Diagnostics, file string) {
	root := l.Nodes[file]
	known := map[string]bool{
		"builtin.dns": true, "builtin.matrix": true, "builtin.measurement": true,
		"builtin.web": true, "builtin.wireguard": true, "builtin.krill": true,
		"builtin.rpki": true, "builtin.dhcp": true,
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
				} else {
					routers, err := tpl.EffectiveRouterSpecs()
					if err != nil {
						d.Addf(file, path+".attach.router", node,
							"template %q has an invalid interior: %v", tplName, err)
					} else if _, ok := routers[s.Attach.Router]; !ok && s.Attach.Router != "" {
						d.Addf(file, path+".attach.router", node,
							"template %q has no router %q", tplName, s.Attach.Router)
					}
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

// validateResources checks that resource quantities are well formed before a
// deployment discovers them one container at a time.
func (l *Loaded) validateResources(d *Diagnostics, file string) {
	root := l.Nodes[file]
	check := func(path string, dd model.DeviceDefaults, node *yaml.Node) {
		validateDeviceResources(d, file, path, dd, node)
	}
	check("defaults", l.Lab.Defaults, nodeAt(root, "defaults"))
	for _, k := range sortedMapKeys(mapKeysAsStrings(l.Lab.Kinds)) {
		kind := model.DeviceKind(k)
		check("kinds."+k, l.Lab.Kinds[kind], nodeAt(root, "kinds."+k))
	}
	for _, name := range sortedMapKeys(l.Lab.Services) {
		check("services."+name, l.Lab.Services[name].DeviceDefaults, nodeAt(root, "services."+name))
	}
	for _, tn := range l.Lab.SortedTemplateNames() {
		tpl := l.Lab.Templates[tn]
		tf := l.Files["template:"+tn]
		if tf == "" {
			tf = file
		}
		troot := l.Nodes[tf]
		for _, rn := range sortedMapKeys(tpl.Routers) {
			validateDeviceResources(d, tf, "routers."+rn, tpl.Routers[rn].DeviceDefaults,
				nodeAt(troot, "routers."+rn))
		}
	}
}

func validateDeviceResources(d *Diagnostics, file, path string, dd model.DeviceDefaults, node *yaml.Node) {
	if dd.Memory != "" {
		if _, err := runtime.ParseMemory(dd.Memory); err != nil {
			d.AddHint(file, path+".memory", node, err.Error(),
				"use Kubernetes-style quantities such as 512Mi or 2Gi")
		}
	}
	if dd.CPUs != nil && *dd.CPUs <= 0 {
		d.Addf(file, path+".cpus", node, "cpus must be positive, got %v", *dd.CPUs)
	}
	if dd.Pids != nil && *dd.Pids < 16 {
		d.Addf(file, path+".pids", node,
			"a pids limit of %d is too low for a container running a routing daemon", *dd.Pids)
	}
	if dd.Requests == nil {
		return
	}
	r := *dd.Requests
	rpath := path + ".requests"
	if r.CPUs < 0 || (r.CPUs == 0 && requestField(node, "cpus")) {
		d.Addf(file, rpath+".cpus", node, "request CPUs must be positive, got %v", r.CPUs)
	}
	if r.Memory != "" {
		if quantity, err := runtime.ParseMemory(r.Memory); err != nil {
			d.AddHint(file, rpath+".memory", node, err.Error(),
				"use Kubernetes-style quantities such as 128Mi or 1Gi")
		} else if quantity <= 0 {
			d.Add(file, rpath+".memory", "request memory must be positive", node)
		}
	}
	if r.Memory == "" && requestField(node, "memory") {
		d.Add(file, rpath+".memory", "request memory must be positive when specified", node)
	}
	if r.Pids < 0 || (r.Pids == 0 && requestField(node, "pids")) {
		d.Addf(file, rpath+".pids", node, "request pids must be positive, got %d", r.Pids)
	}
	if r.EphemeralStorage != "" && r.Disk != "" {
		d.Add(file, rpath, "specify only one of ephemeral_storage and disk", node)
	}
	if r.Storage() != "" {
		if quantity, err := runtime.ParseMemory(r.Storage()); err != nil {
			d.AddHint(file, rpath+".ephemeral_storage", node, err.Error(),
				"use Kubernetes-style quantities such as 256Mi or 1Gi")
		} else if quantity <= 0 {
			d.Add(file, rpath+".ephemeral_storage", "request ephemeral storage must be positive", node)
		}
	}
	if r.Storage() == "" && (requestField(node, "ephemeral_storage") || requestField(node, "disk")) {
		d.Add(file, rpath+".ephemeral_storage", "request ephemeral storage must be positive when specified", node)
	}
	if r.FileDescriptors < 0 || (r.FileDescriptors == 0 && requestField(node, "file_descriptors")) {
		d.Addf(file, rpath+".file_descriptors", node,
			"request file_descriptors must be positive, got %d", r.FileDescriptors)
	}
	if r.NetDevices < 0 || (r.NetDevices == 0 && requestField(node, "netdevs")) {
		d.Addf(file, rpath+".netdevs", node, "request netdevs must be positive, got %d", r.NetDevices)
	}

	// A reservation above its own hard limit is neither a useful request nor
	// an enforceable container contract. Keep the two terms distinct in the
	// diagnostic so authors do not mistake the legacy limits for placement
	// demand.
	if dd.CPUs != nil && r.CPUs > *dd.CPUs {
		d.Addf(file, rpath+".cpus", node,
			"CPU request %.3g exceeds the hard container limit %.3g", r.CPUs, *dd.CPUs)
	}

	if dd.Memory != "" && r.Memory != "" {
		requested, rerr := runtime.ParseMemory(r.Memory)
		limited, lerr := runtime.ParseMemory(dd.Memory)
		if rerr == nil && lerr == nil && requested > limited {
			d.Addf(file, rpath+".memory", node,
				"memory request %s exceeds the hard container limit %s", r.Memory, dd.Memory)
		}
	}

	if dd.Pids != nil && r.Pids > *dd.Pids {
		d.Addf(file, rpath+".pids", node,
			"PID request %d exceeds the hard container limit %d", r.Pids, *dd.Pids)
	}
}

// requestField reports whether an authored requests mapping explicitly named a
// dimension. Zero is otherwise the inheritance sentinel, so this preserves
// partial requests while still rejecting `cpus: 0` as an invalid reservation.
func requestField(node *yaml.Node, key string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != "requests" || node.Content[i+1].Kind != yaml.MappingNode {
			continue
		}
		requests := node.Content[i+1]
		for j := 0; j+1 < len(requests.Content); j += 2 {
			if requests.Content[j].Value == key {
				return true
			}
		}
	}
	return false
}

// mapKeysAsStrings adapts a DeviceKind-keyed map for the string helpers.
func mapKeysAsStrings(m map[model.DeviceKind]model.DeviceDefaults) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[string(k)] = struct{}{}
	}
	return out
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
		if n.Capacity != nil {
			validateBudget(d, file, path+".capacity", *n.Capacity, node)
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
		validateBudget(d, file, "placement.reserve."+name, p.Reserve[name],
			nodeAt(root, "placement.reserve."+name))
	}
	switch p.OnNodeLoss {
	case "", "fail", "reschedule":
	default:
		d.Addf(file, "placement.on_node_loss", nodeAt(root, "placement"),
			"unknown on_node_loss policy %q (fail, reschedule)", p.OnNodeLoss)
	}
}

// validateStatePolicy rejects a durability declaration that cannot deliver
// its promised number of independent copies. A replica on another process in
// the same failure domain does not survive the node or disk loss this policy
// exists to cover.
func (l *Loaded) validateStatePolicy(d *Diagnostics, file string) {
	root := l.Nodes[file]
	p := l.Lab.State
	path := "state"
	clustered := l.Lab.Placement.Strategy != "single-node" && len(l.Lab.Placement.Nodes) > 1

	if p.ReplicationFactor < 1 {
		d.Addf(file, path+".replication_factor", nodeAt(root, path),
			"replication_factor must be at least one, got %d", p.ReplicationFactor)
	}
	if interval, err := time.ParseDuration(p.CaptureInterval); err != nil || interval <= 0 {
		msg := "capture_interval must be a positive Go duration such as 5m"
		if err != nil {
			msg = fmt.Sprintf("capture_interval %q is invalid: %v", p.CaptureInterval, err)
		}
		d.Add(file, path+".capture_interval", msg, nodeAt(root, path))
	}
	retention, retentionErr := time.ParseDuration(p.ReplicaRetention)
	if retentionErr != nil || retention <= 0 {
		msg := "replica_retention must be a positive Go duration such as 168h"
		if retentionErr != nil {
			msg = fmt.Sprintf("replica_retention %q is invalid: %v", p.ReplicaRetention, retentionErr)
		}
		d.Add(file, path+".replica_retention", msg, nodeAt(root, path))
	} else if interval, err := time.ParseDuration(p.CaptureInterval); err == nil && retention < interval {
		d.AddHint(file, path+".replica_retention", nodeAt(root, path),
			"replica_retention is shorter than capture_interval",
			"retain at least one full capture interval so a verified replica remains available")
	}

	domains := map[string]bool{}
	for _, n := range l.Lab.Placement.Nodes {
		if n.Name == "" {
			continue
		}
		domains[n.Domain()] = true
	}
	if clustered {
		if p.ReplicationFactor > len(domains) {
			d.AddHint(file, path+".replication_factor", nodeAt(root, path),
				fmt.Sprintf("replication_factor %d needs %d failure domains, but this cluster has %d",
					p.ReplicationFactor, p.ReplicationFactor, len(domains)),
				"add independently failing nodes, reduce replication_factor, or use single-node placement explicitly")
		}
		if p.ReplicationFactor < 2 {
			d.Warn(file, path+".replication_factor",
				"clustered student state has fewer than two copies and cannot survive one node or disk loss",
				nodeAt(root, path))
		}
	} else {
		if p.ReplicationFactor > 1 {
			d.AddHint(file, path+".replication_factor", nodeAt(root, path),
				"single-node placement cannot place replicas in separate failure domains",
				"add clustered placement nodes or use replication_factor: 1")
		}
		d.Warn(file, path,
			"single-node durability stores one local copy only; loss of this node or its disk can lose student state",
			nodeAt(root, path))
	}
	if !p.FailClosedEnabled() {
		d.Warn(file, path+".fail_closed",
			"fail_closed: false permits destructive work without a verified fresh replica quorum and is an audited data-loss exception",
			nodeAt(root, path))
	}
	if l.Lab.Placement.OnNodeLoss == "reschedule" && len(domains) < 2 {
		d.AddHint(file, "placement.on_node_loss", nodeAt(root, "placement"),
			"reschedule needs another failure domain containing a verified replica",
			"add an independent node or use on_node_loss: fail")
	}
}

func validateBudget(d *Diagnostics, file, path string, b model.Budget, node *yaml.Node) {
	if b.CPUs < 0 {
		d.Addf(file, path+".cpus", node, "CPU capacity must not be negative, got %v", b.CPUs)
	}
	if b.Memory != "" {
		if _, err := runtime.ParseMemory(b.Memory); err != nil {
			d.AddHint(file, path+".memory", node, err.Error(),
				"use Kubernetes-style quantities such as 16Gi")
		}
	}
	if b.Pids < 0 || b.FileDescriptors < 0 || b.NetDevices < 0 || b.Containers < 0 {
		d.Add(file, path, "resource capacities and reservations must not be negative", node)
	}
	if b.EphemeralStorage != "" && b.Disk != "" {
		d.Add(file, path, "specify only one of ephemeral_storage and disk", node)
	}
	if b.Storage() != "" {
		if _, err := runtime.ParseMemory(b.Storage()); err != nil {
			d.AddHint(file, path+".ephemeral_storage", node, err.Error(),
				"use Kubernetes-style quantities such as 32Gi")
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

// validateProvisioning refuses a provisioning declaration that cannot be
// carried out.
//
// Everything here used to be accepted and ignored: a scope was never read, a
// rule naming an interface was skipped, and the `student` list was read by
// nothing at all. A course could declare precisely which half of the
// configuration it wanted to hand out, be told the manifest was valid, and get
// a lab where the split was decided entirely by whether the AS's role happened
// to be "student".
func (l *Loaded) validateProvisioning(d *Diagnostics, file string, root *yaml.Node,
	name string, tpl *model.ASTemplate) {

	base := "templates." + name + ".provisioning"
	node := nodeAt(root, base)
	known := strings.Join(model.KnownDomains(), ", ")

	sawIBGP, sawEBGP := false, false
	for i, r := range tpl.Provisioning.Provisioned {
		path := fmt.Sprintf("%s.provisioned[%d]", base, i)
		if r.Scope == "" && r.DeviceKind == "" && r.Iface == nil {
			d.Add(file, path, "a provisioning rule selects nothing", node)
			continue
		}
		if r.Scope != "" {
			dom, ok := model.NormaliseDomain(r.Scope)
			switch {
			case !ok:
				d.AddHint(file, path+".scope", node,
					fmt.Sprintf("unknown configuration domain %q", r.Scope),
					"known domains: "+known)
			case !model.CanProvision(dom):
				d.AddHint(file, path+".scope", node,
					fmt.Sprintf("%q cannot be provisioned on its own", r.Scope),
					"it is rendered inside a stanza that carries other domains too; "+
						"use `scope: all` to hand out the whole configuration, or leave "+
						"it to the students")
			}
			sawIBGP = sawIBGP || r.Scope == "ibgp"
			sawEBGP = sawEBGP || r.Scope == "ebgp"
		}
		switch r.DeviceKind {
		case "", model.KindRouter, model.KindHost, model.KindSwitch:
		default:
			d.AddHint(file, path+".device_kind", node,
				fmt.Sprintf("provisioning cannot be decided per %q device", r.DeviceKind),
				"device_kind may be router, host or switch")
		}
		if r.Iface != nil {
			dev := r.Iface.Router
			if dev == "" {
				dev = r.Iface.Device
			}
			if dev == "" {
				d.Add(file, path+".iface", "an interface rule must name a router or a device", node)
			}
			if r.Iface.Name == "" {
				d.Add(file, path+".iface.name", "an interface rule must name an interface", node)
			}
		}
	}
	if sawIBGP != sawEBGP {
		// One FRR stanza carries both, so there is no way to hand out one and
		// withhold the other. Saying so is better than quietly giving both.
		d.AddHint(file, base+".provisioned", node,
			"iBGP and eBGP cannot be provisioned separately",
			"they are rendered as one `router bgp` stanza; provision both, or neither")
	}
	for i, dom := range tpl.Provisioning.Student {
		if _, ok := model.NormaliseDomain(dom); !ok {
			d.AddHint(file, fmt.Sprintf("%s.student[%d]", base, i), node,
				fmt.Sprintf("unknown configuration domain %q", dom),
				"known domains: "+known)
		}
	}
}

// validateEgress refuses a block nothing carries out.
//
// `egress:` has been in the manifest, the schema and the design document since
// the first version, documented as the replacement for the legacy platform's
// blanket nat_setup.sh, with the specific example of a validator fetching real
// trust anchors. No code has ever read it. A lab that declares it gets exactly
// the internet access it would have got without it, which is none, and finds
// out when something inside fails to resolve a name.
//
// Refusing is better than ignoring. It costs an author one line and a link to
// the status ledger; ignoring costs them an afternoon.
func (l *Loaded) validateEgress(d *Diagnostics, file string) {
	if len(l.Lab.Egress) == 0 {
		return
	}
	root := l.Nodes[file]
	d.AddHint(file, "egress", nodeAt(root, "egress"),
		"outbound access is not implemented, so this block would do nothing",
		"devices reach only the lab. Remove the block; the design for it is in "+
			"docs/04 section 5 and it is listed as unimplemented in docs/09")
}
