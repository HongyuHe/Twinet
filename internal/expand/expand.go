// Package expand turns an authored lab manifest into a fully resolved topology.
//
// Expansion is the step where 100 nearly identical ASes stop being a template
// and become concrete devices, interfaces and links, each with a stable
// identity, an address from the plan, and an owner (platform or student).
//
// It is deliberately a pure function: given the same manifest, expansion
// produces byte-identical output, including ordering. Everything downstream —
// placement, planning, deployment, grading — depends on that.
package expand

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
)

// Result carries the expanded topology plus any non-fatal notes.
type Result struct {
	Topology *model.Topology
	Warnings []string
}

// Expand resolves a lab into a topology.
func Expand(lab *model.Lab) (*Result, error) {
	e := &expander{
		lab: lab,
		top: &model.Topology{
			Lab:      lab,
			Name:     lab.Metadata.Name,
			Devices:  map[string]*model.Device{},
			ASes:     map[int]*model.AS{},
			Services: map[string]*model.Service{},
		},
	}
	plan, err := e.compilePlan()
	if err != nil {
		return nil, err
	}
	e.plan = plan

	if err := e.expandASes(); err != nil {
		return nil, err
	}
	if err := e.expandPeerings(); err != nil {
		return nil, err
	}
	if err := e.expandServices(); err != nil {
		return nil, err
	}
	e.assignVNIs()
	e.stampLabels()
	e.computeHash()

	return &Result{Topology: e.top, Warnings: e.warnings}, nil
}

type expander struct {
	lab      *model.Lab
	top      *model.Topology
	plan     *ipam.Plan
	warnings []string

	// interASIndex assigns each inter-AS link a stable index so the addressing
	// plan can carve a distinct /24 for it out of 179.0.0.0/8.
	interASIndex map[string]int
}

func (e *expander) warnf(format string, args ...any) {
	e.warnings = append(e.warnings, fmt.Sprintf(format, args...))
}

func (e *expander) compilePlan() (*ipam.Plan, error) {
	a := e.lab.Addressing
	exprs := map[string]string{
		ipam.FieldASBlock:          a.ASBlock,
		ipam.FieldASBlockV6:        a.ASBlockV6,
		ipam.FieldRouterLoopback:   a.RouterLoopback,
		ipam.FieldRouterLoopbackV6: a.RouterLoopbackV6,
		ipam.FieldRouterRouter:     a.RouterRouter,
		ipam.FieldRouterHost:       a.RouterHost,
		ipam.FieldL2Domain:         a.L2Domain,
		ipam.FieldL2DomainV6:       a.L2DomainV6,
		ipam.FieldL2VLAN:           a.L2VLAN,
		ipam.FieldL2VLANV6:         a.L2VLANV6,
		ipam.FieldInterAS:          a.InterAS,
		ipam.FieldIXPPeering:       a.IXPPeering,
	}
	for name, expr := range a.Services {
		exprs["svc_"+name] = expr
	}
	return ipam.Compile(exprs)
}

// ---------------------------------------------------------------------------
// AS expansion
// ---------------------------------------------------------------------------

func (e *expander) expandASes() error {
	// Resolve every declared AS to a concrete spec, checking for duplicates.
	type entry struct {
		asn  int
		spec model.ASSpec
	}
	var entries []entry
	seen := map[int]bool{}
	for gi, g := range e.lab.AutonomousSystems {
		spec := g.ASSpec.Merge(e.lab.ASDefaults)
		asns := g.ASNs()
		if len(asns) == 0 {
			return fmt.Errorf("autonomous_systems[%d]: neither 'range' nor 'list' declares any AS", gi)
		}
		for _, asn := range asns {
			if seen[asn] {
				return fmt.Errorf("autonomous_systems[%d]: AS %d is declared more than once", gi, asn)
			}
			seen[asn] = true
			entries = append(entries, entry{asn: asn, spec: spec})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].asn < entries[j].asn })

	for _, ent := range entries {
		if err := e.expandOneAS(ent.asn, ent.spec); err != nil {
			return fmt.Errorf("AS %d: %w", ent.asn, err)
		}
	}
	return nil
}

func (e *expander) expandOneAS(asn int, spec model.ASSpec) error {
	tplName := spec.Template
	if tplName == "" {
		return fmt.Errorf("no template specified (set as_defaults.template or the group's template)")
	}
	tpl, ok := e.lab.Templates[tplName]
	if !ok {
		return fmt.Errorf("template %q not found (available: %s)", tplName,
			strings.Join(e.lab.SortedTemplateNames(), ", "))
	}

	role := spec.Role
	if role == "" {
		role = model.RoleStudent
	}
	region := spec.Region
	if region == "" && spec.RegionOf != "" {
		v, err := evalScalar(spec.RegionOf, map[string]any{"AS": asn})
		if err != nil {
			return fmt.Errorf("region_of: %w", err)
		}
		region = v
	}

	block, err := e.plan.Eval(ipam.FieldASBlock, ipam.Ctx{AS: asn})
	if err != nil {
		return err
	}
	blockV6 := ""
	if e.plan.Has(ipam.FieldASBlockV6) {
		if blockV6, err = e.plan.Eval(ipam.FieldASBlockV6, ipam.Ctx{AS: asn}); err != nil {
			return err
		}
	}

	as := &model.AS{
		ASN:        asn,
		Role:       role,
		Region:     region,
		Template:   tplName,
		OwnerGroup: e.ownerGroup(asn, spec),
		Nickname:   spec.Nickname,
		Block:      block,
		BlockV6:    blockV6,
		ExtPorts:   map[string]*model.ExtPortBinding{},
		Labels:     spec.Labels,
		Node:       spec.Node,
	}
	e.top.ASes[asn] = as

	// Routers, in deterministic ID order.
	routerNames := sortedKeys(tpl.Routers)
	sort.Slice(routerNames, func(i, j int) bool {
		return tpl.Routers[routerNames[i]].ID < tpl.Routers[routerNames[j]].ID
	})
	byName := map[string]*model.Device{}
	for _, rn := range routerNames {
		rs := tpl.Routers[rn]
		d := e.newDevice(as, rn, model.KindRouter, rs.DeviceDefaults)
		d.RouterID = rs.ID
		d.Services = append([]string{}, rs.Services...)
		d.L2Gateway = rs.L2Gateway
		byName[rn] = d
		as.Routers = append(as.Routers, d)

		// Loopback. Always present; owned by the student in student ASes since
		// configuring it is an explicit assignment task.
		lo := &model.Iface{
			Device: d,
			Name:   "lo",
			Role:   model.RoleLoopback,
			Owner:  e.ownerFor(as, tpl, rn, "lo"),
		}
		if e.plan.Has(ipam.FieldRouterLoopback) {
			addr, err := e.plan.Eval(ipam.FieldRouterLoopback, ipam.Ctx{AS: asn, RouterID: rs.ID, Name: rn})
			if err != nil {
				return err
			}
			lo.Addr4 = addr
		}
		if e.plan.Has(ipam.FieldRouterLoopbackV6) {
			addr, err := e.plan.Eval(ipam.FieldRouterLoopbackV6, ipam.Ctx{AS: asn, RouterID: rs.ID, Name: rn})
			if err != nil {
				return err
			}
			lo.Addr6 = addr
		}
		d.AddIface(lo)
	}

	// External ports must resolve to real routers.
	for _, pn := range sortedKeys(tpl.ExternalPorts) {
		ep := tpl.ExternalPorts[pn]
		r, ok := byName[ep.Router]
		if !ok {
			return fmt.Errorf("external_ports.%s references unknown router %q", pn, ep.Router)
		}
		as.ExtPorts[pn] = &model.ExtPortBinding{Name: pn, Router: r}
	}

	// Per-router L3 hosts.
	hostsEnabled := tpl.Hosts.PerRouter == nil || *tpl.Hosts.PerRouter
	hostName := orDefault(tpl.Hosts.Name, "host")
	for _, rn := range routerNames {
		rs := tpl.Routers[rn]
		if rs.Host != nil && !*rs.Host {
			continue
		}
		if !hostsEnabled && (rs.Host == nil || !*rs.Host) {
			continue
		}
		r := byName[rn]
		hostDev := e.newDevice(as, hostDeviceName(hostName, rn), model.KindHost, tpl.Hosts.DeviceDefaults)

		hostIface := rn + "router"
		if tpl.Hosts.Iface != "" {
			v, err := evalScalar(tpl.Hosts.Iface, map[string]any{"Router": rn, "AS": asn})
			if err != nil {
				return fmt.Errorf("hosts.iface: %w", err)
			}
			hostIface = v
		}

		subnet := ""
		if e.plan.Has(ipam.FieldRouterHost) {
			s, err := e.plan.Eval(ipam.FieldRouterHost, ipam.Ctx{AS: asn, RouterID: rs.ID, Name: rn})
			if err != nil {
				return err
			}
			subnet = s
		}
		hostAddr, routerAddr := hostPair(subnet)
		owner := e.ownerFor(as, tpl, rn, "host")

		hIf := &model.Iface{Device: hostDev, Name: hostIface, Role: model.RoleHostLink, Addr4: hostAddr, Owner: owner}
		rIf := &model.Iface{Device: r, Name: "host", Role: model.RoleHostLink, Addr4: routerAddr, Owner: owner}
		hostDev.AddIface(hIf)
		r.AddIface(rIf)
		e.link(hIf, rIf, model.LinkVeth, e.lab.LinkDefaults, subnet, owner)
	}

	// Internal router-router links.
	for li, il := range tpl.InternalLinks {
		a, ok := byName[il.A]
		if !ok {
			return fmt.Errorf("internal_links[%d]: unknown router %q", li, il.A)
		}
		b, ok := byName[il.B]
		if !ok {
			return fmt.Errorf("internal_links[%d]: unknown router %q", li, il.B)
		}
		subnet := ""
		if il.Subnet != "" {
			v, err := evalScalar(il.Subnet, map[string]any{
				"AS": asn, "RouterID": a.RouterID, "PeerID": b.RouterID, "LinkIndex": li,
			})
			if err != nil {
				return fmt.Errorf("internal_links[%d].subnet: %w", li, err)
			}
			subnet = v
		}
		if subnet == "" && e.plan.Has(ipam.FieldRouterRouter) {
			s, err := e.plan.Eval(ipam.FieldRouterRouter, ipam.Ctx{
				AS: asn, LinkIndex: li, RouterID: a.RouterID, PeerID: b.RouterID,
			})
			if err != nil {
				return err
			}
			subnet = s
		}
		aAddr, bAddr := hostPair(subnet)
		owner := e.ownerFor(as, tpl, il.A, "intra")
		aIf := &model.Iface{Device: a, Name: "port_" + il.B, Role: model.RoleIntraAS, Addr4: aAddr, Owner: owner}
		bIf := &model.Iface{Device: b, Name: "port_" + il.A, Role: model.RoleIntraAS, Addr4: bAddr, Owner: owner}
		a.AddIface(aIf)
		b.AddIface(bIf)
		e.link(aIf, bIf, model.LinkVeth, il.LinkProps.Merge(e.lab.LinkDefaults), subnet, owner)
	}

	// Layer-2 domains.
	for _, dn := range sortedKeys(tpl.L2Domains) {
		if err := e.expandL2Domain(as, tpl, byName, dn, tpl.L2Domains[dn]); err != nil {
			return fmt.Errorf("l2_domains.%s: %w", dn, err)
		}
	}

	for _, d := range as.Devices {
		e.top.Devices[d.ID] = d
	}
	return nil
}

// expandL2Domain builds the switches, L2 hosts, trunks and the gateway's VLAN
// sub-interfaces for one datacenter.
func (e *expander) expandL2Domain(as *model.AS, tpl *model.ASTemplate, routers map[string]*model.Device, name string, dom *model.L2Domain) error {
	gw, ok := routers[dom.Gateway]
	if !ok {
		return fmt.Errorf("gateway %q is not a router in this template", dom.Gateway)
	}

	vlans := sortedIntKeys(dom.VLANs)
	switchNames := sortedKeys(dom.Switches)
	if len(switchNames) == 0 {
		return fmt.Errorf("no switches declared")
	}

	sw := map[string]*model.Device{}
	for _, sn := range switchNames {
		ss := dom.Switches[sn]
		d := e.newDevice(as, l2DeviceName(name, sn), model.KindSwitch, ss.DeviceDefaults)
		d.L2Domain = name
		d.VLANs = vlans
		d.Name = sn
		sw[sn] = d
	}

	// The gateway uplink: one trunk from the first uplink switch to the router,
	// plus one VLAN sub-interface per VLAN on the router side. The sub-interface
	// names match what the course text tells students to expect, e.g. ATL-L2.10.
	uplinkSwitch := switchNames[0]
	for _, sn := range switchNames {
		if u := dom.Switches[sn].Uplink; u != nil && *u {
			uplinkSwitch = sn
			break
		}
	}
	trunkIface := fmt.Sprintf("%s-L2", dom.Gateway)
	gwIf := &model.Iface{Device: gw, Name: trunkIface, Role: model.RoleL2Uplink, Trunk: true,
		Owner: model.OwnerPlatform} // the parent trunk is never student-configured
	gw.AddIface(gwIf)

	swUplink := &model.Iface{Device: sw[uplinkSwitch], Name: "trunk_" + dom.Gateway,
		Role: model.RoleL2Trunk, Trunk: true, Owner: e.ownerFor(as, tpl, uplinkSwitch, "l2")}
	sw[uplinkSwitch].AddIface(swUplink)
	e.link(gwIf, swUplink, model.LinkVeth, e.lab.LinkDefaults, "", model.OwnerPlatform)

	// Router-side VLAN sub-interfaces carry the L3 gateway addresses.
	for vi, v := range vlans {
		sub := &model.Iface{
			Device: gw,
			Name:   fmt.Sprintf("%s.%d", trunkIface, v),
			Parent: trunkIface,
			VLAN:   v,
			Role:   model.RoleL2SubIface,
			Owner:  e.ownerFor(as, tpl, dom.Gateway, "l2"),
		}
		if e.plan.Has(ipam.FieldL2VLAN) {
			s, err := e.plan.Eval(ipam.FieldL2VLAN, ipam.Ctx{AS: as.ASN, L2ID: dom.ID, VLAN: v, VLANIndex: vi})
			if err != nil {
				return err
			}
			addr, _ := hostPair(s)
			sub.Addr4 = addr
		}
		if e.plan.Has(ipam.FieldL2VLANV6) {
			s, err := e.plan.Eval(ipam.FieldL2VLANV6, ipam.Ctx{AS: as.ASN, L2ID: dom.ID, VLAN: v, VLANIndex: vi})
			if err != nil {
				return err
			}
			addr6, _ := hostPairV6(s)
			sub.Addr6 = addr6
		}
		gw.AddIface(sub)
	}

	// Inter-switch trunks.
	for li, sl := range dom.SwitchLinks {
		a, ok := sw[sl.A]
		if !ok {
			return fmt.Errorf("switch_links[%d]: unknown switch %q", li, sl.A)
		}
		b, ok := sw[sl.B]
		if !ok {
			return fmt.Errorf("switch_links[%d]: unknown switch %q", li, sl.B)
		}
		aIf := &model.Iface{Device: a, Name: "trunk_" + sl.B, Role: model.RoleL2Trunk, Trunk: true,
			Owner: e.ownerFor(as, tpl, sl.A, "l2")}
		bIf := &model.Iface{Device: b, Name: "trunk_" + sl.A, Role: model.RoleL2Trunk, Trunk: true,
			Owner: e.ownerFor(as, tpl, sl.B, "l2")}
		a.AddIface(aIf)
		b.AddIface(bIf)
		e.link(aIf, bIf, model.LinkVeth, sl.LinkProps.Merge(e.lab.LinkDefaults), "", model.OwnerPlatform)
	}

	// L2 hosts in access VLANs.
	for _, hn := range sortedKeys(dom.Hosts) {
		h := dom.Hosts[hn]
		s, ok := sw[h.Switch]
		if !ok {
			return fmt.Errorf("hosts.%s: unknown switch %q", hn, h.Switch)
		}
		if _, declared := dom.VLANs[h.VLAN]; len(dom.VLANs) > 0 && !declared {
			return fmt.Errorf("hosts.%s: VLAN %d is not declared in vlans", hn, h.VLAN)
		}
		d := e.newDevice(as, hn, model.KindHost, h.DeviceDefaults)
		d.L2Domain = name
		owner := e.ownerFor(as, tpl, hn, "l2")
		hIf := &model.Iface{Device: d, Name: h.Switch, Role: model.RoleL2Access, VLAN: h.VLAN, Owner: owner}
		sIf := &model.Iface{Device: s, Name: "port_" + hn, Role: model.RoleL2Access, VLAN: h.VLAN, Owner: owner}
		d.AddIface(hIf)
		s.AddIface(sIf)
		e.link(hIf, sIf, model.LinkVeth, h.LinkProps.Merge(e.lab.LinkDefaults), "", owner)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Peerings
// ---------------------------------------------------------------------------

func (e *expander) expandPeerings() error {
	links, err := e.resolvePeeringLinks()
	if err != nil {
		return err
	}

	// Stable index per peering, so the addressing plan produces stable subnets
	// even if the manifest is reordered.
	keys := make([]string, 0, len(links))
	for _, l := range links {
		keys = append(keys, l.Key())
	}
	sort.Strings(keys)
	e.interASIndex = make(map[string]int, len(keys))
	for i, k := range keys {
		e.interASIndex[k] = i
	}

	sort.Slice(links, func(i, j int) bool { return links[i].Key() < links[j].Key() })

	for _, pl := range links {
		if err := e.expandOnePeering(pl); err != nil {
			return fmt.Errorf("peering %s: %w", pl.Key(), err)
		}
	}
	return nil
}

func (e *expander) expandOnePeering(pl model.PeeringLink) error {
	aAS, ok := e.top.ASes[pl.A]
	if !ok {
		return fmt.Errorf("AS %d is not declared", pl.A)
	}
	bAS, ok := e.top.ASes[pl.B]
	if !ok {
		return fmt.Errorf("AS %d is not declared", pl.B)
	}
	aR, err := e.resolveEndpoint(aAS, pl.APort, pl.ARouter)
	if err != nil {
		return fmt.Errorf("side a: %w", err)
	}
	bR, err := e.resolveEndpoint(bAS, pl.BPort, pl.BRouter)
	if err != nil {
		return fmt.Errorf("side b: %w", err)
	}

	idx := e.interASIndex[pl.Key()]
	subnet := pl.Subnet
	if subnet == "" {
		field := ipam.FieldInterAS
		ctx := ipam.Ctx{AS: pl.A, PeerAS: pl.B, LinkIndex: idx}
		if bAS.Role == model.RoleIXP && e.plan.Has(ipam.FieldIXPPeering) {
			field, ctx = ipam.FieldIXPPeering, ipam.Ctx{AS: pl.A, IXP: pl.B, LinkIndex: idx}
		} else if aAS.Role == model.RoleIXP && e.plan.Has(ipam.FieldIXPPeering) {
			field, ctx = ipam.FieldIXPPeering, ipam.Ctx{AS: pl.B, IXP: pl.A, LinkIndex: idx}
		}
		s, err := e.plan.Eval(field, ctx)
		if err != nil {
			return err
		}
		subnet = s
	}

	// At an IXP the addresses are prescribed (180.Z.0.<ASN>), because the
	// course text tells students the exact address to configure. On ordinary
	// inter-AS links the two groups must agree between themselves, so Twinet
	// records the expected .1/.2 convention but leaves it to the students.
	var aAddr, bAddr string
	if aAS.Role == model.RoleIXP || bAS.Role == model.RoleIXP {
		aAddr = hostInSubnet(subnet, pl.A)
		bAddr = hostInSubnet(subnet, pl.B)
	} else {
		aAddr, bAddr = hostPair(subnet)
	}

	owner := model.OwnerStudent
	if aAS.Role != model.RoleStudent && bAS.Role != model.RoleStudent {
		owner = model.OwnerPlatform
	}

	role := model.RoleInterAS
	if aAS.Role == model.RoleIXP || bAS.Role == model.RoleIXP {
		role = model.RoleIXPLink
	}

	aName := extIfaceName(bAS, pl.B)
	bName := extIfaceName(aAS, pl.A)
	aIf := &model.Iface{Device: aR, Name: aName, Role: role, Addr4: aAddr, Owner: ownerOf(aAS, owner)}
	bIf := &model.Iface{Device: bR, Name: bName, Role: role, Addr4: bAddr, Owner: ownerOf(bAS, owner)}
	aR.AddIface(aIf)
	bR.AddIface(bIf)

	l := e.link(aIf, bIf, model.LinkVeth, pl.LinkProps.Merge(e.lab.LinkDefaults), subnet, owner)
	l.InterAS = true
	l.Rel = pl.Rel
	return nil
}

func ownerOf(as *model.AS, def model.ConfigOwner) model.ConfigOwner {
	if as.Role == model.RoleStudent {
		return def
	}
	return model.OwnerPlatform
}

func extIfaceName(peer *model.AS, asn int) string {
	if peer.Role == model.RoleIXP {
		return fmt.Sprintf("ixp_%d", asn)
	}
	return fmt.Sprintf("ext_%d", asn)
}

func (e *expander) resolveEndpoint(as *model.AS, port, router string) (*model.Device, error) {
	if port != "" {
		b, ok := as.ExtPorts[port]
		if !ok {
			return nil, fmt.Errorf("AS %d has no external port %q (available: %s)",
				as.ASN, port, strings.Join(sortedKeys(as.ExtPorts), ", "))
		}
		return b.Router, nil
	}
	if router != "" {
		d, ok := e.top.DeviceInAS(as.ASN, router)
		if !ok {
			return nil, fmt.Errorf("AS %d has no router %q", as.ASN, router)
		}
		return d, nil
	}
	// An IXP or single-router AS has exactly one router; default to it.
	if len(as.Routers) == 1 {
		return as.Routers[0], nil
	}
	return nil, fmt.Errorf("AS %d has %d routers; specify a_port/a_router (or b_port/b_router)", as.ASN, len(as.Routers))
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

func (e *expander) expandServices() error {
	for _, name := range sortedKeys(e.lab.Services) {
		spec := e.lab.Services[name]
		svc := &model.Service{
			Name:   name,
			Kind:   spec.Kind,
			Spec:   spec,
			Attach: spec.Attach,
			Listen: spec.Listen,
			Config: spec.Config,
			Node:   spec.Node,
		}
		if spec.Attach != nil && (spec.Attach.PerAS == nil || *spec.Attach.PerAS) {
			svc.PerAS = true
		}
		e.top.Services[name] = svc

		if spec.Attach == nil {
			continue // a control-plane-only service such as the web UI
		}

		// One service container, with one interface into each AS that has the
		// attachment router. This mirrors the mini-Internet's MATRIX/DNS/
		// MEASUREMENT model, which the course text depends on.
		dev := e.newGlobalDevice(name, model.KindService, spec.DeviceDefaults)
		svc.Device = dev

		field := "svc_" + name
		for _, asn := range e.top.SortedASNs() {
			as := e.top.ASes[asn]
			if as.Role == model.RoleIXP {
				continue
			}
			if spec.Attach.Template != "" && as.Template != spec.Attach.Template {
				continue
			}
			r, ok := e.top.DeviceInAS(asn, spec.Attach.Router)
			if !ok {
				continue
			}
			subnet := ""
			if e.plan.Has(field) {
				s, err := e.plan.Eval(field, ipam.Ctx{AS: asn, Name: name, RouterID: r.RouterID})
				if err != nil {
					return fmt.Errorf("service %s: %w", name, err)
				}
				subnet = s
			}
			rAddr, sAddr := hostPair(subnet)
			// The service side of the link is always platform-configured; the
			// router side too, because the course explicitly tells students not
			// to reconfigure the dns/matrix/measurement interfaces.
			rIf := &model.Iface{Device: r, Name: spec.Attach.Iface, Role: model.RoleService,
				Addr4: rAddr, Owner: model.OwnerPlatform}
			sIf := &model.Iface{Device: dev, Name: fmt.Sprintf("as%d", asn), Role: model.RoleService,
				Addr4: sAddr, Owner: model.OwnerPlatform}
			r.AddIface(rIf)
			dev.AddIface(sIf)
			e.link(rIf, sIf, model.LinkService, e.lab.LinkDefaults, subnet, model.OwnerPlatform)
		}
		e.top.Devices[dev.ID] = dev
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (e *expander) newDevice(as *model.AS, name string, kind model.DeviceKind, over model.DeviceDefaults) *model.Device {
	d := e.materialize(name, kind, over, as.ASN)
	d.Owner = as.OwnerGroup
	as.Devices = append(as.Devices, d)
	return d
}

func (e *expander) newGlobalDevice(name string, kind model.DeviceKind, over model.DeviceDefaults) *model.Device {
	d := e.materialize(name, kind, over, 0)
	d.Owner = "staff"
	return d
}

func (e *expander) materialize(name string, kind model.DeviceKind, over model.DeviceDefaults, asn int) *model.Device {
	dd := over.Merge(e.lab.Kinds[kind]).Merge(e.lab.Defaults)
	d := &model.Device{
		ID:           model.DeviceID(asn, name),
		Name:         name,
		Kind:         kind,
		ASN:          asn,
		Image:        dd.Image,
		Memory:       dd.Memory,
		Restart:      orDefault(dd.Restart, "unless-stopped"),
		Env:          dd.Env,
		Sysctls:      dd.Sysctls,
		Capabilities: dd.Capabilities,
		Binds:        dd.Binds,
		Command:      dd.Command,
		Container:    model.ContainerName(e.lab.Metadata.Name, asn, name),
		Hostname:     hostnameFor(asn, name),
		Labels:       map[string]string{},
	}
	if dd.CPUs != nil {
		d.CPUs = *dd.CPUs
	}
	if dd.Pids != nil {
		d.Pids = *dd.Pids
	}
	if dd.Privileged != nil {
		d.Privileged = *dd.Privileged
	}
	return d
}

func (e *expander) link(a, b *model.Iface, kind model.LinkKind, props model.LinkProps, subnet string, owner model.ConfigOwner) *model.Link {
	id := model.MakeLinkID(a.Device.ID, a.Name, b.Device.ID, b.Name)
	l := &model.Link{ID: id, Kind: kind, A: a, B: b, Props: props, Subnet: subnet, Owner: owner}
	a.Link, b.Link = l, l
	a.Peer, b.Peer = b, a
	a.MAC = alloc.MAC(e.lab.Metadata.Name, a.Device.ID, a.Name)
	b.MAC = alloc.MAC(e.lab.Metadata.Name, b.Device.ID, b.Name)
	e.top.Links = append(e.top.Links, l)
	return l
}

func (e *expander) assignVNIs() {
	sort.Slice(e.top.Links, func(i, j int) bool { return e.top.Links[i].ID < e.top.Links[j].ID })
	ids := make([]string, 0, len(e.top.Links))
	for _, l := range e.top.Links {
		ids = append(ids, l.ID)
	}
	vnis := alloc.AssignVNIs(e.lab.Metadata.Name, ids)
	for _, l := range e.top.Links {
		l.VNI = vnis[l.ID]
	}
}

func (e *expander) stampLabels() {
	for _, d := range e.top.Devices {
		if d.Labels == nil {
			d.Labels = map[string]string{}
		}
		d.Labels["twinet.lab"] = e.lab.Metadata.Name
		d.Labels["twinet.device"] = d.Name
		d.Labels["twinet.kind"] = string(d.Kind)
		if d.ASN > 0 {
			d.Labels["twinet.as"] = strconv.Itoa(d.ASN)
			if as, ok := e.top.ASes[d.ASN]; ok {
				d.Labels["twinet.role"] = string(as.Role)
				if as.Region != "" {
					d.Labels["twinet.region"] = as.Region
				}
			}
		}
		if d.Owner != "" {
			d.Labels["twinet.owner"] = d.Owner
		}
	}
}

// computeHash stamps a content hash of the expanded topology, so a running
// deployment can be compared against a manifest without re-deriving anything.
func (e *expander) computeHash() {
	h := sha256.New()
	for _, d := range e.top.SortedDevices() {
		fmt.Fprintf(h, "d|%s|%s|%s|%s|%s\n", d.ID, d.Kind, d.Image, d.Hostname, d.Container)
		for _, i := range d.Ifaces {
			fmt.Fprintf(h, "  i|%s|%s|%s|%s|%d|%v|%s\n", i.Name, i.MAC, i.Addr4, i.Addr6, i.VLAN, i.Trunk, i.Owner)
		}
	}
	for _, l := range e.top.Links {
		fmt.Fprintf(h, "l|%s|%s|%s|%s|%s|%s|%d\n", l.ID, l.Kind, l.Subnet,
			l.Props.Bandwidth, l.Props.Delay, l.Props.Queue, l.VNI)
	}
	e.top.Hash = hex.EncodeToString(h.Sum(nil))[:16]
}

func (e *expander) ownerGroup(asn int, spec model.ASSpec) string {
	if spec.Role == model.RoleStudent || spec.Role == "" {
		if spec.OwnerGroup != "" {
			v, err := evalScalar(spec.OwnerGroup, map[string]any{"AS": asn})
			if err == nil {
				return v
			}
		}
		return fmt.Sprintf("group%d", asn)
	}
	return "staff"
}

// ownerFor decides whether Twinet or the student configures an object.
func (e *expander) ownerFor(as *model.AS, tpl *model.ASTemplate, device, domain string) model.ConfigOwner {
	if as.Role != model.RoleStudent {
		return model.OwnerPlatform
	}
	for _, r := range tpl.Provisioning.Provisioned {
		if r.Iface != nil && (r.Iface.Router == device || r.Iface.Device == device) {
			// A rule naming a specific interface is handled at the interface
			// level by the caller; at device granularity we keep student
			// ownership so the rest of the device stays unconfigured.
			continue
		}
		if r.DeviceKind != "" && string(r.DeviceKind) == domain {
			return model.OwnerPlatform
		}
	}
	return model.OwnerStudent
}

func hostnameFor(asn int, name string) string {
	if asn == 0 {
		return strings.ToLower(name)
	}
	return fmt.Sprintf("%s.as%d", strings.ToLower(name), asn)
}

func hostDeviceName(base, router string) string {
	if base == "host" {
		return router + "_host"
	}
	return router + "_" + base
}

func l2DeviceName(domain, sw string) string { return domain + "_" + sw }

// hostPair returns the conventional .1/.2 pair inside a subnet.
func hostPair(subnet string) (string, string) {
	if subnet == "" {
		return "", ""
	}
	a, err1 := ipam.Host(subnet, 1)
	b, err2 := ipam.Host(subnet, 2)
	if err1 != nil || err2 != nil {
		return "", ""
	}
	return a, b
}

// hostInSubnet returns the address whose host part is n, used at IXPs where the
// course prescribes 180.Z.0.<ASN>.
func hostInSubnet(subnet string, n int) string {
	a, err := ipam.Host(subnet, n)
	if err != nil {
		return ""
	}
	return a
}

func evalScalar(expr string, data map[string]any) (string, error) {
	t, err := template.New("x").Funcs(ipam.FuncMap()).Option("missingkey=error").Parse(expr)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(b.String()), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedIntKeys[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// hostPairV6 returns the ::1/::2 pair inside an IPv6 subnet.
func hostPairV6(subnet string) (string, string) {
	if subnet == "" {
		return "", ""
	}
	a, err1 := ipam.Host(subnet, 1)
	b, err2 := ipam.Host(subnet, 2)
	if err1 != nil || err2 != nil {
		return "", ""
	}
	return a, b
}
