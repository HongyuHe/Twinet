// Package harness derives a small, self-contained lab from a class topology so
// that one submission can be graded without the rest of the class being
// deployed, or even existing.
//
// Grading against a shared lab is convenient and wrong. Every submission
// observes the same network, so a group that misconfigures a border router
// changes the marks of the groups behind it, a group that blackholes a prefix
// can deny its neighbours the routes they are being marked on, and a re-run
// after one group resubmits silently re-marks everyone. None of that is visible
// in the output: the report says a check failed, not that it failed because of
// someone else's work.
//
// A harness is the fix. For a target AS it keeps that AS whole and replaces the
// rest of the internet with the smallest neighbourhood that still exercises it:
// each nearby AS is reduced to the routers that face the target, still
// announcing its own address block, still speaking the same relationship. From
// inside the student's AS the difference is invisible, because the sessions,
// the peers and the prefixes are the same ones.
//
// What is gained is that the harness is disposable. Its lab name is unique, and
// every derived identifier -- container names, VXLAN identifiers, veth aliases
// -- is a function of that name, so a hundred harnesses can run at once and be
// destroyed independently without a lock or a registry to fall out of date.
package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/model"
)

// CompactCompilerContract changes only when the meaning of Synthetic slicing
// or its generated reference peers changes. It deliberately is not the CLI
// source version: an ordinary controller bug-fix release must still verify a
// previously proven compact/full equivalence artifact.
const CompactCompilerContract = "compact-harness/v2"

// Options controls how much of the class topology a harness keeps.
type Options struct {
	// Depth is how many AS hops of neighbourhood to retain. Zero or less keeps
	// the whole class topology, which is the default and the only setting that
	// is safe without reading the rubric.
	//
	// Reduction is an optimisation, not the isolation mechanism. What isolates
	// one submission from another is that the harness is a private lab in which
	// every AS except the target is configured by Twinet's own reference
	// configuration, so no student's mistake can move another student's mark.
	// That property holds at any depth, including full breadth.
	//
	// Cutting ASes away is therefore a trade of fidelity for capacity, and it
	// is not free: a rubric that checks a session with a particular peer, or a
	// route learned from a particular origin, will fail a correct submission if
	// that AS was sliced off. Measured on the course lab, depth 1 cost a
	// correct submission most of its marks for exactly that reason. Reduce only
	// when the rubric is known to be local to the target's neighbourhood.
	Depth int

	// KeepHosts retains one host per neighbouring AS, needed when a rubric
	// measures reachability end to end rather than in the routing table.
	KeepHosts bool

	// Reduce keeps every autonomous system but only the routers of each that
	// face something already kept, plus one host apiece.
	//
	// Breadth and depth were the same setting, so the only way to make a
	// harness smaller was to cut autonomous systems off it -- and a rubric that
	// checks a session with a particular peer, or a route from a particular
	// origin, then fails a correct submission. Measured on the course lab,
	// depth 1 cost a correct submission most of its marks for exactly that.
	//
	// This keeps the whole internet and shrinks each neighbour to the part of
	// it the target can see: every peer is still there, every prefix is still
	// originated, and what disappears is eleven other systems' interior
	// routers, which no check about this submission can observe. That is what
	// makes a per-submission lab affordable, which is what makes marking a
	// hundred students in their own labs possible at all.
	Reduce bool

	// Synthetic collapses every retained non-target, non-IXP AS to one
	// deterministic reference router. Its external interfaces are preserved
	// and attached to that router, so the renderer still supplies the AS's
	// relationship policy, prefix origin, RPKI behaviour, and link properties
	// without paying for an unobservable interior. The target stays whole and
	// exchanges stay whole because their shared route-server semantics are
	// observable by the rubric.
	//
	// It is deliberately separate from Reduce: callers can retain the older
	// router-facing slice for an appeal, then compare it to this compact
	// substrate before releasing a synthetic-harness mark.
	Synthetic bool

	// Suffix distinguishes harnesses derived from the same target, so a
	// re-mark can run beside the original instead of replacing it.
	Suffix string
}

// Slice returns a new topology containing the target AS in full and a reduced
// neighbourhood around it.
//
// The result shares no mutable state with the input. A harness is deployed,
// mutated by a student's configuration and destroyed, and none of that may be
// visible to the class topology it came from or to a sibling harness being
// graded at the same moment on another node.
func Slice(top *model.Topology, target int, opts Options) (*model.Topology, error) {
	if top == nil {
		return nil, fmt.Errorf("nil topology")
	}
	if _, ok := top.ASes[target]; !ok {
		return nil, fmt.Errorf("AS %d is not in lab %q", target, top.Name)
	}

	keepAS := neighbourhood(top, target, opts.Depth)
	keepDev := devicesToKeep(top, target, keepAS, opts)
	collapsed := syntheticDeviceMap(top, target, keepAS, opts)

	name := harnessName(top.Name, target, opts.Suffix)
	out := &model.Topology{
		Lab:      top.Lab,
		Name:     name,
		Devices:  make(map[string]*model.Device, len(keepDev)),
		ASes:     make(map[int]*model.AS, len(keepAS)),
		Services: map[string]*model.Service{},
		// A harness is disposable by construction: it is a private copy of a
		// class network built to mark one submission, nobody's work lives in
		// it, and it must not outlive the run that asked for it. Marking it
		// here rather than at each call site means a future caller cannot
		// create one that a node would hold forever.
		Ephemeral: true,
	}

	for id := range keepDev {
		d, ok := top.Devices[id]
		if !ok {
			continue
		}
		nd := copyDevice(d)
		// Container names carry the lab name, so re-deriving here is what
		// keeps two harnesses of the same AS from colliding on one node.
		nd.Container = model.ContainerName(name, nd.ASN, nd.Name)
		out.Devices[id] = nd
	}

	for asn := range keepAS {
		src := top.ASes[asn]
		dst := &model.AS{
			ASN:           src.ASN,
			Role:          src.Role,
			Region:        src.Region,
			Template:      src.Template,
			OwnerGroup:    src.OwnerGroup,
			Nickname:      src.Nickname,
			Block:         src.Block,
			BlockV6:       src.BlockV6,
			Labels:        copyStrMap(src.Labels),
			ExtPorts:      map[string]*model.ExtPortBinding{},
			InteriorKind:  src.InteriorKind,
			Distributable: src.Distributable,
		}
		if asn != target {
			// A neighbour exists only to be a credible peer. It keeps its
			// number and its address block, because that is what the target is
			// marked on seeing, but it is no longer the class's copy of that
			// AS and must never itself be graded.
			dst.OwnerGroup = ""
			dst.Role = model.RoleStaff
			// Except an exchange, which is not a peer at all.
			//
			// The role is what tells the renderer to build a route server: one
			// that reflects between members and originates nothing. Rewriting
			// it to staff turned the exchange into an ordinary transit system,
			// so the session the target opens to the route server was to
			// something that was not one -- and a correct submission was
			// quarantined with "CHI->180.140.0.140 Active". Measured on the
			// cluster before this line existed.
			if src.Role == model.RoleIXP {
				dst.Role = model.RoleIXP
			}
		}
		for _, d := range src.Devices {
			if nd, ok := out.Devices[d.ID]; ok {
				dst.Devices = append(dst.Devices, nd)
			}
		}
		for _, r := range src.Routers {
			if nr, ok := out.Devices[r.ID]; ok {
				dst.Routers = append(dst.Routers, nr)
			}
		}
		for _, srcGroup := range src.PlacementGroups {
			if srcGroup == nil {
				continue
			}
			dstGroup := &model.PlacementGroup{
				ID: srcGroup.ID, ASN: srcGroup.ASN, Class: srcGroup.Class,
			}
			for _, d := range srcGroup.Devices {
				if nd, ok := out.Devices[d.ID]; ok {
					dstGroup.Devices = append(dstGroup.Devices, nd)
				}
			}
			if len(dstGroup.Devices) > 0 {
				dst.PlacementGroups = append(dst.PlacementGroups, dstGroup)
			}
		}
		for pname, b := range src.ExtPorts {
			if b == nil || b.Router == nil {
				continue
			}
			routerID := b.Router.ID
			if mapped := collapsed[routerID]; mapped != "" {
				routerID = mapped
			}
			if nr, ok := out.Devices[routerID]; ok {
				dst.ExtPorts[pname] = &model.ExtPortBinding{Name: pname, Router: nr}
			}
		}
		if len(dst.Devices) == 0 {
			continue
		}
		out.ASes[asn] = dst
	}

	if _, ok := out.ASes[target]; !ok {
		return nil, fmt.Errorf("AS %d has no devices after slicing", target)
	}
	copyKeptServices(top, out)

	// A link survives only if both endpoints do. Keeping a half-link would
	// configure an interface towards a router that was never deployed, which
	// converges to a session that is permanently down and a mark the student
	// cannot earn however correct their work is.
	var ids []string
	for _, l := range top.Links {
		if l.A == nil || l.B == nil {
			continue
		}
		aID, bID := devID(l.A), devID(l.B)
		if mapped := collapsed[aID]; mapped != "" {
			aID = mapped
		}
		if mapped := collapsed[bID]; mapped != "" {
			bID = mapped
		}
		// An interior link whose two ends collapsed into one synthetic
		// router cannot carry an observable inter-AS policy or origin.
		if aID == bID || !keepDev[aID] || !keepDev[bID] {
			continue
		}
		nl := copyLink(l)
		nl.A.Device = out.Devices[aID]
		nl.B.Device = out.Devices[bID]
		out.Links = append(out.Links, nl)
		ids = append(ids, nl.ID)
	}

	// VNIs are a function of the lab name, so a harness gets its own overlay
	// numbering without any coordination. Two harnesses may carry the same
	// link identity and must not share a tunnel.
	vnis := alloc.AssignVNIs(name, ids)
	for _, l := range out.Links {
		l.VNI = vnis[l.ID]
	}

	if opts.Synthetic {
		uniquifySyntheticIfaces(out, target)
	}
	rebind(out)
	if opts.Synthetic {
		pruneSyntheticDanglingSubinterfaces(out, target)
	}
	out.Hash = hashTopology(out)
	return out, nil
}

func copyKeptServices(source, target *model.Topology) {
	for name, service := range source.Services {
		if service == nil {
			continue
		}
		copy := *service
		copy.Device = nil
		copy.Replicas = nil
		copy.Config = copyStrMap(service.Config)
		copy.Attachments = map[int]string{}

		retainedReplicas := map[string]bool{}
		for _, replica := range service.Replicas {
			if replica == nil || replica.Device == nil {
				continue
			}
			device := target.Devices[replica.Device.ID]
			if device == nil {
				continue
			}
			replicaCopy := *replica
			replicaCopy.Device = device
			copy.Replicas = append(copy.Replicas, &replicaCopy)
			retainedReplicas[replica.ID] = true
		}
		if service.Device != nil {
			copy.Device = target.Devices[service.Device.ID]
		}
		if copy.Device == nil && len(copy.Replicas) > 0 {
			copy.Device = copy.Replicas[0].Device
		}
		if copy.Device == nil {
			continue
		}
		for asn, replicaID := range service.Attachments {
			if target.ASes[asn] == nil {
				continue
			}
			if len(service.Replicas) == 0 || retainedReplicas[replicaID] {
				copy.Attachments[asn] = replicaID
			}
		}
		target.Services[name] = &copy
	}
}

// neighbourhood returns the ASes within depth AS hops of the target.
func neighbourhood(top *model.Topology, target, depth int) map[int]bool {
	adj := map[int]map[int]bool{}
	for _, l := range top.Links {
		if !l.InterAS || l.A == nil || l.B == nil || asnOf(l.A) == asnOf(l.B) {
			continue
		}
		a, b := asnOf(l.A), asnOf(l.B)
		if adj[a] == nil {
			adj[a] = map[int]bool{}
		}
		if adj[b] == nil {
			adj[b] = map[int]bool{}
		}
		adj[a][b] = true
		adj[b][a] = true
	}

	keep := map[int]bool{target: true}
	if depth <= 0 {
		// Full breadth: every AS is kept, and the harness differs from the
		// class lab only in who owns the target and in being disposable.
		for asn := range top.ASes {
			keep[asn] = true
		}
		return keep
	}
	frontier := []int{target}
	for hop := 0; hop < depth; hop++ {
		var next []int
		for _, asn := range frontier {
			peers := make([]int, 0, len(adj[asn]))
			for p := range adj[asn] {
				peers = append(peers, p)
			}
			sort.Ints(peers)
			for _, p := range peers {
				if !keep[p] {
					keep[p] = true
					next = append(next, p)
				}
			}
		}
		frontier = next
	}
	return keep
}

// devicesToKeep decides which devices of each retained AS to deploy.
func devicesToKeep(top *model.Topology, target int, keepAS map[int]bool, opts Options) map[string]bool {
	keep := map[string]bool{}

	if opts.Depth <= 0 && !opts.Reduce && !opts.Synthetic {
		// Full breadth keeps every device. A reachability check that ends at a
		// host, or an IGP check that crosses an interior router, must find the
		// same network the class lab has.
		for _, d := range top.Devices {
			keep[d.ID] = true
		}
		return keep
	}

	if opts.Synthetic {
		return syntheticDevicesToKeep(top, target, keepAS)
	}

	// The target is kept whole: it is the thing under test, and any check that
	// touches an internal router is a check about the student's own IGP.
	for _, d := range top.ASes[target].Devices {
		keep[d.ID] = true
	}

	// An IXP is kept whole. Its entire value is that it is shared, and
	// reducing it would turn a route server with several members into one with
	// a single member, so the import policy that makes it interesting would
	// never fire and the student would be marked on a session that cannot
	// exhibit the behaviour being marked.
	//
	// Kept whole means kept: the loop below adds routers that face something
	// already kept, and it runs after this, so the members reach the exchange.
	// When this was skipped -- which it was for every reduced harness, because
	// the exchange was only considered for systems inside the retained
	// neighbourhood and reduction retains all of them by a different path --
	// the route server was absent, the target's session to it stayed in
	// Active, and a correct submission was quarantined for it. Measured.
	for asn := range keepAS {
		as := top.ASes[asn]
		if as == nil || asn == target || as.Role != model.RoleIXP {
			continue
		}
		for _, d := range as.Devices {
			keep[d.ID] = true
		}
	}

	// The services the target is cabled to are kept.
	//
	// They belong to no autonomous system, so the rule below -- which keeps
	// routers of retained systems -- skipped them, and the target came up with
	// no interface where the manifest says one is. Its own configuration then
	// failed on the line that addresses it, and the submission was quarantined
	// for something nobody had done. The trust anchor, the resolver and the
	// measurement host are part of the network the exercises are about.
	for _, l := range top.Links {
		if l.A == nil || l.B == nil {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			other := l.B
			if side == l.B {
				other = l.A
			}
			d, ok := top.Devices[devID(side)]
			if !ok || d.Kind != model.KindService {
				continue
			}
			if o, ok := top.Devices[devID(other)]; ok && o.ASN == target {
				keep[d.ID] = true
			}
		}
	}

	// Every other retained AS keeps only the routers that face something
	// already kept. Iterated to a fixed point, so an AS two hops out keeps the
	// router facing its own neighbour rather than only the target.
	for {
		grew := false
		for _, l := range top.Links {
			if l.A == nil || l.B == nil {
				continue
			}
			for _, side := range []*model.Iface{l.A, l.B} {
				other := l.B
				if side == l.B {
					other = l.A
				}
				if keep[devID(side)] || !keep[devID(other)] || !keepAS[asnOf(side)] {
					continue
				}
				d, ok := top.Devices[devID(side)]
				if !ok || d.Kind == model.KindHost {
					continue
				}
				keep[devID(side)] = true
				grew = true
			}
		}
		if !grew {
			break
		}
	}

	if opts.KeepHosts || opts.Reduce {
		asns := make([]int, 0, len(keepAS))
		for asn := range keepAS {
			asns = append(asns, asn)
		}
		sort.Ints(asns)
		for _, asn := range asns {
			as := top.ASes[asn]
			if as == nil || asn == target {
				continue
			}
			if h := firstHostAttachedTo(top, as, keep); h != nil {
				keep[h.ID] = true
			}
		}
	}
	return keep
}

// syntheticDevicesToKeep retains the submission unchanged and selects one
// deterministic reference router for every other ordinary AS. Links are
// rebound to those selected routers in Slice, which retains the real
// relationship graph and AS-level policy while removing remote interiors.
func syntheticDevicesToKeep(top *model.Topology, target int, keepAS map[int]bool) map[string]bool {
	keep := map[string]bool{}
	for asn := range keepAS {
		as := top.ASes[asn]
		if as == nil {
			continue
		}
		switch {
		case asn == target:
			for _, device := range as.Devices {
				keep[device.ID] = true
			}
		case as.Role == model.RoleIXP:
			// A route server's set of members is the observable behaviour;
			// reducing it changes which policy can fire.
			for _, device := range as.Devices {
				keep[device.ID] = true
			}
		default:
			if router := syntheticAnchor(as); router != nil {
				keep[router.ID] = true
			}
		}
	}
	// Services are not AS members. Keep only those directly attached to the
	// target: the target's DNS/RPKI/measurement contract is observable, while
	// a remote AS's duplicate service attachment is not.
	for _, link := range top.Links {
		if link.A == nil || link.B == nil {
			continue
		}
		for _, side := range []*model.Iface{link.A, link.B} {
			other := link.B
			if side == link.B {
				other = link.A
			}
			if side.Device == nil || other == nil || other.Device == nil {
				continue
			}
			if side.Device.Kind == model.KindService && other.Device.ASN == target {
				keep[side.Device.ID] = true
			}
		}
	}
	return keep
}

// syntheticDeviceMap maps every remote ordinary-AS device to its selected
// synthetic router. Target and IXP devices keep their original identity.
func syntheticDeviceMap(top *model.Topology, target int, keepAS map[int]bool, opts Options) map[string]string {
	if !opts.Synthetic {
		return nil
	}
	out := map[string]string{}
	for asn := range keepAS {
		as := top.ASes[asn]
		if as == nil || asn == target || as.Role == model.RoleIXP {
			continue
		}
		anchor := syntheticAnchor(as)
		if anchor == nil {
			continue
		}
		for _, device := range as.Devices {
			out[device.ID] = anchor.ID
		}
	}
	return out
}

func syntheticAnchor(as *model.AS) *model.Device {
	if as == nil {
		return nil
	}
	routers := append([]*model.Device(nil), as.Routers...)
	sort.Slice(routers, func(i, j int) bool { return routers[i].ID < routers[j].ID })
	for _, router := range routers {
		if router != nil && router.IsRouter() {
			return router
		}
	}
	return nil
}

// uniquifySyntheticIfaces makes a collapsed router's many inherited external
// interfaces valid Linux names and derives matching MAC identities. The target
// and route servers keep their authored names because checks name those
// interfaces directly.
func uniquifySyntheticIfaces(top *model.Topology, target int) {
	if top == nil {
		return
	}
	links := append([]*model.Link(nil), top.Links...)
	sort.Slice(links, func(i, j int) bool { return links[i].ID < links[j].ID })
	used := map[string]map[string]bool{}
	for _, link := range links {
		for sideIndex, side := range []*model.Iface{link.A, link.B} {
			if side == nil || side.Device == nil || side.Device.ASN == target {
				continue
			}
			as := top.ASes[side.Device.ASN]
			if as == nil || as.Role == model.RoleIXP {
				continue
			}
			if used[side.Device.ID] == nil {
				used[side.Device.ID] = map[string]bool{}
			}
			name := side.Name
			if name == "" || used[side.Device.ID][name] {
				name = syntheticIfaceName(link.ID, byte('a'+sideIndex), used[side.Device.ID])
				side.Name = name
			}
			used[side.Device.ID][name] = true
			side.MAC = alloc.MAC(top.Name, side.Device.ID, name)
		}
	}
}

func syntheticIfaceName(linkID string, side byte, used map[string]bool) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(linkID))
	_, _ = h.Write([]byte{side})
	for salt := 0; ; salt++ {
		name := fmt.Sprintf("syn%010x", h.Sum64()&0xFFFFFFFFFF)
		if salt > 0 {
			name = fmt.Sprintf("s%02x%09x", salt&0xff, h.Sum64()&0x1FFFFFFFFF)
		}
		if !used[name] {
			return name
		}
		_, _ = h.Write([]byte{byte(salt + 1)})
	}
}

// firstHostAttachedTo finds a host of as directly attached to a router already
// kept, so adding it does not also require adding that AS's interior.
func firstHostAttachedTo(top *model.Topology, as *model.AS, keep map[string]bool) *model.Device {
	cand := map[string]*model.Device{}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost {
			cand[d.ID] = d
		}
	}
	var best *model.Device
	for _, l := range top.Links {
		if l.A == nil || l.B == nil {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			other := l.B
			if side == l.B {
				other = l.A
			}
			h, ok := cand[devID(side)]
			if !ok || !keep[devID(other)] {
				continue
			}
			if best == nil || h.ID < best.ID {
				best = h
			}
		}
	}
	return best
}

// devID and asnOf read an interface's owning device. Interfaces point at their
// device rather than naming it, so a slice must go through the pointer that the
// original graph still holds while the copy is being built.
func devID(i *model.Iface) string {
	if i == nil || i.Device == nil {
		return ""
	}
	return i.Device.ID
}

func asnOf(i *model.Iface) int {
	if i == nil || i.Device == nil {
		return 0
	}
	return i.Device.ASN
}

func copyDevice(d *model.Device) *model.Device {
	nd := *d
	nd.Env = copyStrMap(d.Env)
	nd.Sysctls = copyStrMap(d.Sysctls)
	nd.Labels = copyStrMap(d.Labels)
	nd.Ifaces = nil
	for _, i := range d.Ifaces {
		ni := *i
		ni.Device = &nd
		nd.Ifaces = append(nd.Ifaces, &ni)
	}
	if d.FRR != nil {
		f := *d.FRR
		nd.FRR = &f
	}
	return &nd
}

func copyLink(l *model.Link) *model.Link {
	nl := *l
	a, b := *l.A, *l.B
	nl.A, nl.B = &a, &b
	return &nl
}

// rebind points each copied device's interface list at the copied links.
//
// Copying nodes and edges independently leaves two versions of every attached
// interface. The renderer reads one and the deployer configures the other, so
// the router would be handed an address that is never applied to a wire.
func rebind(top *model.Topology) {
	byDev := map[string][]*model.Iface{}
	for _, l := range top.Links {
		l.A.Link, l.B.Link = l, l
		l.A.Peer, l.B.Peer = l.B, l.A
		if d, ok := top.Devices[devID(l.A)]; ok {
			l.A.Device = d
		}
		if d, ok := top.Devices[devID(l.B)]; ok {
			l.B.Device = d
		}
		byDev[devID(l.A)] = append(byDev[devID(l.A)], l.A)
		byDev[devID(l.B)] = append(byDev[devID(l.B)], l.B)
	}
	for _, d := range top.Devices {
		id := d.ID
		var unlinked []*model.Iface
		for _, i := range d.Ifaces {
			if i.Link == nil {
				unlinked = append(unlinked, i)
			}
		}
		d.Ifaces = append(unlinked, byDev[id]...)
		sort.SliceStable(d.Ifaces, func(a, b int) bool { return d.Ifaces[a].Name < d.Ifaces[b].Name })
	}
}

// pruneSyntheticDanglingSubinterfaces removes child interfaces whose physical
// parent disappeared when a remote AS was collapsed to one reference router.
// The target and route servers are never reduced, so their authored interface
// contract remains exact.
func pruneSyntheticDanglingSubinterfaces(top *model.Topology, target int) {
	for _, device := range top.Devices {
		as := top.ASes[device.ASN]
		if device.ASN == target || as == nil || as.Role == model.RoleIXP {
			continue
		}
		for {
			present := make(map[string]bool, len(device.Ifaces))
			for _, iface := range device.Ifaces {
				present[iface.Name] = true
			}
			kept := device.Ifaces[:0]
			removed := false
			for _, iface := range device.Ifaces {
				if iface.Parent != "" && !present[iface.Parent] {
					removed = true
					continue
				}
				kept = append(kept, iface)
			}
			device.Ifaces = kept
			if !removed {
				break
			}
		}
	}
}

func copyStrMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func hashTopology(t *model.Topology) string {
	h := sha256.New()
	for _, d := range t.SortedDevices() {
		fmt.Fprintf(h, "d|%s|%s|%s|%s\n", d.ID, d.Kind, d.Image, d.Container)
		for _, i := range d.Ifaces {
			fmt.Fprintf(h, "  i|%s|%s|%s|%s\n", i.Name, i.MAC, i.Addr4, i.Owner)
		}
	}
	for _, l := range t.Links {
		fmt.Fprintf(h, "l|%s|%s|%s|%d\n", l.ID, l.Kind, l.Subnet, l.VNI)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// harnessName derives a lab name unique to this submission. Every other
// identifier is a function of it, so uniqueness here buys isolation everywhere.
func harnessName(lab string, asn int, suffix string) string {
	base := fmt.Sprintf("%s-g%d", lab, asn)
	if suffix == "" {
		return base
	}
	// The readable part is sanitised and truncated, which on its own is a
	// collision waiting to happen: "group 7 (late)" and "group-7-late" reduce
	// to the same thing, and so does anything sharing a 24-byte prefix. Two
	// submissions with the same harness name share container names and overlay
	// identifiers, so one deployment reconfigures the other's routers and the
	// marks are meaningless. The digest is of the raw identity, so distinct
	// submissions stay distinct however they are written.
	h := fnv.New64a()
	_, _ = h.Write([]byte(suffix))
	return fmt.Sprintf("%s-%s%x", base, sanitise(suffix), h.Sum64()&0xffff)
}

func sanitise(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 24 {
		out = strings.Trim(out[:24], "-")
	}
	return out
}

// Summary records what a slice retained, written alongside the mark. A student
// who disputes a grade is entitled to know exactly which network produced it.
type Summary struct {
	Lab      string `json:"lab"`
	Target   int    `json:"target_as"`
	ASes     []int  `json:"ases"`
	Devices  int    `json:"devices"`
	Links    int    `json:"links"`
	Depth    int    `json:"depth"`
	From     string `json:"reduced_from"`
	FullSize string `json:"full_size"`
}

// Describe summarises a harness against the topology it came from.
func Describe(full, h *model.Topology, target, depth int) Summary {
	fs, hs := full.Stats(), h.Stats()
	return Summary{
		Lab: h.Name, Target: target, ASes: h.SortedASNs(),
		Devices: hs.Devices, Links: hs.Links, Depth: depth,
		From:     full.Name,
		FullSize: fmt.Sprintf("%d devices, %d links", fs.Devices, fs.Links),
	}
}
