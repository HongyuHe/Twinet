// Package place assigns autonomous systems to cluster nodes.
//
// The default unit of placement is the AS, not the container. That single
// decision is what makes scaling out cheap: an AS's internal links are
// numerous, fast and unshaped, so they stay local veths, while its inter-AS
// links are few and already throttled to a megabit with milliseconds of
// emulated delay, so carrying them over a VXLAN tunnel costs nothing a student
// can observe. A declared distributable Clos is the deliberate narrow
// exception: its spine group and complete leaf groups can split at their
// fabric boundary.
//
// For an eighty-AS class that is roughly two thousand intra-AS links kept local
// and a couple of hundred crossing the fabric.
package place

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	serviceplan "github.com/HongyuHe/twinet/internal/service"
)

// Assignment is the computed placement.
type Assignment struct {
	// ByAS maps AS number to node name.
	ByAS map[int]string
	// ByGroup maps a shape-aware placement group to its node. It is empty for
	// ordinary atomic ASes, so callers and records that only know ByAS remain
	// fully compatible.
	ByGroup map[string]string
	// ByService maps service name to node name.
	//
	// It remains the primary/legacy singleton location. ByServiceReplica is
	// authoritative for a service expanded into multiple replicas.
	ByService map[string]string
	// ByServiceReplica maps a stable logical replica ID to its node.
	ByServiceReplica map[string]string
	// Load is the per-node container count.
	Load map[string]int
	// CrossNodeLinks counts links whose endpoints landed on different nodes.
	CrossNodeLinks int
	// Locality reports local and cross-node links by their topology class.
	Locality map[model.LinkClass]LinkLocality
	// Moved records ASes that could not be left where the record says they
	// were, and why. Each one is a set of containers that will be rebuilt.
	Moved []string
	// Overloaded names nodes whose resource requests exceed effective
	// allocatable capacity. Strict placement refuses these; an audited
	// overcommit retains the diagnostics for the deployment record and UI.
	Overloaded []string
}

// LinkLocality is the placement outcome for one class of link.
type LinkLocality struct {
	Local     int
	CrossNode int
}

// Record is the assignment in the form it is written down in.
func (a *Assignment) Record(lab, strategy string) *Record {
	r := &Record{Lab: lab, Strategy: strategy,
		ByAS: map[int]string{}, ByGroup: map[string]string{}, ByService: map[string]string{},
		ByServiceReplica: map[string]string{}}
	for k, v := range a.ByAS {
		r.ByAS[k] = v
	}
	for k, v := range a.ByGroup {
		r.ByGroup[k] = v
	}
	for k, v := range a.ByService {
		r.ByService[k] = v
	}
	for k, v := range a.ByServiceReplica {
		r.ByServiceReplica[k] = v
	}
	return r
}

// Options tune the placer.
type Options struct {
	// Strategy is pack-by-as, spread-by-as or single-node.
	Strategy string
	// Fixed is where a previous deployment put each AS and service, read back
	// from the record. Anything named here stays where it is.
	//
	// Determinism for one manifest is not enough. Placement is recomputed by
	// every command that has to find a device -- exec, grade, save, the
	// gateway -- so if the answer ever changes, those commands look for
	// containers on nodes that do not have them, and report "no such
	// container" without a hint that the lab is fine and the arithmetic is
	// not. Adding one student to a term already running is enough to move
	// most of the others.
	Fixed *Record
	// Rebalance recomputes from scratch, ignoring the record. Containers move,
	// so it is never implicit.
	Rebalance bool
	// Inventory is the live allocatable and already-reserved state reported by
	// agents. It is optional for offline inspection and mandatory for strict
	// clustered admission.
	Inventory []NodeInventory
	// Strict refuses unknown or over-capacity assignments before placement
	// records or deployment operations can be written.
	Strict bool
	// Overcommit permits an explicit audited escape from Strict. Callers must
	// persist and report this choice; it is never inferred from a warning.
	Overcommit bool
	// Unavailable removes declared nodes from candidate placement without
	// editing the manifest. Node drain uses it while the source remains
	// reachable for a fenced capture; node-loss recovery normally removes the
	// failed node from the active topology before calling Place.
	Unavailable map[string]bool
}

// Record is a placement as it was actually deployed.
type Record struct {
	Lab       string            `json:"lab"`
	Strategy  string            `json:"strategy"`
	ByAS      map[int]string    `json:"by_as"`
	ByGroup   map[string]string `json:"by_group,omitempty"`
	ByService map[string]string `json:"by_service"`
	// ByServiceReplica was added after the singleton service record. Omit it
	// for old graphs so their durable record wire format remains unchanged.
	ByServiceReplica map[string]string `json:"by_service_replica,omitempty"`
	// Overcommit records an operator's explicit admission override so a
	// capacity incident can be traced back to the deployment that accepted it.
	Overcommit bool `json:"overcommit,omitempty"`
}

// Place assigns every AS and service to a node and writes the result back onto
// the topology's devices.
//
// Placement is deterministic for a given manifest: ASes are considered in
// ascending order and ties are broken by node name, so redeploying never
// shuffles a group onto a different machine. That matters because a shuffle
// would rebuild containers a student is working in.
func Place(top *model.Topology, opts Options) (*Assignment, error) {
	lab := top.Lab
	nodes := lab.Placement.Nodes
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes declared under placement.nodes")
	}
	strategy := opts.Strategy
	if strategy == "" {
		strategy = lab.Placement.Strategy
	}
	if strategy == "" {
		strategy = "pack-by-as"
	}

	front := lab.FrontNode()
	if opts.Unavailable[front] {
		for _, node := range lab.Placement.Nodes {
			if !opts.Unavailable[node.Name] {
				front = node.Name
				break
			}
		}
	}
	a := &Assignment{
		ByAS:             map[int]string{},
		ByGroup:          map[string]string{},
		ByService:        map[string]string{},
		ByServiceReplica: map[string]string{},
		Load:             map[string]int{},
	}
	capacity := buildCapacityState(top, opts)
	names, caps, hasCap := capacity.names, capacity.caps, capacity.hasCap
	loads := map[string]demand{}
	for node, load := range capacity.baseline {
		loads[node] = load
	}

	if strategy == "single-node" {
		for _, asn := range top.SortedASNs() {
			a.ByAS[asn] = front
		}
		for _, name := range top.SortedServiceNames() {
			service := top.Services[name]
			if service == nil {
				continue
			}
			for _, replica := range service.SortedReplicas() {
				if replica != nil {
					a.ByServiceReplica[replica.ID] = front
				}
			}
			a.ByService[name] = front
		}
		if opts.Strict && !opts.Overcommit {
			if err := strictAssignmentError(top, a, capacity); err != nil {
				return nil, err
			}
		}
		res, err := finish(top, a)
		if err != nil {
			return nil, err
		}
		res.Overloaded = overloads(top, a, capacity)
		return res, nil
	}
	if len(names) == 0 {
		if opts.Strict && !opts.Overcommit {
			return nil, fmt.Errorf(
				"strict admission has no node with complete allocatable inventory: %s. "+
					"Unknown capacity is neither zero nor unlimited; fix inventory or declare safe capacities, or use the audited --overcommit escape hatch",
				capacity.unknownSummary())
		}
		return nil, fmt.Errorf("no nodes declared under placement.nodes")
	}

	// Explicit pins win over everything.
	pinned := map[int]string{}
	explicitPinned := map[int]bool{}
	pinnedSvc := map[string]string{}
	for _, p := range lab.Placement.Pin {
		for _, asn := range top.SortedASNs() {
			as := top.ASes[asn]
			if matches(p.Match, asn, as) {
				pinned[asn] = p.Node
				explicitPinned[asn] = true
			}
		}
		if p.Match.Service != "" {
			for _, s := range top.SortedServiceNames() {
				if p.Match.Service == "*" || p.Match.Service == s {
					pinnedSvc[s] = p.Node
				}
			}
		}
	}
	// An AS may also pin itself.
	for _, asn := range top.SortedASNs() {
		if n := top.ASes[asn].Node; n != "" {
			pinned[asn] = n
			explicitPinned[asn] = true
		}
	}

	// Where the lab is already running, unless a rebalance was asked for.
	//
	// A recorded assignment is honoured even when the placer would now choose
	// otherwise, because moving an AS destroys and rebuilds every container in
	// it. A node that has since been removed from the manifest is the one case
	// where the AS has to move, and that is reported rather than silently
	// obeyed.
	var moved []string
	if opts.Fixed != nil && !opts.Rebalance {
		for _, asn := range top.SortedASNs() {
			n, ok := opts.Fixed.ByAS[asn]
			if !ok {
				continue
			}
			if _, alreadyPinned := pinned[asn]; alreadyPinned {
				continue
			}
			if !capacity.allNodeName[n] {
				moved = append(moved, fmt.Sprintf("AS %d was on %s, which is no longer a node", asn, n))
				continue
			}
			pinned[asn] = n
		}
		if opts.Strict && !opts.Overcommit {
			groups := make([]string, 0, len(opts.Fixed.ByGroup))
			for group := range opts.Fixed.ByGroup {
				groups = append(groups, group)
			}
			sort.Strings(groups)
			for _, group := range groups {
				node := opts.Fixed.ByGroup[group]
				if capacity.allNodeName[node] && len(capacity.unknown[node]) > 0 {
					return nil, fmt.Errorf(
						"strict admission refuses recorded placement group %s on %s because allocatable %s is unknown; "+
							"use the audited --overcommit escape hatch only when this is intentional",
						group, node, strings.Join(capacity.unknown[node], ", "))
				}
			}
		}
	}

	// Singleton services retain their historic front-node default. Scalable
	// services instead keep a recorded replica placement (or their stable
	// home) and are attached locally after AS placement below.
	serviceMoves, err := placeServices(top, a, names, caps, hasCap, loads, pinnedSvc,
		opts.Fixed, opts.Rebalance, front)
	if err != nil {
		return nil, err
	}
	moved = append(moved, serviceMoves...)

	// What each AS costs, in every dimension a node can run out of. Counting
	// containers alone treats eight small routers and eight four-core ones as
	// the same, so a node accepts both and the second lab starves -- and it
	// starves at run time, as apparent congestion, not at placement time as a
	// refusal anyone could act on.
	weight := map[int]demand{}
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		var d demand
		if as.Distributable {
			d = placementAnchorDemand(as)
		} else {
			for _, dev := range as.Devices {
				d = d.add(deviceDemand(dev))
			}
		}
		weight[asn] = d
	}
	// Honour pins first so their weight is reflected before packing the rest.
	var free []int
	for _, asn := range top.SortedASNs() {
		if n, ok := pinned[asn]; ok {
			if !capacity.allNodeName[n] {
				return nil, fmt.Errorf("AS %d is pinned to unknown node %q", asn, n)
			}
			if opts.Strict && !opts.Overcommit && len(capacity.unknown[n]) > 0 {
				return nil, fmt.Errorf(
					"strict admission refuses pinned AS %d on %s because allocatable %s is unknown; "+
						"use the audited --overcommit escape hatch only when this is intentional",
					asn, n, strings.Join(capacity.unknown[n], ", "))
			}
			a.ByAS[asn] = n
			loads[n] = loads[n].add(weight[asn])
			a.Load[n] += weight[asn].Containers
			continue
		}
		free = append(free, asn)
	}

	switch strategy {
	case "pack-by-as", "spread-by-as":
		// Both walk the peering graph so that each AS is placed while its
		// neighbours are known, and both keep the cluster balanced. They
		// differ in how much imbalance they will accept in exchange for
		// locality: pack-by-as trades a little, spread-by-as almost none.
		//
		// This is the pass the design has always described and the code did
		// not do: without it both strategies put each AS on whichever node
		// was emptiest, which for a chain of peering ASes deals them out
		// round-robin and turns very nearly every inter-AS link into a
		// tunnel -- the exact opposite of the stated objective.
		// How much imbalance each strategy will trade for locality, as a
		// fraction of a node's capacity. pack-by-as accepts a tenth of a node
		// to keep peering ASes together; spread-by-as accepts none, so
		// locality only breaks an exact tie.
		tolerance := 0.0
		if strategy == "pack-by-as" {
			tolerance = 0.10
		}
		g := buildAffinity(top)
		nominal := nominalCapacity(names, caps, hasCap, len(top.Devices))
		for _, asn := range orderForLocality(free, g, weight) {
			n, err := bestForLocality(names, loads, caps, hasCap, weight[asn], tolerance, nominal,
				func(node string) int { return g.pull(asn, node, a.ByAS, front) })
			if err != nil {
				return nil, fmt.Errorf("AS %d: %w", asn, err)
			}
			a.ByAS[asn] = n
			loads[n] = loads[n].add(weight[asn])
			a.Load[n] += weight[asn].Containers
		}
		// The greedy pass places each AS knowing only the ones before it.
		// Local search repairs the choices that later ASes made bad.
		refine(names, a.ByAS, g, weight, loads, caps, hasCap, pinned, front, tolerance, nominal)
		a.Load = map[string]int{}
		for _, n := range names {
			a.Load[n] = loads[n].Containers
		}
	default:
		return nil, fmt.Errorf("unknown placement strategy %q; use pack-by-as, spread-by-as or single-node", strategy)
	}

	if splitMoved, err := distributePlacementGroups(top, a, names, caps, hasCap, capacity.baseline, opts, explicitPinned); err != nil {
		return nil, err
	} else {
		moved = append(moved, splitMoved...)
	}

	// This check deliberately happens before finish stamps Node onto any
	// device. A strict refusal must leave no placement record-worthy mutation,
	// including for pins, recorded locations, services, and split groups.
	if opts.Strict && !opts.Overcommit {
		if err := strictAssignmentError(top, a, capacity); err != nil {
			return nil, err
		}
	}
	res, err := finish(top, a)
	if err != nil {
		return nil, err
	}
	res.Moved = moved
	res.Overloaded = overloads(top, a, capacity)
	return res, nil
}

// sortedNodeNames returns names in stable order for capacity diagnostics.
func sortedNodeNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// finish resolves every device onto a node and computes summary statistics.
// Strict admission runs before this function so a refusal leaves no placement
// side effect, even in memory.
func finish(top *model.Topology, a *Assignment) (*Assignment, error) {
	for _, d := range top.SortedDevices() {
		if d.ASN > 0 {
			n, ok := a.ByGroup[d.PlacementGroup]
			if !ok {
				n, ok = a.ByAS[d.ASN]
			}
			if !ok {
				return nil, fmt.Errorf("device %s belongs to unplaced AS %d or group %q",
					d.ID, d.ASN, d.PlacementGroup)
			}
			d.Node = n
			continue
		}
		// A service device can be a legacy singleton or one of several
		// stable replicas. The replica record, not FrontNode, is the
		// authority for scalable services.
		if node := serviceReplicaNode(top, a, d); node != "" {
			d.Node = node
		} else {
			d.Node = top.Lab.FrontNode()
		}
	}
	for _, name := range top.SortedServiceNames() {
		service := top.Services[name]
		if service == nil {
			continue
		}
		for _, replica := range service.Replicas {
			if replica == nil || replica.Device == nil {
				continue
			}
			replica.Node = replica.Device.Node
		}
	}
	if err := serviceplan.ReconcileAttachments(top, a.ByAS); err != nil {
		return nil, err
	}

	a.Load = map[string]int{}
	for _, d := range top.Devices {
		a.Load[d.Node]++
	}
	a.CrossNodeLinks = 0
	a.Locality = map[model.LinkClass]LinkLocality{}
	for _, l := range top.Links {
		class := l.LocalityClass()
		locality := a.Locality[class]
		if l.CrossNode() {
			a.CrossNodeLinks++
			locality.CrossNode++
		} else {
			locality.Local++
		}
		a.Locality[class] = locality
	}
	return a, nil
}

func matches(m model.PinMatch, asn int, as *model.AS) bool {
	if m.AS != nil && *m.AS != asn {
		return false
	}
	if m.Role != "" && m.Role != as.Role {
		return false
	}
	if m.Region != "" && m.Region != as.Region {
		return false
	}
	if m.AS == nil && m.Role == "" && m.Region == "" {
		return false // a service-only pin does not match an AS
	}
	return true
}

func contains(hay []string, s string) bool {
	for _, h := range hay {
		if h == s {
			return true
		}
	}
	return false
}

// Describe renders the assignment for human consumption.
func (a *Assignment) Describe() string {
	var b strings.Builder
	nodes := make([]string, 0, len(a.Load))
	for n := range a.Load {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		var ases []int
		for asn, node := range a.ByAS {
			if node == n {
				ases = append(ases, asn)
			}
		}
		sort.Ints(ases)
		fmt.Fprintf(&b, "%s: %d containers, %d ASes %v\n", n, a.Load[n], len(ases), ases)
	}
	fmt.Fprintf(&b, "cross-node links: %d\n", a.CrossNodeLinks)
	classes := make([]string, 0, len(a.Locality))
	for class := range a.Locality {
		classes = append(classes, string(class))
	}
	sort.Strings(classes)
	for _, class := range classes {
		v := a.Locality[model.LinkClass(class)]
		fmt.Fprintf(&b, "  %s links: %d local, %d cross-node\n", class, v.Local, v.CrossNode)
	}
	return b.String()
}
