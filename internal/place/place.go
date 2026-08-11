// Package place assigns autonomous systems to cluster nodes.
//
// The unit of placement is the AS, not the container. That single decision is
// what makes scaling out cheap: an AS's internal links are numerous, fast and
// unshaped, so they stay local veths, while its inter-AS links are few and
// already throttled to a megabit with milliseconds of emulated delay, so
// carrying them over a VXLAN tunnel costs nothing a student can observe.
//
// For an eighty-AS class that is roughly two thousand intra-AS links kept local
// and a couple of hundred crossing the fabric.
package place

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Assignment is the computed placement.
type Assignment struct {
	// ByAS maps AS number to node name.
	ByAS map[int]string
	// ByService maps service name to node name.
	ByService map[string]string
	// Load is the per-node container count.
	Load map[string]int
	// CrossNodeLinks counts links whose endpoints landed on different nodes.
	CrossNodeLinks int
	// Moved records ASes that could not be left where the record says they
	// were, and why. Each one is a set of containers that will be rebuilt.
	Moved []string
	// Overloaded names nodes asked to carry more than they declare capacity
	// for. Reported rather than refused: the budgets are hand-written and a
	// stale one should not stop a class running, but the failure it predicts
	// arrives as containers being killed under load an hour later, looking
	// like a bug in the lab.
	Overloaded []string
}

// Record is the assignment in the form it is written down in.
func (a *Assignment) Record(lab, strategy string) *Record {
	r := &Record{Lab: lab, Strategy: strategy,
		ByAS: map[int]string{}, ByService: map[string]string{}}
	for k, v := range a.ByAS {
		r.ByAS[k] = v
	}
	for k, v := range a.ByService {
		r.ByService[k] = v
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
}

// Record is a placement as it was actually deployed.
type Record struct {
	Lab       string            `json:"lab"`
	Strategy  string            `json:"strategy"`
	ByAS      map[int]string    `json:"by_as"`
	ByService map[string]string `json:"by_service"`
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
	a := &Assignment{
		ByAS:      map[int]string{},
		ByService: map[string]string{},
		Load:      map[string]int{},
	}

	if strategy == "single-node" {
		for _, asn := range top.SortedASNs() {
			a.ByAS[asn] = front
		}
		for _, s := range top.SortedServiceNames() {
			a.ByService[s] = front
		}
		return finish(top, a)
	}

	names := make([]string, 0, len(nodes))
	caps := map[string]demand{}
	hasCap := map[string]bool{}
	loads := map[string]demand{}
	for _, n := range nodes {
		names = append(names, n.Name)
		c, ok := capacityOf(n, lab.Placement.Reserve)
		caps[n.Name], hasCap[n.Name] = c, ok
	}
	sort.Strings(names)

	// Explicit pins win over everything.
	pinned := map[int]string{}
	pinnedSvc := map[string]string{}
	for _, p := range lab.Placement.Pin {
		for _, asn := range top.SortedASNs() {
			as := top.ASes[asn]
			if matches(p.Match, asn, as) {
				pinned[asn] = p.Node
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
			if !contains(names, n) {
				moved = append(moved, fmt.Sprintf("AS %d was on %s, which is no longer a node", asn, n))
				continue
			}
			pinned[asn] = n
		}
		for _, s := range top.SortedServiceNames() {
			if n, ok := opts.Fixed.ByService[s]; ok && contains(names, n) {
				pinnedSvc[s] = n
			}
		}
	}

	// Services default to the front node: they publish externally reachable
	// endpoints and are the natural neighbours of the web UI and gateway.
	for _, s := range top.SortedServiceNames() {
		if n, ok := pinnedSvc[s]; ok {
			a.ByService[s] = n
		} else {
			a.ByService[s] = front
		}
	}

	// What each AS costs, in every dimension a node can run out of. Counting
	// containers alone treats eight small routers and eight four-core ones as
	// the same, so a node accepts both and the second lab starves -- and it
	// starves at run time, as apparent congestion, not at placement time as a
	// refusal anyone could act on.
	weight := map[int]demand{}
	for _, asn := range top.SortedASNs() {
		var d demand
		for _, dev := range top.ASes[asn].Devices {
			d = d.add(deviceDemand(dev))
		}
		weight[asn] = d
	}
	for _, s := range top.SortedServiceNames() {
		if svc := top.Services[s]; svc != nil && svc.Device != nil {
			n := a.ByService[s]
			loads[n] = loads[n].add(deviceDemand(svc.Device))
			a.Load[n]++
		}
	}

	// Honour pins first so their weight is reflected before packing the rest.
	var free []int
	for _, asn := range top.SortedASNs() {
		if n, ok := pinned[asn]; ok {
			if !contains(names, n) {
				return nil, fmt.Errorf("AS %d is pinned to unknown node %q", asn, n)
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

	res, err := finish(top, a)
	if err != nil {
		return nil, err
	}
	res.Moved = moved
	return res, nil
}

// finish stamps the assignment onto devices and computes summary statistics.
// checkCapacity reports nodes asked to carry more than they declared.
//
// It runs on the finished assignment rather than inside the balanced placer,
// because it was inside the balanced placer and three ways of placing a lab
// never reached it: the single-node strategy, which puts everything on the
// front node; an explicit pin, which wins over every other consideration; and
// services, which are placed separately. So the arrangements most likely to
// overload a machine -- "put it all here", "put this one here specifically" --
// were exactly the ones nothing checked, and the check applied only to the
// strategy that was already trying to avoid the problem.
//
// It is a warning and not a refusal. The budgets are declared by hand in the
// manifest, and a node whose declared memory is stale should not stop a class
// from running; but somebody has to be told, because the failure it predicts
// arrives as containers being killed under load, an hour later, looking like a
// bug in the lab.
func checkCapacity(top *model.Topology, a *Assignment) []string {
	lab := top.Lab
	if lab == nil {
		return nil
	}
	caps := map[string]demand{}
	known := map[string]bool{}
	for _, n := range lab.Placement.Nodes {
		if c, ok := capacityOf(n, lab.Placement.Reserve); ok {
			caps[n.Name], known[n.Name] = c, true
		}
	}
	if len(known) == 0 {
		return nil
	}
	load := map[string]demand{}
	for _, d := range top.SortedDevices() {
		if d.Node == "" {
			continue
		}
		load[d.Node] = load[d.Node].add(deviceDemand(d))
	}
	var out []string
	for _, name := range sortedNodeNames(load) {
		if !known[name] {
			continue
		}
		c, l := caps[name], load[name]
		switch {
		case c.Containers > 0 && l.Containers > c.Containers:
			out = append(out, fmt.Sprintf("%s is asked to run %d containers but declares room for %d",
				name, l.Containers, c.Containers))
		case c.CPUs > 0 && l.CPUs > c.CPUs:
			out = append(out, fmt.Sprintf("%s is asked for %.1f CPUs but declares %.1f",
				name, l.CPUs, c.CPUs))
		case c.MemBytes > 0 && l.MemBytes > c.MemBytes:
			out = append(out, fmt.Sprintf("%s is asked for %d MiB but declares %d MiB",
				name, l.MemBytes>>20, c.MemBytes>>20))
		}
	}
	return out
}

func sortedNodeNames(m map[string]demand) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// finish resolves every device onto a node and is the single point every
// placement strategy passes through, which is why the capacity check lives
// here: put anywhere earlier, it is a check on one strategy rather than on the
// answer.
func finish(top *model.Topology, a *Assignment) (*Assignment, error) {
	for _, d := range top.SortedDevices() {
		if d.ASN > 0 {
			n, ok := a.ByAS[d.ASN]
			if !ok {
				return nil, fmt.Errorf("device %s belongs to unplaced AS %d", d.ID, d.ASN)
			}
			d.Node = n
			continue
		}
		// A service device: find the service that owns it.
		placed := false
		for _, sn := range top.SortedServiceNames() {
			svc := top.Services[sn]
			if svc.Device == d {
				d.Node = a.ByService[sn]
				placed = true
				break
			}
		}
		if !placed {
			d.Node = top.Lab.FrontNode()
		}
	}

	a.Load = map[string]int{}
	for _, d := range top.Devices {
		a.Load[d.Node]++
	}
	a.CrossNodeLinks = 0
	for _, l := range top.Links {
		if l.CrossNode() {
			a.CrossNodeLinks++
		}
	}
	a.Overloaded = checkCapacity(top, a)
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
	return b.String()
}
