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
}

// Options tune the placer.
type Options struct {
	// Strategy is pack-by-as, spread-by-as or single-node.
	Strategy string
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
	case "pack-by-as":
		// First-fit-decreasing by weight, then a stable pass in ascending AS
		// order for equal weights, which keeps neighbouring groups together and
		// therefore keeps more inter-AS links local.
		sort.SliceStable(free, func(i, j int) bool {
			if weight[free[i]].Containers != weight[free[j]].Containers {
				return weight[free[i]].Containers > weight[free[j]].Containers
			}
			return free[i] < free[j]
		})
		for _, asn := range free {
			n, err := leastPressured(names, loads, caps, hasCap, weight[asn])
			if err != nil {
				return nil, fmt.Errorf("AS %d: %w", asn, err)
			}
			a.ByAS[asn] = n
			loads[n] = loads[n].add(weight[asn])
			a.Load[n] += weight[asn].Containers
		}
	case "spread-by-as":
		// Round-robin still has to respect capacity. Skipping the check here
		// was a way to build a lab that could not run: the strategy asks for an
		// even spread, not for an impossible one.
		for _, asn := range free {
			n, err := leastPressured(names, loads, caps, hasCap, weight[asn])
			if err != nil {
				return nil, fmt.Errorf("AS %d: %w", asn, err)
			}
			a.ByAS[asn] = n
			loads[n] = loads[n].add(weight[asn])
			a.Load[n] += weight[asn].Containers
		}
	default:
		return nil, fmt.Errorf("unknown placement strategy %q", strategy)
	}

	return finish(top, a)
}

// finish stamps the assignment onto devices and computes summary statistics.
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
