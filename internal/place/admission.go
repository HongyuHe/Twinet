package place

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

type capacityState struct {
	names       []string
	caps        map[string]demand
	hasCap      map[string]bool
	baseline    map[string]demand
	unknown     map[string][]string
	allNodeName map[string]bool
}

func buildCapacityState(top *model.Topology, opts Options) capacityState {
	out := capacityState{
		caps: map[string]demand{}, hasCap: map[string]bool{},
		baseline: map[string]demand{}, unknown: map[string][]string{},
		allNodeName: map[string]bool{},
	}
	if top == nil || top.Lab == nil {
		return out
	}
	inventories := map[string]NodeInventory{}
	for _, inv := range opts.Inventory {
		if inv.Name != "" {
			inventories[inv.Name] = inv
		}
	}
	for _, node := range top.Lab.Placement.Nodes {
		if opts.Unavailable[node.Name] {
			// Retain no candidate capacity for a node being drained. Fixed
			// placement below observes it as absent and records an explicit
			// move instead of silently retaining work on the source.
			continue
		}
		out.allNodeName[node.Name] = true
		inv, hasInventory := inventories[node.Name]
		var ptr *NodeInventory
		if hasInventory {
			ptr = &inv
		}
		cap, has, missing := effectiveCapacityOf(node, top.Lab.Placement.Reserve, ptr)
		out.caps[node.Name], out.hasCap[node.Name] = cap, has
		if hasInventory {
			base := inv.Reserved
			if own, ok := inv.ReservedByLab[top.Name]; ok {
				base = base.sub(own)
			}
			out.baseline[node.Name] = nonNegative(base)
		}
		if len(missing) > 0 {
			out.unknown[node.Name] = missing
		}
		if opts.Strict && !opts.Overcommit && len(missing) > 0 {
			continue
		}
		out.names = append(out.names, node.Name)
	}
	sort.Strings(out.names)
	return out
}

func nonNegative(v demand) demand {
	if v.Containers < 0 {
		v.Containers = 0
	}
	if v.CPUs < 0 {
		v.CPUs = 0
	}
	if v.memoryBytes() < 0 {
		v.MemoryBytes = 0
		v.MemBytes = 0
	}
	if v.DiskBytes < 0 {
		v.DiskBytes = 0
	}
	if v.Pids < 0 {
		v.Pids = 0
	}
	if v.FileDescriptors < 0 {
		v.FileDescriptors = 0
	}
	if v.NetDevices < 0 {
		v.NetDevices = 0
	}
	return v
}

func (s capacityState) unknownSummary() string {
	var parts []string
	for _, name := range sortedNodeNames(s.unknown) {
		parts = append(parts, fmt.Sprintf("%s (%s)", name, strings.Join(s.unknown[name], ", ")))
	}
	return strings.Join(parts, "; ")
}

func nodeForAssignment(top *model.Topology, a *Assignment, d *model.Device) string {
	if d == nil {
		return ""
	}
	if d.ASN != 0 {
		if d.PlacementGroup != "" {
			if node := a.ByGroup[d.PlacementGroup]; node != "" {
				return node
			}
		}
		return a.ByAS[d.ASN]
	}
	for _, name := range top.SortedServiceNames() {
		svc := top.Services[name]
		if svc != nil && svc.Device == d {
			return a.ByService[name]
		}
	}
	return top.Lab.FrontNode()
}

func assignmentDemands(top *model.Topology, a *Assignment, baseline map[string]demand) map[string]demand {
	loads := map[string]demand{}
	for node, load := range baseline {
		loads[node] = load
	}
	if top == nil || a == nil {
		return loads
	}
	for _, d := range top.SortedDevices() {
		node := nodeForAssignment(top, a, d)
		if node == "" {
			continue
		}
		loads[node] = loads[node].add(deviceDemand(d))
	}
	return loads
}

func overloads(top *model.Topology, a *Assignment, state capacityState) []string {
	loads := assignmentDemands(top, a, state.baseline)
	var out []string
	for _, name := range sortedNodeNames(loads) {
		if !state.hasCap[name] {
			continue
		}
		c, l := state.caps[name], loads[name]
		appendOver := func(condition bool, format string, args ...any) {
			if condition {
				out = append(out, fmt.Sprintf(name+" "+format, args...))
			}
		}
		appendOver((c.Containers < 0 && l.Containers > 0) || (c.Containers > 0 && l.Containers > c.Containers),
			"receives %d requested containers but has %d allocatable", l.Containers, nonNegativeCapacityInt(c.Containers))
		appendOver((c.CPUs < 0 && l.CPUs > 0) || (c.CPUs > 0 && l.CPUs > c.CPUs),
			"receives %.2f requested CPUs but has %.2f allocatable (container CPU limits are not admission demand)",
			l.CPUs, nonNegativeCapacityFloat(c.CPUs))
		appendOver((c.memoryBytes() < 0 && l.memoryBytes() > 0) ||
			(c.memoryBytes() > 0 && l.memoryBytes() > c.memoryBytes()),
			"receives %s requested memory but has %s allocatable (container memory limits are not admission demand)",
			humanBytes(l.memoryBytes()), humanBytes(nonNegativeCapacity(c.memoryBytes())))
		appendOver((c.DiskBytes < 0 && l.DiskBytes > 0) || (c.DiskBytes > 0 && l.DiskBytes > c.DiskBytes),
			"receives %s requested ephemeral storage but has %s allocatable",
			humanBytes(l.DiskBytes), humanBytes(nonNegativeCapacity(c.DiskBytes)))
		appendOver((c.Pids < 0 && l.Pids > 0) || (c.Pids > 0 && l.Pids > c.Pids),
			"receives %d requested PIDs but has %d allocatable (container PID limits are not admission demand)",
			l.Pids, nonNegativeCapacity(c.Pids))
		appendOver((c.FileDescriptors < 0 && l.FileDescriptors > 0) ||
			(c.FileDescriptors > 0 && l.FileDescriptors > c.FileDescriptors),
			"receives %d requested file descriptors but has %d allocatable",
			l.FileDescriptors, nonNegativeCapacity(c.FileDescriptors))
		appendOver((c.NetDevices < 0 && l.NetDevices > 0) || (c.NetDevices > 0 && l.NetDevices > c.NetDevices),
			"receives %d requested netdevs but has %d allocatable",
			l.NetDevices, nonNegativeCapacity(c.NetDevices))
	}

	sort.Strings(out)
	return out
}

func nonNegativeCapacity(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func nonNegativeCapacityInt(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func nonNegativeCapacityFloat(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func strictAssignmentError(top *model.Topology, a *Assignment, state capacityState) error {
	if top == nil || a == nil {
		return fmt.Errorf("strict admission needs a topology and assignment")
	}
	for _, d := range top.SortedDevices() {
		node := nodeForAssignment(top, a, d)
		if node == "" {
			return fmt.Errorf("strict admission could not resolve a node for %s", d.ID)
		}
		if !state.allNodeName[node] {
			return fmt.Errorf("strict admission found %s on undeclared node %q", d.ID, node)
		}
		if missing := state.unknown[node]; len(missing) > 0 {
			return fmt.Errorf(
				"strict admission refuses %s on %s because allocatable %s is unknown; "+
					"the value is not treated as zero capacity or as unlimited. Fix node inventory or declare a safe node capacity, or use the audited --overcommit escape hatch",
				d.ID, node, strings.Join(missing, ", "))
		}
	}
	if over := overloads(top, a, state); len(over) > 0 {
		return fmt.Errorf(
			"strict admission refuses this placement before any deployment mutation:\n  %s\n"+
				"These are resource requests, not hard container limits. Add capacity, reduce requests, or use the audited --overcommit escape hatch",
			strings.Join(over, "\n  "))
	}
	return nil
}

// AdmitPlaced verifies a topology whose Device.Node fields are already set.
// It is used by the client immediately before a cluster transaction, so a
// pinned or recorded placement cannot bypass the same strict accounting used
// while choosing a new placement.
func AdmitPlaced(top *model.Topology, inventory []NodeInventory, strict, overcommit bool) error {
	if top == nil || top.Lab == nil {
		return fmt.Errorf("admission needs a topology with a lab")
	}
	a := &Assignment{ByAS: map[int]string{}, ByGroup: map[string]string{}, ByService: map[string]string{}}
	for _, d := range top.SortedDevices() {
		if d.Node == "" {
			continue
		}
		if d.ASN != 0 {
			if d.PlacementGroup != "" {
				a.ByGroup[d.PlacementGroup] = d.Node
			}
			if _, ok := a.ByAS[d.ASN]; !ok {
				a.ByAS[d.ASN] = d.Node
			}
			continue
		}
		for _, name := range top.SortedServiceNames() {
			if svc := top.Services[name]; svc != nil && svc.Device == d {
				a.ByService[name] = d.Node
			}
		}
	}
	state := buildCapacityState(top, Options{
		Inventory: inventory, Strict: strict, Overcommit: overcommit,
	})
	if strict && !overcommit {
		return strictAssignmentError(top, a, state)
	}
	return nil
}
