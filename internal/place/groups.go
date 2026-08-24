package place

import (
	"fmt"

	"github.com/HongyuHe/twinet/internal/model"
)

// distributePlacementGroups applies the one intentionally narrow exception to
// AS-granular placement: a declared distributable Clos may put its spine group
// and complete leaf-with-hosts groups on different nodes. Every other AS
// remains one atomic unit and therefore keeps all of its intra-AS links local.
func distributePlacementGroups(top *model.Topology, a *Assignment, names []string,
	caps map[string]demand, hasCap map[string]bool, baseline map[string]demand, opts Options,
	placementWeights map[string]float64, explicitPinned map[int]bool,
) ([]string, error) {

	if len(names) < 2 {
		return nil, nil
	}
	if a.ByGroup == nil {
		a.ByGroup = map[string]string{}
	}
	loads := placementDemands(top, a, baseline)
	nominal := nominalCapacity(names, caps, hasCap, len(top.Devices))
	var moved []string

	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as == nil || !as.Distributable {
			continue
		}
		groups := as.SortedPlacementGroups()
		if len(groups) < 2 {
			continue
		}

		fixed := map[string]string{}
		hasFixedGroup := false
		hasFixedAS := false
		if opts.Fixed != nil && !opts.Rebalance {
			_, hasFixedAS = opts.Fixed.ByAS[asn]
			for _, g := range groups {
				if n, ok := opts.Fixed.ByGroup[g.ID]; ok {
					hasFixedGroup = true
					if contains(names, n) {
						fixed[g.ID] = n
					} else {
						moved = append(moved, fmt.Sprintf(
							"placement group %s was on %s, which is no longer a node", g.ID, n))
					}
				}
			}
		}

		// A pin means "this AS is here", not "some fabric pieces are here".
		// Likewise an older record without group entries describes a deployed
		// atomic AS and must never silently split it during an upgrade.
		if explicitPinned[asn] || (hasFixedAS && !hasFixedGroup) {
			continue
		}

		anchor, ok := a.ByAS[asn]
		if !ok || !contains(names, anchor) {
			return nil, fmt.Errorf("AS %d has no valid anchor placement for its groups", asn)
		}

		// Rebuild the load from the complete topology, then remove these group
		// demands before assigning the same devices to their final nodes. The
		// AS-level pass only reserved the spine anchor; this full accounting
		// is what lets leaves make an informed cross-node balance decision.
		for _, g := range groups {
			loads[anchor] = loads[anchor].sub(groupDemand(g))
		}

		var anchors, leaves []*model.PlacementGroup
		for _, g := range groups {
			if g.Class == "leaf" {
				leaves = append(leaves, g)
			} else {
				anchors = append(anchors, g)
			}
		}
		if len(anchors) == 0 {
			anchors, leaves = groups[:1], groups[1:]
		}

		// The spine is the representative AS location retained in ByAS for
		// legacy callers and records. A group record may move it, in which
		// case ByAS follows the recorded spine location.
		for _, g := range anchors {
			n := anchor
			if recorded, ok := fixed[g.ID]; ok {
				n = recorded
			}
			a.ByGroup[g.ID] = n
			loads[n] = loads[n].add(groupDemand(g))
			anchor = n
		}
		a.ByAS[asn] = anchor

		for _, g := range leaves {
			n, recorded := fixed[g.ID]
			if !recorded {
				n = bestGroupNode(names, loads, caps, hasCap, placementWeights, groupDemand(g), nominal)
			}
			a.ByGroup[g.ID] = n
			loads[n] = loads[n].add(groupDemand(g))
		}
	}
	return moved, nil
}

func groupDemand(g *model.PlacementGroup) demand {
	var out demand
	if g == nil {
		return out
	}
	for _, d := range g.Devices {
		out = out.add(deviceDemand(d))
	}
	return out
}

// placementAnchorDemand is the part of a distributable fabric that the
// AS-level pass must reserve before leaf groups are spread. Charging the whole
// Clos here would reject a fabric that fits across three nodes simply because
// it cannot fit on its initial spine node.
func placementAnchorDemand(as *model.AS) demand {
	var out demand
	if as == nil {
		return out
	}
	for _, g := range as.PlacementGroups {
		if g.Class != "leaf" {
			out = out.add(groupDemand(g))
		}
	}
	if out.empty() {
		for _, d := range as.Devices {
			out = out.add(deviceDemand(d))
		}
	}
	return out
}

// placementDemands recreates the post-AS-placement load so controlled group
// splitting can rebalance actual CPU/memory/container demand rather than a
// count of group IDs.
func placementDemands(top *model.Topology, a *Assignment, baseline map[string]demand) map[string]demand {
	out := map[string]demand{}
	for node, load := range baseline {
		out[node] = load
	}
	for _, asn := range top.SortedASNs() {
		n := a.ByAS[asn]
		for _, d := range top.ASes[asn].Devices {
			out[n] = out[n].add(deviceDemand(d))
		}
	}
	for _, name := range top.SortedServiceNames() {
		s := top.Services[name]
		for _, device := range serviceDevices(s) {
			node := serviceReplicaNode(top, a, device)
			out[node] = out[node].add(deviceDemand(device))
		}
	}
	return out
}

// bestGroupNode prefers a capacity-fitting least-loaded node. If a hand-written
// capacity is already too small for every candidate, it still chooses the
// least-loaded node and leaves the existing overload report to explain it;
// silently turning a warning into a deployment refusal would break the
// established placement contract.
func bestGroupNode(names []string, loads map[string]demand, caps map[string]demand,
	hasCap map[string]bool, weights map[string]float64, need demand, nominal int) string {

	best, bestPressure, found := "", 0.0, false
	for _, fitOnly := range []bool{true, false} {
		for _, n := range names {
			if fitOnly && !fits(loads[n], need, caps[n], hasCap[n]) {
				continue
			}
			p := placementPressure(loads[n].add(need), caps[n], hasCap[n], nominal, weights[n])
			if !found || p < bestPressure {
				best, bestPressure, found = n, p, true
			}
		}
		if found {
			return best
		}
	}
	return names[0]
}
