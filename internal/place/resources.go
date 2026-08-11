package place

import (
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// demand is what a placement unit costs a node.
//
// Counting containers alone is the obvious thing and it is wrong in the case
// that matters. An autonomous system of eight small routers and one of eight
// routers each given four cores and eight gigabytes look identical to a
// container count, so a node accepts both and the second one starves. The
// failure is not a refusal at placement time, which would be diagnosable, but a
// lab that deploys successfully and then behaves as though the network is
// congested -- which, in a course about congestion, is the worst possible thing
// to be wrong about.
type demand struct {
	Containers int
	CPUs       float64
	MemBytes   int64
}

func (d demand) add(o demand) demand {
	return demand{d.Containers + o.Containers, d.CPUs + o.CPUs, d.MemBytes + o.MemBytes}
}

func (d demand) empty() bool {
	return d.Containers == 0 && d.CPUs == 0 && d.MemBytes == 0
}

// deviceDemand is what one device asks for.
//
// A device with no declared limit still consumes a node, so it is charged a
// nominal share rather than nothing: charging zero would let an unbounded
// number of unlimited containers land on one machine, which is precisely the
// arrangement that looks fine in the plan and falls over in the lab.
func deviceDemand(d *model.Device) demand {
	dem := demand{Containers: 1}
	if d.CPUs > 0 {
		dem.CPUs = d.CPUs
	} else {
		dem.CPUs = 0.05
	}
	if d.Memory != "" {
		if b, err := runtime.ParseMemory(d.Memory); err == nil {
			dem.MemBytes = b
		}
	}
	if dem.MemBytes == 0 {
		dem.MemBytes = 64 << 20
	}
	return dem
}

// capacityOf reads a node's declared budget, minus anything reserved.
func capacityOf(n model.NodeSpec, reserve map[string]model.Budget) (demand, bool) {
	if n.Capacity == nil {
		return demand{}, false
	}
	cap := demand{Containers: n.Capacity.Containers, CPUs: n.Capacity.CPUs}
	if n.Capacity.Memory != "" {
		if b, err := runtime.ParseMemory(n.Capacity.Memory); err == nil {
			cap.MemBytes = b
		}
	}
	// A reservation is capacity that exists but must not be handed out: the
	// agent, the container engine and the kernel all need room, and a node
	// packed to its declared limit has none.
	if r, ok := reserve[n.Name]; ok {
		cap.Containers -= r.Containers
		cap.CPUs -= r.CPUs
		if r.Memory != "" {
			if b, err := runtime.ParseMemory(r.Memory); err == nil {
				cap.MemBytes -= b
			}
		}
	}
	if cap.Containers < 0 {
		cap.Containers = 0
	}
	if cap.CPUs < 0 {
		cap.CPUs = 0
	}
	if cap.MemBytes < 0 {
		cap.MemBytes = 0
	}
	return cap, !cap.empty()
}

// fits reports whether a node can take more demand.
func fits(load, need, cap demand, has bool) bool {
	if !has {
		return true
	}
	if cap.Containers > 0 && load.Containers+need.Containers > cap.Containers {
		return false
	}
	if cap.CPUs > 0 && load.CPUs+need.CPUs > cap.CPUs {
		return false
	}
	if cap.MemBytes > 0 && load.MemBytes+need.MemBytes > cap.MemBytes {
		return false
	}
	return true
}

// pressure scores how full a node is, as the worst of its dimensions.
//
// The worst rather than the average, because a node with spare memory and no
// cores left is full. Averaging hides exactly the case that causes trouble.
//
// nominal is the largest container count any node has been given room for, and
// it exists to keep the scale comparable when only some nodes declare a
// capacity. Returning a raw container count for an undeclared node put it on a
// different scale from the 0..1 ratio used for a declared one: a node holding
// three containers scored 3.0 against a declared node at 99% of its limit
// scoring 0.99, so every AS went to the declared node until it was completely
// full while the undeclared one stayed empty -- the opposite of balancing, from
// a manifest that merely omitted one capacity line.
func pressure(load, cap demand, has bool, nominal int) float64 {
	if !has {
		if nominal <= 0 {
			nominal = 1
		}
		return float64(load.Containers) / float64(nominal)
	}
	worst := 0.0
	if cap.Containers > 0 {
		worst = max(worst, float64(load.Containers)/float64(cap.Containers))
	}
	if cap.CPUs > 0 {
		worst = max(worst, load.CPUs/cap.CPUs)
	}
	if cap.MemBytes > 0 {
		worst = max(worst, float64(load.MemBytes)/float64(cap.MemBytes))
	}
	return worst
}

// nominalCapacity is the yardstick pressure is measured against on nodes that
// declare no capacity of their own.
//
// Where some node has declared one, the largest such figure is the right scale,
// so that a declared and an undeclared node are compared on the same axis.
// Where nobody has, the scale is what one node is actually expected to hold --
// an even share of the lab -- not the whole lab. Using the whole lab made
// pressure a fraction of something no node was ever going to reach, so a
// tolerance of a tenth meant a tenth of two thousand containers rather than a
// tenth of a node's share, and a strategy asked to trade a little balance for
// locality traded 500 containers against 860.
func nominalCapacity(names []string, caps map[string]demand, hasCap map[string]bool, total int) int {
	best := 0
	for _, n := range names {
		if hasCap[n] && caps[n].Containers > best {
			best = caps[n].Containers
		}
	}
	if best == 0 && len(names) > 0 {
		best = (total + len(names) - 1) / len(names)
	}
	if best <= 0 {
		best = 1
	}
	return best
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func describeDemand(d demand) string {
	return fmt.Sprintf("%d container(s), %.2f cpu, %s", d.Containers, d.CPUs, humanBytes(d.MemBytes))
}

func describeLoads(names []string, load map[string]demand, caps map[string]demand, hasCap map[string]bool) string {
	var parts []string
	for _, n := range names {
		if !hasCap[n] {
			parts = append(parts, fmt.Sprintf("%s: %d container(s), no declared capacity", n, load[n].Containers))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %d/%d containers, %.1f/%.1f cpu, %s/%s",
			n, load[n].Containers, caps[n].Containers,
			load[n].CPUs, caps[n].CPUs,
			humanBytes(load[n].MemBytes), humanBytes(caps[n].MemBytes)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n  ")
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGi", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fMi", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// bestForLocality picks the node that keeps the most of an AS's links local,
// among those that would still leave the cluster balanced.
//
// This is the greedy graph-partition pass the design calls for. A link kept
// inside a node is a veth pair rather than a VXLAN tunnel: no encapsulation, no
// reduced MTU, no dependence on the fabric, and nothing to go wrong when
// another node reboots.
//
// Locality is bounded, and the bound is what makes it safe. Pursued without
// one, the greedy choice is always "wherever this AS's neighbours already are",
// so the first node accumulates the whole peering graph and the lab lands on a
// single machine -- the opposite of the scale-out this project exists to
// provide. The bound is expressed against the best balance available at that
// moment rather than as a fixed ceiling: a node qualifies if taking this AS
// would leave it within tolerance of the least loaded option. That set always
// contains at least the least loaded node, so it is never empty, and no
// fallback is needed that would abandon balance entirely -- which is what a
// fixed ceiling required, and it put 108 containers on one node and 52 on
// another from a strategy asking for an even spread.
//
// tolerance is how much imbalance the strategy will trade for locality, as a
// fraction of a node's capacity. Zero means locality breaks exact ties only.
func bestForLocality(names []string, load map[string]demand, caps map[string]demand,
	hasCap map[string]bool, need demand, tolerance float64, nominal int,
	localityOf func(node string) int) (string, error) {

	type cand struct {
		name     string
		pressure float64
		locality int
	}
	var cands []cand
	minP := 0.0
	for _, n := range names {
		if !fits(load[n], need, caps[n], hasCap[n]) {
			continue
		}
		// The pressure the node would be under, not the one it is under.
		// Checking before adding lets a node just inside the line accept an
		// entire autonomous system and finish far outside it.
		p := pressure(load[n].add(need), caps[n], hasCap[n], nominal)
		if len(cands) == 0 || p < minP {
			minP = p
		}
		cands = append(cands, cand{n, p, localityOf(n)})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf(
			"no node has room for %s; the lab needs more nodes, smaller resource requests, "+
				"or a higher declared capacity.\n  %s",
			describeDemand(need), describeLoads(names, load, caps, hasCap))
	}

	best := cand{}
	found := false
	for _, c := range cands {
		if c.pressure > minP+tolerance {
			continue
		}
		if !found || c.locality > best.locality ||
			(c.locality == best.locality && c.pressure < best.pressure) {
			best, found = c, true
		}
	}
	return best.name, nil
}

func (d demand) sub(o demand) demand {
	return demand{d.Containers - o.Containers, d.CPUs - o.CPUs, d.MemBytes - o.MemBytes}
}
