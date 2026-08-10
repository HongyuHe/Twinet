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
func pressure(load, cap demand, has bool) float64 {
	if !has {
		return float64(load.Containers)
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

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// leastPressured picks the emptiest node that can take the demand.
func leastPressured(names []string, load map[string]demand, caps map[string]demand,
	hasCap map[string]bool, need demand) (string, error) {

	best := ""
	bestPressure := 0.0
	for _, n := range names {
		if !fits(load[n], need, caps[n], hasCap[n]) {
			continue
		}
		p := pressure(load[n], caps[n], hasCap[n])
		if best == "" || p < bestPressure {
			best, bestPressure = n, p
		}
	}
	if best == "" {
		return "", fmt.Errorf(
			"no node has room for %s; the lab needs more nodes, smaller resource requests, "+
				"or a higher declared capacity.\n  %s",
			describeDemand(need), describeLoads(names, load, caps, hasCap))
	}
	return best, nil
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
