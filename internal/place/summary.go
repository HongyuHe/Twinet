package place

import (
	"math"

	"github.com/HongyuHe/twinet/internal/model"
)

// ResourcePressure identifies the request dimension closest to its declared
// static capacity. Capacity remains optional; Ratio is zero and Dimension is
// "unbounded" when a node declares no resource upper bound.
type ResourcePressure struct {
	Ratio     float64 `json:"ratio"`
	Dimension string  `json:"dimension"`
}

// CapacitySummary is an offline planning view. Total includes internal FRR
// control sidecars; PrimaryByKind and Controls make that otherwise invisible
// runtime cost explicit.
type CapacitySummary struct {
	Total         Resources                      `json:"total"`
	PrimaryByKind map[model.DeviceKind]Resources `json:"primary_by_kind"`
	Controls      Resources                      `json:"controls"`
	ByNode        map[string]Resources           `json:"by_node"`
	Unplaced      Resources                      `json:"unplaced"`
	Capacity      map[string]Resources           `json:"capacity"`
	CapacityKnown map[string]bool                `json:"capacity_known"`
	Pressure      map[string]ResourcePressure    `json:"pressure"`
}

// SummarizeCapacity calculates requested resources after placement. It uses
// manifest capacity/reserve only for offline pressure; clustered admission
// still takes the minimum with live agent allocatable inventory.
func SummarizeCapacity(top *model.Topology) CapacitySummary {
	out := CapacitySummary{
		PrimaryByKind: map[model.DeviceKind]Resources{},
		ByNode:        map[string]Resources{},
		Capacity:      map[string]Resources{},
		CapacityKnown: map[string]bool{},
		Pressure:      map[string]ResourcePressure{},
	}
	if top == nil {
		return out
	}
	for _, d := range top.SortedDevices() {
		total := deviceDemand(d)
		primary := total
		if control, ok := controlDemand(d); ok {
			primary = primary.sub(control)
			out.Controls = out.Controls.add(control)
		}
		out.Total = out.Total.add(total)
		out.PrimaryByKind[d.Kind] = out.PrimaryByKind[d.Kind].add(primary)
		if d.Node == "" {
			out.Unplaced = out.Unplaced.add(total)
			continue
		}
		out.ByNode[d.Node] = out.ByNode[d.Node].add(total)
	}
	if top.Lab == nil {
		return out
	}
	for _, node := range top.Lab.Placement.Nodes {
		capacity, known := capacityOf(node, top.Lab.Placement.Reserve)
		out.Capacity[node.Name], out.CapacityKnown[node.Name] = capacity, known
		if !known {
			out.Pressure[node.Name] = ResourcePressure{Dimension: "unbounded"}
			continue
		}
		out.Pressure[node.Name] = resourcePressure(out.ByNode[node.Name], capacity)
	}
	return out
}

func controlDemand(d *model.Device) (demand, bool) {
	if d == nil || d.Kind != model.KindRouter || d.EffectiveNOS() != model.DefaultNOS {
		return demand{}, false
	}
	return requestDemand(model.FRRControlResourceRequest()), true
}

func resourcePressure(load, cap demand) ResourcePressure {
	best := ResourcePressure{Dimension: "unbounded"}
	consider := func(dimension string, used, limit float64) {
		if limit <= 0 {
			return
		}
		ratio := used / limit
		if best.Dimension == "unbounded" || ratio > best.Ratio {
			best = ResourcePressure{Ratio: ratio, Dimension: dimension}
		}
	}
	consider("containers", float64(load.Containers), float64(cap.Containers))
	consider("cpu", load.CPUs, cap.CPUs)
	consider("memory", float64(load.memoryBytes()), float64(cap.memoryBytes()))
	consider("ephemeral_storage", float64(load.DiskBytes), float64(cap.DiskBytes))
	consider("pids", float64(load.Pids), float64(cap.Pids))
	consider("file_descriptors", float64(load.FileDescriptors), float64(cap.FileDescriptors))
	consider("netdevs", float64(load.NetDevices), float64(cap.NetDevices))
	if best.Dimension != "unbounded" {
		best.Ratio = math.Max(0, best.Ratio)
	}
	return best
}
