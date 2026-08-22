package place

import (
	"fmt"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Workload is a precomputed multi-node request, such as one disposable
// grading harness. DemandByNode must include placement groups and services,
// not only its container count.
type Workload struct {
	Name         string
	DemandByNode map[string]Resources
}

// SafeWorkerCount derives the widest currently admissible grading wave from
// live inventory. requested is an upper bound, not a promise: a worker count
// that fits yesterday's reservations is not safe to start today. Callers still
// re-check admission immediately before deployment.
func SafeWorkerCount(lab *model.Lab, inventory []NodeInventory, workloads []Workload, requested int) (int, error) {
	if len(workloads) == 0 {
		return 0, nil
	}
	if requested <= 0 || requested > len(workloads) {
		requested = len(workloads)
	}
	waves, err := ScheduleWaves(lab, inventory, workloads, requested)
	if err != nil {
		return 0, err
	}
	if len(waves) == 0 {
		return 0, nil
	}
	return len(waves[0]), nil
}

// ScheduleWaves packs workloads into deterministic capacity-safe waves. max is
// an upper bound, never a command to use that much concurrency. Existing node
// reservations are charged to every wave, so other labs and harnesses cannot
// be ignored by batch grading.
func ScheduleWaves(lab *model.Lab, inventory []NodeInventory, workloads []Workload, max int) ([][]int, error) {
	if lab == nil {
		return nil, fmt.Errorf("capacity scheduling needs a lab")
	}
	if max <= 0 {
		max = 1
	}
	// The scheduler is planning new, uniquely named harnesses. Use a synthetic
	// name so buildCapacityState never subtracts a currently running class lab
	// from baseline reservations.
	top := &model.Topology{Lab: lab, Name: "__harness_scheduler__"}
	state := buildCapacityState(top, Options{Inventory: inventory, Strict: true})
	if len(state.names) == 0 {
		return nil, fmt.Errorf("no node has complete allocatable inventory: %s", state.unknownSummary())
	}
	for _, name := range state.names {
		if !fits(demand{}, state.baseline[name], state.caps[name], state.hasCap[name]) {
			return nil, fmt.Errorf("current reservations already exceed allocatable capacity on %s", name)
		}
	}

	type wave struct {
		indices []int
		loads   map[string]demand
	}
	var waves []wave
	for i, workload := range workloads {
		if err := workloadFits(state, state.baseline, workload); err != nil {
			return nil, fmt.Errorf("%s cannot be admitted before grading starts: %w", workload.Name, err)
		}
		placed := false
		for wi := range waves {
			if len(waves[wi].indices) >= max {
				continue
			}
			if workloadFits(state, waves[wi].loads, workload) != nil {
				continue
			}
			addWorkload(waves[wi].loads, workload)
			waves[wi].indices = append(waves[wi].indices, i)
			placed = true
			break
		}
		if placed {
			continue
		}
		loads := cloneLoads(state.baseline)
		addWorkload(loads, workload)
		waves = append(waves, wave{indices: []int{i}, loads: loads})
	}

	out := make([][]int, len(waves))
	for i, wave := range waves {
		out[i] = wave.indices
	}
	return out, nil
}

func workloadFits(state capacityState, loads map[string]demand, workload Workload) error {
	for node, need := range workload.DemandByNode {
		if !state.allNodeName[node] {
			return fmt.Errorf("it is placed on undeclared node %q", node)
		}
		if missing := state.unknown[node]; len(missing) > 0 {
			return fmt.Errorf("allocatable %s on %s is unknown", strings.Join(missing, ", "), node)
		}
		if !fits(loads[node], need, state.caps[node], state.hasCap[node]) {
			return fmt.Errorf("%s lacks room for %s", node, describeDemand(need))
		}
	}
	return nil
}

func cloneLoads(in map[string]demand) map[string]demand {
	out := map[string]demand{}
	for node, load := range in {
		out[node] = load
	}
	return out
}

func addWorkload(loads map[string]demand, workload Workload) {
	for node, need := range workload.DemandByNode {
		loads[node] = loads[node].add(need)
	}
}
