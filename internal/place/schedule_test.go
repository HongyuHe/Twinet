package place

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestScheduleWavesRespectsCapacityAndParallelUpperBound(t *testing.T) {
	lab := &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "a", Front: true}}}}
	inventory := []NodeInventory{{
		Name: "a", Allocatable: testCapacity(4, 1, 4<<30, 4<<30, 1000, 10000, 100),
	}}
	heavy := Resources{
		Containers: 1, CPUs: 0.75, MemoryBytes: 128 << 20, MemBytes: 128 << 20,
		DiskBytes: 128 << 20, Pids: 32, FileDescriptors: 128, NetDevices: 2,
	}
	waves, err := ScheduleWaves(lab, inventory, []Workload{
		{Name: "one", DemandByNode: map[string]Resources{"a": heavy}},
		{Name: "two", DemandByNode: map[string]Resources{"a": heavy}},
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(waves) != 2 {
		t.Fatalf("two 0.75-CPU harnesses shared %d wave(s), want 2", len(waves))
	}

	light := heavy
	light.CPUs = 0.1
	waves, err = ScheduleWaves(lab, inventory, []Workload{
		{Name: "one", DemandByNode: map[string]Resources{"a": light}},
		{Name: "two", DemandByNode: map[string]Resources{"a": light}},
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(waves) != 2 {
		t.Fatalf("parallel upper bound of one created %d wave(s), want 2", len(waves))
	}
}

func TestSafeWorkerCountUsesLiveAdmissionRatherThanRequestedParallelism(t *testing.T) {
	lab := &model.Lab{Placement: model.Placement{Nodes: []model.NodeSpec{{Name: "a", Front: true}}}}
	inventory := []NodeInventory{{
		Name: "a", Allocatable: testCapacity(10, 1, 4<<30, 4<<30, 1000, 10000, 100),
	}}
	workload := Workload{Name: "harness", DemandByNode: map[string]Resources{
		"a": {
			Containers: 1, CPUs: 0.4, MemoryBytes: 64 << 20, MemBytes: 64 << 20,
			DiskBytes: 64 << 20, Pids: 10, FileDescriptors: 10, NetDevices: 1,
		},
	}}
	count, err := SafeWorkerCount(lab, inventory, []Workload{workload, workload, workload, workload}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("safe workers = %d, want 2 from the 1-CPU live budget", count)
	}
}
