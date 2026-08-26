package place

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func oneNodeLab() *model.Topology {
	lab := &model.Lab{Placement: model.Placement{
		Strategy: "pack-by-as",
		Nodes:    []model.NodeSpec{{Name: "node-0", Front: true}},
	}}
	top := &model.Topology{Name: "cos461", Lab: lab, Devices: map[string]*model.Device{}}
	device := &model.Device{ID: "r1", Name: "r1", Kind: model.KindRouter, ASN: 1,
		Requests: model.DefaultResourceRequest(model.KindRouter)}
	top.Devices[device.ID] = device
	top.ASes = map[int]*model.AS{1: {ASN: 1}}
	return top
}

func completeInventory() NodeInventory {
	containers := 100
	cpus := 32.0
	memory := int64(200 << 30)
	disk := int64(500 << 30)
	pids := int64(500000)
	netdevs := int64(4000)
	return NodeInventory{
		Name: "node-0",
		Allocatable: Capacity{
			Containers: &containers, CPUs: &cpus, MemoryBytes: &memory,
			DiskBytes: &disk, Pids: &pids, NetDevices: &netdevs,
		},
	}
}

// A node whose kernel imposes no file-handle ceiling knows its capacity: the
// dimension constrains nothing. Strict admission must not refuse it the way it
// refuses a dimension nobody could read, and must not treat the absent number
// as an exhausted zero either.
func TestStrictAdmissionAcceptsAnUnlimitedDimension(t *testing.T) {
	inventory := completeInventory()
	inventory.Unlimited = []string{"file descriptors"}

	if err := AdmitPlaced(placedLab(t, inventory), []NodeInventory{inventory}, true, false); err != nil {
		t.Fatalf("strict admission refused a node with an unlimited dimension: %v", err)
	}
}

// The same absent number without that statement is unknown, and unknown is
// still refused: it is neither zero nor unlimited, and guessing either way is
// what strict admission exists to prevent.
func TestStrictAdmissionStillRefusesAnUnknownDimension(t *testing.T) {
	inventory := completeInventory()

	err := AdmitPlaced(placedLab(t, inventory), []NodeInventory{inventory}, true, false)
	if err == nil {
		t.Fatal("strict admission accepted a node with an unreadable dimension")
	}
	if !strings.Contains(err.Error(), "file descriptors") {
		t.Errorf("refusal does not name the unknown dimension: %v", err)
	}
}

// An unlimited dimension must not silently exempt the rest: a node that is out
// of memory is still out of memory.
func TestUnlimitedDimensionDoesNotExemptTheOthers(t *testing.T) {
	inventory := completeInventory()
	inventory.Unlimited = []string{"file descriptors"}
	exhausted := int64(0)
	inventory.Allocatable.MemoryBytes = &exhausted

	err := AdmitPlaced(placedLab(t, inventory), []NodeInventory{inventory}, true, false)
	if err == nil {
		t.Fatal("strict admission accepted a placement onto a node with no memory left")
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Errorf("refusal does not name the exhausted dimension: %v", err)
	}
}

func placedLab(t *testing.T, inventory NodeInventory) *model.Topology {
	t.Helper()
	top := oneNodeLab()
	for _, device := range top.Devices {
		device.Node = inventory.Name
	}
	return top
}
