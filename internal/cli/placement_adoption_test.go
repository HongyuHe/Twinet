package cli

import (
	"strconv"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func adoptionClos(t *testing.T) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology
}

func adoptionContainer(device *model.Device, node string) runtime.Container {
	return runtime.Container{
		Name: device.Container,
		Labels: map[string]string{
			deploy.LabelAS:       strconv.Itoa(device.ASN),
			deploy.LabelNode:     node,
			deploy.LabelDevice:   device.Name,
			deploy.LabelDeviceID: device.ID,
		},
	}
}

func TestRunningPlacementAdoptsDeclaredClosGroups(t *testing.T) {
	top := adoptionClos(t)
	nodes := map[string]string{}
	containers := make([]runtime.Container, 0, len(top.Devices))
	for _, group := range top.ASes[42].SortedPlacementGroups() {
		node := "node-0"
		if group.Class == "leaf" {
			switch len(nodes) % 3 {
			case 0:
				node = "node-1"
			case 1:
				node = "node-2"
			}
		}
		nodes[group.ID] = node
		for _, device := range group.Devices {
			containers = append(containers, adoptionContainer(device, node))
		}
	}

	record, err := runningPlacementRecord(top, containers)
	if err != nil {
		t.Fatal(err)
	}
	if record.ByAS[42] != "node-0" {
		t.Fatalf("Clos anchor = %q, want node-0", record.ByAS[42])
	}
	for group, node := range nodes {
		if record.ByGroup[group] != node {
			t.Errorf("group %s = %q, want %q", group, record.ByGroup[group], node)
		}
	}
}

func TestRunningPlacementRefusesASplitInsideOneClosGroup(t *testing.T) {
	top := adoptionClos(t)
	group := top.ASes[42].SortedPlacementGroups()[0]
	if len(group.Devices) < 2 {
		t.Fatal("fixture group has fewer than two devices")
	}
	containers := []runtime.Container{
		adoptionContainer(group.Devices[0], "node-0"),
		adoptionContainer(group.Devices[1], "node-1"),
	}

	_, err := runningPlacementRecord(top, containers)
	if err == nil || !strings.Contains(err.Error(), group.ID) {
		t.Fatalf("split placement group was accepted: %v", err)
	}
}

func TestHealthyNoopPersistsAnAdoptedPlacement(t *testing.T) {
	dir := t.TempDir()
	top := &model.Topology{
		Name: "lab",
		Lab: &model.Lab{
			Metadata: model.Meta{Name: "lab"},
			Dir:      dir,
		},
	}
	record := &place.Record{
		Lab: "lab", Strategy: "adopted",
		ByAS: map[int]string{3: "node-1"},
	}

	if err := persistAdoptedNoopPlacement(top, record, true); err != nil {
		t.Fatal(err)
	}
	got, err := place.LoadRecord(labPrivateDir(top), top.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ByAS[3] != "node-1" {
		t.Fatalf("persisted placement = %+v", got)
	}
}
