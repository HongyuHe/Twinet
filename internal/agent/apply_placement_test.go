package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestValidateApplyAssignmentRejectsWrongNodeOrSubset(t *testing.T) {
	top := &model.Topology{Devices: map[string]*model.Device{
		"a": {ID: "a", Node: "node-0"},
		"b": {ID: "b", Node: "node-0"},
		"c": {ID: "c", Node: "node-1"},
	}}
	valid := ApplyRequest{
		TargetNode: "node-0", AssignedDevices: []string{"b", "a"}, AssignmentKnown: true,
	}
	if err := validateApplyAssignment(valid, top, "node-0"); err != nil {
		t.Fatalf("valid placement witness: %v", err)
	}
	wrongNode := valid
	wrongNode.TargetNode = "node-2"
	if err := validateApplyAssignment(wrongNode, top, "node-0"); err == nil ||
		!strings.Contains(err.Error(), "reached agent") {
		t.Fatalf("wrong target node error = %v", err)
	}
	wrongSubset := valid
	wrongSubset.AssignedDevices = []string{"a", "c"}
	if err := validateApplyAssignment(wrongSubset, top, "node-0"); err == nil ||
		!strings.Contains(err.Error(), "controller assigned") {
		t.Fatalf("wrong assignment subset error = %v", err)
	}
}

func TestValidateApplyAssignmentAcceptsKnownEmptySubset(t *testing.T) {
	top := &model.Topology{Devices: map[string]*model.Device{
		"a": {ID: "a", Node: "node-1"},
	}}
	req := ApplyRequest{TargetNode: "node-0", AssignmentKnown: true}
	if err := validateApplyAssignment(req, top, "node-0"); err != nil {
		t.Fatalf("empty placement subset: %v", err)
	}
}

func TestValidatePreparedPlacementRejectsNodeDrift(t *testing.T) {
	prepared := &Wire{Lab: "lab", Devices: []WireDev{
		{ID: "a", Node: "node-0"},
		{ID: "b", Node: "node-1"},
	}}
	raw, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	tx := applyTransaction{Requested: raw}
	top := &model.Topology{Devices: map[string]*model.Device{
		"a": {ID: "a", Node: "node-0"},
		"b": {ID: "b", Node: "node-2"},
	}}
	if err := validatePreparedPlacement(tx, top); err == nil ||
		!strings.Contains(err.Error(), `moved device "b"`) {
		t.Fatalf("placement drift error = %v", err)
	}
}
