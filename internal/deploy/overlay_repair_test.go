package deploy

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type absentEndpointRuntime struct{ rt.Runtime }

func (absentEndpointRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateAbsent}, nil
}

func TestOverlayBindingRepairBlocksAbsentEndpointPrecisely(t *testing.T) {
	local := &model.Device{ID: "as1/R1", Node: "node-a", Container: "r1"}
	remote := &model.Device{ID: "as2/R1", Node: "node-b", Container: "r2"}
	a := &model.Iface{Device: local, Name: "a"}
	b := &model.Iface{Device: remote, Name: "b"}
	link := &model.Link{ID: "cross", A: a, B: b, VNI: 7001}
	a.Link, b.Link = link, link
	top := &model.Topology{Name: "lab", Devices: map[string]*model.Device{local.ID: local, remote.ID: remote}, Links: []*model.Link{link}}
	engine := &Engine{
		Runtime: absentEndpointRuntime{}, Node: "node-a",
		PeerUnderlay: map[string]string{"node-b": "10.0.1.2"},
	}
	report, err := engine.ReconcileOverlayBindings(context.Background(), top)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Failed["vni:7001"]; got != "endpoint as1/R1 container is absent" {
		t.Fatalf("repair failure = %q, want precise absent endpoint", got)
	}
	if len(report.Repaired) != 0 {
		t.Fatalf("absent endpoint was repaired: %#v", report)
	}
}
