package deploy

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
)

// pairedOverlayTopology is one node pair carrying several cross-node links,
// which is what a shared trunk actually looks like in a class-scale lab.
func pairedOverlayTopology(vnis ...uint32) (*model.Topology, map[uint32]*model.Device) {
	top := &model.Topology{Name: "lab", Devices: map[string]*model.Device{}}
	local := map[uint32]*model.Device{}
	for i, vni := range vnis {
		left := &model.Device{
			ID: deviceIDFor(i), Node: "node-a", Container: containerFor(i),
		}
		right := &model.Device{
			ID: "as140/FABRIC" + deviceIDFor(i), Node: "node-b", Container: "fabric" + containerFor(i),
		}
		a := &model.Iface{Device: left, Name: "ixp_140"}
		b := &model.Iface{Device: right, Name: "ixp_140"}
		link := &model.Link{ID: "cross-" + deviceIDFor(i), VNI: vni, A: a, B: b}
		a.Link, b.Link = link, link
		left.Ifaces, right.Ifaces = []*model.Iface{a}, []*model.Iface{b}
		top.Devices[left.ID], top.Devices[right.ID] = left, right
		top.Links = append(top.Links, link)
		local[vni] = left
	}
	return top, local
}

func deviceIDFor(i int) string  { return "as" + string(rune('1'+i)) + "/CHI" }
func containerFor(i int) string { return "tw-chi-" + string(rune('1'+i)) }

// The endpoint container is reported absent so the repair stops before it
// would touch host netlink. What is under test is which links a repair
// considers, which is decided before any device is created.
func overlayRepairEngine(top *model.Topology, present map[string]bool,
	inventory netx.OverlayInventory,
) *Engine {
	engine := &Engine{
		Runtime: absentEndpointRuntime{}, Node: "node-a",
		UnderlayIP: "10.0.1.1", PeerUnderlay: map[string]string{"node-b": "10.0.1.2"},
	}
	engine.inspectOverlayInventory = func(string) (netx.OverlayInventory, error) { return inventory, nil }
	engine.hostLinkPresence = func(names []string) (map[string]bool, error) {
		out := map[string]bool{}
		for _, name := range names {
			out[name] = present[name]
		}
		return out, nil
	}
	_ = top
	return engine
}

// A device-scoped repair must look at that device's links and nothing else.
// The node-wide form of this repair is what turned one endpoint's fault into
// a whole node pair losing its bindings.
func TestDeviceOverlayRepairTouchesOnlyThatDevicesLinks(t *testing.T) {
	top, local := pairedOverlayTopology(7001, 7002, 7003)
	engine := overlayRepairEngine(top, nil, netx.OverlayInventory{})
	expected, err := engine.ExpectedOverlayInventory(top)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected.Bindings) != 3 {
		t.Fatalf("expected inventory = %#v, want three bindings", expected.Bindings)
	}
	// Every binding is missing, but only the drifted device is being repaired.
	report, err := engine.ReconcileDeviceOverlayBindings(context.Background(), top, local[7002])
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Repaired) != 0 {
		t.Fatalf("report claimed repairs it could not make: %#v", report)
	}
	if len(report.Failed) != 1 {
		t.Fatalf("device repair reported %d bindings, want only the one belonging to as2/CHI: %#v",
			len(report.Failed), report.Failed)
	}
	if got := report.Failed["vni:7002"]; got != "endpoint as2/CHI container is absent" {
		t.Fatalf("device repair reported %q for vni:7002, want the precise endpoint reason", got)
	}
	if report.Extra != nil {
		t.Fatalf("a device-scoped repair made a claim about the rest of the node: %#v", report.Extra)
	}
}

// A healthy binding is left alone. Repairing what is already correct is how a
// converged lab is made to churn.
func TestDeviceOverlayRepairSkipsHealthyBindings(t *testing.T) {
	top, local := pairedOverlayTopology(7001, 7002)
	engine := overlayRepairEngine(top, nil, netx.OverlayInventory{})
	expected, err := engine.ExpectedOverlayInventory(top)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, binding := range expected.Bindings {
		present[hostSideName(binding.VNI)] = true
	}
	engine = overlayRepairEngine(top, present, netx.OverlayInventory{Bindings: expected.Bindings})
	report, err := engine.ReconcileDeviceOverlayBindings(context.Background(), top, local[7002])
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Repaired) != 0 || len(report.Failed) != 0 {
		t.Fatalf("healthy binding was touched: %#v", report)
	}
}

// The node-wide form still reports every expected binding, so an explicit
// operator reconcile keeps seeing the whole node.
func TestNodeOverlayRepairStillCoversEveryLocalBinding(t *testing.T) {
	top, _ := pairedOverlayTopology(7001, 7002, 7003)
	engine := overlayRepairEngine(top, nil, netx.OverlayInventory{})
	report, err := engine.ReconcileOverlayBindings(context.Background(), top)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 3 {
		t.Fatalf("node repair reported %#v, want all three bindings", report.Failed)
	}
}
