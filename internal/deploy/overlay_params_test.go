package deploy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
)

// TestScaleBuildDerivesOverlayParametersOnce is the executable form of the
// bound R1.O7 requires: deriving multiplex overlay parameters is a pure
// function of the placed topology, so one deployment must scan the link set a
// bounded number of times rather than once per cross-node link.
func TestScaleBuildDerivesOverlayParametersOnce(t *testing.T) {
	top := scaleTopology(t)
	node := "node-1"
	crossNode := 0
	for _, link := range top.Links {
		if link.CrossNode() && (link.A.Device.Node == node || link.B.Device.Node == node) {
			crossNode++
		}
	}
	if crossNode < 2 {
		t.Fatalf("scale placement put %d cross-node links on %s; the bound is untested", crossNode, node)
	}
	eng, _ := scaleEngine(t, top, node)
	before := deploy.OverlayPlanBuilds()
	if _, err := eng.BuildContext(context.Background(), top); err != nil {
		t.Fatal(err)
	}
	got := deploy.OverlayPlanBuilds() - before
	if got != 1 {
		t.Fatalf("building the scale plan scanned the link set %d times for overlay parameters, want exactly 1 "+
			"(%d cross-node links on %s)", got, crossNode, node)
	}
}

// TestOverlayParametersAreStableAcrossEngines guards the cache against the one
// failure that would be invisible in timing: two endpoint agents must derive
// identical VLAN, MTU, and port assignments, and a cached engine must agree
// with a freshly derived one.
func TestOverlayParametersAreStableAcrossEngines(t *testing.T) {
	top := scaleTopology(t)
	first, _ := scaleEngine(t, top, "node-1")
	second, _ := scaleEngine(t, top, "node-2")
	if _, err := first.ExpectedOverlayInventory(top); err != nil {
		t.Fatal(err)
	}
	a, err := first.ExpectedOverlayInventory(top)
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.ExpectedOverlayInventory(top)
	if err != nil {
		t.Fatal(err)
	}
	byVNI := map[uint32]string{}
	for _, binding := range a.Bindings {
		byVNI[binding.VNI] = fmt.Sprintf("vlan=%d mtu=%d port=%d nodes=%s/%s",
			binding.VLAN, binding.MTU, binding.Port, binding.NodeA, binding.NodeB)
	}
	shared := 0
	for _, binding := range b.Bindings {
		want, ok := byVNI[binding.VNI]
		if !ok {
			continue
		}
		shared++
		got := fmt.Sprintf("vlan=%d mtu=%d port=%d nodes=%s/%s",
			binding.VLAN, binding.MTU, binding.Port, binding.NodeA, binding.NodeB)
		if got != want {
			t.Fatalf("VNI %d: node-1 derived %q but node-2 derived %q", binding.VNI, want, got)
		}
	}
	if shared == 0 {
		t.Fatal("the two nodes share no cross-node link, so symmetry was not exercised")
	}
}
