package deploy

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestMultiplexParametersSharePairTunnelButKeepVNIsSeparate(t *testing.T) {
	mtuA, mtuB := 1400, 1600
	leftA := &model.Device{ID: "as1/R1", Node: "node-a"}
	rightA := &model.Device{ID: "as2/R1", Node: "node-b"}
	leftB := &model.Device{ID: "as3/R1", Node: "node-a"}
	rightB := &model.Device{ID: "as4/R1", Node: "node-b"}
	leftC := &model.Device{ID: "as5/R1", Node: "node-a"}
	rightC := &model.Device{ID: "as6/R1", Node: "node-c"}
	linkA := &model.Link{
		ID: "a", VNI: 1,
		A: &model.Iface{Device: leftA}, B: &model.Iface{Device: rightA},
		Props: model.LinkProps{MTU: &mtuA},
	}
	// 4095 initially hashes to the same bridge VLAN as VNI 1, exercising
	// deterministic collision resolution without changing either wire VNI.
	linkB := &model.Link{
		ID: "b", VNI: 4095,
		A: &model.Iface{Device: leftB}, B: &model.Iface{Device: rightB},
		Props: model.LinkProps{MTU: &mtuB},
	}
	linkC := &model.Link{
		ID: "c", VNI: 9001,
		A: &model.Iface{Device: leftC}, B: &model.Iface{Device: rightC},
	}
	top := &model.Topology{Name: "mux-test", Links: []*model.Link{linkB, linkA, linkC}}

	vlanA, pairMTUA, portA, err := multiplexParameters(top, "node-a", "node-b", linkA.VNI)
	if err != nil {
		t.Fatal(err)
	}
	vlanB, pairMTUB, portB, err := multiplexParameters(top, "node-b", "node-a", linkB.VNI)
	if err != nil {
		t.Fatal(err)
	}
	if vlanA == vlanB {
		t.Fatalf("two cross-node VNIs share VLAN %d and would leak frames", vlanA)
	}
	if pairMTUA != mtuB || pairMTUB != mtuB {
		t.Fatalf("pair MTUs = %d and %d, want largest link MTU %d", pairMTUA, pairMTUB, mtuB)
	}
	if portA == 0 || portA != portB {
		t.Fatalf("pair ports = %d and %d, want one deterministic non-zero port", portA, portB)
	}
	_, _, portC, err := multiplexParameters(top, "node-a", "node-c", linkC.VNI)
	if err != nil {
		t.Fatal(err)
	}
	if portC == portA {
		t.Fatalf("different node pairs share UDP port %d", portC)
	}
}
