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
	top := &model.Topology{Links: []*model.Link{linkB, linkA}}

	vlanA, pairMTUA, err := multiplexParameters(top, "node-a", "node-b", linkA.VNI)
	if err != nil {
		t.Fatal(err)
	}
	vlanB, pairMTUB, err := multiplexParameters(top, "node-b", "node-a", linkB.VNI)
	if err != nil {
		t.Fatal(err)
	}
	if vlanA == vlanB {
		t.Fatalf("two cross-node VNIs share VLAN %d and would leak frames", vlanA)
	}
	if pairMTUA != mtuB || pairMTUB != mtuB {
		t.Fatalf("pair MTUs = %d and %d, want largest link MTU %d", pairMTUA, pairMTUB, mtuB)
	}
}
