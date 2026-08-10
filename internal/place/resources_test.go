package place

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func nodesWithCapacity() []model.NodeSpec {
	return []model.NodeSpec{
		{Name: "a", Capacity: &model.Budget{Containers: 100, CPUs: 8, Memory: "16Gi"}},
		{Name: "b", Capacity: &model.Budget{Containers: 100, CPUs: 8, Memory: "16Gi"}},
	}
}

// Counting containers alone treats eight small routers and eight four-core ones
// as identical, so a node accepts both and the second lab starves. The failure
// is not a refusal at placement time, which anyone could act on, but a lab that
// deploys successfully and then behaves as though the network is congested --
// which, in a course about congestion, is the worst thing to be wrong about.
func TestPlacementRefusesWhatWillNotFit(t *testing.T) {
	lab := &model.Lab{}
	lab.Placement.Strategy = "pack-by-as"
	lab.Placement.Nodes = nodesWithCapacity()

	top := &model.Topology{Name: "t", Lab: lab, ASes: map[int]*model.AS{}, Devices: map[string]*model.Device{}}
	// Four ASes of four routers each, every router asking for two cores: 32
	// cores in total against 16 available.
	for asn := 1; asn <= 4; asn++ {
		as := &model.AS{ASN: asn}
		for i := 0; i < 4; i++ {
			d := &model.Device{
				ID: nameOf(asn, i), Name: nameOf(asn, i), ASN: asn,
				Kind: model.KindRouter, CPUs: 2, Memory: "1Gi",
			}
			as.Devices = append(as.Devices, d)
			top.Devices[d.ID] = d
		}
		top.ASes[asn] = as
	}

	_, err := Place(top, Options{})
	if err == nil {
		t.Fatal("placement accepted a lab needing 32 cores onto 16, which would deploy and then starve")
	}
	if !strings.Contains(err.Error(), "cpu") {
		t.Errorf("the refusal does not say what ran out: %v", err)
	}
	t.Logf("refused, correctly: %v", err)
}

// A reservation is capacity that exists but must not be handed out: the agent,
// the container engine and the kernel all need room.
func TestReservedCapacityIsNotHandedOut(t *testing.T) {
	lab := &model.Lab{}
	lab.Placement.Strategy = "pack-by-as"
	lab.Placement.Nodes = []model.NodeSpec{
		{Name: "a", Capacity: &model.Budget{Containers: 10, CPUs: 8, Memory: "16Gi"}},
	}
	lab.Placement.Reserve = map[string]model.Budget{"a": {Containers: 6}}

	top := &model.Topology{Name: "t", Lab: lab, ASes: map[int]*model.AS{}, Devices: map[string]*model.Device{}}
	as := &model.AS{ASN: 1}
	for i := 0; i < 6; i++ {
		d := &model.Device{ID: nameOf(1, i), Name: nameOf(1, i), ASN: 1, Kind: model.KindRouter}
		as.Devices = append(as.Devices, d)
		top.Devices[d.ID] = d
	}
	top.ASes[1] = as

	if _, err := Place(top, Options{}); err == nil {
		t.Fatal("six containers were placed on a node with ten declared and six reserved")
	}
}

// Round-robin still has to respect capacity: the strategy asks for an even
// spread, not for an impossible one.
func TestSpreadStillRespectsCapacity(t *testing.T) {
	lab := &model.Lab{}
	lab.Placement.Strategy = "spread-by-as"
	lab.Placement.Nodes = []model.NodeSpec{
		{Name: "a", Capacity: &model.Budget{Containers: 2}},
		{Name: "b", Capacity: &model.Budget{Containers: 2}},
	}
	top := &model.Topology{Name: "t", Lab: lab, ASes: map[int]*model.AS{}, Devices: map[string]*model.Device{}}
	for asn := 1; asn <= 4; asn++ {
		as := &model.AS{ASN: asn}
		for i := 0; i < 2; i++ {
			d := &model.Device{ID: nameOf(asn, i), Name: nameOf(asn, i), ASN: asn, Kind: model.KindRouter}
			as.Devices = append(as.Devices, d)
			top.Devices[d.ID] = d
		}
		top.ASes[asn] = as
	}
	if _, err := Place(top, Options{}); err == nil {
		t.Fatal("spread placed eight containers onto four slots")
	}
}

func TestPlacementUsesEveryDimension(t *testing.T) {
	// A node full on memory but idle on cores is full.
	load := demand{Containers: 1, CPUs: 0.1, MemBytes: 15 << 30}
	cap := demand{Containers: 100, CPUs: 8, MemBytes: 16 << 30}
	if p := pressure(load, cap, true); p < 0.9 {
		t.Errorf("pressure %f ignores memory; averaging hides the case that causes trouble", p)
	}
}

func nameOf(asn, i int) string {
	return string(rune('a'+asn)) + string(rune('0'+i))
}
