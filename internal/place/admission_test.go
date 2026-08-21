package place

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func testCapacity(containers int, cpu float64, memory, disk, pids, fds, netdevs int64) Capacity {
	return Capacity{
		Containers:      intPtrPlace(containers),
		CPUs:            floatPtrPlace(cpu),
		MemoryBytes:     int64PtrPlace(memory),
		DiskBytes:       int64PtrPlace(disk),
		Pids:            int64PtrPlace(pids),
		FileDescriptors: int64PtrPlace(fds),
		NetDevices:      int64PtrPlace(netdevs),
	}
}

func intPtrPlace(v int) *int           { return &v }
func int64PtrPlace(v int64) *int64     { return &v }
func floatPtrPlace(v float64) *float64 { return &v }

func requestedDevice(asn int, name string, cpu float64, disk int64) *model.Device {
	return &model.Device{
		ID: name, Name: name, ASN: asn, Kind: model.KindRouter,
		Requests: model.ResourceRequest{
			CPUs: cpu, Memory: "128Mi", Pids: 32, EphemeralStorage: byteQuantity(disk),
			FileDescriptors: 128, NetDevices: 2,
		},
	}
}

func byteQuantity(bytes int64) string {
	return stringQuantity(bytes >> 20)
}

func stringQuantity(mebibytes int64) string {
	return strings.TrimSpace(strings.Join([]string{itoa64(mebibytes), "Mi"}, ""))
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}

func admissionTopology(nodes ...string) *model.Topology {
	lab := &model.Lab{Placement: model.Placement{Strategy: "pack-by-as"}}
	for i, name := range nodes {
		lab.Placement.Nodes = append(lab.Placement.Nodes, model.NodeSpec{Name: name, Front: i == 0})
	}
	return &model.Topology{
		Name: "lab", Lab: lab, Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
		Services: map[string]*model.Service{},
	}
}

func addAS(top *model.Topology, asn int, d *model.Device) {
	top.ASes[asn] = &model.AS{ASN: asn, Devices: []*model.Device{d}, Routers: []*model.Device{d}}
	top.Devices[d.ID] = d
}

func TestStrictUnknownInventoryRefusesWithoutPlacementSideEffects(t *testing.T) {
	top := admissionTopology("a")
	d := requestedDevice(1, "as1/R", 0.5, 256<<20)
	addAS(top, 1, d)
	cap := testCapacity(10, 4, 8<<30, 1<<30, 1000, 10000, 100)
	cap.DiskBytes = nil
	_, err := Place(top, Options{Strict: true, Inventory: []NodeInventory{{Name: "a", Allocatable: cap}}})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "unknown") {
		t.Fatalf("unknown allocatable disk did not cause a strict refusal: %v", err)
	}
	if d.Node != "" {
		t.Fatalf("strict refusal stamped a placement on %s", d.Node)
	}
}

func TestKnownZeroInventoryIsExhaustedNotUnlimited(t *testing.T) {
	top := admissionTopology("a")
	d := requestedDevice(1, "as1/R", 0.5, 256<<20)
	addAS(top, 1, d)
	cap := testCapacity(10, 4, 8<<30, 1<<30, 1000, 10000, 100)
	zero := int64(0)
	cap.NetDevices = &zero
	if _, err := Place(top, Options{Strict: true, Inventory: []NodeInventory{{Name: "a", Allocatable: cap}}}); err == nil ||
		!strings.Contains(err.Error(), "netdevs") {
		t.Fatalf("known zero netdev capacity was treated as unlimited: %v", err)
	}
}

func TestCurrentLabReservationIsSubtractedButOtherLabsAreCharged(t *testing.T) {
	top := admissionTopology("a")
	d := requestedDevice(1, "as1/R", 0.5, 256<<20)
	addAS(top, 1, d)
	request := deviceDemand(d)
	inventory := NodeInventory{
		Name: "a", Allocatable: testCapacity(1, 1, 1<<30, 1<<30, 100, 1000, 10),
		Reserved:      resourcesToReservation(request),
		ReservedByLab: map[string]Resources{"lab": resourcesToReservation(request)},
	}
	if _, err := Place(top, Options{Strict: true, Inventory: []NodeInventory{inventory}}); err != nil {
		t.Fatalf("redeploy double-counted its own reservation: %v", err)
	}

	other := inventory
	other.ReservedByLab = map[string]Resources{"other-lab": resourcesToReservation(request)}
	top = admissionTopology("a")
	d = requestedDevice(1, "as1/R", 0.5, 256<<20)
	addAS(top, 1, d)
	if _, err := Place(top, Options{Strict: true, Inventory: []NodeInventory{other}}); err == nil {
		t.Fatal("a reservation from another lab was ignored")
	}
}

func resourcesToReservation(d demand) Resources {
	return Resources{
		Containers: d.Containers, CPUs: d.CPUs, MemoryBytes: d.memoryBytes(), MemBytes: d.memoryBytes(),
		DiskBytes: d.DiskBytes, Pids: d.Pids, FileDescriptors: d.FileDescriptors, NetDevices: d.NetDevices,
	}
}

func TestStrictPinnedPlacementCannotBypassOverload(t *testing.T) {
	top := admissionTopology("a", "b")
	first := requestedDevice(1, "as1/R", 0.75, 256<<20)
	second := requestedDevice(2, "as2/R", 0.75, 256<<20)
	addAS(top, 1, first)
	addAS(top, 2, second)
	one := 1
	two := 2
	top.Lab.Placement.Pin = []model.PlacementPin{
		{Match: model.PinMatch{AS: &one}, Node: "a"},
		{Match: model.PinMatch{AS: &two}, Node: "a"},
	}
	inventory := []NodeInventory{
		{Name: "a", Allocatable: testCapacity(4, 1, 2<<30, 2<<30, 1000, 10000, 100)},
		{Name: "b", Allocatable: testCapacity(4, 1, 2<<30, 2<<30, 1000, 10000, 100)},
	}
	if _, err := Place(top, Options{Strict: true, Inventory: inventory}); err == nil ||
		!strings.Contains(err.Error(), "requested CPUs") {
		t.Fatalf("pinned overload bypassed strict admission: %v", err)
	}
}

func TestStrictRecordedPlacementCannotBypassOverload(t *testing.T) {
	top := admissionTopology("a", "b")
	d := requestedDevice(1, "as1/R", 1.5, 256<<20)
	addAS(top, 1, d)
	inventory := []NodeInventory{
		{Name: "a", Allocatable: testCapacity(4, 1, 2<<30, 2<<30, 1000, 10000, 100)},
		{Name: "b", Allocatable: testCapacity(4, 4, 2<<30, 2<<30, 1000, 10000, 100)},
	}
	record := &Record{Lab: "lab", ByAS: map[int]string{1: "a"}, ByService: map[string]string{}}
	if _, err := Place(top, Options{Strict: true, Inventory: inventory, Fixed: record}); err == nil ||
		!strings.Contains(err.Error(), "requested CPUs") {
		t.Fatalf("recorded overload bypassed strict admission: %v", err)
	}
}

func TestPlacementScoresEphemeralStorage(t *testing.T) {
	top := admissionTopology("a", "b")
	d := requestedDevice(1, "as1/R", 0.25, 768<<20)
	addAS(top, 1, d)
	inventory := []NodeInventory{
		{Name: "a", Allocatable: testCapacity(10, 8, 8<<30, 512<<20, 1000, 10000, 100)},
		{Name: "b", Allocatable: testCapacity(10, 8, 8<<30, 2<<30, 1000, 10000, 100)},
	}
	a, err := Place(top, Options{Strict: true, Inventory: inventory})
	if err != nil {
		t.Fatal(err)
	}
	if a.ByAS[1] != "b" {
		t.Fatalf("disk request was not scored; AS landed on %q", a.ByAS[1])
	}
}
