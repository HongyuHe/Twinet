package place

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// Capacity was checked inside the balanced placer, so three ways of placing a
// lab never reached it: the single-node strategy, which puts everything on the
// front node; an explicit pin, which wins over every other consideration; and
// services, which are placed separately.
//
// The arrangements most likely to overload a machine -- "put it all here",
// "put this one here specifically" -- were exactly the ones nothing checked,
// and the check applied only to the strategy that was already trying to avoid
// the problem.
//
// It is a warning rather than a refusal, because the budgets are written by
// hand in the manifest and a stale one should not stop a class running. But
// somebody has to be told: the failure it predicts arrives as containers being
// killed under load an hour later, looking like a bug in the lab.
func TestOverloadIsNoticedOnEveryPlacementPath(t *testing.T) {
	cases := []struct {
		name  string
		build func() *model.Topology
	}{
		{
			name:  "single-node puts the whole lab on one machine",
			build: func() *model.Topology { return overloadedLab("single-node", false) },
		},
		{
			name:  "a pin overrides the balancer",
			build: func() *model.Topology { return overloadedLab("pack-by-as", true) },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := Place(c.build(), Options{})
			if err != nil {
				// A refusal is also an acceptable answer; silence is not.
				return
			}
			if len(a.Overloaded) == 0 {
				t.Errorf("a node was asked for far more than it declares and nothing "+
					"said so. The containers that do not fit are killed under load an "+
					"hour later, which reads as a broken lab rather than a placement "+
					"that never fitted. (load: %v)", a.Load)
			}
		})
	}
}

// And it must stay quiet when the lab does fit, or the warning becomes noise
// people learn to ignore -- which is the same as not having it.
func TestAFittingLabIsNotReportedAsOverloaded(t *testing.T) {
	lab := &model.Lab{}
	lab.Placement.Strategy = "pack-by-as"
	lab.Placement.Nodes = []model.NodeSpec{
		{Name: "a", Front: true, Capacity: &model.Budget{Containers: 100, CPUs: 32, Memory: "64Gi"}},
		{Name: "b", Capacity: &model.Budget{Containers: 100, CPUs: 32, Memory: "64Gi"}},
	}

	a, err := Place(labOf(lab, 2, 2, 1, "256Mi"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Overloaded) != 0 {
		t.Errorf("a lab that fits comfortably was reported as overloaded: %v", a.Overloaded)
	}
}

func TestPlacementWeightDoesNotReduceAdmissionCapacity(t *testing.T) {
	lab := &model.Lab{}
	lab.Placement.Strategy = "spread-by-as"
	capacity := &model.Budget{
		Containers: 100, CPUs: 100, Memory: "100Gi", Pids: 100000,
		EphemeralStorage: "100Gi", FileDescriptors: 100000, NetDevices: 100000,
	}
	lab.Placement.Nodes = []model.NodeSpec{
		{
			Name: "a", Front: true, PlacementWeight: 0.5,
			Capacity: capacity,
		},
		{Name: "b", Capacity: capacity},
	}
	top := labOf(lab, 12, 1, 1, "64Mi")
	assignment, err := Place(top, Options{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if assignment.Load["a"] >= assignment.Load["b"] {
		t.Fatalf("slower node received %d devices, faster node %d",
			assignment.Load["a"], assignment.Load["b"])
	}
	summary := SummarizeCapacity(top)
	if summary.Capacity["a"].Containers != summary.Capacity["b"].Containers {
		t.Fatal("placement weight was incorrectly subtracted from admission capacity")
	}
}

func TestDrainExcludesSourceButPreservesRecordedGroupsElsewhere(t *testing.T) {
	lab := &model.Lab{Placement: model.Placement{
		Strategy: "pack-by-as",
		Nodes:    []model.NodeSpec{{Name: "a", Front: true}, {Name: "b"}, {Name: "c"}},
	}}
	lab.Normalize()
	top := labOf(lab, 2, 1, 0.1, "64Mi")
	record := &Record{Lab: top.Name, ByAS: map[int]string{1: "a", 2: "b"},
		ByGroup: map[string]string{}, ByService: map[string]string{}}
	assignment, err := Place(top, Options{Fixed: record, Unavailable: map[string]bool{"a": true}})
	if err != nil {
		t.Fatal(err)
	}
	if assignment.ByAS[1] == "a" {
		t.Fatal("drain left AS 1 on its unavailable source node")
	}
	if assignment.ByAS[2] != "b" {
		t.Fatalf("drain moved an unrelated recorded AS from b to %s", assignment.ByAS[2])
	}
	if len(assignment.Moved) != 1 {
		t.Fatalf("drain did not record exactly its source move: %v", assignment.Moved)
	}
}

// overloadedLab builds a lab that cannot fit on the machines it declares.
func overloadedLab(strategy string, pin bool) *model.Topology {
	lab := &model.Lab{}
	lab.Placement.Strategy = strategy
	lab.Placement.Nodes = []model.NodeSpec{
		{Name: "a", Front: true, Capacity: &model.Budget{Containers: 4, CPUs: 2, Memory: "1Gi"}},
		{Name: "b", Capacity: &model.Budget{Containers: 4, CPUs: 2, Memory: "1Gi"}},
	}
	if pin {
		for asn := 1; asn <= 4; asn++ {
			n := asn
			lab.Placement.Pin = append(lab.Placement.Pin,
				model.PlacementPin{Match: model.PinMatch{AS: &n}, Node: "a"})
		}
	}
	return labOf(lab, 4, 4, 1, "1Gi")
}

func labOf(lab *model.Lab, ases, perAS int, cpus float64, mem string) *model.Topology {
	top := &model.Topology{
		Name: "t", Lab: lab,
		ASes: map[int]*model.AS{}, Devices: map[string]*model.Device{},
	}
	for asn := 1; asn <= ases; asn++ {
		as := &model.AS{ASN: asn}
		for i := 0; i < perAS; i++ {
			d := &model.Device{
				ID: nameOf(asn, i), Name: nameOf(asn, i), ASN: asn,
				Kind: model.KindRouter, CPUs: cpus, Memory: mem,
			}
			as.Devices = append(as.Devices, d)
			as.Routers = append(as.Routers, d)
			top.Devices[d.ID] = d
		}
		top.ASes[asn] = as
	}
	return top
}
