package place

import (
	"fmt"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// peeringLab builds a lab of n autonomous systems wired as a tiered internet:
// every AS peers with a few neighbours, which is the shape a class actually
// deploys and the shape placement has to partition well.
func peeringLab(n, nodes, perAS int) *model.Topology {
	lab := &model.Lab{}
	for i := 0; i < nodes; i++ {
		lab.Placement.Nodes = append(lab.Placement.Nodes,
			model.NodeSpec{Name: fmt.Sprintf("node-%d", i), Front: i == 0})
	}
	top := &model.Topology{Name: "t", Lab: lab,
		ASes: map[int]*model.AS{}, Devices: map[string]*model.Device{}}

	for asn := 1; asn <= n; asn++ {
		as := &model.AS{ASN: asn}
		for i := 0; i < perAS; i++ {
			d := &model.Device{ID: fmt.Sprintf("as%d/r%d", asn, i),
				Name: fmt.Sprintf("r%d", i), ASN: asn, Kind: model.KindRouter}
			as.Devices = append(as.Devices, d)
			as.Routers = append(as.Routers, d)
			top.Devices[d.ID] = d
			// An intra-AS link, which must never cross a node.
			if i > 0 {
				top.Links = append(top.Links, link(as.Devices[i-1], d, false))
			}
		}
		top.ASes[asn] = as
	}
	// Peer each AS with the next three, wrapping: a ring with chords, which
	// has a genuine partition structure without being trivially separable.
	for asn := 1; asn <= n; asn++ {
		for _, off := range []int{1, 2, 3} {
			other := (asn+off-1)%n + 1
			if other <= asn {
				continue
			}
			top.Links = append(top.Links,
				link(top.ASes[asn].Devices[0], top.ASes[other].Devices[0], true))
		}
	}
	return top
}

func link(a, b *model.Device, interAS bool) *model.Link {
	ia := &model.Iface{Device: a, Name: "eth0"}
	ib := &model.Iface{Device: b, Name: "eth0"}
	l := &model.Link{A: ia, B: ib, InterAS: interAS}
	ia.Link, ib.Link = l, l
	a.Ifaces = append(a.Ifaces, ia)
	b.Ifaces = append(b.Ifaces, ib)
	return l
}

func crossing(top *model.Topology) (inter, interTotal, intra int) {
	for _, l := range top.Links {
		if l.InterAS {
			interTotal++
			if l.CrossNode() {
				inter++
			}
		} else if l.CrossNode() {
			intra++
		}
	}
	return
}

func spread(a *Assignment) (lo, hi int) {
	lo = 1 << 30
	for _, v := range a.Load {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return
}

// The point of placing whole autonomous systems rather than containers is that
// a link kept inside a node is a veth pair instead of a VXLAN tunnel. Placement
// therefore has to partition the peering graph, not merely balance a count.
//
// It did not. Both strategies put each AS on whichever node was emptiest, which
// for a peering graph deals neighbours out round-robin: at eighty autonomous
// systems on three nodes, 71% of inter-AS links crossed the fabric, against a
// design document promising a pass that minimises exactly that number.
func TestPlacementKeepsPeeringASesTogether(t *testing.T) {
	for _, strategy := range []string{"pack-by-as", "spread-by-as"} {
		top := peeringLab(80, 3, 25)
		a, err := Place(top, Options{Strategy: strategy})
		if err != nil {
			t.Fatalf("%s: %v", strategy, err)
		}
		inter, total, intra := crossing(top)
		if intra != 0 {
			t.Errorf("%s: %d intra-AS links cross a node; an AS must never be split", strategy, intra)
		}
		// Round-robin on this graph crosses roughly seven links in ten. Any
		// honest partition does far better; the bar is set well below what
		// the implementation achieves so that it tests the property rather
		// than the current constant.
		if got := float64(inter) / float64(total); got > 0.55 {
			t.Errorf("%s: %d of %d inter-AS links cross (%.0f%%); the partition is no better "+
				"than dealing ASes out in turn", strategy, inter, total, got*100)
		}
		lo, hi := spread(a)
		if lo == 0 {
			t.Errorf("%s: a node was left empty while others carry the lab", strategy)
		}
		// Locality is bounded by balance: trading the whole lab onto one node
		// would keep every link local and defeat the purpose.
		if float64(hi) > 1.5*float64(lo) {
			t.Errorf("%s: load %d..%d is too uneven; locality must not be bought "+
				"with the cluster's balance", strategy, lo, hi)
		}
	}
}

// Redeploying must not shuffle a group onto a different machine: that would
// rebuild containers a student is working in. The partitioner uses maps, so
// this is not free -- every tie has to be broken by something ordered.
func TestPlacementIsIdenticalOnEveryRun(t *testing.T) {
	var first map[int]string
	for i := 0; i < 12; i++ {
		top := peeringLab(40, 4, 12)
		a, err := Place(top, Options{Strategy: "pack-by-as"})
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = a.ByAS
			continue
		}
		for asn, node := range first {
			if a.ByAS[asn] != node {
				t.Fatalf("run %d put AS %d on %s, the first run put it on %s",
					i, asn, a.ByAS[asn], node)
			}
		}
	}
}

// spread-by-as asks for an even spread and must deliver one even where
// locality would prefer otherwise; pack-by-as may trade a little balance for
// locality, but only a little.
func TestSpreadIsMoreEvenThanPack(t *testing.T) {
	tops := map[string]*model.Topology{
		"pack-by-as":   peeringLab(80, 3, 25),
		"spread-by-as": peeringLab(80, 3, 25),
	}
	ev := map[string]int{}
	for s, top := range tops {
		if _, err := Place(top, Options{Strategy: s}); err != nil {
			t.Fatal(err)
		}
		a, _ := Place(top, Options{Strategy: s})
		lo, hi := spread(a)
		ev[s] = hi - lo
	}
	if ev["spread-by-as"] > ev["pack-by-as"] {
		t.Errorf("spread-by-as varies by %d containers and pack-by-as by %d; "+
			"the two strategies were once the same code and must not be again",
			ev["spread-by-as"], ev["pack-by-as"])
	}
}

// A node that declares no capacity used to be scored on a different scale from
// one that did -- a raw container count against a 0..1 ratio -- so it looked
// enormously more loaded and every AS went to the declared node until that node
// was completely full. A manifest that merely omitted one capacity line
// therefore got the opposite of balancing.
func TestANodeWithoutADeclaredCapacityStillTakesWork(t *testing.T) {
	top := peeringLab(12, 2, 8)
	top.Lab.Placement.Nodes[0].Capacity = &model.Budget{Containers: 200, CPUs: 64, Memory: "128Gi"}
	a, err := Place(top, Options{Strategy: "spread-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	lo, hi := spread(a)
	if lo == 0 {
		t.Fatalf("the node with no declared capacity was given nothing: %v", a.Load)
	}
	if float64(hi) > 2*float64(lo) {
		t.Errorf("load %d..%d: declaring a capacity on one node should not send "+
			"the lab there", lo, hi)
	}
}
