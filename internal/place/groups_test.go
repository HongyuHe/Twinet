package place

import (
	"reflect"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func loadClosTopology(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	if d := l.Validate(); d.HasErrors() {
		t.Fatal(d.Err())
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return res.Topology
}

func TestDistributableClosSplitsOnlyAtSpineLeafBoundary(t *testing.T) {
	top := loadClosTopology(t)
	// The full 11-device fabric does not fit on any one five-container node,
	// but its spine and leaf groups fit across the three-node declaration.
	// This proves the AS-level admission pass reserves only the anchor rather
	// than rejecting a Clos before its declared split can happen.
	for i := range top.Lab.Placement.Nodes {
		top.Lab.Placement.Nodes[i].Capacity = &model.Budget{Containers: 5}
	}
	a, err := Place(top, Options{Strategy: "pack-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(a.ByGroup); got != 4 {
		t.Fatalf("got %d Clos group assignments, want spine plus 3 leaf groups", got)
	}
	nodes := map[string]bool{}
	for _, d := range top.ASes[42].Devices {
		nodes[d.Node] = true
	}
	if len(nodes) != 3 {
		t.Fatalf("Clos used %d node(s), want all 3 declared nodes: %v", len(nodes), nodes)
	}

	for _, d := range top.ASes[42].Devices {
		want := a.ByGroup[d.PlacementGroup]
		if d.Node != want {
			t.Errorf("%s is on %s, group %s is assigned to %s",
				d.ID, d.Node, d.PlacementGroup, want)
		}
	}
	if got := a.Locality[model.LinkClassSpineLeaf].CrossNode; got == 0 {
		t.Error("no spine-leaf link crossed a node; the declared Clos was not distributed")
	}
	if got := a.Locality[model.LinkClassLeafHost].CrossNode; got != 0 {
		t.Errorf("%d leaf-host link(s) crossed a node; leaves and their hosts must stay local", got)
	}
	desc := a.Describe()
	if !strings.Contains(desc, "spine-leaf links:") || !strings.Contains(desc, "leaf-host links:") {
		t.Errorf("placement report lacks link-class locality:\n%s", desc)
	}

	againTop := loadClosTopology(t)
	for i := range againTop.Lab.Placement.Nodes {
		againTop.Lab.Placement.Nodes[i].Capacity = &model.Budget{Containers: 5}
	}
	again, err := Place(againTop, Options{Strategy: "pack-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.ByGroup, again.ByGroup) || !reflect.DeepEqual(a.ByAS, again.ByAS) {
		t.Errorf("Clos placement changed between identical runs:\nfirst groups=%v AS=%v\nagain groups=%v AS=%v",
			a.ByGroup, a.ByAS, again.ByGroup, again.ByAS)
	}
}

func TestClosPlacementRecordIsStableAndOldRecordsRemainCompatible(t *testing.T) {
	first, err := Place(loadClosTopology(t), Options{Strategy: "pack-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	rec := first.Record("clos", "pack-by-as")
	if len(rec.ByGroup) == 0 {
		t.Fatal("a distributed Clos record omitted its group assignments")
	}

	dir := t.TempDir()
	if err := SaveRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRecord(dir, "clos")
	if err != nil {
		t.Fatal(err)
	}
	held, err := Place(loadClosTopology(t), Options{Strategy: "pack-by-as", Fixed: loaded})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.ByGroup, held.ByGroup) {
		t.Errorf("group record did not reproduce placement:\nwant %v\ngot  %v", first.ByGroup, held.ByGroup)
	}

	// Records written before placement groups contained only by_as. They
	// describe an already-deployed atomic AS, so respecting one must not
	// silently move its leaves onto other nodes during an upgrade.
	old := &Record{Lab: "clos", Strategy: "pack-by-as",
		ByAS: map[int]string{42: first.ByAS[42]}, ByService: map[string]string{}}
	legacyTop := loadClosTopology(t)
	legacy, err := Place(legacyTop, Options{Strategy: "pack-by-as", Fixed: old})
	if err != nil {
		t.Fatal(err)
	}
	if len(legacy.ByGroup) != 0 {
		t.Errorf("old by_as-only record unexpectedly gained group assignments: %v", legacy.ByGroup)
	}
	for _, d := range legacyTop.ASes[42].Devices {
		if d.Node != old.ByAS[42] {
			t.Errorf("old record put %s on %s instead of preserved AS node %s",
				d.ID, d.Node, old.ByAS[42])
		}
	}
}

func TestOrdinaryASesRemainAtomic(t *testing.T) {
	l, err := manifest.Load("../../examples/advnet")
	if err != nil {
		t.Fatal(err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Place(res.Topology, Options{Strategy: "pack-by-as"}); err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Topology.Links {
		if l.A == nil || l.B == nil || l.A.Device.ASN == 0 || l.A.Device.ASN != l.B.Device.ASN {
			continue
		}
		if l.CrossNode() {
			t.Errorf("ordinary AS-local link %s crosses nodes", l.ID)
		}
	}
}
