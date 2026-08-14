package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

// A scenario that names its own answer cannot measure an agent that has read
// it, and everything Twinet ships is published. These pin the mechanism that
// replaces the written-down answer with one drawn at run time.

func twoASLab(t *testing.T) *model.Topology {
	t.Helper()
	top := &model.Topology{
		Lab:     &model.Lab{},
		Devices: map[string]*model.Device{},
	}
	mk := func(asn int, name string, kind model.DeviceKind) *model.Device {
		d := &model.Device{ID: model.DeviceID(asn, name), Name: name, Kind: kind, ASN: asn}
		top.Devices[d.ID] = d
		return d
	}
	link := func(a, b *model.Device, an, bn string, inter bool) {
		ai := &model.Iface{Name: an, Device: a}
		bi := &model.Iface{Name: bn, Device: b}
		l := &model.Link{A: ai, B: bi, InterAS: inter}
		ai.Link, bi.Link = l, l
		ai.Peer, bi.Peer = bi, ai
		a.Ifaces = append(a.Ifaces, ai)
		b.Ifaces = append(b.Ifaces, bi)
		top.Links = append(top.Links, l)
	}
	a1 := mk(3, "ATL", model.KindRouter)
	a2 := mk(3, "BOS", model.KindRouter)
	a3 := mk(3, "CHI", model.KindRouter)
	h1 := mk(3, "ATL_host", model.KindHost)
	b1 := mk(4, "NYC", model.KindRouter)
	link(a1, a2, "port_BOS", "port_ATL", false)
	link(a2, a3, "port_CHI", "port_BOS", false)
	link(a1, b1, "ext_4", "ext_3", true)
	link(a1, h1, "host", "eth0", false)
	return top
}

func TestASelectorDrawsOnlyFromTheFamilyItNames(t *testing.T) {
	top := twoASLab(t)
	cases := []struct {
		kind string
		want []string
	}{
		{selectInternalLink, []string{"ATL:port_BOS", "BOS:port_ATL", "BOS:port_CHI", "CHI:port_BOS"}},
		{selectExternalLink, []string{"ATL:ext_4", "NYC:ext_3"}},
		{selectRouter, []string{"ATL:", "BOS:", "CHI:", "NYC:"}},
		{selectHost, []string{"ATL_host:"}},
	}
	for _, c := range cases {
		s := &Selector{Kind: c.kind}
		var got []string
		for _, tg := range s.candidates(top) {
			got = append(got, tg.Device+":"+tg.Iface)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s drew from %v, wanted %v", c.kind, got, c.want)
		}
	}
	// The link to a host is not an internal link between routers, or a fault
	// meant for the core would land on an access port and the episode would be
	// about something else.
	for _, tg := range (&Selector{Kind: selectInternalLink}).candidates(top) {
		if tg.Iface == "host" {
			t.Error("an access link was offered as an internal one")
		}
	}
}

func TestASelectorHonoursItsRestrictions(t *testing.T) {
	top := twoASLab(t)
	s := &Selector{Kind: selectRouter, AS: []int{3}, Exclude: []string{"BOS"}}
	var got []string
	for _, tg := range s.candidates(top) {
		if tg.AS != 3 {
			t.Errorf("drew from AS %d, which the selector excluded", tg.AS)
		}
		got = append(got, tg.Device)
	}
	if strings.Join(got, ",") != "ATL,CHI" {
		t.Errorf("drew %v; BOS was excluded and AS 4 was out of scope", got)
	}
}

func TestADrawIsReproducibleFromItsSeedAndNotOtherwise(t *testing.T) {
	top := twoASLab(t)
	specs := []FaultSpec{{Type: "ospf_neighbor_missing",
		Select: &Selector{Kind: selectInternalLink, AS: []int{3}}}}
	first, err := drawTargets(top, specs, 99)
	if err != nil {
		t.Fatal(err)
	}
	// Every candidate is offered, in an order the seed decides: the first is
	// the draw and the rest are what to try if it cannot host the fault.
	if len(first[0]) != 4 {
		t.Errorf("the draw offered %d of 4 candidates, so an unsuitable one would end "+
			"the episode", len(first[0]))
	}
	if d := describeDraw("ospf_neighbor_missing", first[0][0], len(first[0])); !strings.Contains(d, "1 of 4") {
		t.Errorf("the draw was not described as one of the candidates: %s", d)
	}
	again, err := drawTargets(top, specs, 99)
	if err != nil {
		t.Fatal(err)
	}
	if first[0][0].DeviceID() != again[0][0].DeviceID() || first[0][0].Iface != again[0][0].Iface {
		t.Errorf("the same seed drew %v and then %v, so an episode cannot be replayed",
			first[0][0], again[0][0])
	}
	// And the draw has to move, or "drawn at run time" is a pinned target with
	// extra steps.
	seen := map[string]bool{}
	for seed := int64(1); seed <= 40; seed++ {
		got, err := drawTargets(top, specs, seed)
		if err != nil {
			t.Fatal(err)
		}
		seen[got[0][0].Device+":"+got[0][0].Iface] = true
	}
	if len(seen) < 2 {
		t.Errorf("40 seeds drew %d distinct target(s); the answer is effectively written "+
			"down after all", len(seen))
	}
}

func TestAFaultTheLabCannotHostIsRefusedRatherThanSkipped(t *testing.T) {
	top := twoASLab(t)
	_, err := drawTargets(top, []FaultSpec{
		{Type: "ospf_neighbor_missing", Select: &Selector{Kind: selectHost, AS: []int{9}}},
	}, 1)
	if err == nil {
		t.Fatal("a selector that matches nothing was accepted, so the episode would have " +
			"one fewer fault than its ground truth claims")
	}
	if !strings.Contains(err.Error(), "nothing in this lab matches") {
		t.Errorf("unhelpful refusal: %v", err)
	}
}

func TestAPinnedTargetSurvivesTheDrawAndIsReported(t *testing.T) {
	top := twoASLab(t)
	specs := []FaultSpec{
		{Type: "icmp_acl_block", Target: fault.Target{AS: 3, Device: "BOS"}},
		{Type: "ospf_neighbor_missing", Select: &Selector{Kind: selectInternalLink}},
	}
	got, err := drawTargets(top, specs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0]) != 1 || got[0][0].Device != "BOS" {
		t.Errorf("a pinned target was overwritten by a draw: %v", got[0])
	}
	pinned := pinnedTargets(specs)
	if len(pinned) != 1 || !strings.Contains(pinned[0], "BOS") {
		t.Errorf("the pinned fault was not reported as pinned: %v", pinned)
	}
}

func TestASelectorRefusesAFamilyItDoesNotHave(t *testing.T) {
	if err := (&Selector{Kind: "everything"}).Valid(); err == nil {
		t.Fatal("an unknown target family was accepted, so a scenario would silently " +
			"inject nothing where it said it would")
	}
	if err := (&Selector{}).Valid(); err == nil {
		t.Fatal("a selector with no family was accepted")
	}
	if err := (&Selector{Kind: selectRouter}).Valid(); err != nil {
		t.Fatalf("a valid selector was refused: %v", err)
	}
}
