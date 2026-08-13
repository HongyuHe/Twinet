package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// The assignment lets neighbouring groups agree their own peering addresses.
// Twinet plans them, and the other end of every session is a rendered reference
// expecting the planned address -- so a group that agreed something else could
// not bring the session up at all, and lost the marks for every question that
// depends on it. That is a submission marked wrong for an answer the assignment
// permits.
func TestTheReferenceAdaptsToTheAddressAGroupActuallyUsed(t *testing.T) {
	mine := &model.Iface{Name: "port_HOU", Addr4: "179.3.4.1/24", Owner: model.OwnerStudent}
	theirs := &model.Iface{Name: "port_ATL", Addr4: "179.3.4.2/24", Owner: model.OwnerStudent}
	a := &model.Device{ID: "as3/ATL", Name: "ATL", ASN: 3, Kind: model.KindRouter}
	b := &model.Device{ID: "as4/HOU", Name: "HOU", ASN: 4, Kind: model.KindRouter}
	mine.Device, theirs.Device = a, b
	link := &model.Link{A: mine, B: theirs, InterAS: true}
	mine.Link, theirs.Link = link, link
	top := &model.Topology{
		Name: "cos461", Lab: &model.Lab{},
		Devices: map[string]*model.Device{a.ID: a, b.ID: b},
		Links:   []*model.Link{link},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{a}, Routers: []*model.Device{a}},
			4: {ASN: 4, Role: model.RoleStudent, Devices: []*model.Device{b}, Routers: []*model.Device{b}},
		},
	}

	var ran []string
	exec := func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
		body := strings.Join(cmd, " ")
		ran = append(ran, id+": "+body)
		switch {
		case strings.Contains(body, "ip -o -4 addr show dev port_HOU"):
			// The group agreed something else with their neighbour.
			return rt.ExecResult{Stdout: "10.34.0.1/30\n"}, nil
		case strings.Contains(body, "show running-config"):
			return rt.ExecResult{Stdout: strings.Join([]string{
				"router bgp 4",
				" neighbor 179.3.4.1 remote-as 3",
				" neighbor 179.3.4.1 description a customer",
				" address-family ipv4 unicast",
				"  neighbor 179.3.4.1 activate",
				"  neighbor 179.3.4.1 route-map LP-CUSTOMER in",
				"  neighbor 179.3.4.1 route-map EXPORT-CUSTOMER out",
				" exit-address-family",
				"exit",
			}, "\n")}, nil
		}
		return rt.ExecResult{}, nil
	}

	ads, undo, problems := adaptNeighbours(context.Background(), exec, top, 3)
	if len(problems) > 0 {
		t.Fatalf("adapting reported problems: %v", problems)
	}
	if len(ads) != 1 {
		t.Fatalf("the reference was not adapted to the group's addressing: %v\n%s",
			ads, strings.Join(ran, "\n"))
	}
	all := strings.Join(ran, "\n")
	if !strings.Contains(all, "ip addr replace 10.34.0.2/30 brd + dev port_ATL") {
		t.Errorf("the reference end was not given an address in the group's subnet:\n%s", all)
	}
	for _, want := range []string{
		"neighbor 10.34.0.1 remote-as 3",
		"neighbor 10.34.0.1 route-map LP-CUSTOMER in",
		"neighbor 10.34.0.1 route-map EXPORT-CUSTOMER out",
		"neighbor 10.34.0.1 activate",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the adapted session is missing %q, so it would come up without the "+
				"policy the reference uses -- or not at all:\n%s", want, all)
		}
	}

	// And it must all be removed again, or the next submission is graded
	// against the last group's addressing.
	ran = nil
	if err := undo(context.Background()); err != nil {
		t.Fatal(err)
	}
	all = strings.Join(ran, "\n")
	if !strings.Contains(all, "no neighbor 10.34.0.1") ||
		!strings.Contains(all, "ip addr del 10.34.0.2/30") {
		t.Errorf("the adaptation was not undone:\n%s", all)
	}
}

// A group that used the planned address must not cause any change at all: the
// adaptation exists for the case the assignment permits, not as a second way of
// configuring every lab.
func TestNothingIsAdaptedWhenTheGroupUsedThePlannedAddress(t *testing.T) {
	mine := &model.Iface{Name: "port_HOU", Addr4: "179.3.4.1/24", Owner: model.OwnerStudent}
	theirs := &model.Iface{Name: "port_ATL", Addr4: "179.3.4.2/24", Owner: model.OwnerStudent}
	a := &model.Device{ID: "as3/ATL", Name: "ATL", ASN: 3, Kind: model.KindRouter}
	b := &model.Device{ID: "as4/HOU", Name: "HOU", ASN: 4, Kind: model.KindRouter}
	mine.Device, theirs.Device = a, b
	link := &model.Link{A: mine, B: theirs, InterAS: true}
	mine.Link, theirs.Link = link, link
	top := &model.Topology{
		Name: "cos461", Lab: &model.Lab{},
		Devices: map[string]*model.Device{a.ID: a, b.ID: b},
		Links:   []*model.Link{link},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{a}},
			4: {ASN: 4, Role: model.RoleStudent, Devices: []*model.Device{b}},
		},
	}
	exec := func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		if strings.Contains(strings.Join(cmd, " "), "ip -o -4 addr show") {
			return rt.ExecResult{Stdout: "179.3.4.1/24\n"}, nil
		}
		t.Errorf("something was changed for a group that used the planned address: %v", cmd)
		return rt.ExecResult{}, nil
	}
	if ads, _, _ := adaptNeighbours(context.Background(), exec, top, 3); len(ads) != 0 {
		t.Errorf("adapted %v for a group that used the planned address", ads)
	}
}
