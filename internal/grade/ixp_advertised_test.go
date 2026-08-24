package grade

import (
	"reflect"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestAdvertisedIXPMembersUsesNeighborAddress(t *testing.T) {
	rs := &model.Device{ID: "as140/RS", ASN: 140}
	member := &model.Device{ID: "as3/ALL", ASN: 3}
	rsIface := &model.Iface{
		Device: rs, Role: model.RoleIXPLink, Addr4: "180.140.0.140/24",
	}
	memberIface := &model.Iface{
		Device: member, Role: model.RoleIXPLink, Addr4: "180.140.0.3/24",
	}
	link := &model.Link{A: rsIface, B: memberIface}
	rsIface.Link, memberIface.Link = link, link
	rsIface.Peer, memberIface.Peer = memberIface, rsIface
	rs.Ifaces = []*model.Iface{rsIface}
	member.Ifaces = []*model.Iface{memberIface}
	top := &model.Topology{
		Devices: map[string]*model.Device{rs.ID: rs, member.ID: member},
		Links:   []*model.Link{link},
		ASes: map[int]*model.AS{
			3:   {ASN: 3, Devices: []*model.Device{member}},
			140: {ASN: 140, Role: model.RoleIXP, Devices: []*model.Device{rs}},
		},
	}

	got := advertisedIXPMembers(top, 140, map[string]advertisedIXPPeer{
		"180.140.0.3": {Hostname: "node-2.example.invalid"},
	})
	if want := []int{3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("advertised members = %v, want %v", got, want)
	}
}
