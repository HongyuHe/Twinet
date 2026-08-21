package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestBirdRendererGeneratesReferenceBGPPolicy(t *testing.T) {
	bird := &model.Device{ID: "as1/ALL", Name: "ALL", Kind: model.KindRouter, ASN: 1, NOS: "bird", RouterID: 1}
	peer := &model.Device{ID: "as3/EDGE", Name: "EDGE", Kind: model.KindRouter, ASN: 3, RouterID: 1}
	loopback := &model.Iface{Device: bird, Name: "lo", Addr4: "1.151.0.1/24"}
	external := &model.Iface{Device: bird, Name: "ext_3_EDGE", Role: model.RoleInterAS, Addr4: "192.0.2.1/24"}
	peerExternal := &model.Iface{Device: peer, Name: "ext_1_ALL", Role: model.RoleInterAS, Addr4: "192.0.2.2/24"}
	link := &model.Link{A: external, B: peerExternal, InterAS: true, Rel: model.RelCustomer}
	external.Link, external.Peer = link, peerExternal
	peerExternal.Link, peerExternal.Peer = link, external
	bird.Ifaces = []*model.Iface{loopback, external}
	peer.Ifaces = []*model.Iface{peerExternal}
	topology := &model.Topology{
		Devices: map[string]*model.Device{bird.ID: bird, peer.ID: peer},
		ASes: map[int]*model.AS{
			1: {ASN: 1, Role: model.RoleStaff, Block: "1.0.0.0/8", Routers: []*model.Device{bird}},
			3: {ASN: 3, Role: model.RoleStudent, Block: "3.0.0.0/8", Routers: []*model.Device{peer}},
		},
	}
	config, err := BirdRouter(topology, bird)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"protocol static own4", "filter import_ebgp_ext_3_EDGE",
		"bgp_local_pref = 100", "protocol bgp ebgp_ext_3_EDGE",
		"neighbor 192.0.2.2 as 3",
	} {
		if !strings.Contains(config.Platform, want) {
			t.Fatalf("BIRD golden configuration is missing %q:\n%s", want, config.Platform)
		}
	}
}

func TestBirdRendererUsesBirdPaths(t *testing.T) {
	d := &model.Device{ID: "as1/ALL", Name: "ALL", Kind: model.KindRouter, ASN: 1, NOS: "bird", RouterID: 1}
	d.Ifaces = []*model.Iface{{Device: d, Name: "lo", Addr4: "1.151.0.1/24"}}
	topology := &model.Topology{
		Devices: map[string]*model.Device{d.ID: d},
		ASes:    map[int]*model.AS{1: {ASN: 1, Role: model.RoleStaff, Block: "1.0.0.0/8", Routers: []*model.Device{d}}},
	}
	files, err := New(topology, ModePlatform).Files(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["/etc/bird/bird.conf"]; !ok {
		t.Fatalf("BIRD files = %v, want /etc/bird/bird.conf", files)
	}
	if _, old := files["/etc/frr/frr.conf"]; old {
		t.Fatalf("BIRD renderer wrote FRR configuration: %v", files)
	}
}
