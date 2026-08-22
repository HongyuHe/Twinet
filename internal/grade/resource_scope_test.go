package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestBGPRefreshResourcesSeparateIBGPAndEBGPSessions(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A", ASN: 3, Kind: model.KindRouter}
	b := &model.Device{ID: "as3/B", Name: "B", ASN: 3, Kind: model.KindRouter}
	peer := &model.Device{ID: "as1/P", Name: "P", ASN: 1, Kind: model.KindRouter}
	a.Ifaces = []*model.Iface{
		{Name: "lo", Device: a, Addr4: "10.3.0.1/32"},
		{Name: "ext", Device: a, Role: model.RoleInterAS, Peer: &model.Iface{Device: peer}},
	}
	b.Ifaces = []*model.Iface{{Name: "lo", Device: b, Addr4: "10.3.0.2/32"}}
	env := &Env{Topology: &model.Topology{ASes: map[int]*model.AS{
		3: {ASN: 3, Routers: []*model.Device{a, b}, Devices: []*model.Device{a, b}},
	}}}
	i := bgpRefreshResources("bgp.ibgp_full_mesh", env)
	e := bgpRefreshResources("bgp.ebgp_established", env)
	for _, left := range i {
		for _, right := range e {
			if left.key() == right.key() {
				t.Fatalf("iBGP and eBGP refreshes share over-broad lock %q", left.key())
			}
		}
	}
}
