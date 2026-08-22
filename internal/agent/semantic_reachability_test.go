package agent

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestReferenceReachabilityTargetsCoverRemoteASHosts(t *testing.T) {
	makeHost := func(asn int, address string) *model.Device {
		host := &model.Device{ID: "as-host", Kind: model.KindHost, ASN: asn}
		host.Ifaces = []*model.Iface{{Device: host, Name: "host", Addr4: address}}
		return host
	}
	h5 := makeHost(5, "5.101.0.1/24")
	h10 := makeHost(10, "10.101.0.1/24")
	top := &model.Topology{
		ASes: map[int]*model.AS{
			3:  {ASN: 3},
			5:  {ASN: 5, Devices: []*model.Device{h5}},
			10: {ASN: 10, Devices: []*model.Device{h10}},
		},
	}
	got := referenceReachabilityTargets(top, 3)
	if len(got) != 2 || got[0] != "10.101.0.1" || got[1] != "5.101.0.1" {
		t.Fatalf("reference targets = %v", got)
	}
}
