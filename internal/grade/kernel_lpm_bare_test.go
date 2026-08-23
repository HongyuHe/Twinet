package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/netstate"
)

func TestKernelLPMNormalizesBareAndCIDRHostRoutes(t *testing.T) {
	routes := []netstate.Route{
		{Prefix: "3.153.0.1", Family: "ipv4", Table: "main", Protocol: "ospf",
			Selected: true, NextHops: []netstate.NextHop{{Device: "PHY"}, {Device: "BOS"}}},
		{Prefix: "2001:db8::1", Family: "ipv6", Table: "main", Protocol: "ospf",
			Selected: true, NextHops: []netstate.NextHop{{Device: "v6tun"}}},
	}
	for _, target := range []string{"3.153.0.1", "3.153.0.1/32"} {
		got := kernelLPM(routes, target)
		if len(got) != 1 || len(got[0].NextHops) != 2 {
			t.Fatalf("IPv4 target %q got %#v", target, got)
		}
	}
	for _, target := range []string{"2001:db8::1", "2001:db8::1/128"} {
		got := kernelLPM(routes, target)
		if len(got) != 1 || got[0].NextHops[0].Device != "v6tun" {
			t.Fatalf("IPv6 target %q got %#v", target, got)
		}
	}
}
