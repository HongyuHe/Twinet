package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/netstate"
)

func TestKernelLPMSelectsMainTableLongestPrefixAndECMP(t *testing.T) {
	routes := []netstate.Route{
		{Prefix: "0.0.0.0/0", Family: "ipv4", Table: "main", Metric: 100, Selected: true},
		{Prefix: "3.153.0.0/16", Family: "ipv4", Table: "main", Metric: 20, Selected: true,
			NextHops: []netstate.NextHop{{Device: "slow"}}},
		{Prefix: "3.153.0.0/24", Family: "ipv4", Table: "main", Metric: 10, Selected: true,
			NextHops: []netstate.NextHop{{Device: "a"}, {Device: "b"}}},
		{Prefix: "3.153.0.0/24", Family: "ipv4", Table: "100", Metric: 1, Selected: true,
			NextHops: []netstate.NextHop{{Device: "policy"}}},
		{Prefix: "3.153.0.1/32", Family: "ipv4", Table: "main", Metric: 1,
			NextHops: []netstate.NextHop{{Device: "not-installed"}}},
	}
	got := kernelLPM(routes, "3.153.0.1/32")
	if len(got) != 1 || len(got[0].NextHops) != 2 || got[0].NextHops[0].Device != "a" {
		t.Fatalf("LPM result = %#v", got)
	}
}

func TestKernelLPMHandlesIPv6DefaultAndMoreSpecific(t *testing.T) {
	routes := []netstate.Route{
		{Prefix: "default", Family: "ipv6", Table: "254", Metric: 100, Installed: true},
		{Prefix: "2001:db8::/32", Family: "ipv6", Table: "main", Metric: 5, Installed: true},
		{Prefix: "2001:db8:1::/48", Family: "ipv6", Table: "main", Metric: 5, Installed: true},
	}
	got := kernelLPM(routes, "2001:db8:1::42/128")
	if len(got) != 1 || got[0].Prefix != "2001:db8:1::/48" {
		t.Fatalf("IPv6 LPM result = %#v", got)
	}
	defaultRoute := kernelLPM(routes, "2001:dead::1/128")
	if len(defaultRoute) != 1 || defaultRoute[0].Prefix != "default" {
		t.Fatalf("IPv6 default result = %#v", defaultRoute)
	}
}
