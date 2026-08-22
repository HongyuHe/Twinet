package netx

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRecoveryKeepsCompatibleActiveTrunkDespiteLegacyPortAndMTU(t *testing.T) {
	local := net.ParseIP("10.0.1.1")
	vx := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{MTU: 1450},
		FlowBased: true,
		SrcAddr:   local,
		Port:      VXLANPort,
		Learning:  false,
	}
	if !canKeepRecoveryTrunk(vx, local, 0) {
		t.Fatal("recovery would replace a forwarding legacy trunk solely for port/MTU drift")
	}
	if canKeepActivePort(vx, local, 0, 1500) {
		t.Fatal("ordinary convergence unexpectedly accepted an MTU mismatch")
	}
}
