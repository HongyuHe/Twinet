package netx

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func existingTunnel() *netlink.Vxlan {
	return &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: "twvx100", MTU: 1450},
		VxlanId:      100,
		SrcAddr:      net.ParseIP("10.0.0.1"),
		Group:        net.ParseIP("10.0.0.2"),
		Port:         4789,
		VtepDevIndex: 7,
	}
}

// A tunnel that already exists is kept, because tearing down the fabric of a
// running class on every deploy is worse than leaving it alone.
func TestATunnelThatStillMatchesIsKept(t *testing.T) {
	vx := existingTunnel()
	spec := OverlaySpec{VNI: 100, LocalIP: "10.0.0.1", RemoteIP: "10.0.0.2", MTU: 1450, Port: 4789}
	if why := overlayDiffers(vx, spec, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"),
		7, 4789, 1450); why != "" {
		t.Errorf("an unchanged tunnel was going to be rebuilt: %s", why)
	}
}

// Only the remote and the VNI used to be compared. A tunnel built before the
// source address, underlay interface, VTEP port or MTU changed was kept exactly
// as it was -- a working-looking tunnel that behaves differently from the one
// the manifest describes, with the deployment reporting success.
func TestATunnelThatNoLongerMatchesIsReplaced(t *testing.T) {
	spec := OverlaySpec{VNI: 100, LocalIP: "10.0.0.1", RemoteIP: "10.0.0.2", MTU: 1450, Port: 4789}

	cases := []struct {
		name                    string
		remote, local           net.IP
		vtepIdx, port, mtu, vni int
		want                    string
	}{
		{"the peer moved to another node", net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.1"), 7, 4789, 1450, 100, "remote"},
		{"this node's underlay address changed", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.5"), 7, 4789, 1450, 100, "sourced from 10.0.0.1"},
		{"the underlay interface changed", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 9, 4789, 1450, 100, "interface index"},
		{"the VTEP port changed", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 7, 8472, 1450, 100, "VTEP port"},
		{"the MTU changed", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 7, 4789, 1400, 100, "MTU"},
		{"the identifier changed", net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 7, 4789, 1450, 101, "VNI"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := spec
			s.VNI = uint32(c.vni)
			why := overlayDiffers(existingTunnel(), s, c.remote, c.local,
				c.vtepIdx, c.port, c.mtu)
			if why == "" {
				t.Fatalf("%s and the tunnel was kept. It will carry traffic that looks "+
					"right and is not what the lab describes, and the deploy will say "+
					"it succeeded", c.name)
			}
			if !strings.Contains(why, c.want) {
				t.Errorf("the reason given is %q, which does not mention %q, so nobody "+
					"reading the log learns what changed", why, c.want)
			}
		})
	}
}

// A property the caller did not ask for is not a reason to rebuild.
func TestAnUnspecifiedPropertyIsNotADifference(t *testing.T) {
	spec := OverlaySpec{VNI: 100, RemoteIP: "10.0.0.2"}
	if why := overlayDiffers(existingTunnel(), spec, net.ParseIP("10.0.0.2"), nil,
		0, 0, 0); why != "" {
		t.Errorf("a tunnel was rebuilt over a property the lab does not specify: %s", why)
	}
}
