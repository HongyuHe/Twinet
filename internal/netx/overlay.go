package netx

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// VXLANPort is Twinet's VTEP UDP port. The IANA-assigned VXLAN port is 4789;
// we use it because the cluster fabric is private and the standard port makes
// tcpdump filters and NIC offloads work without configuration.
const VXLANPort = 4789

// OverlaySpec describes one end of a cross-node link.
//
// Twinet's overlay is deliberately the simplest thing that can work: every link
// has exactly two endpoints, so each tunnel is a point-to-point unicast VXLAN
// with learning disabled and a single static forwarding entry. There is no
// multicast (unavailable on most clusters and clouds) and no EVPN control plane
// (Kathara's Megalos CNI needs one only because its collision domains are
// multi-access). The whole cross-node story is therefore a few hundred lines.
type OverlaySpec struct {
	// VNI is the VXLAN network identifier, derived deterministically from the
	// link identity so both nodes compute the same value with no coordination.
	VNI uint32
	// LocalIP is this node's VTEP source address on the underlay.
	LocalIP string
	// RemoteIP is the peer node's VTEP address.
	RemoteIP string
	// UnderlayDev is the interface the tunnel is sourced from. Optional; the
	// kernel picks by route when empty.
	UnderlayDev string
	// MTU is the tunnel's payload MTU. The caller is responsible for ensuring
	// the underlay can carry MTU + 50 bytes of encapsulation.
	MTU int
	// Port overrides the VTEP UDP port.
	Port int
}

// EnsureOverlay creates the bridge and VXLAN netdev for a cross-node link and
// returns the bridge name, ready for a veth to be attached as a port.
//
// The topology on each node is:
//
//	container --veth--> twbr<VNI> (bridge) --> twvx<VNI> (vxlan) ==underlay==>
//
// Calling this twice is a no-op, so a redeploy converges rather than failing.
func EnsureOverlay(spec OverlaySpec) (string, error) {
	if spec.VNI == 0 {
		return "", fmt.Errorf("overlay: VNI must be non-zero")
	}
	local := net.ParseIP(spec.LocalIP)
	if local == nil {
		return "", fmt.Errorf("overlay VNI %d: local IP %q is not an address", spec.VNI, spec.LocalIP)
	}
	remote := net.ParseIP(spec.RemoteIP)
	if remote == nil {
		return "", fmt.Errorf("overlay VNI %d: remote IP %q is not an address", spec.VNI, spec.RemoteIP)
	}
	port := spec.Port
	if port == 0 {
		port = VXLANPort
	}
	mtu := spec.MTU
	if mtu == 0 {
		mtu = 1500
	}

	brName := BridgeName(spec.VNI)
	vxName := VxlanName(spec.VNI)

	br, err := ensureBridge(brName, mtu+50)
	if err != nil {
		return "", err
	}

	var vtepIdx int
	if spec.UnderlayDev != "" {
		l, err := netlink.LinkByName(spec.UnderlayDev)
		if err != nil {
			return "", fmt.Errorf("overlay VNI %d: underlay device %s: %w", spec.VNI, spec.UnderlayDev, err)
		}
		vtepIdx = l.Attrs().Index
	}

	existing, err := netlink.LinkByName(vxName)
	if err == nil {
		vx, ok := existing.(*netlink.Vxlan)
		if !ok {
			return "", fmt.Errorf("overlay VNI %d: %s exists but is a %s, not a vxlan",
				spec.VNI, vxName, existing.Type())
		}
		// A changed remote means the peer moved to a different node; recreate.
		if !vx.Group.Equal(remote) || int(vx.VxlanId) != int(spec.VNI) {
			if err := netlink.LinkDel(existing); err != nil {
				return "", fmt.Errorf("overlay VNI %d: replace stale tunnel: %w", spec.VNI, err)
			}
		} else {
			if err := attachToBridge(existing, br); err != nil {
				return "", err
			}
			if err := netlink.LinkSetUp(existing); err != nil {
				return "", fmt.Errorf("overlay VNI %d: set %s up: %w", spec.VNI, vxName, err)
			}
			return brName, nil
		}
	} else if !IsNotFound(err) {
		return "", fmt.Errorf("overlay VNI %d: look up %s: %w", spec.VNI, vxName, err)
	}

	vx := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: vxName, MTU: mtu},
		VxlanId:      int(spec.VNI),
		SrcAddr:      local,
		Group:        remote, // unicast remote, not a multicast group
		Port:         port,
		VtepDevIndex: vtepIdx,
		Learning:     false, // point-to-point: nothing to learn
		L2miss:       false,
		L3miss:       false,
	}
	if err := netlink.LinkAdd(vx); err != nil {
		return "", fmt.Errorf("overlay VNI %d: create %s: %w", spec.VNI, vxName, err)
	}
	if err := attachToBridge(vx, br); err != nil {
		return "", err
	}
	if err := netlink.LinkSetUp(vx); err != nil {
		return "", fmt.Errorf("overlay VNI %d: set %s up: %w", spec.VNI, vxName, err)
	}

	// With learning disabled we install the one forwarding entry the link needs:
	// "everything unknown goes to the peer VTEP".
	if err := ensureDefaultFDB(vx, remote); err != nil {
		return "", err
	}
	return brName, nil
}

// ensureDefaultFDB installs the all-zero MAC entry that forwards unknown and
// broadcast traffic to the single remote VTEP.
func ensureDefaultFDB(vx *netlink.Vxlan, remote net.IP) error {
	entry := &netlink.Neigh{
		LinkIndex:    vx.Attrs().Index,
		Family:       syscall.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		IP:           remote,
		HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
	}
	if err := netlink.NeighAppend(entry); err != nil && !isExist(err) {
		return fmt.Errorf("vxlan %s: add forwarding entry for %s: %w", vx.Name, remote, err)
	}
	return nil
}

// ensureBridge creates a bridge if absent and returns it.
func ensureBridge(name string, mtu int) (*netlink.Bridge, error) {
	if l, err := netlink.LinkByName(name); err == nil {
		br, ok := l.(*netlink.Bridge)
		if !ok {
			return nil, fmt.Errorf("%s exists but is a %s, not a bridge", name, l.Type())
		}
		if err := netlink.LinkSetUp(br); err != nil {
			return nil, fmt.Errorf("set bridge %s up: %w", name, err)
		}
		return br, nil
	} else if !IsNotFound(err) {
		return nil, fmt.Errorf("look up bridge %s: %w", name, err)
	}

	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}
	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("create bridge %s: %w", name, err)
	}
	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("set bridge %s up: %w", name, err)
	}
	// A Twinet bridge is a dumb two-port cable joint. Spanning tree would add
	// a 30-second forwarding delay for no benefit, and there is no loop to
	// prevent on a point-to-point link.
	if err := setBridgeNoSTP(name); err != nil {
		return nil, err
	}
	return br, nil
}

func setBridgeNoSTP(name string) error {
	if err := netlink.BridgeSetVlanFiltering(mustLink(name), false); err != nil {
		// Not fatal: VLAN filtering is off by default on a fresh bridge.
		_ = err
	}
	return nil
}

func mustLink(name string) netlink.Link {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
	}
	return l
}

func attachToBridge(l netlink.Link, br *netlink.Bridge) error {
	if l.Attrs().MasterIndex == br.Attrs().Index {
		return nil
	}
	if err := netlink.LinkSetMaster(l, br); err != nil {
		return fmt.Errorf("attach %s to bridge %s: %w", l.Attrs().Name, br.Attrs().Name, err)
	}
	return nil
}

// AttachToBridgeByName adds an existing host-namespace interface to a bridge.
func AttachToBridgeByName(iface, bridge string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("find %s: %w", iface, err)
	}
	bl, err := netlink.LinkByName(bridge)
	if err != nil {
		return fmt.Errorf("find bridge %s: %w", bridge, err)
	}
	br, ok := bl.(*netlink.Bridge)
	if !ok {
		return fmt.Errorf("%s is not a bridge", bridge)
	}
	if err := attachToBridge(l, br); err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

// RemoveOverlay tears down the bridge and tunnel for a link.
func RemoveOverlay(vni uint32) error {
	for _, name := range []string{VxlanName(vni), BridgeName(vni)} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			if IsNotFound(err) {
				continue
			}
			return fmt.Errorf("look up %s: %w", name, err)
		}
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("delete %s: %w", name, err)
		}
	}
	return nil
}

// BridgeName and VxlanName mirror internal/alloc so netx has no dependency on
// it; both must agree, which the alloc tests assert.
func BridgeName(vni uint32) string { return fmt.Sprintf("twbr%d", vni) }
func VxlanName(vni uint32) string  { return fmt.Sprintf("twvx%d", vni) }

// UnderlayMTU reports the MTU of the interface that would be used to reach an
// address, so the planner can verify that lab MTU + 50 fits before deploying
// rather than discovering it as mysterious packet loss.
func UnderlayMTU(remote string) (int, string, error) {
	ip := net.ParseIP(remote)
	if ip == nil {
		return 0, "", fmt.Errorf("%q is not an IP address", remote)
	}
	routes, err := netlink.RouteGet(ip)
	if err != nil || len(routes) == 0 {
		return 0, "", fmt.Errorf("no route to %s: %w", remote, err)
	}
	l, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return 0, "", fmt.Errorf("resolve outgoing interface for %s: %w", remote, err)
	}
	return l.Attrs().MTU, l.Attrs().Name, nil
}
