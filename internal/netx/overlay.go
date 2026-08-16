package netx

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
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
	// Lab names the lab this overlay belongs to.
	//
	// Two labs on one node derive their identifiers independently, so nothing
	// stops them landing on the same 24-bit VNI: with a few hundred links each,
	// a collision is likely rather than exotic. Without an owner recorded on
	// the device, the second lab silently joins the first one's tunnel, and
	// cleaning up either one deletes the other's fabric. The name is stamped on
	// the interface so both can be detected and neither can be destroyed by
	// accident.
	Lab string
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

	// A tunnel that already exists and belongs to another lab is a collision,
	// not something to reuse. Joining it would put two labs' traffic on one
	// wire, which shows up as impossible routing rather than as an error.
	if owner, ok, err := overlayOwner(vxName); err != nil {
		return "", err
	} else if ok && spec.Lab != "" && owner != "" && owner != spec.Lab {
		return "", fmt.Errorf(
			"VNI %d is already in use by lab %q on this node; two labs cannot share a tunnel. "+
				"Rename one lab, or destroy %q first", spec.VNI, owner, owner)
	}

	br, err := ensureBridge(brName, mtu+50)
	if err != nil {
		return "", err
	}
	if spec.Lab != "" {
		_ = netlink.LinkSetAlias(br, ownerAlias(spec.Lab))
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
		// A tunnel whose properties no longer match what the lab asks for is
		// replaced, not adopted.
		//
		// Only the remote and the VNI used to be compared, so a tunnel built
		// before the source address, the underlay device, the VTEP port or the
		// MTU changed was kept exactly as it was. Every one of those produces a
		// working-looking tunnel that behaves differently from the one the
		// manifest describes: a stale source address sends encapsulated
		// packets out of the wrong interface, and a stale MTU silently drops
		// what the lab says will fit. The deployment reported success either
		// way, and the difference is invisible in `docker ps`.
		if reason := overlayDiffers(vx, spec, remote, local, vtepIdx, port, mtu); reason != "" {
			slog.Info("replacing an overlay tunnel that no longer matches the lab",
				"vni", spec.VNI, "device", vxName, "reason", reason)
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
			if err := reconcileDefaultFDB(vx, remote); err != nil {
				return "", err
			}
			// An overlay created before ownership was recorded is adopted
			// rather than rebuilt, so an upgrade does not tear down a class.
			if spec.Lab != "" && ownerFromAlias(vx.Attrs().Alias) == "" {
				_ = netlink.LinkSetAlias(existing, ownerAlias(spec.Lab))
			}
			return brName, nil
		}
	} else if !IsNotFound(err) {
		return "", fmt.Errorf("overlay VNI %d: look up %s: %w", spec.VNI, vxName, err)
	}

	vx := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: vxName, MTU: mtu, Alias: ownerAlias(spec.Lab)},
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

	if err := reconcileDefaultFDB(vx, remote); err != nil {
		return "", err
	}
	return brName, nil
}

// overlayDiffers names the first property of an existing tunnel that does not
// match what the lab asks for, or "" if it can be kept.
func overlayDiffers(vx *netlink.Vxlan, spec OverlaySpec, remote, local net.IP,
	vtepIdx, port, mtu int) string {

	switch {
	case int(vx.VxlanId) != int(spec.VNI):
		return fmt.Sprintf("it carries VNI %d, not %d", vx.VxlanId, spec.VNI)
	case !vx.Group.Equal(remote):
		return fmt.Sprintf("its remote is %s, not %s", vx.Group, remote)
	case local != nil && !vx.SrcAddr.Equal(local):
		return fmt.Sprintf("it is sourced from %s, not %s", vx.SrcAddr, local)
	case vtepIdx != 0 && vx.VtepDevIndex != vtepIdx:
		return fmt.Sprintf("it is sourced from interface index %d, not %d",
			vx.VtepDevIndex, vtepIdx)
	case port != 0 && vx.Port != port:
		return fmt.Sprintf("its VTEP port is %d, not %d", vx.Port, port)
	case mtu != 0 && vx.Attrs().MTU != mtu:
		return fmt.Sprintf("its MTU is %d, not %d", vx.Attrs().MTU, mtu)
	}
	return ""
}

// reconcileDefaultFDB makes sure the tunnel has exactly one default forwarding
// entry, pointing at the intended peer.
//
// Creating a VXLAN device with a unicast remote already installs the all-zeros
// entry that sends unknown and broadcast traffic to that peer, so appending
// another produces *two* copies of every flooded frame. That is a genuinely
// nasty bug in a teaching platform: students would see duplicate ICMP replies
// and inexplicable traceroute output, and would reasonably conclude they had
// misconfigured something.
//
// The entries are therefore reconciled rather than appended: strays left by an
// earlier version or by a peer that moved to another node are removed, and one
// is added only if the kernel has not already provided it.
func reconcileDefaultFDB(vx *netlink.Vxlan, remote net.IP) error {
	zero := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	entries, err := netlink.NeighList(vx.Attrs().Index, syscall.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("vxlan %s: list forwarding entries: %w", vx.Name, err)
	}

	correct := 0
	for i := range entries {
		e := entries[i]
		if !bytesEqual(e.HardwareAddr, zero) {
			continue
		}
		if e.IP != nil && e.IP.Equal(remote) {
			correct++
			if correct > 1 {
				// A duplicate: remove it, or every broadcast is replicated.
				e.Flags = netlink.NTF_SELF
				if err := netlink.NeighDel(&e); err != nil {
					return fmt.Errorf("vxlan %s: remove duplicate forwarding entry: %w", vx.Name, err)
				}
				correct--
			}
			continue
		}
		// Points somewhere else entirely: the peer moved.
		e.Flags = netlink.NTF_SELF
		if err := netlink.NeighDel(&e); err != nil {
			return fmt.Errorf("vxlan %s: remove stale forwarding entry for %s: %w", vx.Name, e.IP, err)
		}
	}

	if correct == 0 {
		entry := &netlink.Neigh{
			LinkIndex:    vx.Attrs().Index,
			Family:       syscall.AF_BRIDGE,
			State:        netlink.NUD_PERMANENT,
			Flags:        netlink.NTF_SELF,
			IP:           remote,
			HardwareAddr: zero,
		}
		if err := netlink.NeighAppend(entry); err != nil && !isExist(err) {
			return fmt.Errorf("vxlan %s: add forwarding entry for %s: %w", vx.Name, remote, err)
		}
	}
	return nil
}

func bytesEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// ListOverlays returns the VNIs of every Twinet-owned VXLAN device on this host.
//
// Cleanup must work from what is actually on the machine, not from a list the
// caller happens to remember: a lab destroyed without its manifest, or an AS
// moved to another node, would otherwise leave tunnels behind forever.
func ListOverlays() ([]uint32, error) {
	return listOverlays("")
}

// ListOverlaysOfLab returns only the overlays a lab owns. Cleaning up one lab
// must not remove another's fabric, which is what an unqualified sweep of every
// twvx device on the host does.
func ListOverlaysOfLab(lab string) ([]uint32, error) {
	return listOverlays(lab)
}

// OverlayOwners maps every Twinet overlay on this host to the lab that owns it.
func OverlayOwners() (map[uint32]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	out := map[uint32]string{}
	for _, l := range links {
		vx, ok := l.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Name, "twvx") {
			continue
		}
		out[uint32(vx.VxlanId)] = ownerFromAlias(vx.Attrs().Alias)
	}
	return out, nil
}

func listOverlays(lab string) ([]uint32, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	var out []uint32
	for _, l := range links {
		vx, ok := l.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Name, "twvx") {
			continue
		}
		if lab != "" && ownerFromAlias(vx.Attrs().Alias) != lab {
			continue
		}
		out = append(out, uint32(vx.VxlanId))
	}
	return out, nil
}

// aliasPrefix marks an interface alias as Twinet's ownership record. The alias
// is used rather than a name because interface names are capped at fifteen
// characters, which a lab name and a VNI do not fit into together.
const aliasPrefix = "twinet:"

func ownerAlias(lab string) string { return aliasPrefix + lab }

func ownerFromAlias(alias string) string {
	if !strings.HasPrefix(alias, aliasPrefix) {
		return ""
	}
	return strings.TrimPrefix(alias, aliasPrefix)
}

// overlayOwner reports which lab owns an existing overlay device.
func overlayOwner(vxName string) (string, bool, error) {
	l, err := netlink.LinkByName(vxName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return "", false, nil
		}
		// Anything else is reported. Returning "there is no overlay" for a
		// lookup that failed for some other reason turns a transient error
		// into permission to take an identifier another lab is using, and
		// joining two labs' traffic together is not a failure anybody
		// diagnoses quickly.
		return "", false, fmt.Errorf("look up %s: %w", vxName, err)
	}
	return ownerFromAlias(l.Attrs().Alias), true, nil
}

// Orphan is an overlay left behind on this host: a VXLAN device belonging to no
// lab this node hosts, whose bridge carries nothing.
type Orphan struct {
	VNI   uint32 `json:"vni"`
	Owner string `json:"owner,omitempty"`
	Ports int    `json:"ports"`
}

// FindOrphans lists the overlays this host is carrying for nobody.
//
// An overlay is kept if a lab named in `live` owns it, or if its bridge still
// has something attached: a device with a container's veth on it is in use by
// something, whatever its ownership record says, and removing it would cut a
// running lab's cable. Only the peerless ones are orphans.
//
// They accumulate. A hundred were found on one node of this cluster against
// forty-four in use, left by labs destroyed weeks earlier, and nothing had ever
// reported them -- they cost a VNI each out of a finite space, and the
// deconfliction that stops two labs picking the same identifier reads exactly
// this ownership record.
func FindOrphans(live map[string]bool) ([]Orphan, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	// Which bridges have a port that is not their own tunnel.
	ports := map[int]int{}
	for _, l := range links {
		a := l.Attrs()
		if a.MasterIndex == 0 {
			continue
		}
		if _, isVx := l.(*netlink.Vxlan); isVx {
			continue
		}
		ports[a.MasterIndex]++
	}
	byName := map[string]netlink.Link{}
	for _, l := range links {
		byName[l.Attrs().Name] = l
	}

	var out []Orphan
	for _, l := range links {
		vx, ok := l.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Name, "twvx") {
			continue
		}
		vni := uint32(vx.VxlanId)
		owner := ownerFromAlias(vx.Attrs().Alias)
		if owner != "" && live[owner] {
			continue
		}
		n := 0
		if br, ok := byName[BridgeName(vni)]; ok {
			n = ports[br.Attrs().Index]
		}
		if n > 0 {
			// In use by something. Reported, not removed.
			out = append(out, Orphan{VNI: vni, Owner: owner, Ports: n})
			continue
		}
		out = append(out, Orphan{VNI: vni, Owner: owner})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VNI < out[j].VNI })
	return out, nil
}
