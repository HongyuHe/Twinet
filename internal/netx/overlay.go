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

// OverlaySpec describes one end of a legacy per-link cross-node tunnel.
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

// EnsureOverlay creates the legacy bridge and VXLAN netdev for a cross-node
// link and returns the bridge name, ready for a veth to be attached as a port.
//
// New deployments use EnsureMultiplexOverlay. This remains for safe cleanup
// and convergence of labs created by older agents.
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
			if existing.Attrs().Flags&net.FlagUp == 0 {
				if err := netlink.LinkSetUp(existing); err != nil {
					return "", fmt.Errorf("overlay VNI %d: set %s up: %w", spec.VNI, vxName, err)
				}
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
		if br.Attrs().Flags&net.FlagUp == 0 {
			if err := netlink.LinkSetUp(br); err != nil {
				return nil, fmt.Errorf("set bridge %s up: %w", name, err)
			}
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
	if l.Attrs().Flags&net.FlagUp == 0 {
		return netlink.LinkSetUp(l)
	}
	return nil
}

// RemoveOverlay tears down a link's multiplex binding and any legacy
// per-link bridge/tunnel. It is intentionally VNI-based so older callers can
// clean up a mixed-version lab without knowing which representation created it.
func RemoveOverlay(vni uint32) error {
	var problems []string
	if err := removeMultiplexVNI(vni); err != nil {
		problems = append(problems, err.Error())
	}
	if err := RemoveLegacyOverlay(vni); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%s", strings.Join(problems, "; "))
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

// ListOverlays returns every active Twinet VNI on this host, including legacy
// per-link tunnels and bindings on shared multiplex tunnels.
//
// Cleanup must work from what is actually on the machine, not from a list the
// caller happens to remember: a lab destroyed without its manifest, or an AS
// moved to another node, would otherwise leave tunnels behind forever.
func ListOverlays() ([]uint32, error) {
	return listOverlays("")
}

// ListOverlaysOfLab returns only the active VNIs a lab owns, across legacy and
// multiplexed overlays. Cleaning up one lab must not remove another's fabric.
func ListOverlaysOfLab(lab string) ([]uint32, error) {
	return listOverlays(lab)
}

// OverlayPortsOfLab counts, for every VNI a lab owns on this host, the
// non-tunnel ports still attached to the object carrying it.
//
// It answers one question: is something still using this overlay? A count above
// zero means a container's veth is on that bridge, so removing the overlay
// would cut a cable that is carrying traffic -- which is exactly what a cleanup
// run from partial information does when it works from a name alone. Callers
// that remove overlays without a manifest use this to leave those alone and say
// so, rather than reporting a success measured only by what they deleted.
func OverlayPortsOfLab(lab string) (map[uint32]int, error) {
	links, err := listHostLinks()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	ports := map[int]int{}
	byName := map[string]netlink.Link{}
	for _, l := range links {
		a := l.Attrs()
		byName[a.Name] = l
		if a.MasterIndex == 0 {
			continue
		}
		if _, isVx := l.(*netlink.Vxlan); isVx {
			continue
		}
		ports[a.MasterIndex]++
	}

	out := map[uint32]int{}
	for _, l := range links {
		vx, ok := l.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Name, "twvx") {
			continue
		}
		if lab != "" && ownerFromAlias(vx.Attrs().Alias) != lab {
			continue
		}
		vni := uint32(vx.VxlanId)
		if br, ok := byName[BridgeName(vni)]; ok {
			out[vni] = ports[br.Attrs().Index]
			continue
		}
		out[vni] = 0
	}

	h, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	devices, err := multiplexDevices(h, lab)
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		vnis, err := multiplexVNIs(h, device.vx)
		if err != nil {
			return nil, err
		}
		attached := 0
		if device.br != nil {
			attached = ports[device.br.Attrs().Index]
		}
		for _, vni := range vnis {
			// A shared tunnel carries many logical links. Any port on its
			// bridge belongs to one of them, and this cannot tell which, so
			// every binding on a busy pair is treated as in use.
			if seen, ok := out[vni]; !ok || attached > seen {
				out[vni] = attached
			}
		}
	}
	return out, nil
}

// OverlayOwners maps every Twinet overlay on this host to the lab that owns it.
func OverlayOwners() (map[uint32]string, error) {
	links, err := listHostLinks()
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
	multiplex, err := multiplexOwners()
	if err != nil {
		return nil, err
	}
	for vni, owner := range multiplex {
		if previous, exists := out[vni]; exists && previous != "" && owner != "" && previous != owner {
			return nil, fmt.Errorf("VNI %d is owned by both labs %q and %q", vni, previous, owner)
		}
		out[vni] = owner
	}
	return out, nil
}

// LegacyOverlayOwnerAdoption records alias values changed while repairing a
// legacy per-link overlay. Revert restores precisely those values without
// deleting or recreating the live networking objects.
type LegacyOverlayOwnerAdoption struct {
	vni                     uint32
	lab                     string
	vxlanAlias, bridgeAlias string
	changed                 bool
}

// Revert restores the aliases that preceded AdoptLegacyOverlayOwner.
func (a LegacyOverlayOwnerAdoption) Revert() error {
	if !a.changed {
		return nil
	}
	vx, br, err := legacyOverlayLinks(a.vni, a.lab)
	if err != nil {
		return err
	}
	want := ownerAlias(a.lab)
	if vx.Attrs().Alias != want || br.Attrs().Alias != want {
		return fmt.Errorf("VNI %d ownership changed while adoption was rolling back", a.vni)
	}
	if err := netlink.LinkSetAlias(vx, a.vxlanAlias); err != nil {
		return fmt.Errorf("restore VNI %d VXLAN ownership: %w", a.vni, err)
	}
	if err := netlink.LinkSetAlias(br, a.bridgeAlias); err != nil {
		_ = netlink.LinkSetAlias(vx, want)
		return fmt.Errorf("restore VNI %d bridge ownership: %w", a.vni, err)
	}
	return nil
}

// AdoptLegacyOverlayOwner stamps the ownership aliases on an existing
// per-link overlay without changing its tunnel, bridge, forwarding database,
// ports, or link state.
//
// It is intentionally narrow: both objects must be Twinet's expected VXLAN
// and bridge, and every pre-existing alias must either be empty or already
// name lab. An arbitrary alias, a missing bridge, or another owner's alias is
// ambiguous and is refused rather than overwritten. An already-correct alias
// on one half may be completed on the other, and Revert preserves that prior
// known ownership if a later reservation in the same batch fails.
func AdoptLegacyOverlayOwner(vni uint32, lab string) (LegacyOverlayOwnerAdoption, error) {
	vx, br, err := legacyOverlayLinks(vni, lab)
	if err != nil {
		return LegacyOverlayOwnerAdoption{}, err
	}
	want := ownerAlias(lab)
	vxBefore, brBefore := vx.Attrs().Alias, br.Attrs().Alias
	if vxBefore == want && brBefore == want {
		return LegacyOverlayOwnerAdoption{vni: vni, lab: lab}, nil
	}
	if err := netlink.LinkSetAlias(vx, want); err != nil {
		return LegacyOverlayOwnerAdoption{}, fmt.Errorf("stamp VNI %d VXLAN ownership: %w", vni, err)
	}
	if err := netlink.LinkSetAlias(br, want); err != nil {
		_ = netlink.LinkSetAlias(vx, vxBefore)
		return LegacyOverlayOwnerAdoption{}, fmt.Errorf("stamp VNI %d bridge ownership: %w", vni, err)
	}
	return LegacyOverlayOwnerAdoption{
		vni: vni, lab: lab, vxlanAlias: vxBefore, bridgeAlias: brBefore, changed: true,
	}, nil
}

func legacyOverlayLinks(vni uint32, lab string) (*netlink.Vxlan, *netlink.Bridge, error) {
	if vni == 0 {
		return nil, nil, fmt.Errorf("legacy overlay VNI must be non-zero")
	}
	if lab == "" {
		return nil, nil, fmt.Errorf("legacy overlay adoption needs a lab owner")
	}
	vxLink, err := netlink.LinkByName(VxlanName(vni))
	if err != nil {
		return nil, nil, fmt.Errorf("find legacy VXLAN for VNI %d: %w", vni, err)
	}
	vx, ok := vxLink.(*netlink.Vxlan)
	if !ok || uint32(vx.VxlanId) != vni {
		return nil, nil, fmt.Errorf("VNI %d device %s is not the expected VXLAN",
			vni, VxlanName(vni))
	}
	brLink, err := netlink.LinkByName(BridgeName(vni))
	if err != nil {
		return nil, nil, fmt.Errorf("find legacy bridge for VNI %d: %w", vni, err)
	}
	br, ok := brLink.(*netlink.Bridge)
	if !ok {
		return nil, nil, fmt.Errorf("VNI %d device %s is not the expected bridge",
			vni, BridgeName(vni))
	}
	want := ownerAlias(lab)
	vxAlias, brAlias := vx.Attrs().Alias, br.Attrs().Alias
	switch {
	case vxAlias == want && brAlias == want:
		return vx, br, nil
	case (vxAlias == "" || vxAlias == want) && (brAlias == "" || brAlias == want):
		return vx, br, nil
	default:
		return nil, nil, fmt.Errorf(
			"VNI %d has inconsistent or unknown ownership aliases %q and %q",
			vni, vxAlias, brAlias)
	}
}

func listOverlays(lab string) ([]uint32, error) {
	links, err := listHostLinks()
	if err != nil {
		return nil, fmt.Errorf("list host interfaces: %w", err)
	}
	seen := map[uint32]bool{}
	for _, l := range links {
		vx, ok := l.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Name, "twvx") {
			continue
		}
		if lab != "" && ownerFromAlias(vx.Attrs().Alias) != lab {
			continue
		}
		seen[uint32(vx.VxlanId)] = true
	}
	multiplex, err := listMultiplexVNIs(lab)
	if err != nil {
		return nil, err
	}
	for _, vni := range multiplex {
		seen[vni] = true
	}
	out := make([]uint32, 0, len(seen))
	for vni := range seen {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// aliasPrefix marks an interface alias as Twinet's ownership record. The alias
// is used rather than a name because interface names are capped at fifteen
// characters, which a lab name and a VNI do not fit into together.
const aliasPrefix = "twinet:"

func ownerAlias(lab string) string { return aliasPrefix + lab }

func ownerFromAlias(alias string) string {
	if key, ok := pairKeyFromAlias(alias); ok {
		return key.lab
	}
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
	links, err := listHostLinks()
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
