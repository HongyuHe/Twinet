package netx

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

// LogicalBinding is one VNI/VLAN mapping a topology requires at a node. It is
// intentionally independent from the number of Linux devices carrying it.
type LogicalBinding struct {
	VNI    uint32 `json:"vni"`
	VLAN   uint16 `json:"vlan"`
	Peer   string `json:"peer"`
	MTU    int    `json:"mtu"`
	Port   int    `json:"port"`
	NodeA  string `json:"node_a,omitempty"`
	NodeB  string `json:"node_b,omitempty"`
	Legacy bool   `json:"legacy,omitempty"`
}

// PhysicalTrunk is one bridge/VXLAN carrier. A multiplex trunk can carry many
// LogicalBindings; legacy trunks carry one VNI each.
type PhysicalTrunk struct {
	Bridge string `json:"bridge,omitempty"`
	Vxlan  string `json:"vxlan"`
	MTU    int    `json:"mtu"`
	Port   int    `json:"port"`
	NodeA  string `json:"node_a,omitempty"`
	NodeB  string `json:"node_b,omitempty"`
	Legacy bool   `json:"legacy,omitempty"`
}

// OverlayInventory distinguishes link correctness from physical object count.
// Bindings intentionally preserves duplicates so callers can reject a VNI
// mapped through two trunks instead of silently deduplicating corruption.
type OverlayInventory struct {
	Bindings []LogicalBinding `json:"logical_bindings"`
	Trunks   []PhysicalTrunk  `json:"physical_trunks"`
}

func (i OverlayInventory) normalize() OverlayInventory {
	out := OverlayInventory{
		Bindings: append([]LogicalBinding(nil), i.Bindings...),
		Trunks:   append([]PhysicalTrunk(nil), i.Trunks...),
	}
	sort.Slice(out.Bindings, func(a, b int) bool {
		x, y := out.Bindings[a], out.Bindings[b]
		if x.VNI != y.VNI {
			return x.VNI < y.VNI
		}
		if x.NodeA != y.NodeA {
			return x.NodeA < y.NodeA
		}
		if x.NodeB != y.NodeB {
			return x.NodeB < y.NodeB
		}
		return x.Peer < y.Peer
	})
	sort.Slice(out.Trunks, func(a, b int) bool {
		x, y := out.Trunks[a], out.Trunks[b]
		if x.NodeA != y.NodeA {
			return x.NodeA < y.NodeA
		}
		if x.NodeB != y.NodeB {
			return x.NodeB < y.NodeB
		}
		if x.Vxlan != y.Vxlan {
			return x.Vxlan < y.Vxlan
		}
		return x.Bridge < y.Bridge
	})
	return out
}

// InspectOverlayInventory returns observed VNI bindings and physical carrier
// objects for one lab. It is one host netlink survey; callers must not infer
// logical link count from Trunks.
func InspectOverlayInventory(lab string) (OverlayInventory, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return OverlayInventory{}, fmt.Errorf("open host netlink handle: %w", err)
	}
	defer h.Close()
	out := OverlayInventory{}
	devices, err := multiplexDevices(h, lab)
	if err != nil {
		return OverlayInventory{}, err
	}
	tunnels, err := h.BridgeVlanTunnelShow()
	if err != nil {
		return OverlayInventory{}, fmt.Errorf("list VLAN tunnel mappings: %w", err)
	}
	vlanFor := map[uint32]uint16{}
	for _, tunnel := range tunnels {
		// VNI allocation is node-global; the multiplex reconciler already
		// rejects an ambiguous mapping before traffic can use it.
		if previous, exists := vlanFor[tunnel.TunId]; exists && previous != tunnel.Vid {
			return OverlayInventory{}, fmt.Errorf("VNI %d maps to VLANs %d and %d", tunnel.TunId, previous, tunnel.Vid)
		}
		vlanFor[tunnel.TunId] = tunnel.Vid
	}
	seenMultiplex := map[uint32]bool{}
	for _, device := range devices {
		bridge := ""
		if device.br != nil {
			bridge = device.br.Attrs().Name
		}
		out.Trunks = append(out.Trunks, PhysicalTrunk{
			Bridge: bridge, Vxlan: device.vx.Attrs().Name,
			MTU: device.vx.Attrs().MTU, Port: device.vx.Port,
			NodeA: device.key.a, NodeB: device.key.b,
		})
		entries, err := listExternalFDB(device.vx)
		if err != nil {
			return OverlayInventory{}, err
		}
		for _, entry := range entries {
			if entry.SourceVNI == 0 || entry.IP == nil || !isZeroMAC(entry.HardwareAddr) {
				continue
			}
			vlan, ok := vlanFor[entry.SourceVNI]
			if !ok {
				return OverlayInventory{}, fmt.Errorf("multiplex VNI %d on %s has no VLAN mapping",
					entry.SourceVNI, device.vx.Attrs().Name)
			}
			out.Bindings = append(out.Bindings, LogicalBinding{
				VNI: entry.SourceVNI, VLAN: vlan, Peer: entry.IP.String(),
				MTU: device.vx.Attrs().MTU, Port: device.vx.Port,
				NodeA: device.key.a, NodeB: device.key.b,
			})
			seenMultiplex[entry.SourceVNI] = true
		}
	}

	links, err := listHandleLinks(h)
	if err != nil {
		return OverlayInventory{}, fmt.Errorf("list host interfaces: %w", err)
	}
	for _, link := range links {
		vx, ok := link.(*netlink.Vxlan)
		if !ok || !strings.HasPrefix(vx.Attrs().Name, "twvx") {
			continue
		}
		if lab != "" && ownerFromAlias(vx.Attrs().Alias) != lab {
			continue
		}
		vni := uint32(vx.VxlanId)
		if vni == 0 {
			continue
		}
		out.Trunks = append(out.Trunks, PhysicalTrunk{
			Bridge: BridgeName(vni), Vxlan: vx.Attrs().Name,
			MTU: vx.Attrs().MTU, Port: vx.Port, Legacy: true,
		})
		// During a safe migration both representations can coexist. The
		// multiplex mapping is authoritative for the logical binding, while
		// the legacy device remains visible as an extra physical carrier.
		if seenMultiplex[vni] {
			continue
		}
		peer := ""
		if vx.Group != nil {
			peer = vx.Group.String()
		}
		out.Bindings = append(out.Bindings, LogicalBinding{
			VNI: vni, Peer: peer, MTU: vx.Attrs().MTU, Port: vx.Port, Legacy: true,
		})
	}
	return out.normalize(), nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, part := range mac {
		if part != 0 {
			return false
		}
	}
	return true
}
