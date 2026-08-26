package deploy

import (
	"fmt"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
)

// ExpectedOverlayInventory derives logical bindings and shared physical trunks
// from the final placed topology for this Engine's node.
func (e *Engine) ExpectedOverlayInventory(top *model.Topology) (netx.OverlayInventory, error) {
	out := netx.OverlayInventory{}
	if top == nil {
		return out, nil
	}
	trunks := map[string]netx.PhysicalTrunk{}
	for _, link := range top.Links {
		if link == nil || !link.CrossNode() ||
			(link.A.Device.Node != e.Node && link.B.Device.Node != e.Node) {
			continue
		}
		var remoteNode string
		switch e.Node {
		case link.A.Device.Node:
			remoteNode = link.B.Device.Node
		case link.B.Device.Node:
			remoteNode = link.A.Device.Node
		}
		peer := e.PeerUnderlay[remoteNode]
		if peer == "" {
			return netx.OverlayInventory{}, fmt.Errorf("link %s has no underlay peer for %s", link.ID, remoteNode)
		}
		vlan, mtu, port, err := e.multiplexParameters(top, e.Node, remoteNode, link.VNI)
		if err != nil {
			return netx.OverlayInventory{}, fmt.Errorf("link %s: %w", link.ID, err)
		}
		a, b := e.Node, remoteNode
		if a > b {
			a, b = b, a
		}
		bridge, vxlan, err := netx.MultiplexOverlayNames(top.Name, a, b)
		if err != nil {
			return netx.OverlayInventory{}, err
		}
		out.Bindings = append(out.Bindings, netx.LogicalBinding{
			VNI: link.VNI, VLAN: vlan, Peer: peer, MTU: mtu, Port: port, NodeA: a, NodeB: b,
		})
		key := a + "\x00" + b
		trunks[key] = netx.PhysicalTrunk{
			Bridge: bridge, Vxlan: vxlan, MTU: mtu, Port: port, NodeA: a, NodeB: b,
		}
	}
	for _, trunk := range trunks {
		out.Trunks = append(out.Trunks, trunk)
	}
	sort.Slice(out.Bindings, func(i, j int) bool { return out.Bindings[i].VNI < out.Bindings[j].VNI })
	sort.Slice(out.Trunks, func(i, j int) bool {
		if out.Trunks[i].NodeA != out.Trunks[j].NodeA {
			return out.Trunks[i].NodeA < out.Trunks[j].NodeA
		}
		return out.Trunks[i].NodeB < out.Trunks[j].NodeB
	})
	return out, nil
}
