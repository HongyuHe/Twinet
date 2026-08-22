package deploy

import (
	"context"
	"fmt"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// OverlayRepairReport reports binding-level work. Extras are deliberately
// reported rather than removed: ownership/policy must prove staleness before a
// repair path may delete someone else's VNI.
type OverlayRepairReport struct {
	Repaired []string          `json:"repaired"`
	Failed   map[string]string `json:"failed,omitempty"`
	Extra    []string          `json:"extra,omitempty"`
}

// ReconcileOverlayBindings restores only missing or mismatched logical
// bindings for live cross-node endpoints. It never creates/replaces a
// container or deletes an extra binding.
func (e *Engine) ReconcileOverlayBindings(ctx context.Context, top *model.Topology) (OverlayRepairReport, error) {
	report := OverlayRepairReport{Failed: map[string]string{}}
	if e.Runtime == nil {
		return report, fmt.Errorf("overlay binding repair needs a container runtime")
	}
	expected, err := e.ExpectedOverlayInventory(top)
	if err != nil {
		return report, err
	}
	actual, err := netx.InspectOverlayInventory(top.Name)
	if err != nil {
		return report, err
	}
	actualByVNI := map[uint32][]netx.LogicalBinding{}
	for _, binding := range actual.Bindings {
		actualByVNI[binding.VNI] = append(actualByVNI[binding.VNI], binding)
	}
	expectedByVNI := map[uint32]netx.LogicalBinding{}
	for _, binding := range expected.Bindings {
		expectedByVNI[binding.VNI] = binding
	}
	links := map[uint32]*model.Link{}
	for _, link := range top.Links {
		if link != nil && link.CrossNode() && link.VNI != 0 &&
			(link.A.Device.Node == e.Node || link.B.Device.Node == e.Node) {
			links[link.VNI] = link
		}
	}
	for vni := range actualByVNI {
		if _, wanted := expectedByVNI[vni]; !wanted {
			report.Extra = append(report.Extra, bindingID(vni))
		}
	}
	for _, binding := range expected.Bindings {
		actualBindings := actualByVNI[binding.VNI]
		if len(actualBindings) == 1 && sameBinding(binding, actualBindings[0]) {
			continue
		}
		link := links[binding.VNI]
		if link == nil {
			report.Failed[bindingID(binding.VNI)] = "topology has no local link for expected binding"
			continue
		}
		if err := e.reconcileOverlayLink(ctx, top, link); err != nil {
			report.Failed[bindingID(binding.VNI)] = err.Error()
			continue
		}
		report.Repaired = append(report.Repaired, bindingID(binding.VNI))
	}
	sort.Strings(report.Repaired)
	sort.Strings(report.Extra)
	if len(report.Failed) == 0 {
		report.Failed = nil
	}
	return report, nil
}

func (e *Engine) reconcileOverlayLink(ctx context.Context, top *model.Topology, link *model.Link) error {
	var local, remote *model.Iface
	switch e.Node {
	case link.A.Device.Node:
		local, remote = link.A, link.B
	case link.B.Device.Node:
		local, remote = link.B, link.A
	default:
		return nil
	}
	current, err := e.Runtime.Inspect(ctx, local.Device.Container)
	if err != nil {
		return fmt.Errorf("endpoint %s: inspect: %w", local.Device.ID, err)
	}
	if current.State == runtime.StateAbsent {
		return fmt.Errorf("endpoint %s container is absent", local.Device.ID)
	}
	if !current.State.Joinable() {
		return fmt.Errorf("endpoint %s container is %s, not joinable", local.Device.ID, current.State)
	}
	if _, err := e.Runtime.NSPath(ctx, local.Device.Container); err != nil {
		return fmt.Errorf("endpoint %s namespace: %w", local.Device.ID, err)
	}
	hostPort := hostSideName(link.VNI)
	present, err := netx.HostLinkPresent(hostPort)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("endpoint %s host port %s is absent", local.Device.ID, hostPort)
	}
	peer := e.PeerUnderlay[remote.Device.Node]
	if peer == "" {
		return fmt.Errorf("no underlay peer for node %s", remote.Device.Node)
	}
	vlan, mtu, port, err := multiplexParameters(top, e.Node, remote.Device.Node, link.VNI)
	if err != nil {
		return err
	}
	bridge, err := netx.EnsureMultiplexOverlay(netx.MultiplexOverlaySpec{
		Lab:            top.Name,
		LocalNode:      e.Node,
		RemoteNode:     remote.Device.Node,
		LocalIP:        e.UnderlayIP,
		RemoteIP:       peer,
		UnderlayDev:    e.UnderlayDev,
		MTU:            mtu,
		Port:           port,
		VNI:            link.VNI,
		VLAN:           vlan,
		PreserveActive: true,
		ForcePort:      true,
	})
	if err != nil {
		return err
	}
	if err := netx.AttachToMultiplexOverlay(hostPort, bridge, vlan); err != nil {
		return err
	}
	return nil
}

func sameBinding(want, got netx.LogicalBinding) bool {
	return want.VNI == got.VNI && want.VLAN == got.VLAN && want.Peer == got.Peer &&
		want.MTU == got.MTU && want.Port == got.Port && want.NodeA == got.NodeA && want.NodeB == got.NodeB &&
		!got.Legacy
}

func bindingID(vni uint32) string { return fmt.Sprintf("vni:%d", vni) }
