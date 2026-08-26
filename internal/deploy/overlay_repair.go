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
	return e.reconcileOverlayBindings(ctx, top, nil)
}

// ReconcileDeviceOverlayBindings restores the cross-node bindings of the links
// that terminate on one device.
//
// It exists so that automatic repair of a single device does not have to ask
// for a node-wide overlay pass, and so that the answer to "this router lost
// its IXP interface" is the one veth and the one VNI binding it is missing.
// Extras are not reported: a device-scoped caller has not looked at the rest
// of the node and must not be able to make a claim about it.
func (e *Engine) ReconcileDeviceOverlayBindings(ctx context.Context, top *model.Topology,
	device *model.Device,
) (OverlayRepairReport, error) {
	if top == nil || device == nil {
		return OverlayRepairReport{}, fmt.Errorf("device overlay repair needs a topology device")
	}
	report, err := e.reconcileOverlayBindings(ctx, top, func(link *model.Link) bool {
		return link.A.Device.ID == device.ID || link.B.Device.ID == device.ID
	})
	report.Extra = nil
	return report, err
}

func (e *Engine) reconcileOverlayBindings(ctx context.Context, top *model.Topology,
	want func(*model.Link) bool,
) (OverlayRepairReport, error) {
	report := OverlayRepairReport{Failed: map[string]string{}}
	if e.Runtime == nil {
		return report, fmt.Errorf("overlay binding repair needs a container runtime")
	}
	expected, err := e.ExpectedOverlayInventory(top)
	if err != nil {
		return report, err
	}
	actual, err := e.observedOverlayInventory(top.Name)
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
			if want != nil && !want(link) {
				continue
			}
			links[link.VNI] = link
		}
	}
	hostPortNames := make([]string, 0, len(links))
	for vni := range links {
		hostPortNames = append(hostPortNames, hostSideName(vni))
	}
	hostPorts, err := e.hostLinksPresent(hostPortNames)
	if err != nil {
		return report, err
	}
	if want == nil {
		for vni := range actualByVNI {
			if _, wanted := expectedByVNI[vni]; !wanted {
				report.Extra = append(report.Extra, bindingID(vni))
			}
		}
	}
	for _, binding := range expected.Bindings {
		link := links[binding.VNI]
		if link == nil {
			if want != nil {
				continue
			}
			report.Failed[bindingID(binding.VNI)] = "topology has no local link for expected binding"
			continue
		}
		actualBindings := actualByVNI[binding.VNI]
		if overlayEndpointHealthy(binding, actualBindings, hostPorts[hostSideName(binding.VNI)]) {
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

func (e *Engine) hostLinksPresent(names []string) (map[string]bool, error) {
	if e.hostLinkPresence != nil {
		return e.hostLinkPresence(names)
	}
	return netx.HostLinksPresent(names)
}

func (e *Engine) hostLinkPresent(name string) (bool, error) {
	if e.hostLinkPresence != nil {
		present, err := e.hostLinkPresence([]string{name})
		return present[name], err
	}
	return netx.HostLinkPresent(name)
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
	present, err := e.hostLinkPresent(hostPort)
	if err != nil {
		return err
	}
	if !present {
		// A container restart or interrupted high-width apply can lose both
		// halves of this endpoint while leaving the shared trunk intact.
		// Recreate this one link idempotently; reporting it as unrepairable
		// strands an otherwise committed scale deployment.
		return e.wireCrossNode(ctx, top, link)
	}
	peer := e.PeerUnderlay[remote.Device.Node]
	if peer == "" {
		return fmt.Errorf("no underlay peer for node %s", remote.Device.Node)
	}
	vlan, mtu, port, err := e.multiplexParameters(top, e.Node, remote.Device.Node, link.VNI)
	if err != nil {
		return err
	}
	bridge, err := netx.EnsureMultiplexOverlay(netx.MultiplexOverlaySpec{
		Lab:         top.Name,
		LocalNode:   e.Node,
		RemoteNode:  remote.Device.Node,
		LocalIP:     e.UnderlayIP,
		RemoteIP:    peer,
		UnderlayDev: e.UnderlayDev,
		MTU:         mtu,
		Port:        port,
		VNI:         link.VNI,
		VLAN:        vlan,
		// An explicit node reconcile is cluster-fanned-out, so it may move
		// both endpoints from a legacy receive port to the current pair
		// port. Recovery/status uses the default false and will report a
		// port/MTU drift rather than changing only one endpoint.
		PreserveActive: !e.ForceOverlayReconcile,
		ForcePort:      e.ForceOverlayReconcile,
	})
	if err != nil {
		return err
	}
	if err := netx.AttachToMultiplexOverlay(hostPort, bridge, vlan); err != nil {
		return err
	}
	return nil
}

func overlayEndpointHealthy(want netx.LogicalBinding, got []netx.LogicalBinding, hostPortPresent bool) bool {
	return hostPortPresent && len(got) == 1 && sameBinding(want, got[0])
}

func sameBinding(want, got netx.LogicalBinding) bool {
	return want.VNI == got.VNI && want.VLAN == got.VLAN && want.Peer == got.Peer &&
		want.MTU == got.MTU && want.Port == got.Port && want.NodeA == got.NodeA && want.NodeB == got.NodeB &&
		!got.Legacy
}

func bindingID(vni uint32) string { return fmt.Sprintf("vni:%d", vni) }
