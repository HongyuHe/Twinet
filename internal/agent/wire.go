package agent

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/HongyuHe/twinet/internal/model"
)

// Wire is the serialisable form of an expanded topology.
//
// The in-memory model is a graph with pointers in both directions (an interface
// knows its device, its link and its peer), which JSON cannot represent
// directly. Rather than litter the model with serialisation concerns or resort
// to reflection tricks, the wire form is a flat, explicit projection with
// string references, and Rehydrate reconstructs the graph and re-establishes
// every invariant.
//
// Being explicit here also pins the control-plane-to-agent contract: adding a
// field to the model does not silently change what a node receives.
type Wire struct {
	Lab      string      `json:"lab"`
	Hash     string      `json:"hash"`
	Devices  []WireDev   `json:"devices"`
	Links    []WireLink  `json:"links"`
	ASes     []WireAS    `json:"ases"`
	Services []WireSvc   `json:"services,omitempty"`
	Defaults WireDefault `json:"defaults"`
	// PeerUnderlay maps node name to VTEP address. It is carried with the lab
	// so a node can rebuild a cross-node link on its own initiative, which it
	// must be able to do: a container that restarts at three in the morning
	// cannot wait for a controller to come round again.
	PeerUnderlay map[string]string `json:"peer_underlay,omitempty"`
	// Mode is what the lab was applied as, "platform" or "solve".
	//
	// The node has to remember it. Its repair loop re-renders a device that
	// has lost its wiring, and re-rendering in platform mode a lab that was
	// deployed solved deletes the reference solution from that router --
	// quietly, as a side effect of a repair that reports success.
	Mode string `json:"mode,omitempty"`
	// Ungraded is the one AS that was left at the platform's own configuration
	// while the rest of the lab was solved, for a private grading harness.
	//
	// It is recorded with the mode because a repair that replays only the mode
	// rebuilds a solved renderer for every AS -- including this one, which is
	// the student's. The device would come back holding the reference answer
	// for the very system being marked, and nothing would say so.
	Ungraded int `json:"ungraded_as,omitempty"`
	// LabSpec is the manifest itself, carried whole.
	//
	// Reconstructing a minimal Lab on the far side and copying across the few
	// fields the agent was known to need is a bug generator: every new
	// manifest field silently arrives empty, the renderer produces something
	// subtly different from what the author wrote, and nothing anywhere
	// reports it. That cost a debugging session over an RPKI payload that was
	// correct on the controller and empty on the node. Carrying the whole
	// specification makes the class of bug impossible rather than fixing this
	// instance of it.
	LabSpec json.RawMessage `json:"lab_spec,omitempty"`
}

// WireDev is one device.
type WireDev struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	AS           int               `json:"as,omitempty"`
	RouterID     int               `json:"router_id,omitempty"`
	Node         string            `json:"node"`
	Image        string            `json:"image"`
	ImageID      string            `json:"image_id,omitempty"`
	Container    string            `json:"container"`
	Hostname     string            `json:"hostname"`
	Owner        string            `json:"owner,omitempty"`
	CPUs         float64           `json:"cpus,omitempty"`
	Memory       string            `json:"memory,omitempty"`
	Pids         int64             `json:"pids,omitempty"`
	Restart      string            `json:"restart,omitempty"`
	Privileged   bool              `json:"privileged,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Sysctls      map[string]string `json:"sysctls,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Binds        []string          `json:"binds,omitempty"`
	Command      []string          `json:"command,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	ServiceKind  string            `json:"service_kind,omitempty"`
	L2Gateway    string            `json:"l2_gateway,omitempty"`
	L2Domain     string            `json:"l2_domain,omitempty"`
	VLANs        []int             `json:"vlans,omitempty"`
	Ifaces       []WireIface       `json:"ifaces,omitempty"`
}

// WireIface is one interface.
type WireIface struct {
	Name   string `json:"name"`
	MAC    string `json:"mac,omitempty"`
	Addr4  string `json:"addr4,omitempty"`
	Addr6  string `json:"addr6,omitempty"`
	Owner  string `json:"owner"`
	VLAN   int    `json:"vlan,omitempty"`
	Trunk  bool   `json:"trunk,omitempty"`
	Parent string `json:"parent,omitempty"`
	Role   string `json:"role"`
	LinkID string `json:"link_id,omitempty"`
	// VRF is the virtual routing table this interface belongs to.
	//
	// It has to cross the wire, and it was the missing piece: the controller
	// rendered `interface X vrf Y` correctly while the node put the interface
	// in the main table, because the node's copy of the model had no VRF at
	// all. Nothing reported a problem -- the daemon was configured for a table
	// the kernel did not have, and every customer's routes quietly shared one.
	VRF string `json:"vrf,omitempty"`
}

// WireLink is one link.
type WireLink struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	ADevice  string `json:"a_device"`
	AIface   string `json:"a_iface"`
	BDevice  string `json:"b_device"`
	BIface   string `json:"b_iface"`
	Subnet   string `json:"subnet,omitempty"`
	SubnetV6 string `json:"subnet_v6,omitempty"`
	Rel      string `json:"rel,omitempty"`
	InterAS  bool   `json:"inter_as,omitempty"`
	Segment  string `json:"segment,omitempty"`
	VNI      uint32 `json:"vni"`
	Owner    string `json:"owner"`
	// Shaping.
	Bandwidth string `json:"bandwidth,omitempty"`
	Delay     string `json:"delay,omitempty"`
	Queue     string `json:"queue,omitempty"`
	Loss      string `json:"loss,omitempty"`
	MTU       *int   `json:"mtu,omitempty"`
}

// WireAS is one autonomous system.
type WireAS struct {
	ASN        int      `json:"asn"`
	Role       string   `json:"role"`
	Region     string   `json:"region,omitempty"`
	Template   string   `json:"template,omitempty"`
	OwnerGroup string   `json:"owner_group,omitempty"`
	Block      string   `json:"block,omitempty"`
	BlockV6    string   `json:"block_v6,omitempty"`
	Routers    []string `json:"routers,omitempty"`
	Devices    []string `json:"devices,omitempty"`
	// MPLS and VRFs carry the advanced course's declarations, which the node
	// needs in order to create the kernel routing tables and the renderer
	// needs in order to configure them.
	MPLSEnabled bool                     `json:"mpls_enabled,omitempty"`
	MPLSCore    []string                 `json:"mpls_core,omitempty"`
	VRFs        map[string]model.VRFSpec `json:"vrfs,omitempty"`
	// Provisioned is the compiled provisioning declaration: which
	// configuration domains Twinet configures for a student AS. The node
	// renders the device, so a node that did not receive this would hand out a
	// different half of the configuration from the one the manifest asked for,
	// and nothing downstream would say so.
	Provisioned       []string `json:"provisioned,omitempty"`
	ProvisionedIfaces []string `json:"provisioned_ifaces,omitempty"`
	// Multicast carries the PIM exercise's declaration. The node decides from
	// it whether to run pimd and what the reference solution is, so a node that
	// did not receive it would deploy a lab where the exercise cannot be
	// configured at all.
	Multicast model.MulticastSpec `json:"multicast,omitempty"`
}

// WireSvc is one auxiliary service.
type WireSvc struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Device string            `json:"device,omitempty"`
	Node   string            `json:"node,omitempty"`
	Listen string            `json:"listen,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

// WireDefault carries lab-wide settings the agent needs.
type WireDefault struct {
	MTU int `json:"mtu,omitempty"`
}

// Serialise projects a topology onto the wire form.
func Serialise(top *model.Topology) *Wire {
	w := &Wire{Lab: top.Name, Hash: top.Hash}
	if top.Lab != nil {
		if top.Lab.LinkDefaults.MTU != nil {
			w.Defaults.MTU = *top.Lab.LinkDefaults.MTU
		}
		// The manifest travels whole, so a field added to it reaches the node
		// without anyone remembering to extend this projection.
		if raw, err := json.Marshal(top.Lab); err == nil {
			w.LabSpec = raw
		}
	}

	for _, d := range top.SortedDevices() {
		wd := WireDev{
			ServiceKind: d.ServiceKind,
			ID:          d.ID, Name: d.Name, Kind: string(d.Kind), AS: d.ASN,
			RouterID: d.RouterID, Node: d.Node, Image: d.Image, ImageID: d.ImageID,
			Container: d.Container, Hostname: d.Hostname, Owner: d.Owner,
			CPUs: d.CPUs, Memory: d.Memory, Pids: d.Pids, Restart: d.Restart,
			Privileged: d.Privileged, Env: d.Env, Sysctls: d.Sysctls,
			Capabilities: d.Capabilities, Binds: d.Binds, Command: d.Command,
			Labels: d.Labels, L2Gateway: d.L2Gateway, L2Domain: d.L2Domain,
			VLANs: d.VLANs,
		}
		for _, i := range d.Ifaces {
			wi := WireIface{
				Name: i.Name, MAC: i.MAC, Addr4: i.Addr4, Addr6: i.Addr6,
				Owner: string(i.Owner), VLAN: i.VLAN, Trunk: i.Trunk,
				Parent: i.Parent, Role: string(i.Role), VRF: i.VRF,
			}
			if i.Link != nil {
				wi.LinkID = i.Link.ID
			}
			wd.Ifaces = append(wd.Ifaces, wi)
		}
		w.Devices = append(w.Devices, wd)
	}

	for _, l := range top.Links {
		wl := WireLink{
			ID: l.ID, Kind: string(l.Kind),
			ADevice: l.A.Device.ID, AIface: l.A.Name,
			BDevice: l.B.Device.ID, BIface: l.B.Name,
			Subnet: l.Subnet, SubnetV6: l.SubnetV6, Rel: string(l.Rel),
			InterAS: l.InterAS, Segment: l.Segment, VNI: l.VNI,
			Owner:     string(l.Owner),
			Bandwidth: l.Props.Bandwidth, Delay: l.Props.Delay,
			Queue: l.Props.Queue, Loss: l.Props.Loss, MTU: l.Props.MTU,
		}
		w.Links = append(w.Links, wl)
	}

	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		wa := WireAS{
			ASN: as.ASN, Role: string(as.Role), Region: as.Region,
			Template: as.Template, OwnerGroup: as.OwnerGroup,
			Block: as.Block, BlockV6: as.BlockV6,
			MPLSEnabled: as.MPLS.Enabled, MPLSCore: as.MPLS.Core,
			Multicast:         as.Multicast,
			Provisioned:       sortedSetKeys(as.Provisioned),
			ProvisionedIfaces: sortedSetKeys(as.ProvisionedIfaces),
		}
		if len(as.VRFs) > 0 {
			wa.VRFs = map[string]model.VRFSpec{}
			for n, v := range as.VRFs {
				wa.VRFs[n] = *v
			}
		}
		for _, r := range as.Routers {
			wa.Routers = append(wa.Routers, r.ID)
		}
		for _, d := range as.Devices {
			wa.Devices = append(wa.Devices, d.ID)
		}
		w.ASes = append(w.ASes, wa)
	}

	for _, n := range top.SortedServiceNames() {
		s := top.Services[n]
		ws := WireSvc{Name: s.Name, Kind: s.Kind, Node: s.Node, Listen: s.Listen, Config: s.Config}
		if s.Device != nil {
			ws.Device = s.Device.ID
		}
		w.Services = append(w.Services, ws)
	}
	return w
}

// Rehydrate reconstructs the in-memory graph from the wire form.
//
// Every reference is resolved explicitly and a dangling one is an error, so a
// truncated or mismatched payload fails immediately with a precise message
// rather than producing a topology with silent holes in it.
func (w *Wire) Rehydrate() (*model.Topology, error) {
	if w.Lab == "" {
		return nil, fmt.Errorf("the wire topology has no lab name")
	}
	mtu := w.Defaults.MTU
	if mtu == 0 {
		mtu = 1500
	}
	lab := &model.Lab{}
	if len(w.LabSpec) > 0 {
		if err := json.Unmarshal(w.LabSpec, lab); err != nil {
			return nil, fmt.Errorf("decode the lab specification: %w", err)
		}
	}
	lab.Metadata.Name = w.Lab
	if lab.LinkDefaults.MTU == nil {
		lab.LinkDefaults.MTU = &mtu
	}

	top := &model.Topology{
		Lab: lab, Name: w.Lab, Hash: w.Hash,
		Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
		Services: map[string]*model.Service{},
	}

	// Devices and their interfaces, without cross-references yet.
	ifaceOf := map[string]*model.Iface{} // "devID|ifName" -> iface
	for i := range w.Devices {
		wd := &w.Devices[i]
		d := &model.Device{
			ID: wd.ID, Name: wd.Name, Kind: model.DeviceKind(wd.Kind), ASN: wd.AS,
			RouterID: wd.RouterID, Node: wd.Node, Image: wd.Image, ImageID: wd.ImageID,
			Container: wd.Container, Hostname: wd.Hostname, Owner: wd.Owner,
			CPUs: wd.CPUs, Memory: wd.Memory, Pids: wd.Pids, Restart: wd.Restart,
			Privileged: wd.Privileged, Env: wd.Env, Sysctls: wd.Sysctls,
			Capabilities: wd.Capabilities, Binds: wd.Binds, Command: wd.Command,
			Labels: wd.Labels, L2Gateway: wd.L2Gateway, L2Domain: wd.L2Domain,
			ServiceKind: wd.ServiceKind,
			VLANs:       wd.VLANs,
		}
		for _, wi := range wd.Ifaces {
			ifc := &model.Iface{
				Device: d, Name: wi.Name, MAC: wi.MAC, Addr4: wi.Addr4, Addr6: wi.Addr6,
				Owner: model.ConfigOwner(wi.Owner), VLAN: wi.VLAN, Trunk: wi.Trunk,
				Parent: wi.Parent, Role: model.IfaceRole(wi.Role), VRF: wi.VRF,
			}
			d.Ifaces = append(d.Ifaces, ifc)
			ifaceOf[wd.ID+"|"+wi.Name] = ifc
		}
		top.Devices[d.ID] = d
	}

	// Links, resolving both endpoints.
	for _, wl := range w.Links {
		a, ok := ifaceOf[wl.ADevice+"|"+wl.AIface]
		if !ok {
			return nil, fmt.Errorf("link %s references unknown interface %s:%s", wl.ID, wl.ADevice, wl.AIface)
		}
		b, ok := ifaceOf[wl.BDevice+"|"+wl.BIface]
		if !ok {
			return nil, fmt.Errorf("link %s references unknown interface %s:%s", wl.ID, wl.BDevice, wl.BIface)
		}
		l := &model.Link{
			ID: wl.ID, Kind: model.LinkKind(wl.Kind), A: a, B: b,
			Subnet: wl.Subnet, SubnetV6: wl.SubnetV6, Rel: model.Relationship(wl.Rel),
			InterAS: wl.InterAS, Segment: wl.Segment, VNI: wl.VNI,
			Owner: model.ConfigOwner(wl.Owner),
			Props: model.LinkProps{
				Bandwidth: wl.Bandwidth, Delay: wl.Delay,
				Queue: wl.Queue, Loss: wl.Loss, MTU: wl.MTU,
			},
		}
		a.Link, b.Link = l, l
		a.Peer, b.Peer = b, a
		top.Links = append(top.Links, l)
	}

	// Autonomous systems.
	for _, wa := range w.ASes {
		as := &model.AS{
			ASN: wa.ASN, Role: model.ASRole(wa.Role), Region: wa.Region,
			Template: wa.Template, OwnerGroup: wa.OwnerGroup,
			Block: wa.Block, BlockV6: wa.BlockV6,
			ExtPorts:          map[string]*model.ExtPortBinding{},
			MPLS:              model.MPLSSpec{Enabled: wa.MPLSEnabled, Core: wa.MPLSCore},
			Multicast:         wa.Multicast,
			Provisioned:       setOf(wa.Provisioned),
			ProvisionedIfaces: setOf(wa.ProvisionedIfaces),
		}
		if len(wa.VRFs) > 0 {
			as.VRFs = map[string]*model.VRFSpec{}
			for n, v := range wa.VRFs {
				vv := v
				as.VRFs[n] = &vv
			}
		}
		for _, id := range wa.Routers {
			d, ok := top.Devices[id]
			if !ok {
				return nil, fmt.Errorf("AS %d references unknown router %s", wa.ASN, id)
			}
			as.Routers = append(as.Routers, d)
		}
		for _, id := range wa.Devices {
			d, ok := top.Devices[id]
			if !ok {
				return nil, fmt.Errorf("AS %d references unknown device %s", wa.ASN, id)
			}
			as.Devices = append(as.Devices, d)
		}
		top.ASes[as.ASN] = as
	}

	// Services.
	for _, ws := range w.Services {
		s := &model.Service{Name: ws.Name, Kind: ws.Kind, Node: ws.Node,
			Listen: ws.Listen, Config: ws.Config}
		if ws.Device != "" {
			d, ok := top.Devices[ws.Device]
			if !ok {
				return nil, fmt.Errorf("service %s references unknown device %s", ws.Name, ws.Device)
			}
			s.Device = d
		}
		top.Services[s.Name] = s
	}

	return top, nil
}

// sortedSetKeys renders a set as a stable list for the wire.
func sortedSetKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func setOf(v []string) map[string]bool {
	if len(v) == 0 {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(v))
	for _, k := range v {
		out[k] = true
	}
	return out
}
