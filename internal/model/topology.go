package model

import (
	"fmt"
	"sort"
	"strings"
)

// ConfigOwner says who is responsible for a piece of configuration. It is the
// runtime form of the Provisioning contract and the reason Twinet can both
// deliberately leave a network unfinished and still know the right answer.
type ConfigOwner string

const (
	// OwnerPlatform: Twinet renders and applies this configuration.
	OwnerPlatform ConfigOwner = "platform"
	// OwnerStudent: deliberately left unconfigured for the student to do.
	// Twinet still records the expected value for grading and for `twinet solve`.
	OwnerStudent ConfigOwner = "student"
)

// Topology is the fully expanded, resolved lab: every AS instantiated, every
// device named, every link endpoint concrete. Planning, placement, deployment
// and grading operate exclusively on this structure.
type Topology struct {
	Lab      *Lab
	Name     string
	Devices  map[string]*Device // keyed by Device.ID
	Links    []*Link
	ASes     map[int]*AS
	Services map[string]*Service

	// Hash is a content hash of the expanded topology, stamped onto every
	// container so drift between manifest and deployment is detectable.
	Hash string
}

// AS is one expanded autonomous system.
type AS struct {
	ASN        int
	Role       ASRole
	Region     string
	Template   string
	OwnerGroup string
	Nickname   string
	Block      string // the AS's IPv4 /8, e.g. "12.0.0.0/8"
	BlockV6    string
	Devices    []*Device
	Routers    []*Device // subset of Devices, in template order
	ExtPorts   map[string]*ExtPortBinding
	Labels     map[string]string
	Node       string // pinned node, empty means "let the placer decide"
}

// ExtPortBinding resolves a named external port to a concrete router.
type ExtPortBinding struct {
	Name   string
	Router *Device
}

// Device is one container in the expanded topology.
type Device struct {
	// ID is the globally unique device identity, "as12/ATL" or "svc/dns".
	ID   string
	Name string // short name within the AS, e.g. "ATL"
	Kind DeviceKind
	ASN  int // 0 for lab-global services

	Image string
	// ImageID is the digest the reference resolved to when the lab was
	// planned. It is part of a container's identity: a tag rebuilt in place is
	// different software under an unchanged name.
	ImageID      string
	CPUs         float64
	Memory       string
	Pids         int64
	Restart      string
	Env          map[string]string
	Sysctls      map[string]string
	Capabilities []string
	Binds        []string
	Privileged   bool
	Command      []string
	Labels       map[string]string

	// RouterID is the stable per-AS router index used by the addressing plan.
	RouterID int
	// Node is the cluster node this device is placed on. Filled by the placer.
	Node string
	// Ifaces are the device's interfaces, in deterministic order.
	Ifaces []*Iface
	// Services names the services attached to this device.
	Services []string
	// L2Gateway is the L2 domain this router is gateway for, if any.
	L2Gateway string
	// VLANs is populated for switches: the set of VLAN ids in their domain.
	VLANs []int
	// L2Domain is the domain a switch or L2 host belongs to.
	L2Domain string
	// Owner identifies who may access this device (a student group, or staff).
	Owner string
	// Container is the runtime container name; derived, stable, unique.
	Container string
	// Hostname as seen inside the container.
	Hostname string
	// FRR is router-specific rendered configuration state.
	FRR *FRRConfig
}

// IsRouter reports whether the device runs FRR.
func (d *Device) IsRouter() bool { return d.Kind == KindRouter }

// IfaceByName returns the named interface.
func (d *Device) IfaceByName(name string) (*Iface, bool) {
	for _, i := range d.Ifaces {
		if i.Name == name {
			return i, true
		}
	}
	return nil, false
}

// AddIface appends an interface, keeping the slice sorted by name for
// determinism.
func (d *Device) AddIface(i *Iface) {
	d.Ifaces = append(d.Ifaces, i)
	sort.SliceStable(d.Ifaces, func(a, b int) bool { return d.Ifaces[a].Name < d.Ifaces[b].Name })
}

// Iface is one network interface on a device.
type Iface struct {
	// Name is the in-container interface name, e.g. "port_HOU" or "ATL-L2.10".
	Name string
	// Device is the owning device.
	Device *Device
	// Link is the link this interface terminates, nil for pure sub-interfaces.
	Link *Link
	// MAC is the deterministic locally administered address.
	MAC string
	// Addr4 and Addr6 are the addresses from the plan. They are applied only
	// when Owner is OwnerPlatform; otherwise they are the *expected* answer.
	Addr4 string
	Addr6 string
	// Owner says whether Twinet configures this interface or the student does.
	Owner ConfigOwner
	// Prescribed says whether the assignment mandates this exact address.
	//
	// Some addresses are dictated ("the loopback of router Y is X.[150+Y].0.1")
	// and some are the student's to choose ("use the subnet X.200.0.0/23; you
	// are free to use any address in it"). Grading must not confuse the two: a
	// check that demanded the reference answer for a free choice would fail a
	// perfectly correct student, which is worse than not checking at all.
	Prescribed bool
	// Subnet is the prefix this interface's address must fall inside, used to
	// grade a free choice.
	Subnet string
	// VLAN is the access VLAN for switch ports and the tag for sub-interfaces.
	VLAN int
	// Trunk marks a switch port carrying tagged traffic for multiple VLANs.
	Trunk bool
	// Parent names the parent interface for VLAN sub-interfaces.
	Parent string
	// Role annotates what the interface is for, used by config rendering.
	Role IfaceRole
	// Peer is the interface at the other end, for point-to-point links.
	Peer *Iface
}

// IfaceRole classifies an interface for configuration rendering and grading.
type IfaceRole string

const (
	RoleLoopback   IfaceRole = "loopback"
	RoleIntraAS    IfaceRole = "intra-as"
	RoleInterAS    IfaceRole = "inter-as"
	RoleHostLink   IfaceRole = "host"
	RoleL2Uplink   IfaceRole = "l2-uplink"
	RoleL2Access   IfaceRole = "l2-access"
	RoleL2Trunk    IfaceRole = "l2-trunk"
	RoleL2SubIface IfaceRole = "l2-subiface"
	RoleService    IfaceRole = "service"
	RoleIXPLink    IfaceRole = "ixp"
)

// LinkKind classifies how a link must be realised.
type LinkKind string

const (
	// LinkVeth is a point-to-point link between two devices.
	LinkVeth LinkKind = "veth"
	// LinkService is a point-to-point link to a lab-global service container.
	LinkService LinkKind = "service"
	// LinkFabric is a cable into a shared L2 fabric such as an IXP.
	LinkFabric LinkKind = "fabric"
)

// Link is a point-to-point layer-2 segment between exactly two interfaces.
// Twinet has no multi-access segments by design: switches are real devices, so
// every cable is a cable. This is what makes cross-node VXLAN trivial (a
// unicast tunnel with a static FDB and no learning or EVPN control plane).
type Link struct {
	// ID is a stable, order-independent identity used to derive the VNI, the
	// veth altname and the diffing key.
	ID string
	// Kind classifies the link.
	Kind LinkKind
	// A and B are the two endpoints.
	A *Iface
	B *Iface
	// Props are the resolved shaping properties.
	Props LinkProps
	// Subnet is the IPv4 prefix assigned to this link, if any.
	Subnet string
	// SubnetV6 is the IPv6 prefix, if any.
	SubnetV6 string
	// Rel is the business relationship for inter-AS links, from A's side.
	Rel Relationship
	// InterAS is true when A and B are in different ASes.
	InterAS bool
	// Segment names the shared broadcast domain this link belongs to, empty
	// for an ordinary point-to-point link.
	//
	// Twinet has no multi-access link type: a shared LAN is modelled as a real
	// switch with a cable to each participant, which is both what the hardware
	// actually is and what keeps cross-node wiring a simple two-ended tunnel.
	// Segment records the logical grouping so that addressing and validation
	// can treat those cables as one subnet.
	Segment string
	// VNI is the VXLAN network identifier used when the endpoints land on
	// different nodes. Deterministically derived from ID.
	VNI uint32
	// Owner says whether Twinet addresses this link or the student does.
	Owner ConfigOwner
}

// Endpoints returns the two interfaces in deterministic order.
func (l *Link) Endpoints() (*Iface, *Iface) { return l.A, l.B }

// CrossNode reports whether the link's endpoints are on different nodes.
func (l *Link) CrossNode() bool {
	if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
		return false
	}
	return l.A.Device.Node != l.B.Device.Node
}

// Other returns the endpoint opposite to i.
func (l *Link) Other(i *Iface) *Iface {
	if l.A == i {
		return l.B
	}
	return l.A
}

// MakeLinkID builds the canonical, order-independent link identity.
func MakeLinkID(devA, ifA, devB, ifB string) string {
	a := devA + ":" + ifA
	b := devB + ":" + ifB
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

// Service is an expanded auxiliary service.
type Service struct {
	Name   string
	Kind   string
	Device *Device
	Spec   *ServiceSpec
	PerAS  bool
	Attach *ServiceAttach
	Listen string
	Config map[string]string
	Node   string
}

// FRRConfig holds the rendered routing configuration for a router, split by
// owner so that `twinet deploy` applies only the platform's part while
// `twinet solve` can additionally apply the student's part.
type FRRConfig struct {
	// Platform is the configuration Twinet always applies.
	Platform string
	// Expected is the reference solution: what a correct student would add.
	Expected string
	// Daemons is the FRR daemons file contents.
	Daemons string
}

// SortedDevices returns all devices in deterministic ID order.
func (t *Topology) SortedDevices() []*Device {
	out := make([]*Device, 0, len(t.Devices))
	for _, d := range t.Devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SortedASNs returns AS numbers in ascending order.
func (t *Topology) SortedASNs() []int {
	out := make([]int, 0, len(t.ASes))
	for n := range t.ASes {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// SortedServiceNames returns service names in deterministic order.
func (t *Topology) SortedServiceNames() []string {
	out := make([]string, 0, len(t.Services))
	for n := range t.Services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DevicesOnNode returns the devices placed on the named node.
func (t *Topology) DevicesOnNode(node string) []*Device {
	var out []*Device
	for _, d := range t.SortedDevices() {
		if d.Node == node {
			out = append(out, d)
		}
	}
	return out
}

// LinksTouchingNode returns links with at least one endpoint on the node.
func (t *Topology) LinksTouchingNode(node string) []*Link {
	var out []*Link
	for _, l := range t.Links {
		if (l.A != nil && l.A.Device.Node == node) || (l.B != nil && l.B.Device.Node == node) {
			out = append(out, l)
		}
	}
	return out
}

// Device looks up a device by ID.
func (t *Topology) Device(id string) (*Device, bool) {
	d, ok := t.Devices[id]
	return d, ok
}

// DeviceInAS finds a device by AS number and short name.
func (t *Topology) DeviceInAS(asn int, name string) (*Device, bool) {
	return t.Device(DeviceID(asn, name))
}

// DeviceID builds the canonical device identity.
func DeviceID(asn int, name string) string {
	if asn == 0 {
		return "svc/" + name
	}
	return fmt.Sprintf("as%d/%s", asn, name)
}

// ContainerName builds the runtime container name for a device.
func ContainerName(lab string, asn int, name string) string {
	if asn == 0 {
		return fmt.Sprintf("twinet-%s-svc-%s", lab, strings.ToLower(name))
	}
	return fmt.Sprintf("twinet-%s-as%d-%s", lab, asn, strings.ToLower(name))
}

// Stats summarises a topology for status output and capacity planning.
type Stats struct {
	ASes      int
	Devices   int
	Routers   int
	Hosts     int
	Switches  int
	Services  int
	Links     int
	InterAS   int
	CrossNode int
	PerNode   map[string]int
}

// Stats computes summary statistics.
func (t *Topology) Stats() Stats {
	s := Stats{PerNode: map[string]int{}}
	s.ASes = len(t.ASes)
	s.Services = len(t.Services)
	for _, d := range t.Devices {
		s.Devices++
		s.PerNode[d.Node]++
		switch d.Kind {
		case KindRouter:
			s.Routers++
		case KindHost:
			s.Hosts++
		case KindSwitch:
			s.Switches++
		}
	}
	for _, l := range t.Links {
		s.Links++
		if l.InterAS {
			s.InterAS++
		}
		if l.CrossNode() {
			s.CrossNode++
		}
	}
	return s
}
