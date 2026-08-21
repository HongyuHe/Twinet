// Package model defines the typed topology model for Twinet.
//
// The model is the single source of truth for a lab. Everything else —
// addressing, VXLAN identifiers, container names, DNS zones, IXP route-server
// configuration, the web UI and the grading topology — is derived from it.
//
// The model is split into two layers:
//
//   - The *authored* layer (Lab, ASTemplate and their sub-structures) mirrors
//     what a course author writes in YAML. It is compact and full of templates,
//     ranges and inheritance.
//   - The *expanded* layer (Topology, Device, Link, ...) is the fully resolved
//     graph: every AS instantiated, every device named, every link endpoint
//     concrete. Planning, placement and deployment operate only on this layer.
//
// Expansion from the authored to the expanded layer lives in internal/expand.
package model

import (
	"fmt"
	"sort"
	"strings"
)

// APIVersion is the manifest schema version this build understands.
const APIVersion = "twinet.dev/v1"

// Kind values for the top-level documents Twinet accepts.
const (
	KindLab        = "Lab"
	KindASTemplate = "ASTemplate"
	KindRubric     = "Rubric"
)

// DeviceKind enumerates the kinds of device Twinet can instantiate.
type DeviceKind string

const (
	KindRouter  DeviceKind = "router"
	KindHost    DeviceKind = "host"
	KindSwitch  DeviceKind = "switch"
	KindService DeviceKind = "service"
)

// Valid reports whether k is a known device kind.
func (k DeviceKind) Valid() bool {
	switch k {
	case KindRouter, KindHost, KindSwitch, KindService:
		return true
	}
	return false
}

// ASRole describes who operates an autonomous system, which drives both access
// control and how much of the AS Twinet pre-configures.
type ASRole string

const (
	// RoleStudent ASes are operated by a student group. Twinet provisions only
	// the service attachment points and leaves the rest deliberately empty.
	RoleStudent ASRole = "student"
	// RoleStaff ASes are operated by the course staff and are fully configured
	// by Twinet, so they behave as a stable backdrop for the students.
	RoleStaff ASRole = "staff"
	// RoleIXP ASes are internet exchange points running a route server.
	RoleIXP ASRole = "ixp"
)

// Valid reports whether r is a known AS role.
func (r ASRole) Valid() bool {
	switch r {
	case RoleStudent, RoleStaff, RoleIXP:
		return true
	}
	return false
}

// Relationship is the business relationship of an inter-AS link, as seen from
// the "a" side of the peering.
type Relationship string

const (
	RelProvider Relationship = "provider" // a is the provider of b
	RelCustomer Relationship = "customer" // a is the customer of b
	RelPeer     Relationship = "peer"
)

// Valid reports whether r is a known relationship.
func (r Relationship) Valid() bool {
	switch r {
	case RelProvider, RelCustomer, RelPeer:
		return true
	}
	return false
}

// Inverse returns the relationship as seen from the other side of the link.
func (r Relationship) Inverse() Relationship {
	switch r {
	case RelProvider:
		return RelCustomer
	case RelCustomer:
		return RelProvider
	default:
		return RelPeer
	}
}

// Meta is the metadata block shared by every top-level document.
type Meta struct {
	Name        string `yaml:"name" json:"name" jsonschema:"required,description=Unique name of the object"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Course and Term are recorded on a report so a mark can be traced to the
	// class that produced it. Term already appears in a lab's description;
	// Course is carried through to the grading report.
	Course string            `yaml:"course,omitempty" json:"course,omitempty"`
	Term   string            `yaml:"term,omitempty" json:"term,omitempty"`
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Lab is the top-level manifest: the complete description of one deployment.
type Lab struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion" jsonschema:"required"`
	Kind       string `yaml:"kind" json:"kind" jsonschema:"required"`
	Metadata   Meta   `yaml:"metadata" json:"metadata" jsonschema:"required"`

	// Defaults apply to every device in the lab and have the lowest precedence.
	Defaults DeviceDefaults `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	// Kinds carries per-device-kind defaults, overriding Defaults.
	Kinds map[DeviceKind]DeviceDefaults `yaml:"kinds,omitempty" json:"kinds,omitempty"`
	// LinkDefaults apply to every link unless the link overrides them.
	LinkDefaults LinkProps `yaml:"link_defaults,omitempty" json:"link_defaults,omitempty"`

	// Addressing is the lab-wide IP addressing plan, expressed as templates.
	Addressing Addressing `yaml:"addressing" json:"addressing" jsonschema:"required"`

	// Templates holds AS templates. They are normally loaded from the
	// templates/ directory next to the manifest, but may also be inlined.
	Templates map[string]*ASTemplate `yaml:"templates,omitempty" json:"templates,omitempty"`

	// ASDefaults apply to every AS group unless overridden.
	ASDefaults ASSpec `yaml:"as_defaults,omitempty" json:"as_defaults,omitempty"`
	// AutonomousSystems declares the ASes in the lab, usually as ranges.
	AutonomousSystems []ASGroup `yaml:"autonomous_systems" json:"autonomous_systems" jsonschema:"required"`

	// Peerings declares the inter-AS topology.
	Peerings Peerings `yaml:"peerings,omitempty" json:"peerings,omitempty"`

	// Services declares the auxiliary services attached to the lab.
	Services map[string]*ServiceSpec `yaml:"services,omitempty" json:"services,omitempty"`

	// Behaviours declares scripted misconfigurations (hijacks, failures).
	Behaviours map[string]*Behaviour `yaml:"behaviours,omitempty" json:"behaviours,omitempty"`

	// RPKI declares the deliberate discrepancies in the lab's trust anchor.
	//
	// They are declared rather than incidental because an exercise has to be
	// able to state exactly which announcement is meant to be invalid, and
	// because a student who filters everything that is not explicitly valid
	// must be caught: without a not-found route in the lab, that student scores
	// full marks for a router that would black-hole most of the internet.
	RPKI RPKISpec `yaml:"rpki,omitempty" json:"rpki,omitempty"`

	// Access configures how students reach their devices.
	Access Access `yaml:"access,omitempty" json:"access,omitempty"`

	// Placement configures how ASes are distributed across cluster nodes.
	Placement Placement `yaml:"placement,omitempty" json:"placement,omitempty"`

	// Egress optionally allows named devices to reach the outside world.
	Egress []EgressRule `yaml:"egress,omitempty" json:"egress,omitempty"`

	// Dir is the directory the manifest was loaded from. Not serialised.
	Dir string `yaml:"-" json:"-"`
}

// DeviceDefaults carries the per-device settings that participate in the
// defaults -> kind -> device inheritance chain. Pointer fields distinguish
// "unset" (inherit) from "explicitly set to the zero value".
type DeviceDefaults struct {
	Image        string            `yaml:"image,omitempty" json:"image,omitempty"`
	CPUs         *float64          `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory       string            `yaml:"memory,omitempty" json:"memory,omitempty"`
	Pids         *int64            `yaml:"pids,omitempty" json:"pids,omitempty"`
	Restart      string            `yaml:"restart,omitempty" json:"restart,omitempty"`
	DNS          string            `yaml:"dns,omitempty" json:"dns,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Sysctls      map[string]string `yaml:"sysctls,omitempty" json:"sysctls,omitempty"`
	Capabilities []string          `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Binds        []string          `yaml:"binds,omitempty" json:"binds,omitempty"`
	Privileged   *bool             `yaml:"privileged,omitempty" json:"privileged,omitempty"`
	Command      []string          `yaml:"command,omitempty" json:"command,omitempty"`
}

// Merge returns a copy of d with any unset field taken from base.
// Maps and slices are merged rather than replaced, with d winning on conflict.
func (d DeviceDefaults) Merge(base DeviceDefaults) DeviceDefaults {
	out := d
	if out.Image == "" {
		out.Image = base.Image
	}
	if out.CPUs == nil {
		out.CPUs = base.CPUs
	}
	if out.Memory == "" {
		out.Memory = base.Memory
	}
	if out.Pids == nil {
		out.Pids = base.Pids
	}
	if out.Restart == "" {
		out.Restart = base.Restart
	}
	if out.DNS == "" {
		out.DNS = base.DNS
	}
	if out.Privileged == nil {
		out.Privileged = base.Privileged
	}
	if len(out.Command) == 0 {
		out.Command = base.Command
	}
	out.Env = mergeStringMap(base.Env, out.Env)
	out.Sysctls = mergeStringMap(base.Sysctls, out.Sysctls)
	out.Capabilities = mergeStringSet(base.Capabilities, out.Capabilities)
	out.Binds = append(append([]string{}, base.Binds...), out.Binds...)
	return out
}

func mergeStringMap(base, over map[string]string) map[string]string {
	if base == nil && over == nil {
		return nil
	}
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func mergeStringSet(base, over []string) []string {
	if len(base) == 0 && len(over) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(base)+len(over))
	out := make([]string, 0, len(base)+len(over))
	for _, s := range append(append([]string{}, base...), over...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// LinkProps are the traffic-shaping and framing properties of a link. They are
// pedagogically load-bearing: the courses ask students to discover which links
// are slow, so these values must be expressible per link.
type LinkProps struct {
	Bandwidth string `yaml:"bandwidth,omitempty" json:"bandwidth,omitempty" jsonschema:"description=tc rate, e.g. 1mbit"`
	Delay     string `yaml:"delay,omitempty" json:"delay,omitempty" jsonschema:"description=one-way netem delay, e.g. 2.5ms"`
	Queue     string `yaml:"queue,omitempty" json:"queue,omitempty" jsonschema:"description=tbf latency (max queueing time), e.g. 50ms"`
	Loss      string `yaml:"loss,omitempty" json:"loss,omitempty" jsonschema:"description=netem loss, e.g. 0.1%"`
	MTU       *int   `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

// Merge returns a copy of p with unset fields taken from base.
func (p LinkProps) Merge(base LinkProps) LinkProps {
	out := p
	if out.Bandwidth == "" {
		out.Bandwidth = base.Bandwidth
	}
	if out.Delay == "" {
		out.Delay = base.Delay
	}
	if out.Queue == "" {
		out.Queue = base.Queue
	}
	if out.Loss == "" {
		out.Loss = base.Loss
	}
	if out.MTU == nil {
		out.MTU = base.MTU
	}
	return out
}

// Addressing is the lab-wide IP plan. Every field is a Go template evaluated
// against a context that binds AS, RouterID, PeerAS, LinkIndex, VLAN and L2ID.
// This replaces the legacy platform's subnet_config.sh bash functions.
type Addressing struct {
	ASBlock   string `yaml:"as_block" json:"as_block" jsonschema:"required"`
	ASBlockV6 string `yaml:"as_block_v6,omitempty" json:"as_block_v6,omitempty"`

	RouterLoopback   string `yaml:"router_loopback" json:"router_loopback" jsonschema:"required"`
	RouterLoopbackV6 string `yaml:"router_loopback_v6,omitempty" json:"router_loopback_v6,omitempty"`
	RouterRouter     string `yaml:"router_router" json:"router_router" jsonschema:"required"`
	// RouterRouterRole is the optional scalable address expression for links
	// emitted by an interior generator. It receives Role, PeerRole,
	// RoleIndex, PeerRoleIndex and RoleLinkIndex in addition to the legacy
	// addressing context, so a large Clos need not squeeze every link through
	// the old byte-sized LinkIndex convention.
	RouterRouterRole string `yaml:"router_router_role,omitempty" json:"router_router_role,omitempty"`
	RouterHost       string `yaml:"router_host" json:"router_host" jsonschema:"required"`

	L2Domain   string `yaml:"l2_domain,omitempty" json:"l2_domain,omitempty"`
	L2DomainV6 string `yaml:"l2_domain_v6,omitempty" json:"l2_domain_v6,omitempty"`
	L2VLAN     string `yaml:"l2_vlan,omitempty" json:"l2_vlan,omitempty"`
	L2VLANV6   string `yaml:"l2_vlan_v6,omitempty" json:"l2_vlan_v6,omitempty"`
	InterAS    string `yaml:"inter_as" json:"inter_as" jsonschema:"required"`
	IXPPeering string `yaml:"ixp_peering,omitempty" json:"ixp_peering,omitempty"`

	// Service subnets. Each is a /24 shared between the AS-side router
	// interface (.1) and the service (.2), unless the template says otherwise.
	Services map[string]string `yaml:"services,omitempty" json:"services,omitempty"`
}

// ASSpec is the set of per-AS knobs that can be defaulted and overridden.
type ASSpec struct {
	Template   string            `yaml:"template,omitempty" json:"template,omitempty"`
	Role       ASRole            `yaml:"role,omitempty" json:"role,omitempty"`
	OwnerGroup string            `yaml:"owner_group,omitempty" json:"owner_group,omitempty"`
	Region     string            `yaml:"region,omitempty" json:"region,omitempty"`
	RegionOf   string            `yaml:"region_of,omitempty" json:"region_of,omitempty" jsonschema:"description=template computing the region from the ASN"`
	Nickname   string            `yaml:"nickname,omitempty" json:"nickname,omitempty"`
	Services   []string          `yaml:"services,omitempty" json:"services,omitempty"`
	Behaviours []string          `yaml:"behaviours,omitempty" json:"behaviours,omitempty"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Node       string            `yaml:"node,omitempty" json:"node,omitempty" jsonschema:"description=pin this AS to a specific cluster node"`
}

// Merge returns a copy of s with unset fields taken from base.
func (s ASSpec) Merge(base ASSpec) ASSpec {
	out := s
	if out.Template == "" {
		out.Template = base.Template
	}
	if out.Role == "" {
		out.Role = base.Role
	}
	if out.OwnerGroup == "" {
		out.OwnerGroup = base.OwnerGroup
	}
	if out.Region == "" {
		out.Region = base.Region
	}
	if out.RegionOf == "" {
		out.RegionOf = base.RegionOf
	}
	if out.Nickname == "" {
		out.Nickname = base.Nickname
	}
	if out.Node == "" {
		out.Node = base.Node
	}
	out.Services = mergeStringSet(base.Services, out.Services)
	out.Behaviours = mergeStringSet(base.Behaviours, out.Behaviours)
	out.Labels = mergeStringMap(base.Labels, out.Labels)
	return out
}

// ASGroup declares one or more ASes sharing a spec. Exactly one of Range or
// List must be set.
type ASGroup struct {
	Range  []int `yaml:"range,omitempty" json:"range,omitempty" jsonschema:"description=inclusive [first, last] ASN range"`
	List   []int `yaml:"list,omitempty" json:"list,omitempty"`
	ASSpec `yaml:",inline" json:",inline"`
}

// ASNs returns the concrete AS numbers this group declares, in order.
func (g ASGroup) ASNs() []int {
	if len(g.List) > 0 {
		out := append([]int{}, g.List...)
		sort.Ints(out)
		return out
	}
	if len(g.Range) == 2 {
		out := make([]int, 0, g.Range[1]-g.Range[0]+1)
		for n := g.Range[0]; n <= g.Range[1]; n++ {
			out = append(out, n)
		}
		return out
	}
	return nil
}

// ASTemplate describes the internal topology of an autonomous system. One
// template is instantiated once per AS that references it.
type ASTemplate struct {
	APIVersion string `yaml:"apiVersion,omitempty" json:"apiVersion,omitempty"`
	Kind       string `yaml:"kind,omitempty" json:"kind,omitempty"`
	Metadata   Meta   `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	Routers       map[string]*RouterSpec `yaml:"routers,omitempty" json:"routers,omitempty"`
	Hosts         HostPolicy             `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	InternalLinks []InternalLink         `yaml:"internal_links,omitempty" json:"internal_links,omitempty"`
	L2Domains     map[string]*L2Domain   `yaml:"l2_domains,omitempty" json:"l2_domains,omitempty"`
	ExternalPorts map[string]*ExtPort    `yaml:"external_ports,omitempty" json:"external_ports,omitempty"`
	Provisioning  Provisioning           `yaml:"provisioning,omitempty" json:"provisioning,omitempty"`

	// IXP marks this template as an internet exchange point, in which case
	// Routers must contain exactly one router acting as the route server.
	IXP bool `yaml:"ixp,omitempty" json:"ixp,omitempty"`

	// MPLS turns on label switching and LDP across the AS's interior, which
	// the advanced course's BGP-free core exercise is built on.
	MPLS MPLSSpec `yaml:"mpls,omitempty" json:"mpls,omitempty"`

	// Multicast declares the PIM sparse-mode exercise for this AS.
	Multicast MulticastSpec `yaml:"multicast,omitempty" json:"multicast,omitempty"`

	// VRFs are the virtual routing tables this AS offers. Each is a separate
	// routing table, so two customers using the same private address space can
	// both be carried without either seeing the other.
	VRFs map[string]*VRFSpec `yaml:"vrfs,omitempty" json:"vrfs,omitempty"`

	// Interior optionally replaces the legacy routers/internal_links pair
	// with a typed generated shape. Omitting it is exactly equivalent to
	// kind: explicit and preserves every existing template syntax.
	Interior *InteriorSpec `yaml:"interior,omitempty" json:"interior,omitempty"`
}

// MPLSSpec turns on label switching for an AS.
//
// Enabling it makes the interior forward on labels rather than on destination
// addresses, which is what allows the core routers to carry traffic for
// prefixes they hold no route to -- a "BGP-free core". LDP distributes the
// labels; there is nothing for the author to configure beyond saying which
// routers should run it.
type MPLSSpec struct {
	// Enabled runs LDP on every intra-AS interface of every router that has
	// one, using the router's loopback as the transport address.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Core lists the routers that must not run BGP at all. Naming them is what
	// makes "BGP-free core" a checkable property rather than an aspiration:
	// the grader can say which routers were meant to be free of it.
	Core []string `yaml:"core,omitempty" json:"core,omitempty"`
}

// MulticastSpec turns on the PIM sparse-mode exercise for an AS.
//
// The advanced course's second exercise asks students to enable PIM on every
// interface, IGMP on the host-facing ones, and to point every router at one
// rendezvous point for a group range. All three are properties of the AS rather
// than of a router, so they are declared here: the renderer builds the
// reference from the same statement the grader marks against, and the figure in
// the exercise cannot drift away from the running lab.
type MulticastSpec struct {
	// Enabled runs pimd and, in solve mode, configures the whole exercise.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// RP names the router whose loopback is the rendezvous point.
	RP string `yaml:"rp,omitempty" json:"rp,omitempty"`
	// Groups is the multicast range the rendezvous point serves.
	Groups string `yaml:"groups,omitempty" json:"groups,omitempty"`
	// TestGroup is one address inside Groups that the grader uses: a receiver
	// joins it, a source sends to it, and the tree is inspected. Naming it
	// means the check and the exercise are talking about the same group.
	TestGroup string `yaml:"test_group,omitempty" json:"test_group,omitempty"`
}

// VRFSpec describes one virtual routing and forwarding instance.
//
// The route distinguisher makes two customers' identical prefixes distinct in
// the provider's BGP table; the route targets decide which VRFs may import each
// other's routes, and so decide which sites can reach which. Isolation between
// two banks, and the deliberate lack of it between two branches of one bank,
// are both expressed here and nowhere else.
type VRFSpec struct {
	// Table is the kernel routing table number. Distinct per VRF within an AS.
	Table int `yaml:"table,omitempty" json:"table,omitempty"`
	// RD is the route distinguisher. Leave it empty and each provider edge
	// derives its own from its loopback, which is what you want: the value is
	// part of the key a VPN route is stored under, so two edges using one
	// value overwrite each other's copy of a customer and one of that
	// customer's sites silently vanishes from the other's routing table.
	//
	// Set it only for course material that publishes specific values, and then
	// only where one router terminates the table.
	RD string `yaml:"rd,omitempty" json:"rd,omitempty"`
	// Import and Export are route-target communities.
	Import []string `yaml:"import,omitempty" json:"import,omitempty"`
	Export []string `yaml:"export,omitempty" json:"export,omitempty"`
	// Attach lists the external port names whose interface joins this VRF.
	Attach []string `yaml:"attach,omitempty" json:"attach,omitempty"`
}

// RouterSpec describes one router within an AS template.
type RouterSpec struct {
	ID             int      `yaml:"id" json:"id" jsonschema:"required,description=stable router ID used by the addressing plan"`
	L2Gateway      string   `yaml:"l2_gateway,omitempty" json:"l2_gateway,omitempty" jsonschema:"description=name of the L2 domain this router is the gateway for"`
	Services       []string `yaml:"services,omitempty" json:"services,omitempty"`
	Host           *bool    `yaml:"host,omitempty" json:"host,omitempty" jsonschema:"description=override whether this router gets an attached L3 host"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// HostPolicy controls the automatic per-router L3 host.
type HostPolicy struct {
	PerRouter      *bool  `yaml:"per_router,omitempty" json:"per_router,omitempty"`
	Name           string `yaml:"name,omitempty" json:"name,omitempty" jsonschema:"description=host device name, default host"`
	Iface          string `yaml:"iface,omitempty" json:"iface,omitempty" jsonschema:"description=template for the host-side interface name"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// InternalLink is a link between two routers of the same AS. It unmarshals
// from either the compact form [A, B] or the extended mapping form.
type InternalLink struct {
	A string `yaml:"a" json:"a"`
	B string `yaml:"b" json:"b"`
	// Subnet pins the link's prefix instead of deriving it from the addressing
	// plan. Course material that publishes a topology figure with specific
	// subnets should pin them here, so the platform and the figure cannot drift.
	Subnet    string `yaml:"subnet,omitempty" json:"subnet,omitempty"`
	SubnetV6  string `yaml:"subnet_v6,omitempty" json:"subnet_v6,omitempty"`
	LinkProps `yaml:",inline" json:",inline"`
}

// L2Domain is a layer-2 fabric (a "datacenter") hanging off a gateway router.
type L2Domain struct {
	ID          int                    `yaml:"id" json:"id" jsonschema:"required"`
	Gateway     string                 `yaml:"gateway" json:"gateway" jsonschema:"required,description=router acting as the L3 gateway"`
	VLANs       map[int]string         `yaml:"vlans,omitempty" json:"vlans,omitempty" jsonschema:"description=VLAN id to human name"`
	Switches    map[string]*SwitchSpec `yaml:"switches" json:"switches" jsonschema:"required"`
	SwitchLinks []InternalLink         `yaml:"switch_links,omitempty" json:"switch_links,omitempty"`
	Hosts       map[string]*L2Host     `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

// SwitchSpec describes an Open vSwitch instance.
type SwitchSpec struct {
	MAC            string `yaml:"mac,omitempty" json:"mac,omitempty"`
	Uplink         *bool  `yaml:"uplink,omitempty" json:"uplink,omitempty" jsonschema:"description=whether this switch connects to the gateway router"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// L2Host is a host attached to a switch in an access VLAN.
type L2Host struct {
	Switch         string `yaml:"switch" json:"switch" jsonschema:"required"`
	VLAN           int    `yaml:"vlan" json:"vlan" jsonschema:"required"`
	LinkProps      `yaml:",inline" json:",inline"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// ExtPort is a named attachment point for inter-AS links. Peerings refer to
// these names, which decouples the inter-AS graph from the intra-AS topology.
type ExtPort struct {
	Router string `yaml:"router" json:"router" jsonschema:"required"`
	// VRF names the virtual routing table this port belongs to, empty for the
	// default one.
	VRF string `yaml:"vrf,omitempty" json:"vrf,omitempty"`
}

// Provisioning is the contract that distinguishes what Twinet configures from
// what the student must configure. It is the defining concept of a teaching
// platform and has no equivalent in general-purpose emulators.
type Provisioning struct {
	// Provisioned lists what Twinet configures. Students are told not to touch
	// these, and the grader treats them as given.
	Provisioned []ProvisionRule `yaml:"provisioned,omitempty" json:"provisioned,omitempty"`
	// Student lists the configuration domains deliberately left empty.
	Student []string `yaml:"student,omitempty" json:"student,omitempty"`
}

// ProvisionRule selects objects that Twinet should configure.
type ProvisionRule struct {
	Iface      *IfaceRef  `yaml:"iface,omitempty" json:"iface,omitempty"`
	DeviceKind DeviceKind `yaml:"device_kind,omitempty" json:"device_kind,omitempty"`
	Scope      string     `yaml:"scope,omitempty" json:"scope,omitempty"`
}

// IfaceRef names a specific interface on a specific device.
type IfaceRef struct {
	Router string `yaml:"router,omitempty" json:"router,omitempty"`
	Device string `yaml:"device,omitempty" json:"device,omitempty"`
	Name   string `yaml:"name" json:"name" jsonschema:"required"`
}

// Peerings declares the inter-AS topology, either explicitly or by generator.
type Peerings struct {
	Generator *PeeringGenerator `yaml:"generator,omitempty" json:"generator,omitempty"`
	Links     []PeeringLink     `yaml:"links,omitempty" json:"links,omitempty"`
	Overrides []PeeringLink     `yaml:"overrides,omitempty" json:"overrides,omitempty"`
}

// PeeringGenerator procedurally produces the inter-AS graph.
type PeeringGenerator struct {
	Kind  string  `yaml:"kind" json:"kind" jsonschema:"required,enum=tiered-internet"`
	Tiers [][]int `yaml:"tiers,omitempty" json:"tiers,omitempty"`
	IXPs  []int   `yaml:"ixps,omitempty" json:"ixps,omitempty"`
	// SlowLink injects the pedagogically required high-delay provider and
	// customer link that students must discover and engineer around.
	SlowLink *SlowLinkPolicy `yaml:"slow_link,omitempty" json:"slow_link,omitempty"`
	// Seed makes generation deterministic.
	Seed int64 `yaml:"seed,omitempty" json:"seed,omitempty"`
}

// SlowLinkPolicy configures the high-delay link injection.
type SlowLinkPolicy struct {
	PerAS int    `yaml:"per_as,omitempty" json:"per_as,omitempty"`
	Delay string `yaml:"delay,omitempty" json:"delay,omitempty"`
}

// PeeringLink is one inter-AS link.
type PeeringLink struct {
	A         int          `yaml:"a" json:"a" jsonschema:"required"`
	APort     string       `yaml:"a_port,omitempty" json:"a_port,omitempty"`
	ARouter   string       `yaml:"a_router,omitempty" json:"a_router,omitempty"`
	B         int          `yaml:"b" json:"b" jsonschema:"required"`
	BPort     string       `yaml:"b_port,omitempty" json:"b_port,omitempty"`
	BRouter   string       `yaml:"b_router,omitempty" json:"b_router,omitempty"`
	Rel       Relationship `yaml:"rel,omitempty" json:"rel,omitempty"`
	Subnet    string       `yaml:"subnet,omitempty" json:"subnet,omitempty" jsonschema:"description=override the generated subnet"`
	LinkProps `yaml:",inline" json:",inline"`
}

// Key returns a stable, order-independent identity for the peering.
func (p PeeringLink) Key() string {
	a := fmt.Sprintf("%d:%s", p.A, firstNonEmpty(p.APort, p.ARouter))
	b := fmt.Sprintf("%d:%s", p.B, firstNonEmpty(p.BPort, p.BRouter))
	if a > b {
		a, b = b, a
	}
	return a + "--" + b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ServiceSpec declares an auxiliary service (DNS, matrix, RPKI, ...).
type ServiceSpec struct {
	Kind           string            `yaml:"kind" json:"kind" jsonschema:"required"`
	Attach         *ServiceAttach    `yaml:"attach,omitempty" json:"attach,omitempty"`
	Listen         string            `yaml:"listen,omitempty" json:"listen,omitempty"`
	Config         map[string]string `yaml:"config,omitempty" json:"config,omitempty"`
	Node           string            `yaml:"node,omitempty" json:"node,omitempty"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// ServiceAttach says where in each AS the service connects.
type ServiceAttach struct {
	Template string `yaml:"template,omitempty" json:"template,omitempty"`
	Router   string `yaml:"router" json:"router" jsonschema:"required"`
	Iface    string `yaml:"iface" json:"iface" jsonschema:"required"`
	// PerAS attaches one interface per AS (matrix, measurement, dns) rather
	// than a single global link.
	PerAS *bool `yaml:"per_as,omitempty" json:"per_as,omitempty"`
}

// Behaviour is a scripted, reversible perturbation of the lab: a BGP hijack, a
// link failure, and so on. Replaces the legacy platform's hijack.sh scripts.
type Behaviour struct {
	Kind string `yaml:"kind" json:"kind" jsonschema:"required,enum=bgp-hijack,enum=link-down"`
	// Start is when the behaviour begins: "manual" (the default) or "deploy".
	//
	// Spelled `start` rather than `on` because YAML 1.1 parsers read a bare
	// `on:` key as the boolean true. Go's parser is 1.2 and reads it as a
	// string, so a manifest using `on:` meant one thing to Twinet and another
	// to every other tool that reads it -- including this project's own schema
	// check, which is where it was caught. A key that means different things to
	// two parsers is not a key worth keeping.
	Start   string            `yaml:"start,omitempty" json:"start,omitempty" jsonschema:"enum=manual,enum=deploy"`
	Victims *VictimSelector   `yaml:"victims,omitempty" json:"victims,omitempty"`
	Prefix  string            `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Type    string            `yaml:"type,omitempty" json:"type,omitempty"`
	Via     []string          `yaml:"via,omitempty" json:"via,omitempty"`
	Params  map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// VictimSelector chooses which ASes a behaviour targets.
type VictimSelector struct {
	Rel  string `yaml:"rel,omitempty" json:"rel,omitempty" jsonschema:"description=e.g. same-region"`
	Role ASRole `yaml:"role,omitempty" json:"role,omitempty"`
	List []int  `yaml:"list,omitempty" json:"list,omitempty"`
}

// RPKISpec configures the lab's trust anchor.
type RPKISpec struct {
	// NotFound lists ASes deliberately left without a ROA, which is the common
	// case on the real internet.
	NotFound []int `yaml:"not_found,omitempty" json:"not_found,omitempty"`
	// Invalid maps an AS to a prefix it holds a ROA for but does not announce,
	// so whoever does announce it looks like a hijacker.
	Invalid map[int]string `yaml:"invalid,omitempty" json:"invalid,omitempty"`
}

// Access configures student access to the lab.
type Access struct {
	Mode        string       `yaml:"mode,omitempty" json:"mode,omitempty" jsonschema:"enum=gateway,enum=none"`
	Listen      string       `yaml:"listen,omitempty" json:"listen,omitempty"`
	LegacyPorts *LegacyPorts `yaml:"legacy_ports,omitempty" json:"legacy_ports,omitempty"`
	Node        string       `yaml:"node,omitempty" json:"node,omitempty"`
}

// LegacyPorts reproduces the mini-Internet's "ssh -p 2000+ASN" entry point.
type LegacyPorts struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Base    int  `yaml:"base,omitempty" json:"base,omitempty"`
}

// Placement configures how ASes are distributed across cluster nodes.
type Placement struct {
	Strategy string            `yaml:"strategy,omitempty" json:"strategy,omitempty" jsonschema:"enum=pack-by-as,enum=spread-by-as,enum=single-node"`
	Nodes    []NodeSpec        `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	Pin      []PlacementPin    `yaml:"pin,omitempty" json:"pin,omitempty"`
	Reserve  map[string]Budget `yaml:"reserve,omitempty" json:"reserve,omitempty"`
}

// NodeSpec declares one cluster node.
type NodeSpec struct {
	Name string `yaml:"name" json:"name" jsonschema:"required"`
	// Addr is the agent's gRPC address. Defaults to name:7200.
	Addr string `yaml:"addr,omitempty" json:"addr,omitempty"`
	// UnderlayIP is the VTEP source address for cross-node VXLAN links.
	UnderlayIP string `yaml:"underlay_ip,omitempty" json:"underlay_ip,omitempty"`
	// Capacity optionally caps what may be scheduled here.
	Capacity *Budget `yaml:"capacity,omitempty" json:"capacity,omitempty"`
	// Front marks the node that publishes the web UI, gateway and VPN.
	Front bool `yaml:"front,omitempty" json:"front,omitempty"`
}

// Budget is a resource allowance.
type Budget struct {
	CPUs       float64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory     string  `yaml:"memory,omitempty" json:"memory,omitempty"`
	Containers int     `yaml:"containers,omitempty" json:"containers,omitempty"`
}

// PlacementPin forces matching objects onto a node.
type PlacementPin struct {
	Match PinMatch `yaml:"match" json:"match" jsonschema:"required"`
	Node  string   `yaml:"node" json:"node" jsonschema:"required"`
}

// PinMatch selects objects for a placement pin.
type PinMatch struct {
	AS      *int   `yaml:"as,omitempty" json:"as,omitempty"`
	Role    ASRole `yaml:"role,omitempty" json:"role,omitempty"`
	Service string `yaml:"service,omitempty" json:"service,omitempty"`
	Region  string `yaml:"region,omitempty" json:"region,omitempty"`
}

// EgressRule allows selected devices to reach the outside world.
type EgressRule struct {
	Device string `yaml:"device" json:"device" jsonschema:"required"`
	AS     *int   `yaml:"as,omitempty" json:"as,omitempty"`
}

// Normalize fills in defaults that the rest of the pipeline may assume.
func (l *Lab) Normalize() {
	if l.APIVersion == "" {
		l.APIVersion = APIVersion
	}
	if l.Kind == "" {
		l.Kind = KindLab
	}
	if l.Access.Mode == "" {
		l.Access.Mode = "gateway"
	}
	if l.Access.Listen == "" {
		l.Access.Listen = ":2022"
	}
	if l.Access.LegacyPorts != nil && l.Access.LegacyPorts.Base == 0 {
		l.Access.LegacyPorts.Base = 2000
	}
	if l.Placement.Strategy == "" {
		if len(l.Placement.Nodes) <= 1 {
			l.Placement.Strategy = "single-node"
		} else {
			l.Placement.Strategy = "pack-by-as"
		}
	}
	if len(l.Placement.Nodes) == 0 {
		l.Placement.Nodes = []NodeSpec{{Name: "local", Front: true}}
	}
	hasFront := false
	for i := range l.Placement.Nodes {
		if l.Placement.Nodes[i].Front {
			hasFront = true
		}
	}
	if !hasFront {
		l.Placement.Nodes[0].Front = true
	}
	if l.LinkDefaults.MTU == nil {
		mtu := 1500
		l.LinkDefaults.MTU = &mtu
	}
}

// FrontNode returns the node that publishes externally reachable services.
func (l *Lab) FrontNode() string {
	for _, n := range l.Placement.Nodes {
		if n.Front {
			return n.Name
		}
	}
	if len(l.Placement.Nodes) > 0 {
		return l.Placement.Nodes[0].Name
	}
	return "local"
}

// NodeByName returns the node spec with the given name.
func (l *Lab) NodeByName(name string) (NodeSpec, bool) {
	for _, n := range l.Placement.Nodes {
		if n.Name == name {
			return n, true
		}
	}
	return NodeSpec{}, false
}

// SortedTemplateNames returns template names in deterministic order.
func (l *Lab) SortedTemplateNames() []string {
	out := make([]string, 0, len(l.Templates))
	for k := range l.Templates {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// String renders a compact identity for logs.
func (l *Lab) String() string {
	var b strings.Builder
	b.WriteString(l.Metadata.Name)
	if l.Metadata.Term != "" {
		b.WriteString("@")
		b.WriteString(l.Metadata.Term)
	}
	return b.String()
}

// Empty reports whether no shaping is configured.
func (p LinkProps) Empty() bool {
	return p.Bandwidth == "" && p.Delay == "" && p.Queue == "" && p.Loss == ""
}

// Equal compares two LinkProps by value.
//
// LinkProps holds MTU as a pointer so that "unset" is distinguishable from
// "explicitly zero", which makes the compiler's == compare addresses rather
// than values. Anything comparing shaping must use this.
func (p LinkProps) Equal(o LinkProps) bool {
	if p.Bandwidth != o.Bandwidth || p.Delay != o.Delay ||
		p.Queue != o.Queue || p.Loss != o.Loss {
		return false
	}
	switch {
	case p.MTU == nil && o.MTU == nil:
		return true
	case p.MTU == nil || o.MTU == nil:
		return false
	default:
		return *p.MTU == *o.MTU
	}
}
