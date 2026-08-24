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
	// KindP4 is a BMv2 programmable data-plane switch. It is intentionally
	// distinct from an OVS switch: its program and control-plane contract are
	// part of the topology, rather than an implementation detail of a bridge.
	KindP4 DeviceKind = "p4"
	// KindController is an OpenFlow controller. Controllers are first-class
	// devices so their lifecycle and southbound state can be observed and
	// faulted without changing ordinary, controller-less OVS labs.
	KindController DeviceKind = "controller"
)

// Valid reports whether k is a known device kind.
func (k DeviceKind) Valid() bool {
	switch k {
	case KindRouter, KindHost, KindSwitch, KindService, KindP4, KindController:
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
	// Controllers declares lab-global OpenFlow controllers. A controller is a
	// real device with point-to-point management links to the OVS switches it
	// owns; leaving this empty preserves the historical standalone-switch
	// behaviour exactly.
	Controllers map[string]*ControllerSpec `yaml:"controllers,omitempty" json:"controllers,omitempty"`
	// ServicePolicyVersion opts a manifest into a deliberately versioned set of
	// service defaults. Empty retains the historic singleton expansion so an
	// existing manifest and its topology hash do not change merely by loading
	// it with a newer controller. Version "v2" makes attach-to-every-AS
	// built-ins per-node unless they declare replication explicitly.
	ServicePolicyVersion string `yaml:"service_policy_version,omitempty" json:"service_policy_version,omitempty"`

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

	// Images selects the reproducibility contract for this lab. Development
	// labs may explicitly use tags; released and grading labs resolve every
	// device through a checked image lock.
	Images ImagePolicy `yaml:"images,omitempty" json:"images,omitempty"`

	// State controls durable preservation of student-owned configuration and
	// the agent records needed to repair a lab after a node loss.
	State StatePolicy `yaml:"state,omitempty" json:"state,omitempty"`

	// Egress optionally allows named devices to reach the outside world.
	Egress []EgressRule `yaml:"egress,omitempty" json:"egress,omitempty"`

	// Dir is the directory the manifest was loaded from. Not serialised.
	Dir string `yaml:"-" json:"-"`
}

// DeviceDefaults carries the per-device settings that participate in the
// defaults -> kind -> device inheritance chain. Pointer fields distinguish
// "unset" (inherit) from "explicitly set to the zero value".
type DeviceDefaults struct {
	Image string `yaml:"image,omitempty" json:"image,omitempty"`
	// NOS selects the network operating system for router devices. An omitted
	// value deliberately retains the legacy FRR default; it is not expanded
	// into the topology so existing topology identities remain unchanged.
	//
	// It is accepted in defaults, kinds.router, and an individual RouterSpec.
	// Non-router devices use the normal image/runtime contract and ignore it.
	NOS string `yaml:"nos,omitempty" json:"nos,omitempty" jsonschema:"description=router NOS implementation, e.g. frr or bird"`
	// CPUs, Memory, and Pids are hard runtime limits. They retain the original
	// manifest spelling for backwards compatibility; placement uses Requests,
	// never these limits.
	CPUs   *float64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory string   `yaml:"memory,omitempty" json:"memory,omitempty"`
	Pids   *int64   `yaml:"pids,omitempty" json:"pids,omitempty"`
	// Requests is the schedulable reservation for one device. A nil value
	// inherits; omitted dimensions receive conservative per-kind defaults when
	// the expanded device is materialised.
	Requests     *ResourceRequest  `yaml:"requests,omitempty" json:"requests,omitempty"`
	Restart      string            `yaml:"restart,omitempty" json:"restart,omitempty"`
	DNS          string            `yaml:"dns,omitempty" json:"dns,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Sysctls      map[string]string `yaml:"sysctls,omitempty" json:"sysctls,omitempty"`
	Capabilities []string          `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Binds        []string          `yaml:"binds,omitempty" json:"binds,omitempty"`
	Privileged   *bool             `yaml:"privileged,omitempty" json:"privileged,omitempty"`
	Command      []string          `yaml:"command,omitempty" json:"command,omitempty"`
	// Hardening is inherited with the rest of the device runtime contract.
	// Empty authored values receive the safe Twinet profile for the expanded
	// kind; weakening it requires a named, audited development override.
	Hardening RuntimeHardening `yaml:"hardening,omitempty" json:"hardening,omitempty"`
}

// RuntimeHardening is the portable subset of OCI runtime protections Twinet
// can enforce on every device. It deliberately models policy rather than
// exposing arbitrary Docker security options: a typo in a free-form option is
// indistinguishable from no protection at all.
type RuntimeHardening struct {
	// DevelopmentOverride is an auditable reason for an exceptional local
	// development setting. It is never a production compatibility fallback.
	DevelopmentOverride string `yaml:"development_override,omitempty" json:"development_override,omitempty"`
	NoNewPrivileges     *bool  `yaml:"no_new_privileges,omitempty" json:"no_new_privileges,omitempty"`
	SeccompProfile      string `yaml:"seccomp_profile,omitempty" json:"seccomp_profile,omitempty"`
	AppArmorProfile     string `yaml:"apparmor_profile,omitempty" json:"apparmor_profile,omitempty"`
	ReadOnlyRootfs      *bool  `yaml:"read_only_rootfs,omitempty" json:"read_only_rootfs,omitempty"`
	// WritablePaths are tmpfs mounts used by images that need ephemeral PID
	// files, logs, package state, or generated platform configuration.
	WritablePaths []string `yaml:"writable_paths,omitempty" json:"writable_paths,omitempty"`
	MaskedPaths   []string `yaml:"masked_paths,omitempty" json:"masked_paths,omitempty"`
	ReadonlyPaths []string `yaml:"readonly_paths,omitempty" json:"readonly_paths,omitempty"`
	// RuntimeClass, UsernsMode, and PIDMode are selected explicitly when a
	// deployment uses an alternate OCI runtime or namespace profile. "private"
	// is the safe default and maps to Docker's omitted PID mode.
	RuntimeClass string `yaml:"runtime_class,omitempty" json:"runtime_class,omitempty"`
	UsernsMode   string `yaml:"userns_mode,omitempty" json:"userns_mode,omitempty"`
	PIDMode      string `yaml:"pid_mode,omitempty" json:"pid_mode,omitempty"`
}

// DefaultRuntimeHardening returns the profile applied to every expanded
// device. Docker starts each device without its default bridge network; this
// profile adds the process/filesystem side of the same tenancy boundary.
func DefaultRuntimeHardening(kind DeviceKind) RuntimeHardening {
	truth := true
	// /var/run is a compatibility symlink to /run in every shipped image; do
	// not mount both paths because some OCI runtimes reject overlapping tmpfs
	// mount points.
	writable := []string{"/run", "/var/log", "/tmp", "/var/tmp", "/etc/twinet"}
	switch kind {
	case KindRouter:
		// /etc/frr is a narrowly scoped host bind owned by the FRR sidecar,
		// not a generic writable root filesystem.
	case KindSwitch:
		writable = append(writable, "/etc/openvswitch")
	case KindService:
		writable = append(writable, "/etc/bind", "/var/named")
	case KindP4:
		writable = append(writable, "/etc/twinet/p4")
	}
	return RuntimeHardening{
		NoNewPrivileges: &truth, SeccompProfile: "default", AppArmorProfile: "docker-default",
		ReadOnlyRootfs: &truth, PIDMode: "private", WritablePaths: writable,
		MaskedPaths: []string{
			"/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
			"/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
			"/sys/firmware", "/sys/devices/system/cpu/cpu0/thermal_throttle",
		},
		ReadonlyPaths: []string{
			"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
		},
	}
}

// EffectiveRuntimeHardening merges an authored profile over the safe
// per-device-kind profile.
func EffectiveRuntimeHardening(kind DeviceKind, authored RuntimeHardening) RuntimeHardening {
	return authored.Merge(DefaultRuntimeHardening(kind))
}

// Merge returns h with unset fields inherited from base.
func (h RuntimeHardening) Merge(base RuntimeHardening) RuntimeHardening {
	out := h
	if out.DevelopmentOverride == "" {
		out.DevelopmentOverride = base.DevelopmentOverride
	}
	if out.NoNewPrivileges == nil {
		out.NoNewPrivileges = base.NoNewPrivileges
	}
	if out.SeccompProfile == "" {
		out.SeccompProfile = base.SeccompProfile
	}
	if out.AppArmorProfile == "" {
		out.AppArmorProfile = base.AppArmorProfile
	}
	if out.ReadOnlyRootfs == nil {
		out.ReadOnlyRootfs = base.ReadOnlyRootfs
	}
	if out.RuntimeClass == "" {
		out.RuntimeClass = base.RuntimeClass
	}
	if out.UsernsMode == "" {
		out.UsernsMode = base.UsernsMode
	}
	if out.PIDMode == "" {
		out.PIDMode = base.PIDMode
	}
	out.WritablePaths = mergeStringSet(base.WritablePaths, out.WritablePaths)
	out.MaskedPaths = mergeStringSet(base.MaskedPaths, out.MaskedPaths)
	out.ReadonlyPaths = mergeStringSet(base.ReadonlyPaths, out.ReadonlyPaths)
	return out
}

// DevelopmentOverrideActive reports whether an exceptional setting carries an
// audit reason rather than silently behaving like a legacy insecure default.
func (h RuntimeHardening) DevelopmentOverrideActive() bool {
	return strings.TrimSpace(h.DevelopmentOverride) != ""
}

// ResourceRequest is the capacity a device reserves on its host. It is
// intentionally separate from Docker's CPU, memory, and PID limits: a device
// can be allowed to burst to a limit without reserving that entire limit on a
// node. Zero values mean "inherit" while the request is still authored; every
// expanded Device has a fully populated request.
//
// Disk is accepted as a backwards-friendly synonym for EphemeralStorage.
// New manifests should use ephemeral_storage, which says explicitly that the
// reservation is for disposable container writable-layer and scratch space.
type ResourceRequest struct {
	CPUs             float64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory           string  `yaml:"memory,omitempty" json:"memory,omitempty"`
	Pids             int64   `yaml:"pids,omitempty" json:"pids,omitempty"`
	EphemeralStorage string  `yaml:"ephemeral_storage,omitempty" json:"ephemeral_storage,omitempty"`
	Disk             string  `yaml:"disk,omitempty" json:"disk,omitempty"`
	FileDescriptors  int64   `yaml:"file_descriptors,omitempty" json:"file_descriptors,omitempty"`
	NetDevices       int64   `yaml:"netdevs,omitempty" json:"netdevs,omitempty"`
}

// Merge returns r with every unset dimension inherited from base.
func (r ResourceRequest) Merge(base ResourceRequest) ResourceRequest {
	out := r
	if out.CPUs == 0 {
		out.CPUs = base.CPUs
	}
	if out.Memory == "" {
		out.Memory = base.Memory
	}
	if out.Pids == 0 {
		out.Pids = base.Pids
	}
	// Disk is an authored compatibility alias. Canonicalise it while
	// merging so `disk: 1Gi` overrides the per-kind
	// ephemeral_storage default instead of being shadowed by it.
	storage := out.Storage()
	if storage == "" {
		storage = base.Storage()
	}
	out.EphemeralStorage, out.Disk = storage, ""
	if out.FileDescriptors == 0 {
		out.FileDescriptors = base.FileDescriptors
	}
	if out.NetDevices == 0 {
		out.NetDevices = base.NetDevices
	}
	return out
}

// Empty reports whether no request dimension was authored.
func (r ResourceRequest) Empty() bool {
	return r.CPUs == 0 && r.Memory == "" && r.Pids == 0 &&
		r.EphemeralStorage == "" && r.Disk == "" &&
		r.FileDescriptors == 0 && r.NetDevices == 0
}

// Storage returns the canonical ephemeral-storage quantity, accepting Disk
// from manifests written while the field was still commonly called disk.
func (r ResourceRequest) Storage() string {
	if r.EphemeralStorage != "" {
		return r.EphemeralStorage
	}
	return r.Disk
}

// DefaultResourceRequest returns conservative host reservations for one
// device kind. Limits remain a separate authoring concern.
func DefaultResourceRequest(kind DeviceKind) ResourceRequest {
	switch kind {
	case KindRouter:
		return ResourceRequest{
			// The router shell is intentionally light. Its FRR control
			// sidecar carries the daemon reservation below; together they
			// reserve 0.12 CPU, which is the measured steady-state plus
			// convergence share used by the three-node scale target.
			CPUs: 0.04, Memory: "128Mi", Pids: 64, EphemeralStorage: "256Mi",
			FileDescriptors: 1024, NetDevices: 8,
		}
	case KindSwitch:
		return ResourceRequest{
			// ovs-vswitchd starts one handler per available CPU plus
			// revalidator threads; 64 PIDs kills it on ordinary 56-core
			// teaching workers before it can create br0.
			CPUs: 0.04, Memory: "128Mi", Pids: 512, EphemeralStorage: "128Mi",
			FileDescriptors: 1024, NetDevices: 8,
		}
	case KindService:
		return ResourceRequest{
			// BIND sizes worker/listener threads from visible CPUs. A 64-PID
			// service cgroup aborts on ordinary multi-core nodes before DNS
			// can bind, even though its memory and CPU reservation are sound.
			CPUs: 0.10, Memory: "128Mi", Pids: 512, EphemeralStorage: "256Mi",
			FileDescriptors: 1024, NetDevices: 8,
		}
	case KindP4:
		return ResourceRequest{
			CPUs: 0.50, Memory: "256Mi", Pids: 96, EphemeralStorage: "512Mi",
			FileDescriptors: 1024, NetDevices: 16,
		}
	case KindController:
		return ResourceRequest{
			CPUs: 0.25, Memory: "128Mi", Pids: 64, EphemeralStorage: "128Mi",
			FileDescriptors: 1024, NetDevices: 32,
		}
	default: // hosts and unknown legacy kinds
		return ResourceRequest{
			CPUs: 0.02, Memory: "64Mi", Pids: 32, EphemeralStorage: "64Mi",
			FileDescriptors: 256, NetDevices: 2,
		}
	}
}

// FRRControlResourceRequest is the additional reservation for the isolated
// FRR control sidecar. It is deliberately separate from the router shell so
// admission counts every OCI container the hardened router contract creates.
func FRRControlResourceRequest() ResourceRequest {
	return ResourceRequest{
		// The daemon process is queued through the convergence budget rather
		// than reserving a peak core for every idle router. Together with the
		// 0.04 router shell, this is a 0.12 CPU aggregate request. Runtime
		// limits remain independent burst caps.
		CPUs: 0.08, Memory: "256Mi", Pids: 256, EphemeralStorage: "128Mi",
		FileDescriptors: 1024, NetDevices: 0,
	}
}

// EffectiveResourceRequest fills omitted dimensions with the per-kind default.
func EffectiveResourceRequest(kind DeviceKind, authored *ResourceRequest) ResourceRequest {
	base := DefaultResourceRequest(kind)
	if authored == nil {
		return base
	}
	return authored.Merge(base)
}

// Merge returns a copy of d with any unset field taken from base.
// Maps and slices are merged rather than replaced, with d winning on conflict.
func (d DeviceDefaults) Merge(base DeviceDefaults) DeviceDefaults {
	out := d
	if out.Image == "" {
		out.Image = base.Image
	}
	if out.NOS == "" {
		out.NOS = base.NOS
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
	if out.Requests == nil {
		out.Requests = base.Requests
	} else if base.Requests != nil {
		merged := out.Requests.Merge(*base.Requests)
		out.Requests = &merged
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
	out.Hardening = out.Hardening.Merge(base.Hardening)
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

	Routers map[string]*RouterSpec `yaml:"routers,omitempty" json:"routers,omitempty"`
	// P4Devices are BMv2 switches embedded in an AS. They share
	// internal_links with routers, but their pipeline and typed control-plane
	// contract are declared separately so a P4 fault cannot be accepted for an
	// arbitrary Linux container.
	P4Devices     map[string]*P4DeviceSpec `yaml:"p4_devices,omitempty" json:"p4_devices,omitempty"`
	Hosts         HostPolicy               `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	InternalLinks []InternalLink           `yaml:"internal_links,omitempty" json:"internal_links,omitempty"`
	L2Domains     map[string]*L2Domain     `yaml:"l2_domains,omitempty" json:"l2_domains,omitempty"`
	ExternalPorts map[string]*ExtPort      `yaml:"external_ports,omitempty" json:"external_ports,omitempty"`
	Provisioning  Provisioning             `yaml:"provisioning,omitempty" json:"provisioning,omitempty"`

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
	// Segment optionally declares several point-to-point cables as one
	// shared broadcast domain. It is primarily useful for a BMv2 switch:
	// each cable remains a real veth, while the P4 program supplies the
	// forwarding plane between them.
	SharedSegment string `yaml:"segment,omitempty" json:"segment,omitempty"`
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

// P4DeviceSpec describes one BMv2 simple_switch device. ID shares the router
// ID address-space because an internal link needs deterministic endpoint
// addresses, but P4 devices do not become routing daemons or external ports.
type P4DeviceSpec struct {
	ID             int            `yaml:"id" json:"id" jsonschema:"required,description=stable endpoint ID used by the addressing plan"`
	Program        P4Program      `yaml:"program" json:"program" jsonschema:"required"`
	ControlPlane   P4ControlPlane `yaml:"control_plane" json:"control_plane" jsonschema:"required"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// P4Program identifies a source or compiled BMv2 JSON pipeline. Path is
// relative to the lab directory; Digest pins the exact program bytes so a
// controller cannot silently load a different program under the same path.
//
// A P4 source is compiled during the device's deterministic configure stage,
// after interfaces have been wired. A JSON program is loaded directly.
type P4Program struct {
	Path   string `yaml:"path" json:"path" jsonschema:"required"`
	Digest string `yaml:"digest" json:"digest" jsonschema:"required"`
	// Language defaults to p4-16. It is explicit for the old v1model
	// programs that need a different compiler flag.
	Language string `yaml:"language,omitempty" json:"language,omitempty"`
}

// P4ControlPlane is the contract Twinet can operate against rather than a
// guess at a program's private table names. The BMv2 Thrift endpoint remains
// the transport; these names are the typed program ABI used for deterministic
// loading, probes and reversible faults.
type P4ControlPlane struct {
	ThriftPort        int            `yaml:"thrift_port,omitempty" json:"thrift_port,omitempty"`
	Table             string         `yaml:"table" json:"table" jsonschema:"required"`
	ForwardAction     string         `yaml:"forward_action" json:"forward_action" jsonschema:"required"`
	ThresholdRegister string         `yaml:"threshold_register,omitempty" json:"threshold_register,omitempty"`
	RegisterValues    map[int]int    `yaml:"register_values,omitempty" json:"register_values,omitempty"`
	Entries           []P4TableEntry `yaml:"entries,omitempty" json:"entries,omitempty"`
	// ProbeSource and ProbeDestination name ordinary attached devices. They
	// make a P4 fault prove a forwarding symptom, not merely read back a CLI
	// command that was accepted.
	ProbeSource      string `yaml:"probe_source,omitempty" json:"probe_source,omitempty"`
	ProbeDestination string `yaml:"probe_destination,omitempty" json:"probe_destination,omitempty"`
}

// P4TableEntry is an initial BMv2 CLI command expressed as typed table,
// action, match and action parameters. It is rendered after the program starts
// and is also what lets a missing-entry fault remove a real forwarding entry
// rather than inventing a config-only marker.
type P4TableEntry struct {
	Match  string   `yaml:"match" json:"match" jsonschema:"required"`
	Action string   `yaml:"action,omitempty" json:"action,omitempty"`
	Params []string `yaml:"params,omitempty" json:"params,omitempty"`
}

// ControllerSpec declares an OpenFlow controller and the switches it owns.
// Switches contains expanded device IDs (for example as5/DCN_S1), which makes
// ownership unambiguous across ASes with identical short switch names.
type ControllerSpec struct {
	OpenFlow       OpenFlowSpec `yaml:"openflow" json:"openflow" jsonschema:"required"`
	DeviceDefaults `yaml:",inline" json:",inline"`
}

// OpenFlowSpec is the controller/switch protocol contract. Twinet's bundled
// controller implements OpenFlow 1.3 and exposes an operational connection
// state. A switch only receives a controller endpoint when it appears here,
// preserving non-SDN OVS labs unchanged.
type OpenFlowSpec struct {
	Version  string   `yaml:"version,omitempty" json:"version,omitempty"`
	Listen   string   `yaml:"listen,omitempty" json:"listen,omitempty"`
	Switches []string `yaml:"switches" json:"switches" jsonschema:"required"`
	FailMode string   `yaml:"fail_mode,omitempty" json:"fail_mode,omitempty"`
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

// ServiceReplicationMode determines how a service is expanded.
//
// The spelling is intentionally about the service's desired availability, not
// its container implementation. A DNS or RTR cache can consequently move from
// one replica to another without changing the course-facing identity or
// requiring a different service kind.
type ServiceReplicationMode string

const (
	// ServiceSingleton retains the original one-container service contract.
	// It is the compatibility default for manifests that predate O6.
	ServiceSingleton ServiceReplicationMode = "singleton"
	// ServicePerNode creates one replica for every declared placement node.
	ServicePerNode ServiceReplicationMode = "per-node"
	// ServiceReplicas creates the requested fixed number of replicas.
	ServiceReplicas ServiceReplicationMode = "replicas"
	// ServiceSharded creates deterministic shards of the attached ASes.
	ServiceSharded ServiceReplicationMode = "sharded"
)

// ServiceShardSelector determines how a sharded service assigns ASes before
// locality is considered. A local healthy replica always wins over this
// fallback, so a selector never turns a local service link into a cross-node
// link merely to preserve a hash bucket.
type ServiceShardSelector string

const (
	ServiceShardByAS     ServiceShardSelector = "as"
	ServiceShardByHash   ServiceShardSelector = "hash"
	ServiceShardByNode   ServiceShardSelector = "node"
	ServiceShardByRegion ServiceShardSelector = "region"
)

// ServiceReplicationPolicy is the typed availability declaration for an
// auxiliary service.
//
// Exactly one of the mode-specific dimensions is normally useful:
//
//   - singleton: no additional fields;
//   - per-node: one replica per declared placement node;
//   - replicas: replicas is the requested count;
//   - sharded: shard_size groups attached ASes, using selector.
//
// Selector is deliberately kept independent from placement. It gives a stable
// fallback when no local replica is available; it never authorises an
// automatic rebalance of an already recorded placement.
type ServiceReplicationPolicy struct {
	Mode      ServiceReplicationMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	Replicas  int                    `yaml:"replicas,omitempty" json:"replicas,omitempty"`
	ShardSize int                    `yaml:"shard_size,omitempty" json:"shard_size,omitempty"`
	Selector  ServiceShardSelector   `yaml:"selector,omitempty" json:"selector,omitempty"`
}

// Declared reports whether the manifest explicitly opted into a replication
// policy. Keeping this distinction is what lets old manifests retain their
// original graph and topology hash.
func (p ServiceReplicationPolicy) Declared() bool {
	return p.Mode != "" || p.Replicas != 0 || p.ShardSize != 0 || p.Selector != ""
}

// Effective returns a fully specified policy. The v1 compatibility default is
// singleton. A lab can deliberately opt into the versioned scalable defaults
// with service_policy_version: v2; examples that need the new behaviour
// declare the policy directly so their migration is visible in review.
func (p ServiceReplicationPolicy) Effective(kind string, attached bool, scalableDefaults bool) ServiceReplicationPolicy {
	out := p
	if out.Mode == "" {
		switch {
		case out.Replicas > 0:
			out.Mode = ServiceReplicas
		case out.ShardSize > 0 || out.Selector != "":
			out.Mode = ServiceSharded
		case scalableDefaults && attached && scalableBuiltinService(kind):
			out.Mode = ServicePerNode
		default:
			out.Mode = ServiceSingleton
		}
	}
	if out.Selector == "" {
		out.Selector = ServiceShardByAS
	}
	return out
}

// scalableBuiltinService identifies services where a local read-equivalent
// replica removes an otherwise artificial front-node cross-link. Web and
// gateway use endpoint policy rather than a data-plane attachment.
func scalableBuiltinService(kind string) bool {
	switch kind {
	case "builtin.dns", "builtin.rpki", "builtin.matrix", "builtin.measurement":
		return true
	}
	return false
}

// ServiceSpec declares an auxiliary service (DNS, matrix, RPKI, ...).
type ServiceSpec struct {
	Kind        string                   `yaml:"kind" json:"kind" jsonschema:"required"`
	Attach      *ServiceAttach           `yaml:"attach,omitempty" json:"attach,omitempty"`
	Listen      string                   `yaml:"listen,omitempty" json:"listen,omitempty"`
	Config      map[string]string        `yaml:"config,omitempty" json:"config,omitempty"`
	Node        string                   `yaml:"node,omitempty" json:"node,omitempty"`
	Replication ServiceReplicationPolicy `yaml:"replication,omitempty" json:"replication,omitempty"`
	// Endpoints applies to control-plane services such as builtin.web. Data
	// plane services use Replication for their service identities instead.
	Endpoints EndpointPolicy `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	// LoadBalancer and TrafficGenerator turn a pair of generic containers into
	// a measured data-plane substrate. They are valid only with the matching
	// builtin service kinds and are intentionally typed: a traffic profile
	// declared in a stringly Config map cannot be validated or replayed.
	LoadBalancer     *LoadBalancerSpec     `yaml:"load_balancer,omitempty" json:"load_balancer,omitempty"`
	TrafficGenerator *TrafficGeneratorSpec `yaml:"traffic_generator,omitempty" json:"traffic_generator,omitempty"`
	DeviceDefaults   `yaml:",inline" json:",inline"`
}

// LoadBalancerSpec describes the deterministic HTTP load-balancer runtime.
// MaxInflight is deliberately an enforced runtime limit, not a number used
// only by an injector, so overload is visible in the service's request and
// rejection metrics.
type LoadBalancerSpec struct {
	Listen      string   `yaml:"listen,omitempty" json:"listen,omitempty"`
	Backends    []string `yaml:"backends,omitempty" json:"backends,omitempty"`
	MaxInflight int      `yaml:"max_inflight" json:"max_inflight" jsonschema:"required"`
	MetricsPath string   `yaml:"metrics_path,omitempty" json:"metrics_path,omitempty"`
	WorkDelay   string   `yaml:"work_delay,omitempty" json:"work_delay,omitempty"`
}

// TrafficGeneratorSpec describes a deterministic source of requests used by a
// traffic incident. It can be started independently for a lab exercise and is
// also the native substrate for load_balancer_overload.
type TrafficGeneratorSpec struct {
	Profile TrafficProfile `yaml:"profile" json:"profile" jsonschema:"required"`
}

// TrafficProfile is an immutable traffic shape. A seed and bounded request
// count make a symptom reproducible across runs and prevent one incident from
// consuming the node shared by other labs.
type TrafficProfile struct {
	Name        string `yaml:"name,omitempty" json:"name,omitempty"`
	Target      string `yaml:"target" json:"target" jsonschema:"required"`
	Protocol    string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	Requests    int    `yaml:"requests" json:"requests" jsonschema:"required"`
	Concurrency int    `yaml:"concurrency" json:"concurrency" jsonschema:"required"`
	Rate        int    `yaml:"rate,omitempty" json:"rate,omitempty"`
	Timeout     string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Seed        int64  `yaml:"seed,omitempty" json:"seed,omitempty"`
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

// EndpointMode determines whether every healthy endpoint accepts traffic or
// whether only the deterministic primary does. Standby endpoints are still
// fully configured and publish health, so failover changes no group
// credentials, device placement, or agent trust material.
type EndpointMode string

const (
	EndpointActiveActive  EndpointMode = "active-active"
	EndpointActiveStandby EndpointMode = "active-standby"
)

// EndpointPolicy describes control-plane entry points such as the SSH gateway
// and web overview. VIP is optional: a deterministic multi-endpoint list is
// always available and is the portable baseline when the underlay cannot host
// a real virtual IP.
type EndpointPolicy struct {
	Mode  EndpointMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	Nodes []string     `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	VIP   string       `yaml:"vip,omitempty" json:"vip,omitempty"`
}

// Access configures student access to the lab.
type Access struct {
	Mode        string         `yaml:"mode,omitempty" json:"mode,omitempty" jsonschema:"enum=gateway,enum=none"`
	Listen      string         `yaml:"listen,omitempty" json:"listen,omitempty"`
	LegacyPorts *LegacyPorts   `yaml:"legacy_ports,omitempty" json:"legacy_ports,omitempty"`
	Node        string         `yaml:"node,omitempty" json:"node,omitempty"`
	Endpoints   EndpointPolicy `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
}

// LegacyPorts reproduces the mini-Internet's "ssh -p 2000+ASN" entry point.
type LegacyPorts struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Base    int  `yaml:"base,omitempty" json:"base,omitempty"`
}

// Placement configures how ASes are distributed across cluster nodes.
type Placement struct {
	Strategy string     `yaml:"strategy,omitempty" json:"strategy,omitempty" jsonschema:"enum=pack-by-as,enum=spread-by-as,enum=single-node"`
	Nodes    []NodeSpec `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	// Runtime is the lab-wide container runtime default. A node can override
	// it when a mixed Docker/Podman cluster is deliberate. Empty retains the
	// historic Docker default.
	Runtime string `yaml:"runtime,omitempty" json:"runtime,omitempty" jsonschema:"enum=docker,enum=podman,enum=containerd"`
	// NodePool restricts this lab to nodes carrying the named hardened worker
	// pool. It is a placement constraint, not a label that merely appears in a
	// report after an unsafe assignment was already made.
	NodePool string            `yaml:"node_pool,omitempty" json:"node_pool,omitempty"`
	Pin      []PlacementPin    `yaml:"pin,omitempty" json:"pin,omitempty"`
	Reserve  map[string]Budget `yaml:"reserve,omitempty" json:"reserve,omitempty"`
	// Convergence bounds simultaneous router control-plane starts on one
	// node. It is intentionally separate from steady-state requests: a
	// deployment queues a short burst instead of reserving every router's
	// peak CPU permanently.
	Convergence ConvergenceBudget `yaml:"convergence,omitempty" json:"convergence,omitempty"`
	// OnNodeLoss decides whether a clustered deployment may move work away
	// from an unavailable node. Rescheduling still requires verified durable
	// replicas; it is never permission to rebuild from an empty image.
	OnNodeLoss string `yaml:"on_node_loss,omitempty" json:"on_node_loss,omitempty" jsonschema:"enum=fail,enum=reschedule"`
}

// ConvergenceBudget controls the optional per-lab portion of the node-wide
// convergence queue. Zero uses the agent's shared conservative default.
type ConvergenceBudget struct {
	MaxConcurrent int `yaml:"max_concurrent,omitempty" json:"max_concurrent,omitempty"`
}

// NodeSpec declares one cluster node.
type NodeSpec struct {
	Name string `yaml:"name" json:"name" jsonschema:"required"`
	// Pool selects a dedicated worker pool (for example sandboxed student
	// evaluation workers). An empty pool is the ordinary cluster pool.
	Pool string `yaml:"pool,omitempty" json:"pool,omitempty"`
	// Addr is the agent's gRPC address. Defaults to name:7200.
	Addr string `yaml:"addr,omitempty" json:"addr,omitempty"`
	// UnderlayIP is the VTEP source address for cross-node VXLAN links.
	UnderlayIP string `yaml:"underlay_ip,omitempty" json:"underlay_ip,omitempty"`
	// UnderlayDev pins VXLAN source selection to this host interface.
	UnderlayDev string `yaml:"underlay_dev,omitempty" json:"underlay_dev,omitempty"`
	// Runtime overrides placement.runtime for this node. It is intentionally a
	// backend name, not a free-form command, so validation can compare it with
	// the runtime registry before a deployment acquires a mutation lease.
	Runtime string `yaml:"runtime,omitempty" json:"runtime,omitempty" jsonschema:"enum=docker,enum=podman,enum=containerd"`
	// RuntimeSocket is an optional Unix socket or TCP endpoint for the selected
	// engine. It is a node-local transport address, never a container mount.
	RuntimeSocket string `yaml:"runtime_socket,omitempty" json:"runtime_socket,omitempty"`
	// Capacity optionally caps what may be scheduled here.
	Capacity *Budget `yaml:"capacity,omitempty" json:"capacity,omitempty"`
	// PlacementWeight is relative lifecycle throughput used only to balance
	// new placement. Capacity remains the hard admission boundary. A value of
	// 0 keeps the default weight of 1.
	PlacementWeight float64 `yaml:"placement_weight,omitempty" json:"placement_weight,omitempty" jsonschema:"minimum=0"`
	// Front marks the node that publishes the web UI, gateway and VPN.
	Front bool `yaml:"front,omitempty" json:"front,omitempty"`
	// FailureDomain names the independently failing unit containing this
	// node, such as a rack, availability zone, or host. An omitted value is
	// the node itself, which is conservative for ordinary teaching clusters.
	FailureDomain string `yaml:"failure_domain,omitempty" json:"failure_domain,omitempty"`
	// RuntimeClass and UsernsMode are node-approved defaults used when a
	// device has not selected a more specific hardened runtime profile.
	RuntimeClass string `yaml:"runtime_class,omitempty" json:"runtime_class,omitempty"`
	UsernsMode   string `yaml:"userns_mode,omitempty" json:"userns_mode,omitempty"`
}

// DefaultRuntime is the compatibility selection for manifests written before
// runtime selection was exposed.
const DefaultRuntime = "docker"

// RuntimeForNode returns the requested backend for one placement node. A
// node-specific selection wins over the lab default; an omitted selection keeps
// Docker as it was before the runtime registry existed.
func (l *Lab) RuntimeForNode(name string) string {
	if l != nil {
		if node, ok := l.NodeByName(name); ok && strings.TrimSpace(node.Runtime) != "" {
			return strings.ToLower(strings.TrimSpace(node.Runtime))
		}
		if strings.TrimSpace(l.Placement.Runtime) != "" {
			return strings.ToLower(strings.TrimSpace(l.Placement.Runtime))
		}
	}
	return DefaultRuntime
}

// RuntimeSocketForNode returns the explicit endpoint configured for a node.
// Empty leaves the selected backend's normal secure local socket in use.
func (l *Lab) RuntimeSocketForNode(name string) string {
	if l != nil {
		if node, ok := l.NodeByName(name); ok {
			return strings.TrimSpace(node.RuntimeSocket)
		}
	}
	return ""
}

// ImageMode describes the reproducibility policy that governs image
// references. The aliases accepted by validation keep course configuration
// readable while the canonical values remain stable in reports and locks.
type ImageMode string

const (
	ImageModeDevelopment ImageMode = "development"
	ImageModeRelease     ImageMode = "release"
	ImageModeGrading     ImageMode = "grading"
)

// ImagePolicy binds a manifest to a generated image lock. LockDigest is set
// only after the lock has been checked and is carried to deployment reports;
// it is never authored YAML.
type ImagePolicy struct {
	Mode       ImageMode `yaml:"mode,omitempty" json:"mode,omitempty" jsonschema:"enum=development,enum=release,enum=grading,enum=grade"`
	Lock       string    `yaml:"lock,omitempty" json:"lock,omitempty"`
	LockDigest string    `yaml:"-" json:"lock_digest,omitempty"`
}

// EffectiveMode returns the policy's canonical mode. Empty intentionally stays
// empty so validation can require an explicit development opt-in for mutable
// image tags rather than silently treating every legacy manifest as one.
func (p ImagePolicy) EffectiveMode() ImageMode {
	switch strings.ToLower(strings.TrimSpace(string(p.Mode))) {
	case "grade":
		return ImageModeGrading
	case string(ImageModeDevelopment):
		return ImageModeDevelopment
	case string(ImageModeRelease):
		return ImageModeRelease
	case string(ImageModeGrading):
		return ImageModeGrading
	default:
		return ImageMode(strings.ToLower(strings.TrimSpace(string(p.Mode))))
	}
}

// RequiresImmutableImages reports whether a deployment must use a verified
// digest lock.
func (p ImagePolicy) RequiresImmutableImages() bool {
	switch p.EffectiveMode() {
	case ImageModeRelease, ImageModeGrading:
		return true
	}
	return false
}

// Domain returns the failure domain used for durable-copy placement.
func (n NodeSpec) Domain() string {
	if n.FailureDomain != "" {
		return n.FailureDomain
	}
	return n.Name
}

// StatePolicy is the manifest contract for durable student state.
//
// FailClosed is a pointer so omitted means the safe default (true), while an
// operator who deliberately accepts possible data loss can still state that
// exceptional choice explicitly and receive an audit warning.
type StatePolicy struct {
	// ReplicationFactor counts the source copy. Clustered labs default to two
	// copies in distinct failure domains; a local lab defaults to one.
	ReplicationFactor int `yaml:"replication_factor,omitempty" json:"replication_factor,omitempty"`
	// CaptureInterval is a Go duration such as 5m. Agents capture on this
	// cadence even when no controller or CLI process remains alive.
	CaptureInterval string `yaml:"capture_interval,omitempty" json:"capture_interval,omitempty"`
	// FailClosed refuses a destructive operation when a fresh capture or its
	// replica quorum cannot be confirmed.
	FailClosed *bool `yaml:"fail_closed,omitempty" json:"fail_closed,omitempty"`
	// ReplicaRetention bounds how long non-current durable history remains
	// available after a verified replication quorum makes it unnecessary.
	ReplicaRetention string `yaml:"replica_retention,omitempty" json:"replica_retention,omitempty"`
}

// FailClosedEnabled returns the safe effective policy value.
func (p StatePolicy) FailClosedEnabled() bool {
	return p.FailClosed == nil || *p.FailClosed
}

// Budget is a resource allowance.
type Budget struct {
	CPUs             float64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory           string  `yaml:"memory,omitempty" json:"memory,omitempty"`
	Pids             int64   `yaml:"pids,omitempty" json:"pids,omitempty"`
	EphemeralStorage string  `yaml:"ephemeral_storage,omitempty" json:"ephemeral_storage,omitempty"`
	// Disk is a compatibility alias for ephemeral_storage.
	Disk            string `yaml:"disk,omitempty" json:"disk,omitempty"`
	FileDescriptors int64  `yaml:"file_descriptors,omitempty" json:"file_descriptors,omitempty"`
	NetDevices      int64  `yaml:"netdevs,omitempty" json:"netdevs,omitempty"`
	Containers      int    `yaml:"containers,omitempty" json:"containers,omitempty"`
}

// Storage returns the canonical disk budget, accepting the legacy disk alias.
func (b Budget) Storage() string {
	if b.EphemeralStorage != "" {
		return b.EphemeralStorage
	}
	return b.Disk
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
	clustered := l.Placement.Strategy != "single-node" && len(l.Placement.Nodes) > 1
	if l.State.ReplicationFactor == 0 {
		if clustered {
			l.State.ReplicationFactor = 2
		} else {
			l.State.ReplicationFactor = 1
		}
	}
	if l.State.CaptureInterval == "" {
		l.State.CaptureInterval = "5m"
	}
	if l.State.FailClosed == nil {
		enabled := true
		l.State.FailClosed = &enabled
	}
	if l.State.ReplicaRetention == "" {
		l.State.ReplicaRetention = "168h"
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
