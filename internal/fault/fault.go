// Package fault injects, verifies and resolves network faults.
//
// Twinet uses this for two things at once. In a course it is the scripted
// misconfiguration an exercise is built around, such as the BGP hijack that
// motivates RPKI. In an evaluation it is the incident an AI agent is asked to
// diagnose, following the taxonomy of the NIKA benchmark.
//
// Two rules shape the whole design.
//
// Every fault must be reversible. An episode is inject, observe, resolve, then
// verify the baseline is genuinely back; without that, episode n+1 inherits
// episode n's damage and no measurement is reproducible. So a fault is never
// applied by rewriting configuration wholesale. It records the state it
// replaced and restores exactly that.
//
// Ground truth must never be observable from inside the lab. A fault named in a
// container label, a file or an environment variable that an agent can read
// makes the task trivial. Ground truth lives only in the control plane.
package fault

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Category is NIKA's root-cause taxonomy, reproduced so ground truth
// serialises into the shape its scoring already expects.
type Category string

const (
	CatEndHost    Category = "end_host_failure"
	CatLink       Category = "link_failure"
	CatMisconfig  Category = "misconfiguration"
	CatNodeError  Category = "network_node_error"
	CatAttack     Category = "network_under_attack"
	CatContention Category = "resource_contention"
	CatMultiple   Category = "multiple_faults"
)

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	switch c {
	case CatEndHost, CatLink, CatMisconfig, CatNodeError, CatAttack, CatContention, CatMultiple:
		return true
	}
	return false
}

// Capability names something a fault needs from the runtime, so a fault can be
// refused up front rather than injected half-way.
type Capability string

const (
	CapExec      Capability = "exec"
	CapInterface Capability = "interface"
	CapIP        Capability = "ip"
	CapRoute     Capability = "route"
	CapTC        Capability = "tc"
	CapNFT       Capability = "nft"
	CapProcess   Capability = "process"
	CapFile      Capability = "file"
	CapFRR       Capability = "frr"
	// CapLifecycle is the ability to change a container's run state, which is
	// held by the platform rather than by anything inside the container.
	CapLifecycle Capability = "lifecycle"
	CapOVS       Capability = "ovs"
	CapService   Capability = "service"
	CapDNS       Capability = "dns"
	CapTraffic   Capability = "traffic"
	CapLink      Capability = "link"
)

// Target selects what a fault is applied to.
type Target struct {
	AS     int               `yaml:"as,omitempty" json:"as,omitempty"`
	Device string            `yaml:"device,omitempty" json:"device,omitempty"`
	Iface  string            `yaml:"iface,omitempty" json:"iface,omitempty"`
	Peer   int               `yaml:"peer,omitempty" json:"peer,omitempty"`
	Prefix string            `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Params map[string]string `yaml:"params,omitempty" json:"params,omitempty"`
}

// DeviceID returns the target's device identity.
func (t Target) DeviceID() string {
	if t.Device == "" {
		return ""
	}
	if strings.Contains(t.Device, "/") {
		return t.Device
	}
	return model.DeviceID(t.AS, t.Device)
}

// Param reads a fault-specific argument.
func (t Target) Param(key, def string) string {
	if v, ok := t.Params[key]; ok && v != "" {
		return v
	}
	return def
}

// GroundTruth is the machine-readable answer, in NIKA's shape.
//
// It is returned to the control plane and written to the episode record. It is
// never placed inside the lab.
type GroundTruth struct {
	IsAnomaly     bool     `json:"is_anomaly"`
	FaultyDevices []string `json:"faulty_devices"`
	Category      string   `json:"root_cause_category"`
	Names         []string `json:"root_cause_name"`
	DetailedCause string   `json:"detailed_cause"`
}

// Evidence records what verification observed.
type Evidence struct {
	Verified bool   `json:"verified"`
	Detail   string `json:"detail,omitempty"`
	Observed string `json:"observed,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// Env is what a fault is given to work with.
type Env struct {
	Topology *model.Topology
	// Exec runs a command inside a device.
	Exec func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error)
	// Lifecycle changes a device container's run state: pause, unpause, stop,
	// start or restart. A crashed machine is a paused container, not one with
	// its interfaces taken down, because a paused container still holds its
	// addresses and simply never answers -- which is what makes the fault hard
	// to diagnose and therefore worth injecting.
	Lifecycle func(ctx context.Context, deviceID, action string) error
	// Reshape puts an interface back to the shaping the topology declares,
	// through the platform's own code rather than through tc's command line,
	// so that undoing a traffic-control fault cannot leave a link subtly
	// different from the one the lab describes.
	Reshape func(ctx context.Context, deviceID, iface string) error
	// NodeState reports a device container's run state: running, paused,
	// exited. A fault that freezes a machine can only be verified by asking
	// the platform, because the frozen machine cannot answer for itself and
	// its silence is equally consistent with an unreachable node.
	NodeState func(ctx context.Context, deviceID string) (string, error)
	// Seed makes a time-varying fault replay exactly rather than differing run
	// to run.
	Seed int64
}

// Device resolves a target to a device in the topology.
func (e *Env) Device(t Target) (*model.Device, error) {
	id := t.DeviceID()
	if id == "" {
		return nil, fmt.Errorf("the fault names no device")
	}
	d, ok := e.Topology.Device(id)
	if !ok {
		return nil, fmt.Errorf("no device %q in this lab", id)
	}
	return d, nil
}

// Run executes a command on a device and requires it to succeed.
func (e *Env) Run(ctx context.Context, deviceID string, args ...string) (string, error) {
	res, err := e.Exec(ctx, deviceID, args)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return res.Stdout, fmt.Errorf("%s: exit %d: %s",
			strings.Join(args, " "), res.ExitCode, firstLine(res.Stderr))
	}
	return res.Stdout, nil
}

// Sh runs a shell command on a device.
func (e *Env) Sh(ctx context.Context, deviceID, script string) (string, error) {
	return e.Run(ctx, deviceID, "sh", "-c", script)
}

// Try runs a shell command and tolerates a non-zero exit, for probes.
//
// A non-zero exit is a legitimate answer from the device. A transport failure
// is not an answer at all, and the two must not look alike: a verifier that
// reads an unreachable node as "the fault is not there" reports a successful
// undo on a lab that is still broken, and the contamination is invisible.
// Callers that need to tell them apart use TryE.
func (e *Env) Try(ctx context.Context, deviceID, script string) (string, int) {
	out, code, _ := e.TryE(ctx, deviceID, script)
	return out, code
}

// TryE is Try, but it reports whether the device could be reached at all.
func (e *Env) TryE(ctx context.Context, deviceID, script string) (string, int, error) {
	res, err := e.Exec(ctx, deviceID, []string{"sh", "-c", script})
	if err != nil {
		return "", -1, fmt.Errorf("%s could not be reached: %w", deviceID, err)
	}
	return res.Stdout, res.ExitCode, nil
}

// Vtysh runs an FRR command.
func (e *Env) Vtysh(ctx context.Context, deviceID, command string) (string, error) {
	return e.Run(ctx, deviceID, "vtysh", "-c", command)
}

// VtyshConfig applies FRR configuration lines.
func (e *Env) VtyshConfig(ctx context.Context, deviceID string, lines ...string) error {
	args := []string{"vtysh"}
	for _, l := range lines {
		args = append(args, "-c", l)
	}
	_, err := e.Run(ctx, deviceID, args...)
	return err
}

// State is what a fault saved so it can undo itself.
//
// Reversibility is a contract, not a convention: Inject returns the state it
// replaced and Resolve is given it back. A fault that cannot express its undo
// this way does not belong in the registry.
type State map[string]string

// Fault is one injectable failure mode.
type Fault struct {
	// Name is the registry key, matching NIKA's problem identifier where one
	// exists so the taxonomies line up.
	Name string
	// Category places it in NIKA's taxonomy.
	Category Category
	// Symptom is what an operator would report. It is what an agent is told,
	// and it must not give the cause away.
	Symptom string
	// Describe explains the mechanism, for ground truth and for staff.
	Describe string
	// Needs lists the capabilities required to inject it.
	Needs []Capability
	// Inject applies the fault and returns the state it replaced.
	Inject func(ctx context.Context, env *Env, t Target) (State, error)
	// Verify confirms the fault is actually active.
	//
	// It is given the state Inject recorded, because a predicate that only
	// looks at the target is almost always too loose: "a default route exists"
	// is true both while the gateway is wrong and after it has been put back.
	// Several faults were silently unresolvable until this argument existed.
	Verify func(ctx context.Context, env *Env, t Target, s State) (Evidence, error)
	// Resolve undoes the fault using the state Inject returned.
	Resolve func(ctx context.Context, env *Env, t Target, s State) error
}

// Truth builds the ground truth for an application of this fault.
func (f *Fault) Truth(t Target, detail string) GroundTruth {
	dev := t.DeviceID()
	var devices []string
	if dev != "" {
		devices = []string{dev}
	}
	if detail == "" {
		detail = f.Describe
	}
	return GroundTruth{
		IsAnomaly: true, FaultyDevices: devices,
		Category: string(f.Category), Names: []string{f.Name},
		DetailedCause: detail,
	}
}

// registry holds every known fault.
var registry = map[string]*Fault{}

// Register adds a fault. A duplicate name is a programming error.
func Register(f *Fault) {
	if f.Name == "" {
		panic("fault: registered with no name")
	}
	if !f.Category.Valid() {
		panic("fault: " + f.Name + " has an unknown category " + string(f.Category))
	}
	if f.Inject == nil || f.Verify == nil || f.Resolve == nil {
		// Enforced here rather than discovered mid-episode: a fault that cannot
		// be verified might never have taken effect, and one that cannot be
		// resolved contaminates every episode after it.
		panic("fault: " + f.Name + " must implement Inject, Verify and Resolve")
	}
	if _, dup := registry[f.Name]; dup {
		panic("fault: duplicate registration " + f.Name)
	}
	registry[f.Name] = f
}

// Lookup finds a fault by name.
func Lookup(name string) (*Fault, bool) { f, ok := registry[name]; return f, ok }

// All returns every registered fault, sorted by name.
func All() []*Fault {
	out := make([]*Fault, 0, len(registry))
	for _, f := range registry {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByCategory groups the registry.
func ByCategory() map[Category][]*Fault {
	out := map[Category][]*Fault{}
	for _, f := range All() {
		out[f.Category] = append(out[f.Category], f)
	}
	return out
}

// Injection is a fault applied to a target, with what it needs to undo itself.
type Injection struct {
	Fault      string      `json:"fault"`
	Target     Target      `json:"target"`
	State      State       `json:"state,omitempty"`
	InjectedAt time.Time   `json:"injected_at"`
	Truth      GroundTruth `json:"ground_truth"`
	Evidence   Evidence    `json:"evidence"`
}

// Inject applies a fault and verifies it actually manifested.
//
// Verification is not optional. An incident that failed to inject but is
// presented to an agent as a puzzle produces a meaningless measurement, and in
// that case the agent is right and the benchmark is wrong.
func Inject(ctx context.Context, env *Env, name string, t Target) (*Injection, error) {
	f, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("no fault named %q; try `twinet fault list`", name)
	}
	if t.Device != "" {
		if _, err := env.Device(t); err != nil {
			return nil, err
		}
	}

	state, err := f.Inject(ctx, env, t)
	if err != nil {
		return nil, fmt.Errorf("inject %s: %w", name, err)
	}
	inj := &Injection{
		Fault: name, Target: t, State: state,
		InjectedAt: time.Now().UTC(),
		Truth:      f.Truth(t, ""),
	}

	ev, err := f.Verify(ctx, env, t, state)
	if err != nil {
		if rerr := f.Resolve(ctx, env, t, state); rerr != nil {
			return inj, fmt.Errorf("inject %s: verification failed (%w) and rollback also failed (%v)",
				name, err, rerr)
		}
		return nil, fmt.Errorf("inject %s: could not verify it took effect, so it was rolled back: %w", name, err)
	}
	inj.Evidence = ev
	if !ev.Verified {
		if rerr := f.Resolve(ctx, env, t, state); rerr != nil {
			return inj, fmt.Errorf("inject %s: did not take effect (%s) and rollback failed (%v)",
				name, ev.Detail, rerr)
		}
		return nil, fmt.Errorf("inject %s: it did not take effect, so it was rolled back: %s", name, ev.Detail)
	}
	return inj, nil
}

// Resolve undoes an injection and confirms it is genuinely gone.
func Resolve(ctx context.Context, env *Env, inj *Injection) error {
	f, ok := Lookup(inj.Fault)
	if !ok {
		return fmt.Errorf("no fault named %q", inj.Fault)
	}
	if err := f.Resolve(ctx, env, inj.Target, inj.State); err != nil {
		return fmt.Errorf("resolve %s: %w", inj.Fault, err)
	}
	// A resolve that silently half-worked is the most damaging failure here,
	// because the contamination it leaves behind is invisible: the next episode
	// runs on a lab that is still broken, and its result is attributed to
	// whatever that episode injected.
	//
	// This fails closed. A verification that cannot run is not evidence that
	// the fault is gone; it is the absence of evidence either way, and treating
	// it as success is how contamination becomes silent.
	// The device is probed directly first. Every verifier reads the device, so
	// if it cannot be reached, whatever the verifier concludes is an artefact
	// of the failure rather than an observation of the lab.
	if err := env.reachable(ctx, inj.Target.DeviceID()); err != nil {
		return fmt.Errorf("resolve %s: the undo ran, but %w, so the lab must be "+
			"treated as contaminated", inj.Fault, err)
	}
	ev, err := f.Verify(ctx, env, inj.Target, inj.State)
	if err != nil {
		return fmt.Errorf("resolve %s: the undo ran, but it could not be confirmed, "+
			"so the lab must be treated as contaminated: %w", inj.Fault, err)
	}
	if ev.Verified {
		return fmt.Errorf("resolve %s: the fault is still present afterwards: %s",
			inj.Fault, ev.Detail)
	}
	return nil
}

// State reports a device container's run state.
func (e *Env) State(ctx context.Context, deviceID string) (string, error) {
	if e.NodeState == nil {
		return "", fmt.Errorf("this environment cannot inspect container state")
	}
	return e.NodeState(ctx, deviceID)
}

// reachable reports whether a device can be asked anything at all.
//
// A paused container is deliberately excluded from this: host_crash freezes the
// device, and its own verifier is the one that must interpret the silence.
func (e *Env) reachable(ctx context.Context, deviceID string) error {
	if _, _, err := e.TryE(ctx, deviceID, "true"); err != nil {
		return err
	}
	return nil
}

// Do changes a device's run state, refusing clearly when the environment
// cannot. A fault that silently does nothing is worse than one that fails.
func (e *Env) Do(ctx context.Context, deviceID, action string) error {
	if e.Lifecycle == nil {
		return fmt.Errorf("this environment cannot %s a container", action)
	}
	return e.Lifecycle(ctx, deviceID, action)
}

// Reshaped asks the platform to restore an interface's declared shaping.
func (e *Env) Reshaped(ctx context.Context, deviceID, iface string) error {
	if e.Reshape == nil {
		return fmt.Errorf("this environment cannot restore the shaping of %s", iface)
	}
	return e.Reshape(ctx, deviceID, iface)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}
