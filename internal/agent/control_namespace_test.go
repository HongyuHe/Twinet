package agent

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// splitNamespaceRuntime models the fault this file exists for: a router whose
// task is replaced and a control sidecar that keeps running, perfectly healthy,
// in the namespace the router used to be in.
type splitNamespaceRuntime struct {
	rt.Runtime
	primary     string
	control     string
	identity    map[string]rt.NetnsIdentity
	identityErr map[string]error
	// unsupported models a backend with no namespace-identity capability.
	unsupported bool
	// links is the interface listing each container's namespace would show.
	links        map[string]string
	specLabels   map[string]string
	controlCount int
	primaryCount int
	calls        []string
	removed      []string
	created      []string
	started      []string
	absent       map[string]bool
}

func (r *splitNamespaceRuntime) Name() string { return "containerd" }

func (r *splitNamespaceRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	if r.absent[name] {
		return rt.Container{Name: name, State: rt.StateAbsent}, nil
	}
	labels := map[string]string{}
	if name == r.control {
		labels[deploy.LabelFRRControl] = "true"
		labels[deploy.LabelInternal] = "true"
	}
	if spec := r.specLabels[name]; spec != "" {
		labels[deploy.LabelSpec] = spec
		labels[deploy.LabelRuntimeContract] = deploy.RuntimeSpecContractVersion
	}
	return rt.Container{Name: name, State: rt.StateRunning, PID: 4000, Labels: labels}, nil
}

func (r *splitNamespaceRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.removed = append(r.removed, name)
	r.absent[name] = true
	return nil
}

func (r *splitNamespaceRuntime) Create(_ context.Context, spec *rt.Spec) (string, error) {
	r.created = append(r.created, spec.Name)
	// A sidecar is created against whichever task owns the namespace now, so
	// a rebuild lands wherever the router currently is.
	if strings.HasPrefix(spec.NetworkMode, "container:") {
		donor := strings.TrimPrefix(spec.NetworkMode, "container:")
		r.identity[spec.Name] = r.identity[donor]
		r.links[spec.Name] = r.links[donor]
	}
	r.controlCount = 0
	delete(r.absent, spec.Name)
	return spec.Name, nil
}

// rebuildControl is what a runtime does to a sidecar whose namespace donor has
// been replaced: the old container is removed and a new one is created against
// the donor's current task.
func (r *splitNamespaceRuntime) rebuildControl() {
	_ = r.Remove(context.Background(), r.control, true)
	_, _ = r.Create(context.Background(), &rt.Spec{
		Name: r.control, NetworkMode: "container:" + r.primary,
	})
	_ = r.Start(context.Background(), r.control)
}

func (r *splitNamespaceRuntime) Start(_ context.Context, name string) error {
	r.started = append(r.started, name)
	return nil
}

func (r *splitNamespaceRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
	if r.unsupported {
		return rt.NetnsIdentity{}, fmt.Errorf("%w: containerd", rt.ErrNamespaceIdentityUnsupported)
	}
	if err := r.identityErr[name]; err != nil {
		return rt.NetnsIdentity{}, fmt.Errorf("%w: %s: %w", rt.ErrNamespaceIdentityUnknown, name, err)
	}
	identity, ok := r.identity[name]
	if !ok {
		return rt.NetnsIdentity{}, fmt.Errorf("%w: %s is unknown to this backend",
			rt.ErrNamespaceIdentityUnknown, name)
	}
	return identity, nil
}

func (r *splitNamespaceRuntime) ObservedNetnsIdentity(ctx context.Context,
	container rt.Container,
) (rt.NetnsIdentity, error) {
	return r.NetnsIdentity(ctx, container.Name)
}

func (r *splitNamespaceRuntime) Exec(_ context.Context, container string,
	command rt.ExecCmd,
) (rt.ExecResult, error) {
	body := strings.Join(command.Cmd, " ")
	r.calls = append(r.calls, container+"|"+body)
	switch {
	case strings.Contains(body, "ip -o link show"):
		return rt.ExecResult{Stdout: r.links[container]}, nil
	case container == r.primary && strings.Contains(body, "find_frr"):
		r.primaryCount = 0
		return rt.ExecResult{}, nil
	case container == r.primary && strings.Contains(body, "ps -eo args"):
		return rt.ExecResult{Stdout: strconv.Itoa(r.primaryCount) + "\n"}, nil
	case container == r.control && strings.Contains(body, "__TWINET_DAEMON__"):
		var out strings.Builder
		for _, daemon := range render.EnabledDaemons() {
			fmt.Fprintf(&out, "__TWINET_DAEMON__%s\t%d\n", daemon, r.controlCount)
		}
		return rt.ExecResult{Stdout: out.String()}, nil
	case container == r.control && strings.Contains(body, "find_frr"):
		r.controlCount = 0
		return rt.ExecResult{}, nil
	case container == r.control && strings.Contains(body, "frrinit.sh start"):
		r.controlCount = 1
		return rt.ExecResult{}, nil
	case container == r.control && len(command.Cmd) >= 3 && command.Cmd[0] == "vtysh":
		if r.controlCount == 0 {
			return rt.ExecResult{ExitCode: 1, Stderr: "no vty socket"}, nil
		}
		return rt.ExecResult{}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *splitNamespaceRuntime) ran(fragment string) bool {
	for _, call := range r.calls {
		if strings.Contains(call, fragment) {
			return true
		}
	}
	return false
}

const (
	routerNetns  = 4026552127
	orphanNetns  = 4026535379
	restartNetns = 4026552999
)

func splitNamespaceLab() (*model.Topology, *model.Device, *splitNamespaceRuntime) {
	device := &model.Device{
		ID: "as3/PHY", Name: "PHY", Node: "node-0", Kind: model.KindRouter,
		Container: "twinet-cos461-as3-phy", ASN: 3,
	}
	device.Ifaces = []*model.Iface{
		{Name: "port_ATL", Link: &model.Link{}},
		{Name: "port_NYC", Link: &model.Link{}},
	}
	top := &model.Topology{
		Name: "cos461", Devices: map[string]*model.Device{device.ID: device},
		ASes: map[int]*model.AS{3: {ASN: 3, Devices: []*model.Device{device}}},
	}
	control := deploy.FRRControlContainer(device)
	runtime := &splitNamespaceRuntime{
		primary: device.Container, control: control, controlCount: 1,
		identity: map[string]rt.NetnsIdentity{
			device.Container: {Dev: 4, Inode: routerNetns},
			control:          {Dev: 4, Inode: routerNetns},
		},
		identityErr: map[string]error{},
		links: map[string]string{
			device.Container: "lo port_ATL port_NYC host\n",
			control:          "lo port_ATL port_NYC host\n",
		},
		specLabels: map[string]string{},
		absent:     map[string]bool{},
	}
	return top, device, runtime
}

func splitNamespaceServer(t *testing.T, top *model.Topology, runtime *splitNamespaceRuntime) *Server {
	t.Helper()
	server := &Server{
		cfg: Config{Node: "node-0"}, rt: runtime,
		current: map[string]*model.Topology{top.Name: top},
	}
	// The agent compares a container against the exact OCI request its
	// topology derives, so the fake has to carry that label like a real one.
	for _, device := range top.SortedDevices() {
		hash, err := server.finalSpecHash(top.Name, device)
		if err != nil {
			t.Fatalf("deriving the desired runtime specification: %v", err)
		}
		runtime.specLabels[device.Container] = hash
	}
	return server
}

// orphanSidecar reproduces the reported fault exactly: the router's task is
// replaced, so the router is in a new namespace, and its sidecar is still in
// the old one holding a loopback and no cables.
func orphanSidecar(device *model.Device, runtime *splitNamespaceRuntime) {
	runtime.identity[device.Container] = rt.NetnsIdentity{Dev: 4, Inode: restartNetns}
	runtime.identity[runtime.control] = rt.NetnsIdentity{Dev: 4, Inode: orphanNetns}
	runtime.links[runtime.control] = "lo sit0 gre0 gretap0 erspan0 tunl0\n"
}

func TestBoundSidecarIsProvenAgainstItsRouter(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	proof := server.proveControlNamespace(context.Background(), device)
	if !proof.OK() || !proof.Supported || !proof.Proven || !proof.Match || !proof.Interfaces {
		t.Fatalf("a correctly bound sidecar was not proven: %+v", proof)
	}
	audit := server.auditControls(context.Background(), top.Name)
	if len(audit) != 1 || !audit[0].Healthy || !audit[0].VTY {
		t.Fatalf("a correctly bound sidecar audited as %+v", audit)
	}
	if audit[0].Namespace == nil || !audit[0].Namespace.Match ||
		audit[0].Namespace.Primary != audit[0].Namespace.Control {
		t.Fatalf("the audit did not report the proven namespaces: %+v", audit[0].Namespace)
	}
}

// The whole defect in one test: the router's pid and namespace change, the
// sidecar keeps running with its full daemon set, and everything that reported
// "ok" must now report the split.
func TestRestartedRouterOrphansItsSidecarAndTheAuditSaysSo(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)

	proof := server.proveControlNamespace(context.Background(), device)
	if proof.OK() || proof.Match {
		t.Fatalf("an orphaned sidecar was proven bound: %+v", proof)
	}
	if !strings.HasPrefix(proof.Reason, controlNamespaceSplit) {
		t.Fatalf("the split was not named as such: %s", proof.Reason)
	}
	if !strings.Contains(proof.Reason, "net:[4026535379]") ||
		!strings.Contains(proof.Reason, "net:[4026552999]") {
		t.Fatalf("the diagnostic did not name both namespaces: %s", proof.Reason)
	}

	audit := server.auditControls(context.Background(), top.Name)
	if len(audit) != 1 {
		t.Fatalf("control audit = %+v", audit)
	}
	if audit[0].Healthy {
		t.Fatalf("an orphaned control sidecar audited as healthy: %+v", audit[0])
	}
	// Not "running bgpd=1,ospfd=1,zebra=1 vty=true ok". The daemon set of a
	// sidecar in the wrong namespace is not evidence of anything.
	if len(audit[0].Daemons) != 0 || audit[0].VTY {
		t.Fatalf("the audit still certified daemon/vty health of an orphan: %+v", audit[0])
	}
	if audit[0].Namespace == nil || audit[0].Namespace.Match || !audit[0].Namespace.Proven {
		t.Fatalf("the audit did not report the namespace split: %+v", audit[0].Namespace)
	}

	observation := server.observeDevice(context.Background(), top.Name, device, false)
	if observation.Health != healthBroken ||
		!strings.HasPrefix(observation.Reason, controlNamespaceSplit) {
		t.Fatalf("reconcile did not observe the orphaned sidecar as broken: %+v", observation)
	}
	if class := deviceChangeClass(observation); class != ChangeControl {
		t.Fatalf("the repair class for an orphaned sidecar was %q", class)
	}
}

// A backend that cannot prove inode identity still catches the split, because
// a sidecar in the wrong namespace cannot see the router's cables.
func TestSidecarSplitIsCaughtWithoutTheIdentityCapability(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	runtime.unsupported = true
	server := splitNamespaceServer(t, top, runtime)

	proof := server.proveControlNamespace(context.Background(), device)
	if !proof.OK() || proof.Supported || !proof.Interfaces {
		t.Fatalf("a bound sidecar on a capability-less backend was rejected: %+v", proof)
	}

	orphanSidecar(device, runtime)
	proof = server.proveControlNamespace(context.Background(), device)
	if proof.OK() || proof.Supported {
		t.Fatalf("an orphaned sidecar on a capability-less backend was accepted: %+v", proof)
	}
	if !strings.HasPrefix(proof.Reason, controlNamespaceSplit) ||
		!strings.Contains(proof.Reason, "port_ATL") {
		t.Fatalf("the interface proof did not name the missing cables: %s", proof.Reason)
	}
}

// An identity that cannot be read is never evidence of agreement.
func TestUnreadableNamespaceIsUnknownAndNeverHealthy(t *testing.T) {
	for _, container := range []string{"primary", "control"} {
		t.Run(container, func(t *testing.T) {
			top, device, runtime := splitNamespaceLab()
			target := device.Container
			if container == "control" {
				target = runtime.control
			}
			runtime.identityErr[target] = errors.New("permission denied")
			server := splitNamespaceServer(t, top, runtime)

			proof := server.proveControlNamespace(context.Background(), device)
			if proof.OK() || proof.Proven || proof.Match {
				t.Fatalf("an unreadable namespace was treated as proof: %+v", proof)
			}
			if !strings.HasPrefix(proof.Reason, controlNamespaceUnknown) {
				t.Fatalf("an unreadable namespace was misreported: %s", proof.Reason)
			}
			audit := server.auditControls(context.Background(), top.Name)
			if len(audit) != 1 || audit[0].Healthy {
				t.Fatalf("an unprovable sidecar audited as %+v", audit)
			}
			observation := server.observeDevice(context.Background(), top.Name, device, false)
			if observation.Health != healthUnknown {
				t.Fatalf("an unprovable namespace was observed as %q: %+v",
					observation.Health, observation)
			}
		})
	}
}

// A pid the kernel has handed to something else resolves to a namespace that is
// not a device's. The agent's own namespace is the one identity that proves it,
// because no device is ever in it.
func TestRecycledPIDResolvingToTheHostNamespaceFailsClosed(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	host, err := rt.SelfNetnsIdentity()
	if err != nil {
		t.Skipf("this host does not expose its own namespace identity: %v", err)
	}
	runtime.identity[runtime.control] = host
	runtime.identity[device.Container] = host

	proof := server.proveControlNamespace(context.Background(), device)
	if proof.OK() || proof.Proven {
		t.Fatalf("a namespace identity equal to the agent's own was accepted: %+v", proof)
	}
	if proof.Match {
		t.Fatal("two recycled pids resolving to one host namespace were read as agreement")
	}
	if !strings.HasPrefix(proof.Reason, controlNamespaceUnknown) {
		t.Fatalf("the host-namespace guard was misreported: %s", proof.Reason)
	}
	observation := server.observeDevice(context.Background(), top.Name, device, false)
	if observation.Health != healthUnknown {
		t.Fatalf("a recycled pid produced %q, not unknown: %+v", observation.Health, observation)
	}
}

func TestRebindRecreatesTheSidecarAndReprovesBothIdentities(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)
	runtime.controlCount = 1

	rebuilt := 0
	err := server.rebindControlSidecarWith(context.Background(), top, device,
		func(context.Context) error {
			rebuilt++
			// What RecreateRuntimeSupport does on a live node: the sidecar is
			// removed and created again against the router's current task.
			runtime.rebuildControl()
			return nil
		})
	if err != nil {
		t.Fatalf("rebinding the control sidecar: %v", err)
	}
	if rebuilt != 1 {
		t.Fatalf("the sidecar was rebuilt %d times", rebuilt)
	}
	if len(runtime.removed) != 1 || runtime.removed[0] != runtime.control {
		t.Fatalf("the repair removed %v, not just the sidecar", runtime.removed)
	}
	if !runtime.ran(runtime.control + "|sh -c /usr/lib/frr/frrinit.sh start") {
		t.Fatalf("the daemons were not restarted in the rebuilt sidecar: %v", runtime.calls)
	}
	if runtime.ran(runtime.primary + "|sh -c /usr/lib/frr/frrinit.sh start") {
		t.Fatal("FRR was started in the student's router shell")
	}
	if runtime.controlCount != 1 {
		t.Fatalf("the rebuilt sidecar runs %d copies of each daemon", runtime.controlCount)
	}
	final := server.proveControlNamespace(context.Background(), device)
	if !final.OK() || !final.Match || !final.Interfaces {
		t.Fatalf("the identities did not match after the repair: %+v", final)
	}
	audit := server.auditControls(context.Background(), top.Name)
	if len(audit) != 1 || !audit[0].Healthy || !audit[0].VTY {
		t.Fatalf("the repaired sidecar still audits as %+v", audit)
	}
	for _, daemon := range render.EnabledDaemons() {
		if audit[0].Daemons[daemon] != 1 {
			t.Fatalf("daemon health was not restored: %+v", audit[0].Daemons)
		}
	}
}

// A router that restarts again mid-repair leaves the sidecar bound to a
// namespace that has already gone. The repair must say so rather than report a
// success for the fault it has just recreated.
func TestRebindRefusesWhenTheRouterRestartsAgainMidRepair(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)

	err := server.rebindControlSidecarWith(context.Background(), top, device,
		func(context.Context) error {
			// The sidecar is created against the namespace the router had, and
			// the router is replaced again before the proof.
			runtime.rebuildControl()
			runtime.identity[device.Container] = rt.NetnsIdentity{Dev: 4, Inode: restartNetns + 1}
			runtime.links[device.Container] = "lo port_ATL port_NYC host\n"
			return nil
		})
	if err == nil {
		t.Fatal("a repair racing a restarting router reported success")
	}
	if !strings.Contains(err.Error(), "moved from") {
		t.Fatalf("the race was misreported: %v", err)
	}
	if runtime.ran(runtime.control + "|sh -c /usr/lib/frr/frrinit.sh start") {
		t.Fatal("daemons were started in a sidecar known to be in the wrong namespace")
	}
}

func TestRebindReportsAFailedRebuildRatherThanADaemonFault(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)

	err := server.rebindControlSidecarWith(context.Background(), top, device,
		func(context.Context) error { return errors.New("image is not present") })
	if err == nil || !strings.Contains(err.Error(), "image is not present") {
		t.Fatalf("a failed rebuild was reported as %v", err)
	}
	if !strings.Contains(err.Error(), runtime.control) {
		t.Fatalf("the failure did not name the sidecar: %v", err)
	}
}

func TestOnlyTheSidecarIsRebuiltSoStudentStateSurvives(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)

	if err := server.rebindControlSidecarWith(context.Background(), top, device,
		func(context.Context) error {
			runtime.rebuildControl()
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	for _, removed := range runtime.removed {
		if removed == device.Container {
			t.Fatal("the student's router container was removed by a control-plane repair")
		}
	}
	for _, call := range runtime.calls {
		if strings.HasPrefix(call, device.Container+"|") &&
			strings.Contains(call, "frrinit.sh") {
			t.Fatalf("the repair reached into the student shell: %s", call)
		}
	}
}

// The periodic and event-driven reconcile paths both end in repairLab. A
// namespace split must reach the sidecar rebuild there, and nothing else: the
// router is not rewired, not re-rendered, and not replaced.
func TestReconcileRoutesANamespaceSplitToASidecarRebuild(t *testing.T) {
	top, device, runtime := splitNamespaceLab()
	server := splitNamespaceServer(t, top, runtime)
	orphanSidecar(device, runtime)

	server.repairLab(context.Background(), top, []*model.Device{device})

	if len(runtime.removed) != 1 || runtime.removed[0] != runtime.control {
		t.Fatalf("the repair removed %v; only the control sidecar may be replaced", runtime.removed)
	}
	var planned string
	events, _ := server.eventLog().after(0, top.Name, 100)
	for _, event := range events {
		if event.Action == "change_plan" {
			planned = event.Detail
		}
	}
	if planned != device.ID+"="+string(ChangeControl) {
		t.Fatalf("the repair was planned as %q, not a control-sidecar rebuild", planned)
	}
}
