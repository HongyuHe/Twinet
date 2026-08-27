package deploy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// namespaceAwareRuntime is a containerd-shaped fake whose containers have
// network namespaces the test controls.
type namespaceAwareRuntime struct {
	observedRuntime
	identity  map[string]rt.NetnsIdentity
	failFor   map[string]error
	removed   []string
	nsPathErr error
	// contents is what the continuity probe reads out of each container's
	// network namespace. A container with no entry answers with an empty one,
	// which is what a task that has just restarted has.
	contents map[string]string
	// tunnels and ports are the further readings the proof makes when the
	// store says there is tunnel or bridge-port state to account for. They are
	// separate because they are separate execs, and because a container that
	// is asked for one it has never had should answer with nothing rather than
	// with somebody else's state.
	tunnels map[string]string
	ports   map[string]string
	// frr is the routing configuration vtysh hands back. It is on a
	// filesystem, it survives a namespace being replaced, and a capture must
	// go on storing it when the namespace-backed snapshots are withheld.
	frr map[string]string
	// onProbe runs when a container's namespace is read, so a test can restart
	// a device in the middle of the proof that brackets that reading.
	onProbe func(container string)
	// onCapture runs when a capture reads a container's addressing, so a test
	// can restart a device between the reading and the identity resolved after
	// it -- which is the window the capture guard exists to close.
	onCapture func(container string)
	// onStart runs when a stopped container is started, so a test can give it
	// the new and empty namespace a started task actually gets.
	onStart func(container string)
	// read counts the commands run in each container, so a test can ask which
	// container something looked inside. Reading the wrong one is a defect
	// that leaves no trace in the store when both hold the same state, and a
	// silent one when the reading is thrown away.
	read map[string]int
	// nsMu guards the three maps above. A pass settles every unbaselined
	// device concurrently, and a test that moves one of them mid-proof is
	// writing from one goroutine what another is reading.
	nsMu sync.Mutex
}

func (r *namespaceAwareRuntime) setIdentity(name string, identity rt.NetnsIdentity) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	r.identity[name] = identity
}

func (r *namespaceAwareRuntime) setContents(name, body string) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	r.contents[name] = body
}

func (r *namespaceAwareRuntime) setTunnels(name, body string) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.tunnels == nil {
		r.tunnels = map[string]string{}
	}
	r.tunnels[name] = body
}

func (r *namespaceAwareRuntime) setPorts(name, body string) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.ports == nil {
		r.ports = map[string]string{}
	}
	r.ports[name] = body
}

// readsOf reports how many commands were run inside a container.
func (r *namespaceAwareRuntime) readsOf(name string) int {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	return r.read[name]
}

func (r *namespaceAwareRuntime) setFRR(name, body string) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.frr == nil {
		r.frr = map[string]string{}
	}
	r.frr[name] = body
}

func (*namespaceAwareRuntime) PullImage(context.Context, string, rt.PullPolicy) error { return nil }

// namespaceProbeOutput renders the reading the continuity probe makes of a
// namespace holding exactly these netdevs and addresses.
func namespaceProbeOutput(links []string, addrs map[string][]string) string {
	return namespaceProbeOutputWith(links, addrs, nil, nil)
}

// namespaceProbeOutputWith adds the last two addrCapture sections: the VLAN
// sub-interfaces and VRF masters the addresses above them are allowed to name,
// which are namespace-backed objects in their own right.
func namespaceProbeOutputWith(links []string, addrs map[string][]string,
	vlans, vrfs []string,
) string {
	var body strings.Builder
	body.WriteString("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n")
	for i, name := range links {
		fmt.Fprintf(&body, "%d: %s@if%d: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\n",
			i+2, name, i+40)
	}
	body.WriteString("---\n")
	body.WriteString("1: lo    inet 127.0.0.1/8 scope host lo\n")
	for i, name := range links {
		fmt.Fprintf(&body, "%d: %s    inet6 fe80::1/64 scope link \n", i+2, name)
	}
	for _, name := range append(append([]string{}, links...), "lo") {
		for _, address := range addrs[name] {
			family := "inet"
			if strings.Contains(address, ":") {
				family = "inet6"
			}
			fmt.Fprintf(&body, "9: %s    %s %s scope global %s\n", name, family, address, name)
		}
	}
	// The routes, which are deliberately not compared, then the VLAN and VRF
	// netdevs, which are.
	body.WriteString("---\n---\n---\n")
	for _, line := range vlans {
		body.WriteString(line + "\n")
	}
	body.WriteString("---\n")
	for _, line := range vrfs {
		body.WriteString(line + "\n")
	}
	return body.String()
}

// vlanLinkLine is one `ip -d -o link show type vlan` line, in the shape
// iproute2 prints it: the detail continues after a backslash.
func vlanLinkLine(name, parent, id string) string {
	return fmt.Sprintf("9: %s@%s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue "+
		"state UP mode DEFAULT group default \\    link/ether 02:42:ac:11:00:02 brd "+
		"ff:ff:ff:ff:ff:ff promiscuity 0 \\    vlan protocol 802.1Q id %s <REORDER_HDR> ",
		name, parent, id)
}

// vrfLinkLine is one `ip -d -o link show type vrf` line.
func vrfLinkLine(name, table string) string {
	return fmt.Sprintf("11: %s: <NOARP,MASTER,UP,LOWER_UP> mtu 65575 qdisc noqueue state UP "+
		"mode DEFAULT group default \\    link/ether 12:34:56:78:9a:bc brd ff:ff:ff:ff:ff:ff "+
		"promiscuity 0 \\    vrf table %s ", name, table)
}

// Exec answers the restore marker and the namespace continuity probe honestly.
// The shared fake returns success for almost every command, which would have
// every device in every fixture claiming it still owes its student a replay and
// every namespace answering that it holds whatever it was asked about.
func (r *namespaceAwareRuntime) Exec(ctx context.Context, c string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.nsMu.Lock()
	if r.read == nil {
		r.read = map[string]int{}
	}
	r.read[c]++
	r.nsMu.Unlock()
	if strings.HasPrefix(strings.Join(cmd.Cmd, " "), "test -f "+restoreMarker) {
		return rt.ExecResult{ExitCode: 1}, nil
	}
	if len(cmd.Cmd) == 3 && cmd.Cmd[0] == "sh" {
		switch cmd.Cmd[2] {
		case namespaceContinuityProbe:
			r.nsMu.Lock()
			body, moved := r.contents[c], r.onProbe
			r.nsMu.Unlock()
			if moved != nil {
				moved(c)
			}
			return rt.ExecResult{Stdout: body}, nil
		case addrCapture:
			// What a capture reads is the second half of what the proof
			// reads, out of the same namespace. A fake that let the two
			// disagree could pass a test the kernel would fail.
			r.nsMu.Lock()
			body, moved := r.contents[c], r.onCapture
			r.nsMu.Unlock()
			if moved != nil {
				moved(c)
			}
			_, addrs := splitNamespaceProbe(body)
			return rt.ExecResult{Stdout: addrs}, nil
		case tunnelCapture:
			r.nsMu.Lock()
			defer r.nsMu.Unlock()
			return rt.ExecResult{Stdout: r.tunnels[c]}, nil
		case switchCapture:
			r.nsMu.Lock()
			defer r.nsMu.Unlock()
			return rt.ExecResult{Stdout: r.ports[c]}, nil
		}
	}
	if len(cmd.Cmd) == 3 && cmd.Cmd[0] == "vtysh" {
		r.nsMu.Lock()
		defer r.nsMu.Unlock()
		if body, ok := r.frr[c]; ok {
			return rt.ExecResult{Stdout: body}, nil
		}
	}
	return r.observedRuntime.Exec(ctx, c, cmd)
}

func (*namespaceAwareRuntime) ImageDigest(_ context.Context, ref string) (string, error) {
	return "sha256:" + ref, nil
}

// NSPath is what wiring asks for before it touches netlink, so a test that
// cannot wire anything fails there rather than panicking through an embedded
// interface that is nil.
func (r *namespaceAwareRuntime) NSPath(_ context.Context, name string) (string, error) {
	if r.nsPathErr != nil {
		return "", r.nsPathErr
	}
	return "/proc/self/ns/net", nil
}

func (*namespaceAwareRuntime) Name() string { return "containerd" }

func (r *namespaceAwareRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	for _, container := range r.containers {
		if container.Name == name {
			return container, nil
		}
	}
	return rt.Container{Name: name, State: rt.StateAbsent}, nil
}

func (r *namespaceAwareRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.removed = append(r.removed, name)
	return nil
}

// Start brings a stopped container back, in a new and empty network namespace,
// which is what actually happens: a task's namespace dies with the task, and
// starting the container makes another one.
func (r *namespaceAwareRuntime) Start(_ context.Context, name string) error {
	r.mu.Lock()
	for i := range r.containers {
		if r.containers[i].Name == name {
			r.containers[i].State = rt.StateRunning
		}
	}
	r.mu.Unlock()
	if r.onStart != nil {
		r.onStart(name)
	}
	return nil
}

func (r *namespaceAwareRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if err := r.failFor[name]; err != nil {
		return rt.NetnsIdentity{}, err
	}
	identity, ok := r.identity[name]
	if !ok {
		return rt.NetnsIdentity{}, errors.New("no namespace for " + name)
	}
	return identity, nil
}

func (r *namespaceAwareRuntime) ObservedNetnsIdentity(ctx context.Context,
	container rt.Container,
) (rt.NetnsIdentity, error) {
	return r.NetnsIdentity(ctx, container.Name)
}

func namespaceAwareLab(t *testing.T) (*Engine, *model.Topology, *model.Device, *namespaceAwareRuntime) {
	t.Helper()
	device := &model.Device{
		ID: "as1/R1", Name: "R1", Container: "tw-r1", Kind: model.KindRouter,
		Image: "frr:stable", Node: "node-a", ASN: 1,
	}
	top := &model.Topology{
		Name: "split", Hash: "split-hash", Devices: map[string]*model.Device{device.ID: device},
		ASes: map[int]*model.AS{1: {ASN: 1, Role: model.RoleStudent}},
	}
	runtime := &namespaceAwareRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		identity: map[string]rt.NetnsIdentity{
			device.Container:            {Dev: 4, Inode: 4026552127},
			FRRControlContainer(device): {Dev: 4, Inode: 4026552127},
		},
		failFor:  map[string]error{},
		contents: map[string]string{},
	}
	root := observeTestRoot(t)
	engine := &Engine{
		Runtime: runtime, Node: "node-a", ObservationRoot: root,
		FRRControlRoot: filepath.Join(root, "frr-control"),
	}
	primary, err := engine.FinalSpecHash(top, device)
	if err != nil {
		t.Fatal(err)
	}
	control, err := engine.FinalControlSpecHash(top, device)
	if err != nil {
		t.Fatal(err)
	}
	if control == "" {
		t.Fatal("the fixture router did not derive a control sidecar")
	}
	runtime.containers = []rt.Container{
		{
			Name: device.Container, State: rt.StateRunning, PID: 4242,
			Labels: map[string]string{
				LabelSpec: primary, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
			},
		},
		{
			Name: FRRControlContainer(device), State: rt.StateRunning, PID: 4243,
			Labels: map[string]string{
				LabelSpec: control, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
			},
		},
	}
	return engine, top, device, runtime
}

// An ordinary redeploy of an otherwise unchanged lab must not answer "no
// changes" while a router's control plane is running in a namespace the router
// has left. The label comparison cannot see it; the namespace identity can.
func TestOrphanedSidecarMakesAnOtherwiseCleanDeployDirty(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if diff := engine.LastBuildDiff(); diff.Create[device.ID] {
		t.Fatalf("a correctly bound sidecar was scheduled for repair: %+v", diff.Create)
	}

	runtime.identity[device.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026552999}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	diff := engine.LastBuildDiff()
	if !diff.Create[device.ID] {
		t.Fatal("a deploy reported no work while the router's control sidecar was orphaned")
	}
	if diff.Recreate[device.ID] {
		t.Fatal("a control-plane repair was planned as a replacement of the student's router")
	}
	if diff.Empty() {
		t.Fatal("the build diff was empty while a control sidecar was orphaned")
	}
}

// Not being able to see where a control plane is must schedule the work, not
// certify a no-op.
func TestUnprovableSidecarNamespaceMakesADeployDirty(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	runtime.failFor[FRRControlContainer(device)] = errors.New("permission denied")

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Create[device.ID] {
		t.Fatal("a deploy reported no work while a control sidecar's namespace was unreadable")
	}
}

func TestControlNamespaceProofNeverAssumesCoResidency(t *testing.T) {
	engine, _, device, runtime := namespaceAwareLab(t)
	control := FRRControlContainer(device)

	bound, err := engine.controlSharesPrimaryNamespace(context.Background(), device, control)
	if err != nil || !bound {
		t.Fatalf("a bound sidecar was reported as %t, %v", bound, err)
	}

	runtime.identity[control] = rt.NetnsIdentity{Dev: 4, Inode: 4026535379}
	bound, err = engine.controlSharesPrimaryNamespace(context.Background(), device, control)
	if err != nil || bound {
		t.Fatalf("an orphaned sidecar was reported as %t, %v", bound, err)
	}

	runtime.failFor[control] = errors.New("permission denied")
	if _, err := engine.controlSharesPrimaryNamespace(context.Background(), device, control); err == nil {
		t.Fatal("an unreadable namespace was not refused")
	}

	// The case that let a live deployment report success over a dead control
	// plane: a decorator in front of containerd satisfies Runtime and offers no
	// identity proof. That is a defect in the decorator, not a backend without
	// the capability, and it must be refused rather than read as co-residency.
	hidden := &Engine{Runtime: &opaqueRuntime{Runtime: runtime}}
	if bound, err := hidden.controlSharesPrimaryNamespace(
		context.Background(), device, control); err == nil || bound {
		t.Fatalf("a hidden capability was read as proof: %t, %v", bound, err)
	}
}

// opaqueRuntime is the shape of every runtime decorator: it satisfies Runtime
// by embedding one and therefore exposes none of the backend's capabilities.
type opaqueRuntime struct{ rt.Runtime }

// forwardingRuntime is the same decorator written correctly.
type forwardingRuntime struct{ rt.Runtime }

func (r *forwardingRuntime) Unwrap() rt.Runtime { return r.Runtime }

func TestADecoratorMustNotEraseTheNamespaceProof(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	control := FRRControlContainer(device)
	runtime.identity[control] = rt.NetnsIdentity{Dev: 4, Inode: 4026535379}

	// A decorator that hides the proof must stop the deployment, not let it
	// report a no-op over a sidecar nobody located.
	engine.Runtime = &opaqueRuntime{Runtime: runtime}
	if _, err := engine.Build(top); err == nil {
		t.Fatal("a deployment that cannot prove any namespace reported a diff")
	} else if !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("unexpected refusal: %v", err)
	}

	// A decorator that exposes what it wraps keeps the backend's proof, so the
	// orphaned sidecar is found through it exactly as it is found without it.
	engine.Runtime = &forwardingRuntime{Runtime: runtime}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Create[device.ID] {
		t.Fatal("an orphaned sidecar behind a forwarding decorator was reported as no work")
	}
}

// ensureFRRControl is the deployment's last word on a sidecar. It must never
// reuse one that is not in the router's namespace, and must refuse outright
// when it cannot tell.
func TestEnsureFRRControlNeverReusesAnOrphanedSidecar(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	control := FRRControlContainer(device)
	runtime.identity[control] = rt.NetnsIdentity{Dev: 4, Inode: 4026535379}
	final, err := engine.finalRuntimeSpecs(top, device)
	if err != nil {
		t.Fatal(err)
	}

	err = engine.ensureFRRControl(context.Background(), top, final)
	// An unprivileged test host cannot create the sidecar's shared FRR
	// directories, so the rebuild may not complete here. What must hold in
	// either environment is that the orphan was torn down rather than reused.
	if err != nil && !strings.Contains(err.Error(), "not permitted") &&
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("ensureFRRControl failed for an unexpected reason: %v", err)
	}
	if len(runtime.removed) != 1 || runtime.removed[0] != control {
		t.Fatalf("the orphaned sidecar was not replaced: removed %v", runtime.removed)
	}
}

func TestEnsureFRRControlRefusesAnUnprovableSidecar(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	runtime.failFor[device.Container] = errors.New("permission denied reading namespace")
	final, err := engine.finalRuntimeSpecs(top, device)
	if err != nil {
		t.Fatal(err)
	}
	err = engine.ensureFRRControl(context.Background(), top, final)
	if err == nil {
		t.Fatal("a deployment accepted a control sidecar whose namespace it could not read")
	}
	if !strings.Contains(err.Error(), device.Container) {
		t.Fatalf("the refusal did not name the router: %v", err)
	}
	if len(runtime.removed) != 0 {
		t.Fatalf("an unprovable namespace destroyed containers: %v", runtime.removed)
	}
}

// An agent wraps its engine in a metrics decorator that offers the capability
// unconditionally; the backend behind it may not have it. Reading that as an
// unprovable namespace would mark every router dirty on every pass for ever.
func TestABackendThatCannotProveNamespacesStopsTheDeployment(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	runtime.failFor[device.Container] = fmt.Errorf("%w: unit",
		rt.ErrNamespaceIdentityUnsupported)

	// Reporting a no-op here is the defect. Every backend that runs split
	// control sidecars can prove where they are, so one that cannot is a
	// runtime wired wrongly, and the deployment must say so rather than
	// quietly certify a control plane it never found.
	if _, err := engine.Build(top); err == nil {
		t.Fatalf("device %s was diffed against an unprovable control plane", device.ID)
	} else if !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}
