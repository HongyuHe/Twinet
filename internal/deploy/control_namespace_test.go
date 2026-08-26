package deploy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
}

func (*namespaceAwareRuntime) PullImage(context.Context, string, rt.PullPolicy) error { return nil }

// Exec answers the restore marker honestly. The shared fake returns success
// for almost every command, which would have every device in every fixture
// claiming it still owes its student a replay.
func (r *namespaceAwareRuntime) Exec(ctx context.Context, c string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	if strings.HasPrefix(strings.Join(cmd.Cmd, " "), "test -f "+restoreMarker) {
		return rt.ExecResult{ExitCode: 1}, nil
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

func (r *namespaceAwareRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
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
		failFor: map[string]error{},
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
