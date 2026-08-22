package deploy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func TestRuntimeSpecHashCoversEveryDerivedHardeningField(t *testing.T) {
	base := &runtime.Spec{
		Name: "device", Image: "image@sha256:abc", Hostname: "device",
		Command: []string{"sleep", "infinity"},
		Env:     map[string]string{"A": "1"}, Sysctls: map[string]string{"net.ipv4.ip_forward": "1"},
		Capabilities: []string{"NET_ADMIN"}, CapDrop: []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges", "apparmor=docker-default"},
		ReadOnlyRootfs: true, RuntimeClass: "runc", UsernsMode: "private", PidMode: "private",
		MaskedPaths: []string{"/proc/kcore"}, ReadonlyPaths: []string{"/proc/sys"},
		CPUs: 1, Memory: "128Mi", PidsLimit: 128, Restart: "unless-stopped",
		Binds: []runtime.Bind{{Source: "/host/a", Target: "/etc/twinet"}},
		Tmpfs: map[string]string{"/run": "rw,nosuid,nodev"}, NetworkMode: "none", Init: true,
	}
	want := runtimeSpecHash(base)
	cases := []struct {
		name   string
		change func(*runtime.Spec)
	}{
		{"capabilities", func(s *runtime.Spec) { s.Capabilities = append(s.Capabilities, "NET_RAW") }},
		{"cap-drop", func(s *runtime.Spec) { s.CapDrop = []string{"ALL", "SYS_ADMIN"} }},
		{"security-opt", func(s *runtime.Spec) { s.SecurityOpt = append(s.SecurityOpt, "seccomp=custom") }},
		{"read-only-rootfs", func(s *runtime.Spec) { s.ReadOnlyRootfs = false }},
		{"runtime-class", func(s *runtime.Spec) { s.RuntimeClass = "runsc" }},
		{"userns", func(s *runtime.Spec) { s.UsernsMode = "host" }},
		{"pid-mode", func(s *runtime.Spec) { s.PidMode = "host" }},
		{"masked-paths", func(s *runtime.Spec) { s.MaskedPaths = append(s.MaskedPaths, "/proc/keys") }},
		{"readonly-paths", func(s *runtime.Spec) { s.ReadonlyPaths = append(s.ReadonlyPaths, "/proc/irq") }},
		{"binds", func(s *runtime.Spec) { s.Binds = append(s.Binds, runtime.Bind{Source: "/host/b", Target: "/etc/bind"}) }},
		{"tmpfs", func(s *runtime.Spec) { s.Tmpfs["/var/log"] = "rw,nosuid,nodev" }},
		{"network", func(s *runtime.Spec) { s.NetworkMode = "container:other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cloneRuntimeSpec(base)
			tc.change(spec)
			if got := runtimeSpecHash(spec); got == want {
				t.Fatalf("%s did not change final runtime spec identity", tc.name)
			}
		})
	}
}

func TestLegacyModelSpecLabelForcesFinalSpecMigration(t *testing.T) {
	top := observedTopology(t, 1, nil)
	d := top.Devices["device-000"]
	renderer := observedRenderer{revision: map[string]string{d.ID: "one"}}
	rt := observedRuntime{files: map[string][]byte{}, containers: []runtime.Container{{
		Name: d.Container, State: runtime.StateRunning,
		Labels: map[string]string{LabelSpec: SpecHash(d), LabelHash: top.Hash},
	}}}
	engine := &Engine{
		Runtime: &rt, Node: "node-a", Renderer: renderer,
		ObservationRoot: observeTestRoot(t),
	}
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Create[d.ID] {
		t.Fatalf("legacy model-only LabelSpec %s was accepted instead of migrated", SpecHash(d))
	}
	if p.Len() == 0 {
		t.Fatal("legacy container produced a zero-step plan instead of recreation")
	}
	final, err := engine.FinalSpecHash(top, d)
	if err != nil {
		t.Fatal(err)
	}
	if final == SpecHash(d) {
		t.Fatal("final runtime contract did not differ from legacy model hash")
	}
}

func cloneRuntimeSpec(in *runtime.Spec) *runtime.Spec {
	out := *in
	out.Command = append([]string(nil), in.Command...)
	out.Env = cloneStringMap(in.Env)
	out.Sysctls = cloneStringMap(in.Sysctls)
	out.Capabilities = append([]string(nil), in.Capabilities...)
	out.CapDrop = append([]string(nil), in.CapDrop...)
	out.SecurityOpt = append([]string(nil), in.SecurityOpt...)
	out.MaskedPaths = append([]string(nil), in.MaskedPaths...)
	out.ReadonlyPaths = append([]string(nil), in.ReadonlyPaths...)
	out.Binds = append([]runtime.Bind(nil), in.Binds...)
	out.Tmpfs = cloneStringMap(in.Tmpfs)
	return &out
}

func TestFinalSpecBuildUsesTheSameHashItLabels(t *testing.T) {
	d := &model.Device{
		ID: "svc/dns", Name: "dns", Kind: model.KindService, Image: "svc:latest",
		Container: "dns", Node: "node-a", ServiceKind: "builtin.dns",
		Requests: model.DefaultResourceRequest(model.KindService),
	}
	top := &model.Topology{Name: "lab", Devices: map[string]*model.Device{d.ID: d}}
	engine := &Engine{Runtime: hardeningRuntime{}, WritableRoot: t.TempDir()}
	final, err := engine.finalRuntimeSpecs(top, d)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := final.spec.Labels[LabelSpec], runtimeSpecHash(final.spec); got != want {
		t.Fatalf("create label = %s, hash of create request = %s", got, want)
	}
}

func TestFinalSpecPlanningIsFilesystemSideEffectFree(t *testing.T) {
	d := &model.Device{
		ID: "svc/dns", Name: "dns", Kind: model.KindService, Image: "svc:latest",
		Container: "dns", Node: "node-a", Requests: model.DefaultResourceRequest(model.KindService),
	}
	top := &model.Topology{Name: "lab", Devices: map[string]*model.Device{d.ID: d}}
	root := t.TempDir()
	engine := &Engine{Runtime: hardeningRuntime{}, WritableRoot: root}
	if _, err := engine.RuntimeSpec(context.Background(), top, d); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.FinalSpecHash(top, d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "lab")); !os.IsNotExist(err) {
		t.Fatalf("pure planning created writable bind state: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := engine.FinalSpecHash(top, d)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "lab")); !os.IsNotExist(err) {
		t.Fatalf("concurrent planning created writable bind state: %v", err)
	}
}

type preparationRuntime struct {
	runtime.Runtime
	created bool
	spec    *runtime.Spec
}

func (preparationRuntime) Name() string { return "fake" }

func (r *preparationRuntime) Inspect(context.Context, string) (runtime.Container, error) {
	return runtime.Container{State: runtime.StateAbsent}, nil
}

func (r *preparationRuntime) List(context.Context, runtime.Filter) ([]runtime.Container, error) {
	return nil, nil
}

func (r *preparationRuntime) Create(_ context.Context, spec *runtime.Spec) (string, error) {
	r.created = true
	r.spec = spec
	return "created", nil
}

func (r *preparationRuntime) Start(context.Context, string) error { return nil }
func (r *preparationRuntime) PullImage(context.Context, string, runtime.PullPolicy) error {
	return nil
}
func (r *preparationRuntime) ImageDigest(context.Context, string) (string, error) {
	return "image", nil
}

func TestOnlyDirtyCreatePreparesWritableBindSources(t *testing.T) {
	d := &model.Device{
		ID: "svc/dns", Name: "dns", Kind: model.KindService, Image: "svc:latest",
		Container: "dns", Node: "node-a", Requests: model.DefaultResourceRequest(model.KindService),
	}
	top := &model.Topology{Name: "lab", Devices: map[string]*model.Device{d.ID: d}}
	root := t.TempDir()
	rt := &preparationRuntime{}
	engine := &Engine{Runtime: rt, Node: "node-a", WritableRoot: root, ObservationRoot: t.TempDir()}
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "lab")); !os.IsNotExist(err) {
		t.Fatalf("planning created bind source before dirty create: %v", err)
	}
	if _, err := p.Execute(context.Background(), planOptionsOneWorker()); err != nil {
		t.Fatal(err)
	}
	if !rt.created {
		t.Fatal("dirty create did not reach runtime create")
	}
	for _, bind := range rt.spec.Binds {
		if bind.Target != "/etc/twinet" && bind.Target != "/etc/bind" &&
			bind.Target != "/var/named" && bind.Target != "/var/run/named" {
			continue
		}
		if _, err := os.Stat(bind.Source); err != nil {
			t.Fatalf("dirty create did not prepare %s source %s: %v", bind.Target, bind.Source, err)
		}
	}
}

func planOptionsOneWorker() plan.Options { return plan.Options{Workers: 1} }
