package deploy

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// lifecycleRuntime is an observedRuntime that can also create and start
// containers, so a test can execute a from-scratch plan and count the runtime
// round-trips configuration actually makes.
type lifecycleRuntime struct {
	observedRuntime
	lmu           sync.Mutex
	present       map[string]rt.Container
	copyFromCalls int
}

func newLifecycleRuntime() *lifecycleRuntime {
	return &lifecycleRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		present:         map[string]rt.Container{},
	}
}

func (r *lifecycleRuntime) Name() string { return "fake" }

func (r *lifecycleRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	if c, ok := r.present[name]; ok {
		return c, nil
	}
	return rt.Container{Name: name, State: rt.StateAbsent}, nil
}

func (r *lifecycleRuntime) Create(_ context.Context, spec *rt.Spec) (string, error) {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	labels := map[string]string{}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	r.present[spec.Name] = rt.Container{Name: spec.Name, State: rt.StateCreated, Labels: labels}
	return spec.Name, nil
}

func (r *lifecycleRuntime) Start(_ context.Context, name string) error {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	c, ok := r.present[name]
	if !ok {
		return fmt.Errorf("container %s does not exist", name)
	}
	c.State = rt.StateRunning
	r.present[name] = c
	return nil
}

func (r *lifecycleRuntime) PullImage(context.Context, string, rt.PullPolicy) error { return nil }

func (r *lifecycleRuntime) ImageExists(context.Context, string) (bool, error) { return true, nil }

func (r *lifecycleRuntime) ImageDigest(context.Context, string) (string, error) {
	return "sha256:1111111111111111111111111111111111111111111111111111111111111111", nil
}

func (r *lifecycleRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.lmu.Lock()
	out := make([]rt.Container, 0, len(r.present))
	for _, c := range r.present {
		out = append(out, c)
	}
	r.lmu.Unlock()
	r.mu.Lock()
	r.listCalls++
	r.mu.Unlock()
	return out, nil
}

func (r *lifecycleRuntime) CopyFrom(ctx context.Context, name, path string) ([]byte, error) {
	r.lmu.Lock()
	r.copyFromCalls++
	r.lmu.Unlock()
	return r.observedRuntime.CopyFrom(ctx, name, path)
}

func (r *lifecycleRuntime) copyFromCount() int {
	r.lmu.Lock()
	defer r.lmu.Unlock()
	return r.copyFromCalls
}

// multiFileRenderer gives each device several platform files, which is what a
// service device looks like at scale: its configuration is many generated
// files written one runtime round-trip at a time.
type multiFileRenderer struct {
	files    int
	revision map[string]string
}

func (r multiFileRenderer) Files(d *model.Device) (map[string]FileSpec, error) {
	out := make(map[string]FileSpec, r.files)
	for i := range r.files {
		out[fmt.Sprintf("/etc/twinet/%s/zone-%03d.conf", d.ID, i)] = FileSpec{
			Content: []byte(fmt.Sprintf("device=%s\nzone=%d\nrevision=%s\n", d.ID, i, r.revision[d.ID])),
			Mode:    0o644,
		}
	}
	return out, nil
}

func (r multiFileRenderer) Commands(*model.Device) ([]Command, error) { return nil, nil }

func (multiFileRenderer) Ready(*model.Device, rt.Runtime) *plan.Waiter { return nil }

// TestFreshContainersSkipRedundantConfigurationReads pins the round-trip bound
// R1.F3 depends on: a container this pass created from its image holds none of
// the platform's rendered configuration, so configuration must write it
// without reading every file back first. A container that already existed
// keeps the comparison, because there its content is the only evidence of
// whether a write is needed at all.
func TestFreshContainersSkipRedundantConfigurationReads(t *testing.T) {
	const devices, files = 4, 25
	top := observedTopology(t, devices, nil)
	renderer := multiFileRenderer{files: files, revision: map[string]string{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	runtime := newLifecycleRuntime()
	engine := &Engine{
		Runtime: runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: observeTestRoot(t),
	}

	first, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Execute(context.Background(), plan.Options{Workers: 4}); err != nil {
		t.Fatal(err)
	}
	if got := runtime.copyFromCount(); got != 0 {
		t.Fatalf("from-scratch configuration read back %d files it had just created, want 0", got)
	}
	if _, _, copies := runtime.counts(); copies != devices*files {
		t.Fatalf("from-scratch deployment wrote %d files, want %d", copies, devices*files)
	}
	for _, d := range top.Devices {
		want, err := renderer.Files(d)
		if err != nil {
			t.Fatal(err)
		}
		for path, spec := range want {
			if got := runtime.files[path]; string(got) != string(spec.Content) {
				t.Fatalf("%s was not written with the rendered content: %q", path, got)
			}
		}
	}

	// A second pass reuses the running containers, so the read-back comparison
	// must come back: it is what keeps an unchanged file from being rewritten.
	runtime.resetMutations()
	renderer.revision["device-000"] = "two"
	engine.Renderer = renderer
	second, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if second.Len() != 1 || second.Steps()[0].ID != "configure:device-000" {
		t.Fatalf("second plan = %#v, want only configure:device-000", second.Steps())
	}
	before := runtime.copyFromCount()
	if _, err := second.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	if got := runtime.copyFromCount() - before; got != files {
		t.Fatalf("reused container compared %d files, want %d", got, files)
	}
	if _, _, copies := runtime.counts(); copies != files {
		t.Fatalf("edited device rewrote %d files, want %d", copies, files)
	}

	// Nothing changed now, so the deployment must be a proven no-op.
	runtime.resetMutations()
	third, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if third.Len() != 0 {
		t.Fatalf("no-change plan contained %d steps: %#v", third.Len(), third.Steps())
	}
	if _, execs, copies := runtime.counts(); execs != 0 || copies != 0 {
		t.Fatalf("no-change redeploy mutated: exec %d copy %d", execs, copies)
	}
	for kind, count := range engine.DeploymentStats(nil).Mutations {
		if count != 0 {
			t.Fatalf("no-change mutation %s = %d, want 0", kind, count)
		}
	}
}

// TestCreatedContainerSetResetsPerBuild keeps the fresh-container shortcut
// scoped to the pass that created the container. A later apply through the
// same engine must compare content again.
func TestCreatedContainerSetResetsPerBuild(t *testing.T) {
	top := observedTopology(t, 1, nil)
	renderer := multiFileRenderer{files: 2, revision: map[string]string{"device-000": "one"}}
	runtime := newLifecycleRuntime()
	engine := &Engine{
		Runtime: runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: observeTestRoot(t),
	}
	first, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	if !engine.containerCreatedThisPass("device-000") {
		t.Fatal("the pass that created the container did not record it")
	}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if engine.containerCreatedThisPass("device-000") {
		t.Fatal("a later build still treats the container as freshly created")
	}
}
