package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type observedRuntime struct {
	rt.Runtime
	mu         sync.Mutex
	containers []rt.Container
	files      map[string][]byte
	listCalls  int
	execs      int
	copies     int
}

func (r *observedRuntime) Name() string { return "fake" }

func (r *observedRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listCalls++
	return append([]rt.Container(nil), r.containers...), nil
}

func (r *observedRuntime) CopyFrom(_ context.Context, _ string, path string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, ok := r.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), body...), nil
}

func (r *observedRuntime) CopyTo(_ context.Context, _ string, path string, _ int64, body []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.copies++
	r.files[path] = append([]byte(nil), body...)
	return nil
}

func (r *observedRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.execs++
	if strings.Contains(strings.Join(cmd.Cmd, " "), "cat "+configurationMarker) {
		return rt.ExecResult{ExitCode: 1}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *observedRuntime) counts() (lists, execs, copies int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listCalls, r.execs, r.copies
}

func (r *observedRuntime) resetMutations() {
	r.mu.Lock()
	r.execs, r.copies = 0, 0
	r.mu.Unlock()
}

type observedRenderer struct {
	revision map[string]string
}

func (r observedRenderer) Files(d *model.Device) (map[string]FileSpec, error) {
	return map[string]FileSpec{
		"/etc/twinet/platform.conf": {Content: []byte("device=" + d.ID + "\nrevision=" + r.revision[d.ID] + "\n"), Mode: 0o644},
	}, nil
}

func (r observedRenderer) Commands(d *model.Device) ([]Command, error) {
	return []Command{{Args: []string{"daemonctl", "reload", d.ID}, Describe: "reload"}}, nil
}

func (r observedRenderer) Ready(*model.Device, rt.Runtime) *plan.Waiter { return nil }

func seedObservedContainers(t *testing.T, engine *Engine, top *model.Topology,
	runtime *observedRuntime,
) {
	t.Helper()
	for _, d := range top.Devices {
		hash, err := engine.FinalSpecHash(top, d)
		if err != nil {
			t.Fatal(err)
		}
		runtime.containers = append(runtime.containers, rt.Container{
			Name: d.Container, State: rt.StateRunning,
			Labels: map[string]string{
				LabelSpec: hash, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
			},
		})
	}
}

func TestObservedNoChangeBuildUsesOneRuntimeListForLargeNode(t *testing.T) {
	top := observedTopology(t, 212, nil)
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)

	first, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if first.Len() != 0 {
		t.Fatalf("trusted initial snapshot planned %d mutations, want 0", first.Len())
	}
	if lists, execs, copies := runtime.counts(); lists != 1 || execs != 0 || copies != 0 {
		t.Fatalf("initial observation calls = list %d exec %d copy %d, want 1/0/0", lists, execs, copies)
	}

	start := time.Now()
	second, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if second.Len() != 0 {
		t.Fatalf("no-change plan contained %d steps: %#v", second.Len(), second.Steps())
	}
	if rep, err := second.Execute(context.Background(), plan.Options{}); err != nil || rep.Done() != 0 {
		t.Fatalf("no-change execute = %#v, %v", rep, err)
	}
	if lists, execs, copies := runtime.counts(); lists != 2 || execs != 0 || copies != 0 {
		t.Fatalf("no-change observation calls = list %d exec %d copy %d, want 2/0/0", lists, execs, copies)
	}
	if diff := engine.LastBuildDiff(); !diff.Empty() || len(diff.Capture) != 0 {
		t.Fatalf("no-change dirty set = %#v", diff)
	}
	for kind, count := range engine.DeploymentStats(nil).Mutations {
		if count != 0 {
			t.Fatalf("no-change mutation %s = %d, want 0", kind, count)
		}
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("212-device synthetic no-change build took %s, want under 30s", elapsed)
	}
}

func TestObservedNoChangeBuildScalesTo84AS(t *testing.T) {
	const devices = 2012
	top := observedTopology(t, devices, nil)
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)
	if p, err := engine.Build(top); err != nil || p.Len() != 0 {
		t.Fatalf("84-AS bootstrap build = %#v, %v", p, err)
	}
	start := time.Now()
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 0 {
		t.Fatalf("84-AS no-change plan contains %d steps", p.Len())
	}
	if rep, err := p.Execute(context.Background(), plan.Options{}); err != nil || rep.Done() != 0 {
		t.Fatalf("84-AS no-change execute = %#v, %v", rep, err)
	}
	if got := time.Since(start); got > 30*time.Second {
		t.Fatalf("84-AS synthetic no-change build took %s, want under 30s", got)
	}
	if lists, execs, copies := runtime.counts(); lists != 2 || execs != 0 || copies != 0 {
		t.Fatalf("84-AS no-change calls = list %d exec %d copy %d, want 2/0/0", lists, execs, copies)
	}
}

func TestObservedServiceConfigChangeTouchesOnlyThatService(t *testing.T) {
	top := observedTopology(t, 2, nil)
	serviceID := "device-001"
	top.Devices[serviceID].ASN = 0
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)
	if p, err := engine.Build(top); err != nil || p.Len() != 1 {
		t.Fatalf("bootstrap build = %#v, %v", p, err)
	} else if _, err := p.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	runtime.resetMutations()
	renderer.revision[serviceID] = "two"
	engine.Renderer = renderer
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 1 || p.Steps()[0].ID != "configure:"+serviceID {
		t.Fatalf("service edit plan = %#v, want only configure:%s", p.Steps(), serviceID)
	}
	if got := engine.DirtyCaptureDevices(); len(got) != 0 {
		t.Fatalf("service edit dirty capture = %v, want none for a non-student service", got)
	}
	if _, err := p.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	if _, execs, copies := runtime.counts(); execs != 2 || copies != 1 {
		t.Fatalf("service edit mutations = exec %d copy %d, want 2/1", execs, copies)
	}
	stats := engine.DeploymentStats(nil)
	if stats.Mutations["copy"] != 1 || stats.Mutations["command"] != 1 || stats.Mutations["configure"] != 1 {
		t.Fatalf("service mutation stats = %#v, want one copy/command/configure", stats.Mutations)
	}
	if p, err := engine.Build(top); err != nil || p.Len() != 0 {
		t.Fatalf("post-service no-change build = %#v, %v", p, err)
	}
	if _, execs, copies := runtime.counts(); execs != 2 || copies != 1 {
		t.Fatalf("post-service no-change mutated again: exec %d copy %d", execs, copies)
	}
}

func TestObservedBootstrapRepairsServiceFilesWithoutTouchingRouters(t *testing.T) {
	top := observedTopology(t, 2, nil)
	serviceID := "device-001"
	top.Devices[serviceID].ASN = 0
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 1 || p.Steps()[0].ID != "configure:"+serviceID {
		t.Fatalf("bootstrap service repair plan = %#v, want only configure:%s", p.Steps(), serviceID)
	}
}

func TestObservedStudentConfigChangeMarksOnlyThatDeviceForCapture(t *testing.T) {
	top := observedTopology(t, 3, nil)
	target := "device-002"
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)
	if p, err := engine.Build(top); err != nil || p.Len() != 0 {
		t.Fatalf("bootstrap = %#v, %v", p, err)
	}
	renderer.revision[target] = "two"
	engine.Renderer = renderer
	if p, err := engine.Build(top); err != nil || p.Len() != 1 {
		t.Fatalf("student config diff = %#v, %v", p, err)
	}
	if got := engine.DirtyCaptureDevices(); len(got) != 1 || got[0] != target {
		t.Fatalf("dirty capture devices = %v, want [%s]", got, target)
	}
}

func TestObservedDelayChangePlansOnlyItsWire(t *testing.T) {
	delay := "5ms"
	top := observedTopology(t, 2, []*model.Link{observedLink("link-a", &delay)})
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, d := range top.Devices {
		renderer.revision[d.ID] = "one"
	}
	engine := &Engine{Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t)}
	seedObservedContainers(t, engine, top, &runtime)
	if p, err := engine.Build(top); err != nil || p.Len() != 0 {
		t.Fatalf("bootstrap build = %#v, %v", p, err)
	}
	changed := "25ms"
	top.Links[0].Props.Delay = changed
	top.Hash = "changed-delay"
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if p.Len() != 1 || p.Steps()[0].ID != "wire:link-a" {
		t.Fatalf("delay edit plan = %#v, want only wire:link-a", p.Steps())
	}
}

func TestDelayMutationCountsExactlyTwoQdiscEndpointsClusterWide(t *testing.T) {
	link := observedLink("delay", ptrString("10ms"))
	link.A.Device = &model.Device{Node: "node-a"}
	link.B.Device = &model.Device{Node: "node-b"}
	if got := qdiscEndpointsOnNode(link, "node-a") + qdiscEndpointsOnNode(link, "node-b"); got != 2 {
		t.Fatalf("cluster delay edit qdisc endpoints = %d, want 2", got)
	}
}

func ptrString(value string) *string { return &value }

func observedTopology(t *testing.T, count int, links []*model.Link) *model.Topology {
	t.Helper()
	top := &model.Topology{
		Name: "observed-lab", Hash: "observed-hash", Devices: map[string]*model.Device{},
		ASes: map[int]*model.AS{1: {ASN: 1, Role: model.RoleStudent}},
	}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("device-%03d", i)
		d := &model.Device{ID: id, Name: id, Container: "tw-" + id, Image: "image:stable", Node: "node-a", ASN: 1}
		top.Devices[id] = d
	}
	for _, link := range links {
		link.A.Device = top.Devices["device-000"]
		link.B.Device = top.Devices["device-001"]
		link.A.Device.Ifaces = append(link.A.Device.Ifaces, link.A)
		link.B.Device.Ifaces = append(link.B.Device.Ifaces, link.B)
		top.Links = append(top.Links, link)
	}
	return top
}

func observedLink(id string, delay *string) *model.Link {
	props := model.LinkProps{}
	if delay != nil {
		props.Delay = *delay
	}
	return &model.Link{
		ID: id, Kind: model.LinkVeth, Props: props,
		A: &model.Iface{Name: "a0"}, B: &model.Iface{Name: "b0"},
	}
}

func observeTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(".test-observe-" + strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}
