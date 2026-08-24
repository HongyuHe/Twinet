package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

type destroyRuntime struct {
	rt.Runtime
	containers []rt.Container
	release    <-chan struct{}
	started    chan struct{}
	fails      map[string]error
	waitCancel bool
	running    atomic.Int64
	peak       atomic.Int64
	removed    atomic.Int64
}

func (r *destroyRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	return append([]rt.Container(nil), r.containers...), nil
}

func (r *destroyRuntime) Remove(ctx context.Context, name string, _ bool) error {
	n := r.running.Add(1)
	for {
		old := r.peak.Load()
		if n <= old || r.peak.CompareAndSwap(old, n) {
			break
		}
	}
	if r.started != nil {
		r.started <- struct{}{}
	}
	if r.release != nil {
		<-r.release
	}
	if r.waitCancel {
		<-ctx.Done()
	}
	r.running.Add(-1)
	r.removed.Add(1)
	if r.waitCancel {
		return ctx.Err()
	}
	return r.fails[name]
}

func TestDestroyUsesBoundedParallelWorkers(t *testing.T) {
	release := make(chan struct{})
	runtime := &destroyRuntime{
		release: release,
		started: make(chan struct{}, 8),
		containers: []rt.Container{
			{Name: "d"}, {Name: "b"}, {Name: "a"}, {Name: "c"},
			{Name: "e"}, {Name: "f"}, {Name: "g"}, {Name: "h"},
		},
	}
	engine := &Engine{Runtime: runtime, Workers: 3,
		removeEmptyMultiplex: func(string) ([]string, error) { return nil, nil }}
	done := make(chan error, 1)
	go func() { done <- engine.Destroy(context.Background(), "lab") }()
	for i := 0; i < 3; i++ {
		select {
		case <-runtime.started:
		case <-time.After(time.Second):
			t.Fatalf("only %d teardown workers started", i)
		}
	}
	if got := runtime.peak.Load(); got != 3 {
		t.Fatalf("teardown peak = %d, want worker bound 3", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if got := runtime.removed.Load(); got != 8 {
		t.Fatalf("removed %d containers, want 8", got)
	}
}

func TestDestroyReportsConcurrentFailuresDeterministically(t *testing.T) {
	runtime := &destroyRuntime{
		containers: []rt.Container{{Name: "z"}, {Name: "a"}, {Name: "m"}},
		fails: map[string]error{
			"z": errors.New("z failed"),
			"a": errors.New("a failed"),
		},
	}

	err := (&Engine{Runtime: runtime, Workers: 3,
		removeEmptyMultiplex: func(string) ([]string, error) { return nil, nil }}).Destroy(context.Background(), "lab")
	if err == nil {
		t.Fatal("destroy unexpectedly succeeded")
	}
	const want = "remove a: a failed; remove z: z failed"
	if got := err.Error(); got != want {
		t.Fatalf("destroy error = %q, want %q", got, want)
	}
}

func TestDestroyRemovesObservedDeploymentState(t *testing.T) {
	root := t.TempDir()
	engine := &Engine{
		Runtime: &destroyRuntime{}, ObservationRoot: root,
		removeEmptyMultiplex: func(string) ([]string, error) { return nil, nil },
	}
	path := engine.observationPath("lab")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Destroy(context.Background(), "lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("destroy left observed deployment state %s: %v", path, err)
	}
}

func TestDestroyCancellationDoesNotStartQueuedTeardown(t *testing.T) {
	runtime := &destroyRuntime{
		containers: []rt.Container{{Name: "a"}, {Name: "b"}, {Name: "c"}},
		started:    make(chan struct{}, 3),
		waitCancel: true,
	}
	engine := &Engine{Runtime: runtime, Workers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- engine.Destroy(ctx, "lab") }()
	select {
	case <-runtime.started:
	case <-time.After(time.Second):
		t.Fatal("first teardown operation did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("destroy error = %v, want cancellation", err)
	}
	if got := runtime.removed.Load(); got != 1 {
		t.Fatalf("destroy started %d removals after cancellation, want 1", got)
	}
}

type captureRuntime struct {
	rt.Runtime
	failContainer string
	mu            sync.Mutex
	running       int
	peak          int
	removals      int
	containers    []rt.Container
}

func (r *captureRuntime) Inspect(_ context.Context, _ string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (r *captureRuntime) Exec(_ context.Context, container string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.mu.Lock()
	r.running++
	if r.running > r.peak {
		r.peak = r.running
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running--
		r.mu.Unlock()
	}()
	time.Sleep(10 * time.Millisecond)
	if container == r.failContainer && len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh" {
		return rt.ExecResult{}, errors.New("router is unreachable")
	}
	if len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh" {
		return rt.ExecResult{Stdout: "router bgp 1\n"}, nil
	}
	return rt.ExecResult{Stdout: "1: lo\n"}, nil
}

func (r *captureRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	return append([]rt.Container(nil), r.containers...), nil
}

func (r *captureRuntime) Remove(_ context.Context, _ string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removals++
	return nil
}

func TestCaptureAllUsesBoundedParallelReads(t *testing.T) {
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	top := &model.Topology{
		Name: "lab", Hash: "topology",
		Devices: map[string]*model.Device{},
		ASes:    map[int]*model.AS{},
	}
	for i := 1; i <= 4; i++ {
		d := &model.Device{
			ID: fmt.Sprintf("as%d/R1", i), ASN: i, Node: "node", Kind: model.KindRouter,
			Container: fmt.Sprintf("r%d", i),
		}
		top.Devices[d.ID] = d
		top.ASes[i] = &model.AS{ASN: i, Role: model.RoleStudent}
	}
	runtime := &captureRuntime{}
	saved, err := (&Engine{Runtime: runtime, Node: "node", Workers: 2}).CaptureAll(
		context.Background(), top, store)
	if err != nil {
		t.Fatalf("capture all: %v", err)
	}
	if saved == 0 {
		t.Fatal("capture all did not save any snapshots")
	}
	runtime.mu.Lock()
	peak := runtime.peak
	runtime.mu.Unlock()
	if peak != 2 {
		t.Fatalf("capture peak = %d, want worker bound 2", peak)
	}
}

func TestPruneRefusesAllRemovalsWhenAnyCaptureFails(t *testing.T) {
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &captureRuntime{
		failContainer: "bad",
		containers: []rt.Container{
			{Name: "good", Labels: map[string]string{
				LabelLab: "lab", LabelNode: "node", LabelDeviceID: "as1/R1", LabelKind: "router",
			}},
			{Name: "bad", Labels: map[string]string{
				LabelLab: "lab", LabelNode: "node", LabelDeviceID: "as2/R1", LabelKind: "router",
			}},
		},
	}
	top := &model.Topology{
		Name: "lab", Hash: "topology", Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	removed, err := (&Engine{Runtime: runtime, Node: "node", Workers: 2, State: store}).PruneOrphans(
		context.Background(), top)
	if err == nil {
		t.Fatal("prune succeeded despite an unreadable student container")
	}
	if !strings.Contains(err.Error(), "refusing to remove bad") {
		t.Fatalf("prune failed for the wrong reason: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("prune removed %v even though capture failed", removed)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.removals != 0 {
		t.Fatalf("prune removed %d containers after capture failed", runtime.removals)
	}
}

func testStateStore(t *testing.T) (*state.Store, error) {
	t.Helper()
	dir := filepath.Join(".test-state-" + strings.ReplaceAll(t.Name(), "/", "-"))
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return state.Open(dir)
}
