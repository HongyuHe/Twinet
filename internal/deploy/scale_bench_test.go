package deploy_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// scaleTopology is the release-gate topology: the 84-AS teaching mini-Internet
// placed across the three declared workers. It is the shape whose deploy and
// convergence must fit the acceptance budget, so planning benchmarks measure
// it rather than a synthetic stand-in.
func scaleTopology(tb testing.TB) *model.Topology {
	tb.Helper()
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		tb.Fatal(err)
	}
	res, err := expand.Expand(loaded.Lab)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := place.Place(res.Topology, place.Options{}); err != nil {
		tb.Fatal(err)
	}
	return res.Topology
}

// absentRuntime reports every container as absent. Planning then has to render
// and hash every device on the node, which is the observation cost a
// from-scratch scale deployment pays.
type absentRuntime struct {
	mu    sync.Mutex
	calls map[string]int
}

func (r *absentRuntime) record(op string) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	r.calls[op]++
	r.mu.Unlock()
}

func (r *absentRuntime) Name() string                         { return "memory" }
func (r *absentRuntime) Ping(context.Context) (string, error) { return "memory", nil }
func (r *absentRuntime) Close() error                         { return nil }
func (r *absentRuntime) ImageExists(context.Context, string) (bool, error) {
	return true, nil
}

func (r *absentRuntime) PullImage(context.Context, string, runtime.PullPolicy) error { return nil }

func (r *absentRuntime) Create(context.Context, *runtime.Spec) (string, error) {
	return "", errors.New("memory runtime does not create containers")
}
func (r *absentRuntime) Start(context.Context, string) error                 { return nil }
func (r *absentRuntime) Stop(context.Context, string, time.Duration) error   { return nil }
func (r *absentRuntime) Pause(context.Context, string) error                 { return nil }
func (r *absentRuntime) Unpause(context.Context, string) error               { return nil }
func (r *absentRuntime) Remove(context.Context, string, bool) error          { return nil }
func (r *absentRuntime) ImageDigest(context.Context, string) (string, error) { return "", nil }

func (r *absentRuntime) Inspect(_ context.Context, name string) (runtime.Container, error) {
	r.record("inspect")
	return runtime.Container{Name: name, State: runtime.StateAbsent}, nil
}

func (r *absentRuntime) List(context.Context, runtime.Filter) ([]runtime.Container, error) {
	r.record("list")
	return nil, nil
}

func (r *absentRuntime) NSPath(_ context.Context, name string) (string, error) {
	r.record("nspath")
	return "", fmt.Errorf("container %s is absent", name)
}

func (r *absentRuntime) Exec(context.Context, string, runtime.ExecCmd) (runtime.ExecResult, error) {
	r.record("exec")
	return runtime.ExecResult{}, nil
}

func (r *absentRuntime) CopyTo(context.Context, string, string, int64, []byte) error { return nil }

func (r *absentRuntime) CopyFrom(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func scaleEngine(tb testing.TB, top *model.Topology, node string) (*deploy.Engine, *absentRuntime) {
	tb.Helper()
	rt := &absentRuntime{}
	return &deploy.Engine{
		Runtime:         rt,
		Node:            node,
		Renderer:        render.New(top, render.ModePlatform),
		UnderlayIP:      "10.0.1.2",
		UnderlayDev:     "eth0",
		PeerUnderlay:    map[string]string{"node-0": "10.0.1.1", "node-1": "10.0.1.2", "node-2": "10.0.1.3"},
		ObservationRoot: tb.TempDir(),
		// Planning benchmarks must not persist or mutate node-local state.
		ObservationReadOnly: true,
	}, rt
}

// BenchmarkScaleBuildPlan measures the whole node-local planning pass for the
// release-gate topology: observation, rendering, final runtime specs, and the
// desired wire hashes. It is the CPU cost that precedes every container
// operation in the measured apply phase.
func BenchmarkScaleBuildPlan(b *testing.B) {
	top := scaleTopology(b)
	eng, _ := scaleEngine(b, top, "node-1")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := eng.BuildContext(ctx, top); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScaleExpectedOverlayInventory isolates the overlay derivation that
// R1.O7 names: one call per cross-node link on the node, each of which used to
// rescan every link in the topology.
func BenchmarkScaleExpectedOverlayInventory(b *testing.B) {
	top := scaleTopology(b)
	eng, _ := scaleEngine(b, top, "node-1")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := eng.ExpectedOverlayInventory(top); err != nil {
			b.Fatal(err)
		}
	}
}

// TestScaleConfigurationReadBackCost quantifies the round-trips the fresh
// container shortcut removes on the release-gate topology. Every rendered file
// used to cost one read-back before its write, and on containerd both halves
// are a full container exec, so the saving is one exec per rendered file per
// from-scratch deployment.
func TestScaleConfigurationReadBackCost(t *testing.T) {
	top := scaleTopology(t)
	renderer := render.New(top, render.ModePlatform)
	for _, node := range []string{"node-0", "node-1", "node-2"} {
		files, devices, worst := 0, 0, 0
		for _, d := range top.DevicesOnNode(node) {
			rendered, err := renderer.Files(d)
			if err != nil {
				t.Fatal(err)
			}
			devices++
			files += len(rendered)
			if len(rendered) > worst {
				worst = len(rendered)
			}
		}
		if files == 0 {
			t.Fatalf("%s rendered no platform files, so the saving is untested", node)
		}
		t.Logf("%s: %d devices, %d rendered files, %d on the single largest device; "+
			"a from-scratch deployment no longer reads any of them back before writing",
			node, devices, files, worst)
		// The largest device's files are written one after another inside a
		// single plan step, so halving its round-trips shortens the longest
		// serial section of the apply phase rather than only its total work.
		if worst < 100 {
			t.Fatalf("%s largest device renders only %d files; the serial tail this "+
				"guards is not present in the fixture", node, worst)
		}
	}
}
