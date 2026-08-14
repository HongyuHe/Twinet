package cli

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func deviceWithCables() []*model.Device {
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}
	d.Ifaces = []*model.Iface{
		{Name: "port_BOS", Link: &model.Link{}},
		{Name: "ATL-L2.10", VLAN: 10},
	}
	return []*model.Device{d}
}

// Rewiring removes an interface and adds it back, so for a moment during any
// deploy or repair the interface genuinely is not there. Loading a submission
// in that moment failed on its first line and quarantined its owner -- seven of
// eight students in one recorded class run. The condition is temporary by
// construction, so the right answer is to wait for it.
func TestLoadingWaitsOutATransientlyMissingInterface(t *testing.T) {
	var calls atomic.Int32
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		// The interface comes back on the third look, as it would when
		// whatever removed it finishes putting it back.
		if calls.Add(1) < 3 {
			return rt.ExecResult{Stdout: "lo\nATL-L2.10\n"}, nil
		}
		return rt.ExecResult{Stdout: "lo\nport_BOS\nATL-L2.10\n"}, nil
	}

	start := time.Now()
	if err := waitForWiring(context.Background(), exec, deviceWithCables(), 30*time.Second); err != nil {
		t.Fatalf("gave up on an interface that came back after %v: %v", time.Since(start), err)
	}
	if calls.Load() < 3 {
		t.Errorf("returned after %d checks without ever seeing the interface", calls.Load())
	}
}

// Waiting forever would be worse than failing: a genuinely absent interface
// produces the same symptom, and a grading run that hangs with no output is
// harder to diagnose than one that stops and names the device.
func TestAnInterfaceThatNeverComesBackIsReported(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{Stdout: "lo\nATL-L2.10\n"}, nil
	}
	err := waitForWiring(context.Background(), exec, deviceWithCables(), 3*time.Second)
	if err == nil {
		t.Fatal("waiting succeeded for an interface that was never there")
	}
	for _, want := range []string{"as3/ATL", "port_BOS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not name %s, so it does not say where to look: %v",
				want, err)
		}
	}
}

func TestAFullyWiredDeviceIsNotWaitedFor(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{Stdout: "lo\nport_BOS\nATL-L2.10\n"}, nil
	}
	start := time.Now()
	if err := waitForWiring(context.Background(), exec, deviceWithCables(), 30*time.Second); err != nil {
		t.Fatalf("a fully wired device was waited for: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("checking a healthy device took %v", d)
	}
}
