package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// faultedRuntime is a container that is broken on purpose.
type faultedRuntime struct {
	rt.Runtime
	marked  bool
	repairs int
}

func (f *faultedRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (f *faultedRuntime) Exec(_ context.Context, _ string, c rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(c.Cmd, " ")
	switch {
	case strings.Contains(body, "test -f "+fault.InjectedMarker):
		if !f.marked {
			return rt.ExecResult{ExitCode: 1}, nil
		}
		return rt.ExecResult{}, nil
	case strings.Contains(body, "ip -o link show"):
		return rt.ExecResult{Stdout: "lo\nport_BOS\n"}, nil
	case strings.Contains(body, "frrinit.sh start"):
		f.repairs++
		return rt.ExecResult{}, nil
	case strings.Contains(body, "pidof"):
		// Every routing daemon is dead: this is the injected fault.
		return rt.ExecResult{Stdout: " " + strings.Join(render.EnabledDaemons(), " ") + "\n"}, nil
	}
	return rt.ExecResult{}, nil
}

func faultedRouter() *model.Device {
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, Container: "c"}
	d.Ifaces = []*model.Iface{{Name: "port_BOS", Link: &model.Link{}}}
	return d
}

// Stopping a routing daemon is a supported fault. The repair loop restarted it
// within the minute, so an episode kept open for somebody to diagnose lost its
// fault while the recorded ground truth went on saying the fault was live.
// Every answer graded against that truth is wrong, and nothing reports it.
func TestADeliberatelyBrokenDeviceIsNotRepaired(t *testing.T) {
	f := &faultedRuntime{marked: true}
	s := &Server{rt: f}
	s.cfg.Node = "node-0"

	if why := s.brokenBecause(context.Background(), faultedRouter()); why != "" {
		t.Fatalf("a device carrying an injected fault was reported as broken (%q), so the "+
			"repair loop will undo the fault and the episode's ground truth becomes a lie", why)
	}
}

// The exemption must be exactly as narrow as the fault. A device that is broken
// by accident still has to be repaired.
func TestADeviceBrokenByAccidentIsStillRepaired(t *testing.T) {
	f := &faultedRuntime{marked: false}
	s := &Server{rt: f}
	s.cfg.Node = "node-0"

	why := s.brokenBecause(context.Background(), faultedRouter())
	if why == "" {
		t.Fatal("a router with every routing daemon dead was reported healthy")
	}
	if !strings.HasPrefix(why, daemonsDown) {
		t.Errorf("the reason given was %q, not dead daemons", why)
	}
}
