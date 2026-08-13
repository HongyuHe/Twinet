package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// fakeRuntime answers exec with whatever the test says the container would.
type fakeRuntime struct {
	rt.Runtime
	// links is the interface listing, already reduced to bare names, which is
	// what the command the agent runs produces.
	links   string
	running map[string]bool
	started bool
}

func (f *fakeRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (f *fakeRuntime) Exec(_ context.Context, _ string, c rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(c.Cmd, " ")
	switch {
	case strings.Contains(body, "ip -o link show"):
		return rt.ExecResult{Stdout: f.links}, nil
	case strings.Contains(body, "frrinit.sh start"):
		f.started = true
		for _, d := range render.EnabledDaemons() {
			f.running[d] = true
		}
		return rt.ExecResult{}, nil
	case strings.Contains(body, "pidof"):
		var missing []string
		for _, d := range render.EnabledDaemons() {
			if !f.running[d] {
				missing = append(missing, d)
			}
		}
		return rt.ExecResult{Stdout: " " + strings.Join(missing, " ") + "\n"}, nil
	}
	return rt.ExecResult{}, nil
}

func routerWithTwoCables() *model.Device {
	d := &model.Device{ID: "as1/ATL", Name: "ATL", Kind: model.KindRouter, Container: "c"}
	d.Ifaces = []*model.Iface{
		{Name: "port_BOS", Link: &model.Link{}},
		{Name: "port_CHI", Link: &model.Link{}},
	}
	return d
}

// The check for a router's routing daemons used to be `vtysh -c "show
// version"`, which answers as long as any one daemon is up. A router with
// zebra alive and ospfd and bgpd dead therefore looked healthy to the repair
// loop and was never revisited.
//
// It is not hypothetical: thirty-odd routers were found in that state in a
// class-scale lab, and the symptom was students being marked down because
// their neighbours had no routing process.
func TestARouterWithZebraAloneIsNotHealthy(t *testing.T) {
	f := &fakeRuntime{
		links:   "lo\nport_BOS\nport_CHI\n",
		running: map[string]bool{"zebra": true},
	}
	s := &Server{rt: f}
	s.cfg.Node = "node-0"

	why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables())
	if why == "" {
		t.Fatal("a router running only zebra was reported healthy. OSPF and BGP " +
			"cannot come up on it, and the failure will appear on its neighbours.")
	}
	if !strings.HasPrefix(why, daemonsDown) {
		t.Errorf("the reason given was %q, which does not identify this as dead daemons, "+
			"so the repair will rewire the device instead of starting them", why)
	}
	for _, want := range []string{"ospfd", "bgpd"} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason does not name %s: %q", want, why)
		}
	}
}

func TestARouterRunningEverythingIsHealthy(t *testing.T) {
	running := map[string]bool{}
	for _, d := range render.EnabledDaemons() {
		running[d] = true
	}
	f := &fakeRuntime{
		links:   "lo\nport_BOS\nport_CHI\n",
		running: running,
	}
	s := &Server{rt: f}
	s.cfg.Node = "node-0"

	if why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables()); why != "" {
		t.Errorf("a healthy router was reported broken: %q", why)
	}
}

// Starting the daemons is the proportionate repair: the device has its cables,
// so rewiring it would re-render its configuration, and in a lab deployed at
// the reference that throws the reference solution away.
func TestDeadDaemonsAreStartedRatherThanTheDeviceRebuilt(t *testing.T) {
	f := &fakeRuntime{
		links:   "lo\nport_BOS\nport_CHI\n",
		running: map[string]bool{"zebra": true},
	}
	s := &Server{rt: f}
	s.cfg.Node = "node-0"

	if err := s.startDaemons(context.Background(), "lab", routerWithTwoCables()); err != nil {
		t.Fatalf("starting the daemons: %v", err)
	}
	if !f.started {
		t.Error("frrinit.sh was never run")
	}
	if why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables()); why != "" {
		t.Errorf("the router is still reported broken after the repair: %q", why)
	}
}

// A device missing some of its interfaces is usually a deploy in progress, so
// it is given time. But it used to be given for ever: the state was recognised,
// named in a comment, and reported as healthy, so a device that lost one cable
// of six stayed that way until somebody redeployed. Its neighbours failed to
// reach through it and the marks landed on them.
func TestADeviceMissingOneCableIsEventuallyRepaired(t *testing.T) {
	f := &fakeRuntime{
		// port_CHI is gone; port_BOS is still there.
		links:   "lo\nport_BOS\n",
		running: map[string]bool{},
	}
	for _, d := range render.EnabledDaemons() {
		f.running[d] = true
	}
	s := &Server{rt: f, partial: map[string]int{}}
	s.cfg.Node = "node-0"

	for i := 1; i < partialWiringGrace; i++ {
		if why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables()); why != "" {
			t.Fatalf("survey %d reported the device broken (%q); a deploy in progress "+
				"would be rewired underneath itself", i, why)
		}
	}
	why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables())
	if why == "" {
		t.Fatal("a device that has been missing an interface across every survey is " +
			"still reported healthy, so nothing will ever put the cable back")
	}
	if !strings.Contains(why, "port_CHI") {
		t.Errorf("the reason does not name the missing interface: %q", why)
	}
}

// A device that gets its interface back must not carry the count forward.
func TestADeviceThatRecoversStartsAgain(t *testing.T) {
	f := &fakeRuntime{links: "lo\nport_BOS\n", running: map[string]bool{}}
	for _, d := range render.EnabledDaemons() {
		f.running[d] = true
	}
	s := &Server{rt: f, partial: map[string]int{}}
	s.cfg.Node = "node-0"

	s.brokenBecause(context.Background(), "cos461", routerWithTwoCables())
	f.links = "lo\nport_BOS\nport_CHI\n"
	if why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables()); why != "" {
		t.Fatalf("a fully wired device was reported broken: %q", why)
	}
	f.links = "lo\nport_BOS\n"
	if why := s.brokenBecause(context.Background(), "cos461", routerWithTwoCables()); why != "" {
		t.Errorf("a device that had recovered and then lost a cable again was reported "+
			"broken on the first survey (%q); the count should have restarted", why)
	}
}
