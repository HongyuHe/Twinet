package agent

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// reconcileEvery is how often the node checks that its containers still look
// the way the lab says they should.
//
// A minute is short enough that a student who restarted a router sees it come
// back before they have finished reading the error, and long enough that the
// check costs nothing measurable next to the lab itself.
const reconcileEvery = time.Minute

// reconcileLoop repairs devices that have lost their wiring.
//
// A container that restarts -- because someone typed `docker restart`, because
// it ran out of memory, because the host rebooted -- comes back with an empty
// network namespace. Every interface is gone; only lo and the kernel's sit0
// remain. The container is running, its health check may even pass, and it can
// reach nothing at all.
//
// Nothing used to notice. The wiring is idempotent and a deploy would put it
// back, but a deploy only runs when a person runs one, and the person has no
// reason to until the symptom is reported. Between those two moments the device
// is a black hole in the middle of somebody's assignment, and the most likely
// conclusion they draw is that their own configuration is at fault.
func (s *Server) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reconcileOnce(ctx)
		}
	}
}

func (s *Server) reconcileOnce(ctx context.Context) {
	s.mu.Lock()
	labs := make(map[string]*model.Topology, len(s.current))
	for name, top := range s.current {
		labs[name] = top
	}
	s.mu.Unlock()

	for name, top := range labs {
		if top == nil {
			continue
		}
		// The survey runs without the lab lock. Holding it for the whole scan
		// made a background maintenance task block the operator: a deploy
		// arriving mid-sweep was refused with "another operation is already
		// running", for a sweep that in the normal case finds nothing to do.
		// Reading a container's interface list changes nothing, so it does not
		// need to exclude anyone.
		broken := s.survey(ctx, top)
		if len(broken) == 0 {
			continue
		}
		// Repairing does change things, so it takes the lock -- and yields
		// immediately if a deploy or a destroy holds it, because whatever they
		// are doing is a better answer than this loop's.
		if err := s.acquire(name, "reconcile"); err != nil {
			continue
		}
		s.repairLab(ctx, top, broken)
		s.release(name)
	}
}

// survey reports which of this node's devices have lost their wiring.
func (s *Server) survey(ctx context.Context, top *model.Topology) []*model.Device {
	var broken []*model.Device
	for _, d := range top.Devices {
		if d.Node != s.cfg.Node {
			continue
		}
		if s.hasLostItsWiring(ctx, d) {
			broken = append(broken, d)
		}
	}
	return broken
}

// repairLab rewires the devices whose namespaces have been emptied, and puts
// back the configuration they were holding.
func (s *Server) repairLab(ctx context.Context, top *model.Topology, broken []*model.Device) {
	// Re-checked under the lock: the survey ran without it, so a deploy may
	// have repaired these already in the meantime, and rewiring a device that
	// is now fine would undo work rather than restore it.
	still := make([]*model.Device, 0, len(broken))
	for _, d := range broken {
		if s.hasLostItsWiring(ctx, d) {
			still = append(still, d)
		}
	}
	broken = still
	if len(broken) == 0 {
		return
	}

	names := make([]string, len(broken))
	for i, d := range broken {
		names[i] = d.ID
	}
	slog.Warn("devices are not as the lab says they should be; repairing",
		"lab", top.Name, "devices", strings.Join(names, ","),
		"reason", s.brokenBecause(ctx, broken[0]))

	// The engine needs a renderer.
	//
	// Without one, configure() returns success having done nothing, so a
	// repaired router came back with its cables and none of its configuration:
	// no addresses on the VLAN sub-interfaces, no tunnel, and FRR not running.
	// The device then had enough interfaces to look healthy to the detector
	// below, so it was never revisited. A restarted router stayed broken
	// forever while the logs said it had been repaired.
	//
	// Platform mode, never solve: this rebuilds what Twinet owns. Anything the
	// student wrote comes back from the snapshot store instead, which is the
	// only copy of it that exists.
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, State: s.store,
		Renderer:     render.New(top, render.ModePlatform),
		UnderlayIP:   s.cfg.UnderlayIP,
		UnderlayDev:  s.cfg.UnderlayDev,
		PeerUnderlay: s.peerUnderlay(top.Name),
	}
	for _, d := range broken {
		if err := eng.RewireDevice(ctx, top, d); err != nil {
			slog.Error("rewiring failed", "device", d.ID, "err", err)
			continue
		}
		if _, err := deploy.Restore(ctx, s.rt, d, top.Name, s.store); err != nil {
			slog.Error("configuration could not be put back after rewiring",
				"device", d.ID, "err", err)
			continue
		}
		// Confirmed, not assumed. A repair that reports success without being
		// checked is how the previous version of this loop claimed to have
		// fixed routers it had left with no addresses and no routing daemon.
		if why := s.brokenBecause(ctx, d); why != "" {
			slog.Error("device is still not right after being repaired",
				"device", d.ID, "reason", why)
			continue
		}
		slog.Info("device repaired and its configuration put back", "device", d.ID)
	}
}

// hasLostItsWiring reports whether a running container is missing something the
// lab says it should have.
//
// Counting interfaces is not enough, and believing it was hid a real failure:
// a repaired router had its cables back and nothing else -- no addresses, no
// VLAN sub-interfaces, no tunnel, and no routing daemon -- but the count said
// it was fine, so it was never looked at again. The check therefore asks for
// each thing separately and reports a device as broken if any of them is
// missing.
func (s *Server) hasLostItsWiring(ctx context.Context, d *model.Device) bool {
	return s.brokenBecause(ctx, d) != ""
}

// brokenBecause names the first thing a device is missing, or "" if it is well.
func (s *Server) brokenBecause(ctx context.Context, d *model.Device) string {
	want := map[string]bool{}
	for _, i := range d.Ifaces {
		if i.Link != nil || i.VLAN > 0 {
			want[i.Name] = true
		}
	}
	if len(want) == 0 {
		return ""
	}
	c, err := s.rt.Inspect(ctx, d.Container)
	if err != nil || !c.State.Joinable() {
		return ""
	}

	res, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{
		Cmd: []string{"sh", "-c", `ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1`}})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	have := map[string]bool{}
	for _, n := range strings.Fields(res.Stdout) {
		have[n] = true
	}
	// A device with none of its interfaces is unambiguously broken. A device
	// missing some of them is far more likely to be a deploy in progress, and
	// rewiring underneath one would be worse than waiting for the next tick.
	present := 0
	for n := range want {
		if have[n] {
			present++
		}
	}
	switch {
	case present == 0:
		return "it has none of its interfaces"
	case present < len(want):
		// Not acted on, but worth saying: a device that stays here is stuck.
		return ""
	}

	// The interfaces are there. A router still needs its daemons: after a
	// restart the namespace is new and FRR is not running in it, and vtysh
	// cannot reach anything.
	if d.Kind == model.KindRouter {
		if r, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "vtysh -c 'show version' >/dev/null 2>&1 && echo up"}}); err == nil &&
			!strings.Contains(r.Stdout, "up") {
			return "its routing daemons are not answering"
		}
	}
	if d.Kind == model.KindSwitch {
		if r, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "ovs-vsctl list-br 2>/dev/null | grep -c ."}}); err == nil &&
			strings.TrimSpace(r.Stdout) == "0" {
			return "it has no bridge"
		}
	}
	return ""
}

// peerUnderlay returns the VTEP addresses recorded for a lab.
func (s *Server) peerUnderlay(lab string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peers[lab]
}
