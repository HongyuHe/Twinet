package agent

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
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
	slog.Warn("devices came back with an empty network namespace; rewiring",
		"lab", top.Name, "devices", strings.Join(names, ","))

	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, State: s.store,
		UnderlayIP: s.cfg.UnderlayIP, UnderlayDev: s.cfg.UnderlayDev,
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
		slog.Info("device rewired and its configuration put back", "device", d.ID)
	}
}

// hasLostItsWiring reports whether a running container is missing interfaces
// the lab says it should have.
//
// Only a container that should have interfaces and has none is treated as
// broken. A partially wired device is left alone: it is far more likely to be a
// deploy in progress than a failure, and rewiring underneath one would be worse
// than waiting for the next tick.
func (s *Server) hasLostItsWiring(ctx context.Context, d *model.Device) bool {
	want := 0
	for _, i := range d.Ifaces {
		if i.Link != nil {
			want++
		}
	}
	if want == 0 {
		return false
	}
	c, err := s.rt.Inspect(ctx, d.Container)
	if err != nil || !c.State.Joinable() {
		return false
	}
	res, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "ip -o link show 2>/dev/null | wc -l"}})
	if err != nil || res.ExitCode != 0 {
		return false
	}
	// lo and the kernel's own sit0 are always present and are not wiring.
	return strings.TrimSpace(res.Stdout) == "2" || strings.TrimSpace(res.Stdout) == "1"
}

// peerUnderlay returns the VTEP addresses recorded for a lab.
func (s *Server) peerUnderlay(lab string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peers[lab]
}
