package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
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
		// An external operation -- grading, most often -- has asked to be left
		// alone with this lab. It is deliberately manipulating devices, and a
		// device mid-manipulation is indistinguishable from a broken one.
		if who := s.heldBy(name); who != "" {
			slog.Debug("leaving lab alone while it is held",
				"lab", name, "holder", who)
			continue
		}
		// The survey runs without the lab lock. Holding it for the whole scan
		// made a background maintenance task block the operator: a deploy
		// arriving mid-sweep was refused with "another operation is already
		// running", for a sweep that in the normal case finds nothing to do.
		// Reading a container's interface list changes nothing, so it does not
		// need to exclude anyone.
		// A lab whose containers have all gone is a lab that was removed, and
		// this node was never told. Its record kept the repair loop trying to
		// rewire devices whose peers no longer exist, once a minute, for as
		// long as the node was up -- four such labs were found on one cluster,
		// with 461 leftover overlay devices between them.
		//
		// Forgetting it is safe in the only direction that matters: if the lab
		// is redeployed, the deployment sends the topology again.
		if s.labIsGone(ctx, top) {
			slog.Info("forgetting a lab whose containers have all been removed",
				"lab", name)
			s.forgetLab(name)
			continue
		}

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
		// A device that was broken on purpose is not a device to repair. The
		// record lives on this node rather than in the container, because a
		// marker inside the device under test tells an agent being evaluated
		// on root-cause analysis that a fault was injected.
		if s.isExempt(top.Name, d.ID) {
			continue
		}
		if s.hasLostItsWiring(ctx, top.Name, d) {
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
		if s.hasLostItsWiring(ctx, top.Name, d) {
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
		"reason", s.brokenBecause(ctx, top.Name, broken[0]))

	// The engine needs a renderer.
	//
	// Without one, configure() returns success having done nothing, so a
	// repaired router came back with its cables and none of its configuration:
	// no addresses on the VLAN sub-interfaces, no tunnel, and FRR not running.
	// The device then had enough interfaces to look healthy to the detector
	// below, so it was never revisited. A restarted router stayed broken
	// forever while the logs said it had been repaired.
	//
	// Rendered in whatever mode the lab was applied with.
	//
	// It was always platform mode, on the reasoning that anything a student
	// wrote comes back from the snapshot store. That is right for a teaching
	// lab and wrong for a lab deployed at the reference, which is what every
	// grading run uses: repairing one router there re-rendered it without the
	// reference solution, so a class was graded against a network in which
	// some systems had quietly stopped being the answer they were meant to be.
	// Nothing reported it, because the repair itself succeeded.
	// The mode alone is not enough. A private grading harness is deployed
	// solved *except* for the one system being marked, which keeps the
	// platform's starting configuration; replaying only "solve" rebuilds that
	// system holding the reference answer, for the student whose work is being
	// marked against it, and reports the repair as a success.
	s.mu.Lock()
	mode := s.modes[top.Name]
	ungraded := s.ungraded[top.Name]
	s.mu.Unlock()
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, State: s.store,
		Renderer:        renderer(top, render.Mode(mode), ungraded),
		WritesReference: render.Mode(mode) == render.ModeSolve,
		UnderlayIP:      s.cfg.UnderlayIP,
		UnderlayDev:     s.cfg.UnderlayDev,
		PeerUnderlay:    s.peerUnderlay(top.Name),
	}
	for _, d := range broken {
		if s.givingUpOn(top.Name, d.ID) {
			continue
		}
		// A router whose cables are all present and whose daemons have died
		// needs the daemons started, not the device rebuilt. Rewiring it would
		// re-render its configuration in platform mode, which in a lab
		// deployed at the reference throws the reference solution away -- a
		// far worse outcome than the fault being repaired.
		if why := s.brokenBecause(ctx, top.Name, d); strings.HasPrefix(why, daemonsDown) {
			if err := s.startDaemons(ctx, top.Name, d); err != nil {
				slog.Error("routing daemons could not be started", "device", d.ID, "err", err)
				continue
			}
			slog.Info("routing daemons restarted", "device", d.ID)
			continue
		}
		if err := eng.RewireDevice(ctx, top, d); err != nil {
			s.repairFailed(top.Name, d.ID, "rewiring failed", err)
			continue
		}
		// Not while the lab is deployed at the reference.
		//
		// The deployment path has refused this for a while; the repair loop
		// did it anyway. Replaying a student's snapshot over a solved router
		// leaves that system holding somebody's old work while the class is
		// being marked against it -- and every check on it passes, because it
		// is a converged network, just not the answer. A repair runs
		// unattended every few seconds, so this needed no unusual sequence of
		// events to happen.
		if !eng.WritesReference {
			if _, err := deploy.Restore(ctx, s.rt, d, top.Name, s.store); err != nil {
				s.repairFailed(top.Name, d.ID, "configuration could not be put back after rewiring", err)
				continue
			}
		}
		// Confirmed, not assumed. A repair that reports success without being
		// checked is how the previous version of this loop claimed to have
		// fixed routers it had left with no addresses and no routing daemon.
		if why := s.brokenBecause(ctx, top.Name, d); why != "" {
			s.repairFailed(top.Name, d.ID, "device is still not right after being repaired",
				errors.New(why))
			continue
		}
		s.repairSucceeded(top.Name, d.ID)
		slog.Info("device repaired and its configuration put back", "device", d.ID)
	}
}

// daemonsDown prefixes the reason a router is broken when the only thing wrong
// with it is that its routing processes are not running. The repair for that is
// to start them, not to rewire the device, so the two cases are told apart.
const daemonsDown = "these routing daemons are not running:"

// missingDaemons names the routing processes a router should be running and is
// not, or "" when they are all there.
func (s *Server) missingDaemons(ctx context.Context, d *model.Device, as *model.AS) string {
	script := "miss=''; for p in " + strings.Join(render.EnabledDaemonsFor(as), " ") +
		"; do pidof \"$p\" >/dev/null 2>&1 || miss=\"$miss $p\"; done; echo \"$miss\""
	r, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil || r.ExitCode != 0 {
		// Not reachable is not the same as not running, and guessing here
		// would have the loop rewiring devices because a node was busy.
		return ""
	}
	return strings.TrimRight(strings.TrimLeft(r.Stdout, " "), " \n")
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
func (s *Server) hasLostItsWiring(ctx context.Context, lab string, d *model.Device) bool {
	return s.brokenBecause(ctx, lab, d) != ""
}

// brokenBecause names the first thing a device is missing, or "" if it is well.
func (s *Server) brokenBecause(ctx context.Context, lab string, d *model.Device) string {
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
		// A device missing some of its interfaces is usually a deploy in
		// progress, and rewiring underneath one would be worse than waiting.
		// But it used to wait for ever: the state was recognised, named in a
		// comment, and then reported as healthy, so a device that lost one
		// cable of six stayed that way until somebody redeployed. Its
		// neighbours failed to reach through it, and the marks landed on them.
		//
		// So it is given time to be a deploy, and repaired if it is not. The
		// count is per device, and cleared as soon as the device is whole.
		if s.partiallyWiredFor(lab, d.ID) < partialWiringGrace {
			return ""
		}
		missing := make([]string, 0, len(want)-present)
		for n := range want {
			if !have[n] {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		return "it is missing " + strings.Join(missing, ", ")
	}
	s.wholeAgain(lab, d.ID)

	// The interfaces are there. A router still needs its daemons: after a
	// restart the namespace is new and FRR is not running in it.
	//
	// Each daemon is asked for by name. This used to run `vtysh -c "show
	// version"`, which answers as long as *any* daemon is up -- so a router
	// with zebra alive and ospfd and bgpd dead was reported healthy and never
	// looked at again. Thirty-odd routers were found in exactly that state,
	// and the only symptom was students being marked down for neighbours that
	// had no routing process.
	if d.Kind == model.KindRouter {
		as := s.asOf(lab, d)
		if missing := s.missingDaemons(ctx, d, as); missing != "" {
			return daemonsDown + missing
		}
		if dup := s.duplicateDaemons(ctx, d, as); dup != "" {
			return daemonsDown + " duplicated: " + dup
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

// startDaemons brings FRR back up on a router whose processes have died.
//
// Safe on a student's router because FRR reads its configuration from the file
// it was given, so starting a dead daemon restores what was there rather than
// replacing it.
func (s *Server) startDaemons(ctx context.Context, lab string, d *model.Device) error {
	// Stopped properly before being started.
	//
	// This used to kill watchfrr, delete the pid files, and start. Deleting the
	// pid files is what made it wrong: the init script then has no idea the
	// daemons are already running, so it starts a second copy of every one of
	// them. Four zebras were found in one container that way, and the symptom
	// is not a crash -- it is a router whose FRR configuration is correct, whose
	// running-config shows the address, and whose kernel interface never gets
	// it, because the zebra that owns the netlink socket is not the one holding
	// the configuration. Six routers of one system were in that state and every
	// grading run marked their owner down for it.
	script := strings.Join([]string{
		// watchfrr outlives a plain stop and holds the pid lock.
		"for p in $(ps -ef | awk '/watchfrr/ && !/awk/ {print $1}'); do kill $p 2>/dev/null || true; done",
		"/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true",
		// Anything that survived the stop, by name, because starting on top of
		// a live daemon is the failure above.
		"for p in $(ps -ef | awk '/usr\\/lib\\/frr\\// && !/awk/ && !/frrinit/ {print $1}'); do kill $p 2>/dev/null || true; done",
		"sleep 1",
		"rm -f /var/run/frr/*.pid /var/run/frr/*.vty 2>/dev/null || true",
		"/usr/lib/frr/frrinit.sh start >/dev/null 2>&1 || true",
	}, "\n")
	if _, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}}); err != nil {
		return err
	}
	// And given time to come up.
	//
	// frrinit.sh returns before the daemons have forked and written their pid
	// files, so asking immediately answered "still not running" for daemons
	// that were seconds from being up. The repair reported failure three times
	// and gave up on routers that had in fact recovered, while the logs said
	// they could not be started.
	as := s.asOf(lab, d)
	var missing string
	for i := 0; i < 20; i++ {
		missing = s.missingDaemons(ctx, d, as)
		if missing == "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("still not running:%s", missing)
}

// duplicateDaemons names routing processes a router is running more than one
// copy of.
//
// Two zebras is not a redundant router, it is a broken one: they compete for
// the same netlink socket and the same interface state, and the loser's
// configuration is applied to nothing. It produces a device whose files and
// whose running-config are both correct and whose kernel is not, which is
// indistinguishable from a student mistake and was being marked as one.
func (s *Server) duplicateDaemons(ctx context.Context, d *model.Device, as *model.AS) string {
	var dup []string
	for _, name := range render.EnabledDaemonsFor(as) {
		// The daemon proper, which is the one started with -d.
		//
		// Matching the name alone counted ldpd's two privilege-separated
		// children -- "ldpd -L" and "ldpd -E", which every healthy router
		// with LDP has -- as two extra copies of ldpd. Every router in the
		// lab was then declared broken and restarted, for ever, and the
		// symptom was a class whose marks fell a little further every time
		// it was graded.
		script := "ps -ef | awk '/usr\\/lib\\/frr\\/" + name + " -d/ && !/awk/' | wc -l"
		r, err := s.rt.Exec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
		if err != nil || r.ExitCode != 0 {
			return ""
		}
		n, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
		if err != nil {
			return ""
		}
		if n > 1 {
			dup = append(dup, fmt.Sprintf("%s (%d)", name, n))
		}
	}
	if len(dup) == 0 {
		return ""
	}
	sort.Strings(dup)
	return strings.Join(dup, " ")
}

// Repairs that cannot succeed are attempted a few times and then left alone.
//
// A lab that is half removed -- the routers gone, their attached hosts still
// running -- cannot be rewired: the other end of every cable is a container
// that no longer exists. The loop retried each of those devices every minute
// for as long as the node was up, filling the log with identical failures and
// doing the work of a full survey on a lab nobody was using. Four such labs
// were found on one node, left behind by grading runs whose cleanup had not
// finished, and the noise made the one lab that was genuinely broken hard to
// see.
//
// Giving up is recorded once, loudly, naming the device. It is not silence:
// somebody has to remove the remains, and the message says so. A later
// successful repair clears the count, so a device that recovers by itself is
// looked after again without anything having to be restarted.
const repairAttemptsBeforeGivingUp = 3

// repairKey identifies a device within its lab.
//
// Keying on the device alone was wrong in a way that only shows up at class
// scale: every private grading harness contains as3/ATL, and so does the class
// lab. Three failed repairs in an abandoned harness therefore switched off
// self-repair for the real device of the same name, in the lab a class is
// being taught in, and nothing said so.
func repairKey(lab, id string) string { return lab + "|" + id }

func (s *Server) givingUpOn(lab, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repairFails[repairKey(lab, id)] >= repairAttemptsBeforeGivingUp
}

func (s *Server) repairFailed(lab, id, what string, err error) {
	k := repairKey(lab, id)
	s.mu.Lock()
	s.repairFails[k]++
	n := s.repairFails[k]
	s.mu.Unlock()

	slog.Error(what, "lab", lab, "device", id, "err", err, "attempt", n)
	if n == repairAttemptsBeforeGivingUp {
		slog.Error("giving up on repairing this device; it will be left as it is until "+
			"something deploys or removes it. A device whose peers no longer exist cannot "+
			"be rewired, and a lab in that state needs removing rather than repairing",
			"lab", lab, "device", id, "attempts", n)
	}
}

func (s *Server) repairSucceeded(lab, id string) {
	s.mu.Lock()
	delete(s.repairFails, repairKey(lab, id))
	s.mu.Unlock()
}

// labIsGone reports whether none of a lab's devices on this node still exist.
//
// "None at all" rather than "some", deliberately. A lab midway through being
// deployed, or one whose containers are stopped, must not be forgotten -- the
// record is what a restart needs in order to bring them back. Only a lab with
// nothing left of it on this node is one that has been removed.
func (s *Server) labIsGone(ctx context.Context, top *model.Topology) bool {
	mine := 0
	for _, d := range top.Devices {
		if d.Node != s.cfg.Node {
			continue
		}
		mine++
		c, err := s.rt.Inspect(ctx, d.Container)
		if err != nil {
			// Unreadable is not absent, and guessing here would throw away the
			// record of a live lab because the runtime was busy.
			return false
		}
		if c.State != rt.StateAbsent {
			return false
		}
	}
	return mine > 0
}

// forgetLab drops everything this node remembers about a lab.
func (s *Server) forgetLab(name string) {
	s.mu.Lock()
	delete(s.current, name)
	delete(s.modes, name)
	delete(s.ungraded, name)
	delete(s.peers, name)
	delete(s.exempt, name)
	for k := range s.repairFails {
		if strings.HasPrefix(k, name+"|") {
			delete(s.repairFails, k)
		}
	}
	for k := range s.partial {
		if strings.HasPrefix(k, name+"|") {
			delete(s.partial, k)
		}
	}
	store := s.store
	s.mu.Unlock()

	if store != nil {
		if err := store.ForgetTopology(name); err != nil {
			slog.Warn("removing the record of a lab that is gone", "lab", name, "err", err)
		}
	}
}

// partialWiringGrace is how many surveys a device may be missing some of its
// interfaces before it is treated as broken rather than as mid-deployment.
//
// Three surveys is three minutes, which is longer than any deploy takes to
// wire one device and far shorter than the "until somebody notices" that this
// replaced.
const partialWiringGrace = 3

// partiallyWiredFor counts consecutive surveys in which a device has been
// missing some of its interfaces.
// Keyed by lab and device, like the repair counter beside it.
//
// Device identifiers repeat by design: every private grading harness contains
// as3/ATL and so does the class lab. Keyed on the device alone, one lab's
// surveys advanced another's count and one lab's recovery cleared it, so a
// device could be rewired during its own deployment or never repaired at all,
// depending on what else the node happened to be running.
func (s *Server) partiallyWiredFor(lab, id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.partial == nil {
		s.partial = map[string]int{}
	}
	k := repairKey(lab, id)
	s.partial[k]++
	return s.partial[k]
}

// wholeAgain forgets that a device was ever partially wired.
func (s *Server) wholeAgain(lab, id string) {
	s.mu.Lock()
	delete(s.partial, repairKey(lab, id))
	s.mu.Unlock()
}

// asOf returns the autonomous system a device belongs to in a lab this node
// currently holds, or nil when the node has no record of it. It exists so that
// a per-AS decision -- which routing daemons should be running -- is made from
// the same declaration the renderer used.
func (s *Server) asOf(lab string, d *model.Device) *model.AS {
	if d == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	top, ok := s.current[lab]
	if !ok || top == nil {
		return nil
	}
	return top.ASes[d.ASN]
}
