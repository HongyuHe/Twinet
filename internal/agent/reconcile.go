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
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Reconciliation is event driven. Audits are deliberately much less frequent
// than the old once-a-minute Docker-inspect-and-exec sweep: lifecycle events
// repair the normal failure path promptly, while samples and full audits catch
// a lost event stream or an out-of-band change.
const (
	reconcileEvery     = 5 * time.Minute
	reconcileFullEvery = 10 * time.Minute
	reconcileRetryMin  = 100 * time.Millisecond
	reconcileRetryMax  = 5 * time.Second
	// semanticSampleWidth bounds the cheap dynamic-state audit fan-out while
	// avoiding a one-device-per-five-minutes blind spot that left an idle
	// recovered host broken for hours.
	semanticSampleWidth = 8
)

type deviceHealth string

const (
	healthHealthy deviceHealth = "healthy"
	healthBroken  deviceHealth = "broken"
	healthUnknown deviceHealth = "unknown"
	healthPartial deviceHealth = "partial"
)

type deviceObservation struct {
	Health      deviceHealth
	Reason      string
	State       rt.State
	SpecMatches bool
}

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
	s.startReconcileWorkers(ctx)
	go s.runtimeEventLoop(ctx)

	// A new agent has no event history before it subscribed. A sampled startup
	// pass closes that gap without immediately turning a cold restart into one
	// exec per device.
	s.reconcileSample(ctx)
	sample := time.NewTicker(reconcileEvery)
	full := time.NewTicker(reconcileFullEvery)
	defer sample.Stop()
	defer full.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sample.C:
			s.reconcileSample(ctx)
		case <-full.C:
			s.reconcileOnce(ctx)
		}
	}
}

// runtimeEventSource returns the native event source when the runtime offers
// one. Tests often inject a Runtime directly, so the fallback is intentional.
func (s *Server) runtimeEventSource() rt.EventSource {
	if s.eventSource != nil {
		return s.eventSource
	}
	source, _ := s.rt.(rt.EventSource)
	return source
}

// runtimeEventLoop reconnects after every terminal event-stream error. A
// stream ending is not proof the host is healthy, so the sampled/full audits
// remain active while reconnect is retried with a bounded delay.
func (s *Server) runtimeEventLoop(ctx context.Context) {
	source := s.runtimeEventSource()
	if source == nil {
		s.recordEvent("", "", "runtime", "", "event_subscription", "unknown",
			"runtime does not expose lifecycle events; audit backstop is active")
		return
	}
	retry := reconcileRetryMin
	for {
		if ctx.Err() != nil {
			return
		}
		streamCtx, cancel := context.WithCancel(ctx)
		start := time.Now()
		subscription := source.Subscribe(streamCtx, rt.EventFilter{
			Labels: map[string]string{deploy.LabelManaged: "true"},
		})
		s.metricRegistry().observeRuntime("subscribe", time.Since(start), nil)
		s.recordEvent("", "", "runtime", "", "event_subscription", "success", "connected")
		retry = reconcileRetryMin

		events, errs := subscription.Events, subscription.Errors
		terminal := error(nil)
		for events != nil || errs != nil {
			select {
			case <-ctx.Done():
				cancel()
				return
			case event, ok := <-events:
				if !ok {
					events = nil
					continue
				}
				s.metricRegistry().observeRuntimeEvent(string(event.Action))
				s.handleRuntimeEvent(ctx, event)
			case err, ok := <-errs:
				if !ok {
					errs = nil
					continue
				}
				terminal = err
				cancel()
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if terminal == nil {
			terminal = rt.ErrEventStreamClosed
		}
		s.metricRegistry().observeRuntime("subscribe", 0, terminal)
		s.recordEvent("", "", "runtime", "", "event_subscription", "error", terminal.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry *= 2
		if retry > reconcileRetryMax {
			retry = reconcileRetryMax
		}
	}
}

func (s *Server) handleRuntimeEvent(ctx context.Context, event rt.Event) {
	lab := event.Labels[deploy.LabelLab]
	if lab == "" {
		lab = s.labOfContainer(event.Name)
	}
	if lab == "" {
		return
	}
	device := event.Labels[deploy.LabelDeviceID]
	if device == "" {
		device = event.Name
	}
	s.recordEvent(lab, event.Labels[deploy.LabelGen], "runtime", "",
		"container."+string(event.Action), "scheduled", device)
	s.queueReconcile(ctx, lab, device)
}

type reconcileRequest struct {
	lab    string
	device string
}

// startReconcileWorkers bounds event-triggered repair fan-out independently
// of the runtime limiter. A Docker reconnect can replay many events; it must
// not create one goroutine per historical device.
func (s *Server) startReconcileWorkers(ctx context.Context) {
	s.reconcileWorkersOnce.Do(func() {
		s.reconcileMu.Lock()
		s.reconcileQueue = make(chan reconcileRequest, 1024)
		s.reconcileContext = ctx
		if s.reconcilePending == nil {
			s.reconcilePending = map[string]bool{}
		}
		queue := s.reconcileQueue
		s.reconcileMu.Unlock()
		for range 4 {
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case request := <-queue:
						s.reconcileTarget(ctx, request)
						s.reconcileMu.Lock()
						delete(s.reconcilePending, repairKey(request.lab, request.device))
						s.reconcileMu.Unlock()
					}
				}
			}()
		}
	})
}

func (s *Server) queueReconcile(ctx context.Context, lab, device string) {
	if lab == "" {
		return
	}
	if reason := s.ordinaryMaintenanceSuppression(lab); reason != "" {
		s.metricRegistry().observeRepair("recovery")
		return
	}
	s.reconcileMu.Lock()
	queue := s.reconcileQueue
	if queue == nil {
		s.reconcileMu.Unlock()
		return
	}
	key := repairKey(lab, device)
	if s.reconcilePending[key] {
		s.reconcileMu.Unlock()
		return
	}
	s.reconcilePending[key] = true
	s.reconcileMu.Unlock()
	request := reconcileRequest{lab: lab, device: device}
	select {
	case queue <- request:
		s.metricRegistry().observeRepair("scheduled")
	case <-ctx.Done():
		s.reconcileMu.Lock()
		delete(s.reconcilePending, key)
		s.reconcileMu.Unlock()
	default:
		// The full audit is the recovery path for a queue overflow. Do not
		// block Docker event intake behind a storm of duplicate deaths.
		s.reconcileMu.Lock()
		delete(s.reconcilePending, key)
		s.reconcileMu.Unlock()
		s.recordEvent(lab, "", "reconcile", "", "repair_queue", "backoff",
			"event repair queue is full; audit backstop will retry")
	}
}

func (s *Server) queueReconcileAfter(lab, device string, delay time.Duration) {
	if delay <= 0 {
		return
	}
	s.reconcileMu.Lock()
	ctx := s.reconcileContext
	queue := s.reconcileQueue
	s.reconcileMu.Unlock()
	if ctx == nil || queue == nil {
		return
	}
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.queueReconcile(ctx, lab, device)
		}
	}()
}

func (s *Server) reconcileTarget(ctx context.Context, request reconcileRequest) {
	if reason := s.ordinaryMaintenanceSuppression(request.lab); reason != "" {
		s.metricRegistry().observeRepair("recovery")
		s.recordEvent(request.lab, "", "reconcile", "", "repair_skipped", "recovery", reason)
		return
	}
	s.mu.Lock()
	top := s.current[request.lab]
	s.mu.Unlock()
	if top == nil {
		return
	}
	if who := s.heldBy(request.lab); who != "" {
		s.metricRegistry().observeRepair("held")
		s.recordEvent(request.lab, "", "reconcile", "", "repair_skipped", "held", who)
		return
	}
	if who := s.mutationLeaseHolder(request.lab); who != "" {
		s.metricRegistry().observeRepair("held")
		s.recordEvent(request.lab, "", "reconcile", "", "repair_skipped", "held", who)
		return
	}
	var devices []*model.Device
	for _, device := range top.SortedDevices() {
		if device.Node != s.cfg.Node {
			continue
		}
		if request.device == "" || request.device == device.ID || request.device == device.Container {
			devices = append(devices, device)
		}
	}
	if len(devices) == 0 {
		return
	}
	broken := make([]*model.Device, 0, len(devices))
	for _, device := range devices {
		if s.isExempt(request.lab, device.ID) {
			s.metricRegistry().observeRepair("exempt")
			continue
		}
		observation := s.observeDevice(ctx, request.lab, device, true)
		s.rememberHealth(request.lab, device.ID, observation)
		switch observation.Health {
		case healthHealthy:
			s.repairSucceeded(request.lab, device.ID)
		case healthBroken:
			broken = append(broken, device)
		case healthUnknown:
			s.metricRegistry().observeRepair("unknown")
		}
	}
	if len(broken) == 0 {
		return
	}
	repairCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	opID, done, err := s.acquireOperation(request.lab, "reconcile", cancel)
	if err != nil {
		return
	}
	defer s.releaseOperation(request.lab, opID, done)
	s.repairLab(repairCtx, top, broken)
}

// rememberHealth keeps only the last bounded state per device. It makes a
// partial or unreadable observation visible in the event stream without
// emitting an event on every sampled audit.
func (s *Server) rememberHealth(lab, device string, observation deviceObservation) {
	key := repairKey(lab, device)
	s.mu.Lock()
	if s.health == nil {
		s.health = map[string]deviceObservation{}
	}
	previous, known := s.health[key]
	s.health[key] = observation
	s.mu.Unlock()
	if known && previous.Health == observation.Health && previous.Reason == observation.Reason {
		return
	}
	result := string(observation.Health)
	if observation.Health == healthHealthy {
		result = "success"
	}
	s.recordEvent(lab, "", "reconcile", "", "device_health", result,
		device+": "+observation.Reason)
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
		if who := s.mutationLeaseHolder(name); who != "" {
			slog.Debug("leaving lab alone while a fenced mutation is active",
				"lab", name, "holder", who)
			continue
		}
		if why := s.ordinaryMaintenanceSuppression(name); why != "" {
			slog.Debug("leaving lab alone while durable recovery owns it",
				"lab", name, "reason", why)
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
		repairCtx, cancel := context.WithCancel(ctx)
		opID, done, err := s.acquireOperation(name, "reconcile", cancel)
		if err != nil {
			cancel()
			continue
		}
		s.repairLab(repairCtx, top, broken)
		cancel()
		s.releaseOperation(name, opID, done)
	}
}

// reconcileSample checks one local device from each lab. It is cheap enough
// to run while an event stream is reconnecting, while reconcileOnce remains
// the low-frequency complete backstop.
func (s *Server) reconcileSample(ctx context.Context) {
	s.mu.Lock()
	labs := make(map[string]*model.Topology, len(s.current))
	for name, top := range s.current {
		labs[name] = top
	}
	s.mu.Unlock()
	for name, top := range labs {
		if top == nil || s.heldBy(name) != "" || s.mutationLeaseHolder(name) != "" ||
			s.ordinaryMaintenanceSuppression(name) != "" {
			continue
		}
		var devices []*model.Device
		for _, device := range top.SortedDevices() {
			if device.Node == s.cfg.Node {
				devices = append(devices, device)
			}
		}
		if len(devices) == 0 {
			continue
		}
		slot := int(time.Now().Unix() / int64(reconcileEvery/time.Second))
		start := (slot * semanticSampleWidth) % len(devices)
		width := semanticSampleWidth
		if width > len(devices) {
			width = len(devices)
		}
		for offset := 0; offset < width; offset++ {
			s.queueReconcile(ctx, name, devices[(start+offset)%len(devices)].ID)
		}
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
			s.metricRegistry().observeRepair("exempt")
			continue
		}
		observation := s.observeDevice(ctx, top.Name, d, true)
		s.rememberHealth(top.Name, d.ID, observation)
		switch observation.Health {
		case healthHealthy:
			// A device which comes back by itself must not retain the failure
			// history accumulated while it was unavailable.
			s.repairSucceeded(top.Name, d.ID)
		case healthUnknown:
			s.metricRegistry().observeRepair("unknown")
		case healthPartial:
			// Partial is explicit and is never called healthy. It receives a
			// short deploy grace, then observeDevice upgrades it to broken.
		case healthBroken:
			broken = append(broken, d)
		}
	}
	return broken
}

// repairLab rewires the devices whose namespaces have been emptied, and puts
// back the configuration they were holding.
func (s *Server) repairLab(ctx context.Context, top *model.Topology, broken []*model.Device) {
	// The hold and fence checks above the survey are intentionally repeated
	// after acquiring the local repair lease. A grader or controller can take
	// either lease in the gap; repairing beneath it would mutate a submission
	// or mix deployment generations.
	if who := s.heldBy(top.Name); who != "" {
		s.metricRegistry().observeRepair("held")
		s.recordEvent(top.Name, "", "reconcile", "", "repair_skipped", "held", who)
		return
	}
	if who := s.mutationLeaseHolder(top.Name); who != "" {
		s.metricRegistry().observeRepair("held")
		s.recordEvent(top.Name, "", "reconcile", "", "repair_skipped", "held", who)
		return
	}
	if reason := s.ordinaryMaintenanceSuppression(top.Name); reason != "" {
		s.metricRegistry().observeRepair("recovery")
		s.recordEvent(top.Name, "", "reconcile", "", "repair_skipped", "recovery", reason)
		return
	}
	if s.repairHook != nil {
		s.repairHook(ctx, top, broken)
		return
	}

	// Re-checked under the lock: the survey ran without it, so a deploy may
	// have repaired these already in the meantime, and rewiring a device that
	// is now fine would undo work rather than restore it.
	still := make([]*model.Device, 0, len(broken))
	for _, d := range broken {
		if s.isExempt(top.Name, d.ID) {
			s.metricRegistry().observeRepair("exempt")
			continue
		}
		observation := s.observeDevice(ctx, top.Name, d, false)
		s.rememberHealth(top.Name, d.ID, observation)
		if observation.Health == healthHealthy {
			s.repairSucceeded(top.Name, d.ID)
			continue
		}
		if observation.Health == healthBroken {
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
	reason := s.observeDevice(ctx, top.Name, broken[0], false).Reason
	slog.Warn("devices are not as the lab says they should be; repairing",
		"lab", top.Name, "devices", strings.Join(names, ","),
		"reason", reason)

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
		Limiter:         s.workLimiter(),
		Renderer:        renderer(top, render.Mode(mode), ungraded),
		WritesReference: render.Mode(mode) == render.ModeSolve,
		UnderlayIP:      s.cfg.UnderlayIP,
		UnderlayDev:     s.cfg.UnderlayDev,
		PeerUnderlay:    s.peerUnderlay(top.Name),
		ModeKey:         rendererModeKey(render.Mode(mode), ungraded),
	}
	for _, d := range broken {
		if reason := s.ordinaryMaintenanceSuppression(top.Name); reason != "" {
			s.metricRegistry().observeRepair("recovery")
			s.recordEvent(top.Name, "", "reconcile", "", "repair_skipped", "recovery", reason)
			return
		}
		if s.givingUpOn(top.Name, d.ID) {
			s.metricRegistry().observeRepair("backoff")
			s.recordEvent(top.Name, "", "reconcile", "", "repair_deferred", "backoff",
				d.ID+" remains in bounded retry backoff")
			continue
		}
		observation := s.observeDevice(ctx, top.Name, d, false)
		if observation.Health != healthBroken {
			if observation.Health == healthHealthy {
				s.repairSucceeded(top.Name, d.ID)
			}
			continue
		}
		class := deviceChangeClass(observation)
		s.recordEvent(top.Name, "", "reconcile", "", "change_plan", "scheduled",
			d.ID+"="+string(class))
		if reason := s.ordinaryMaintenanceSuppression(top.Name); reason != "" {
			s.metricRegistry().observeRepair("recovery")
			return
		}
		if err := s.reviveDevice(ctx, eng, top, d, observation); err != nil {
			s.repairFailed(top.Name, d.ID, "container lifecycle repair failed", err)
			s.recordEvent(top.Name, "", "reconcile", "", "repair", "error",
				d.ID+": "+err.Error())
			continue
		}
		if observation.State != rt.StateRunning || !observation.SpecMatches {
			if err := s.waitForJoinable(ctx, d.Container); err != nil {
				s.repairFailed(top.Name, d.ID, "container did not become joinable after lifecycle repair", err)
				s.recordEvent(top.Name, "", "reconcile", "", "repair", "error",
					d.ID+": "+err.Error())
				continue
			}
		}
		// A router whose cables are all present and whose daemons have died
		// needs the daemons started, not the device rebuilt. Rewiring it would
		// re-render its configuration in platform mode, which in a lab
		// deployed at the reference throws the reference solution away -- a
		// far worse outcome than the fault being repaired.
		if why := observation.Reason; strings.HasPrefix(why, daemonsDown) {
			if err := s.startDaemons(ctx, top.Name, d); err == nil {
				s.repairSucceeded(top.Name, d.ID)
				s.metricRegistry().observeRepair("success")
				s.recordEvent(top.Name, "", "reconcile", "", "repair", "success",
					d.ID+" routing daemons restarted")
				slog.Info("routing daemons restarted", "device", d.ID)
				continue
			} else {
				// Starting is futile when the reason they are not running is
				// that the configuration says not to run them.
				//
				// A container recreated by an interrupted deployment comes up
				// with the image's own /etc/frr/daemons, in which bgpd, ospfd
				// and ldpd are all off. frrinit.sh then honours that file and
				// starts nothing, the repair reports failure three times, and
				// the device is abandoned -- a router with no BGP in a lab
				// nobody is watching, found here as one AS whose customer
				// session had been down for forty minutes with every ping
				// between them succeeding. Rewiring re-renders the files,
				// which is what such a device actually needs.
				slog.Error("routing daemons could not be started; rebuilding the device so "+
					"its configuration is written again", "device", d.ID, "err", err)
			}
		}
		if reason := s.ordinaryMaintenanceSuppression(top.Name); reason != "" {
			s.metricRegistry().observeRepair("recovery")
			return
		}
		if err := eng.RewireDevice(ctx, top, d); err != nil {
			s.repairFailed(top.Name, d.ID, "rewiring failed", err)
			s.recordEvent(top.Name, "", "reconcile", "", "repair", "error",
				d.ID+": "+err.Error())
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
		if renderModeForDevice(render.Mode(mode), ungraded, d) != render.ModeSolve {
			if reason := s.ordinaryMaintenanceSuppression(top.Name); reason != "" {
				s.metricRegistry().observeRepair("recovery")
				return
			}
			if _, err := deploy.Restore(ctx, s.rt, d, top.Name, s.store); err != nil {
				s.repairFailed(top.Name, d.ID, "configuration could not be put back after rewiring", err)
				s.recordEvent(top.Name, "", "reconcile", "", "repair", "error",
					d.ID+": "+err.Error())
				continue
			}
		}
		// Confirmed, not assumed. A repair that reports success without being
		// checked is how the previous version of this loop claimed to have
		// fixed routers it had left with no addresses and no routing daemon.
		after := s.observeDevice(ctx, top.Name, d, false)
		s.rememberHealth(top.Name, d.ID, after)
		if after.Health != healthHealthy {
			reason := after.Reason
			if reason == "" {
				reason = string(after.Health)
			}
			s.repairFailed(top.Name, d.ID, "device is still not right after being repaired",
				errors.New(reason))
			s.recordEvent(top.Name, "", "reconcile", "", "repair", "error",
				d.ID+": "+reason)
			continue
		}
		s.repairSucceeded(top.Name, d.ID)
		s.metricRegistry().observeRepair("success")
		s.recordEvent(top.Name, "", "reconcile", "", "repair", "success", d.ID)
		slog.Info("device repaired and its configuration put back", "device", d.ID)
	}
}

// reviveDevice moves a non-joinable desired container back to a state where
// wiring can be repaired. An absent container is recreated through the normal
// desired-state engine; exited, dead, and restart-loop states are actively
// restarted rather than being treated as healthy because an exec happened to
// be unavailable.
func (s *Server) reviveDevice(ctx context.Context, eng *deploy.Engine, top *model.Topology,
	d *model.Device, observation deviceObservation,
) error {
	if !observation.SpecMatches || observation.State == rt.StateAbsent {
		return s.recreateDesiredDevice(ctx, eng, top, d)
	}
	switch observation.State {
	case rt.StateRunning:
		return nil
	case rt.StatePaused:
		return s.workLimiter().Run(ctx, []limiter.Kind{limiter.Lifecycle}, func() error {
			return s.rt.Unpause(ctx, d.Container)
		})
	case rt.StateRestarting:
		// Stop breaks Docker's restart-policy loop before Start is asked to
		// create a fresh namespace. A plain Start on a restarting container is
		// often accepted but leaves the old loop in charge.
		if err := s.workLimiter().Run(ctx, []limiter.Kind{limiter.Lifecycle}, func() error {
			return s.rt.Stop(ctx, d.Container, 10*time.Second)
		}); err != nil {
			return err
		}
		fallthrough
	case rt.StateCreated, rt.StateExited, rt.StateDead:
		return s.workLimiter().Run(ctx, []limiter.Kind{limiter.Lifecycle}, func() error {
			return s.rt.Start(ctx, d.Container)
		})
	default:
		return fmt.Errorf("cannot revive container in unrecognised state %q", observation.State)
	}
}

func (s *Server) recreateDesiredDevice(ctx context.Context, eng *deploy.Engine, top *model.Topology,
	d *model.Device,
) error {
	p, err := eng.BuildContext(ctx, top)
	if err != nil {
		return err
	}
	p = p.Restrict(func(step *plan.Step) bool {
		return step.ID == "create:"+d.ID
	})
	report, err := p.Execute(ctx, plan.Options{
		Workers: 1, ContinueOnError: false,
	})
	if err != nil {
		return err
	}
	if report.Failed() {
		return report.Err()
	}
	return nil
}

func (s *Server) waitForJoinable(ctx context.Context, container string) error {
	var last string
	for attempt := 0; attempt < 25; attempt++ {
		observed, err := s.rt.Inspect(ctx, container)
		if err == nil && observed.State == rt.StateRunning {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = string(observed.State)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if last == "" {
		last = "no runtime observation"
	}
	return fmt.Errorf("%s did not become joinable: %s", container, last)
}

// daemonsDown prefixes the reason a router is broken when the only thing wrong
// with it is that its routing processes are not running. The repair for that is
// to start them, not to rewire the device, so the two cases are told apart.
const daemonsDown = "these routing daemons are not running:"

func (s *Server) probeExec(ctx context.Context, container string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	var result rt.ExecResult
	err := s.workLimiter().Run(ctx, []limiter.Kind{limiter.ExecProbe}, func() error {
		var execErr error
		result, execErr = s.rt.Exec(ctx, container, cmd)
		return execErr
	})
	return result, err
}

// frrContainer selects the private privileged control sidecar for an FRR
// router. The router shell remains the student-facing container; daemon
// probes/restarts must never mistake its intentionally empty PID namespace for
// a dead control plane.
func (s *Server) frrContainer(ctx context.Context, d *model.Device) string {
	if d == nil {
		return ""
	}
	if deploy.UsesFRRControl(d) {
		name := deploy.FRRControlContainer(d)
		if c, err := s.rt.Inspect(ctx, name); err == nil && c.State != rt.StateAbsent {
			return name
		}
	}
	return d.Container
}

func (s *Server) requiresFRRControl(d *model.Device) bool {
	if !deploy.UsesFRRControl(d) {
		return false
	}
	switch runtimeNameForReconcile(s.rt) {
	case "docker", "podman":
		return true
	default:
		return false
	}
}

func (s *Server) primaryFRRDaemonCount(ctx context.Context, d *model.Device) (int, error) {
	if !s.requiresFRRControl(d) {
		return 0, nil
	}
	const processes = `watchfrr|zebra|bgpd|ospfd|ospf6d|isisd|ldpd|pimd|staticd|bfdd|ripd|ripngd|pathd|sharpd|mgmtd`
	script := `ps -eo args= | awk '$0 ~ /\/usr\/lib\/frr\/(` + processes +
		`)( |$)/ || $0 ~ /(^|[[:space:]])watchfrr( |$)/ {n++} END {print n+0}'`
	result, err := s.probeExec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil {
		return 0, err
	}
	if result.ExitCode != 0 {
		return 0, fmt.Errorf("primary FRR daemon probe exited %d", result.ExitCode)
	}
	count, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
	if err != nil {
		return 0, fmt.Errorf("parse primary FRR daemon count: %w", err)
	}
	return count, nil
}

func (s *Server) stopPrimaryFRRDaemons(ctx context.Context, d *model.Device) error {
	if !s.requiresFRRControl(d) {
		return nil
	}
	const processes = `watchfrr|zebra|bgpd|ospfd|ospf6d|isisd|ldpd|pimd|staticd|bfdd|ripd|ripngd|pathd|sharpd|mgmtd`
	script := strings.Join([]string{
		`find_frr() { ps -eo pid=,args= | awk '$0 ~ /\/usr\/lib\/frr\/(` + processes + `)( |$)/ || $0 ~ /(^|[[:space:]])watchfrr( |$)/ {print $1}'; }`,
		`pids="$(find_frr)"`,
		`if [ -n "$pids" ]; then kill $pids 2>/dev/null || true; sleep 1; fi`,
		`pids="$(find_frr)"`,
		`if [ -n "$pids" ]; then kill -9 $pids 2>/dev/null || true; sleep 1; fi`,
		`test -z "$(find_frr)"`,
	}, "\n")
	result, err := s.probeExec(ctx, d.Container, rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil {
		return err
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("primary FRR daemon cleanup failed: %w", err)
	}
	return nil
}

// missingDaemons names the routing processes a router should be running and is
// not, or "" when they are all there.
func (s *Server) missingDaemons(ctx context.Context, d *model.Device, as *model.AS) string {
	missing, _ := s.missingDaemonsResult(ctx, d, as)
	return missing
}

func (s *Server) missingDaemonsResult(ctx context.Context, d *model.Device, as *model.AS) (string, error) {
	script := "miss=''; for p in " + strings.Join(render.EnabledDaemonsFor(as), " ") +
		"; do pidof \"$p\" >/dev/null 2>&1 || miss=\"$miss $p\"; done; echo \"$miss\""
	r, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
	if err != nil || r.ExitCode != 0 {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("daemon probe exited %d", r.ExitCode)
	}
	return strings.TrimRight(strings.TrimLeft(r.Stdout, " "), " \n"), nil
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
	return s.observeDevice(ctx, lab, d, true).Health == healthBroken
}

// brokenBecause names the first thing a device is missing, or "" if it is well.
func (s *Server) brokenBecause(ctx context.Context, lab string, d *model.Device) string {
	observation := s.observeDevice(ctx, lab, d, true)
	if observation.Health != healthBroken {
		return ""
	}
	return observation.Reason
}

// observeDevice classifies the desired device as healthy, broken, unknown, or
// partially wired. Unknown is deliberately not healthy: an unreadable runtime
// or failed exec supplies no evidence that a container is usable, but it also
// does not justify destructive rewiring while the node itself may be busy.
func (s *Server) observeDevice(ctx context.Context, lab string, d *model.Device, advancePartial bool) deviceObservation {
	if d == nil {
		return deviceObservation{Health: healthUnknown, Reason: "device declaration is unavailable"}
	}
	want := map[string]bool{}
	for _, i := range d.Ifaces {
		if i.Link != nil || i.VLAN > 0 {
			want[i.Name] = true
		}
	}
	if len(want) == 0 {
		// A device without modelled wires is still required to have a readable,
		// running runtime state. It is otherwise handled below.
	}
	c, err := s.rt.Inspect(ctx, d.Container)
	if err != nil {
		return deviceObservation{Health: healthUnknown, Reason: "runtime inspect unreadable: " + err.Error()}
	}
	wantSpec, specErr := s.finalSpecHash(lab, d)
	if specErr != nil {
		return deviceObservation{Health: healthUnknown, State: c.State,
			Reason: "desired runtime specification is unreadable: " + specErr.Error()}
	}
	specMatches := c.Label(deploy.LabelSpec) == wantSpec
	s.mu.Lock()
	_, hasCurrentTopology := s.current[lab]
	s.mu.Unlock()
	if !hasCurrentTopology && c.Label(deploy.LabelSpec) == "" {
		// Synthetic/offline repair callers have no persisted topology from
		// which to derive a final OCI request. Do not turn that diagnostic
		// fallback into a recreation loop; active agent labs take the strict
		// contract path below.
		specMatches = true
	}
	if hasCurrentTopology && runtimeNameForReconcile(s.rt) != "" {
		specMatches = specMatches && c.Label(deploy.LabelRuntimeContract) == deploy.RuntimeSpecContractVersion
	}
	switch c.State {
	case rt.StateAbsent:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container is absent"}
	case rt.StateExited:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container is exited"}
	case rt.StateDead:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container is dead"}
	case rt.StateRestarting:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container is restart-looping"}
	case rt.StateCreated:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container has not started"}
	case rt.StatePaused:
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container is paused"}
	case rt.StateRunning:
		// Continue below.
	default:
		return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
			Reason: "runtime returned an unknown container state"}
	}
	switch strings.ToLower(strings.TrimSpace(c.Health)) {
	case "", "healthy", "none":
		// Images without a Docker healthcheck intentionally report empty.
	case "unhealthy":
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "container healthcheck is unhealthy"}
	case "starting":
		return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches, Reason: "container healthcheck is still starting"}
	default:
		return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches, Reason: "container healthcheck is unreadable"}
	}
	if !specMatches {
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: false,
			Reason: "container specification no longer matches desired state"}
	}
	if len(want) == 0 {
		return deviceObservation{Health: healthHealthy, State: c.State, SpecMatches: specMatches}
	}

	res, err := s.probeExec(ctx, d.Container, rt.ExecCmd{
		Cmd: []string{"sh", "-c", `ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1`}})
	if err != nil || res.ExitCode != 0 {
		if err != nil {
			return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
				Reason: "interface probe unreadable: " + err.Error()}
		}
		return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
			Reason: fmt.Sprintf("interface probe exited %d", res.ExitCode)}
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
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "it has none of its interfaces"}
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
		count := s.partialCount(lab, d.ID, advancePartial)
		missing := make([]string, 0, len(want)-present)
		for n := range want {
			if !have[n] {
				missing = append(missing, n)
			}
		}
		sort.Strings(missing)
		reason := "it is missing " + strings.Join(missing, ", ")
		if count < partialWiringGrace {
			return deviceObservation{Health: healthPartial, State: c.State, SpecMatches: specMatches, Reason: reason}
		}
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: reason}
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
	// Daemon names are an FRR implementation detail. Other registered router
	// NOSes still receive runtime/wiring health, but must not be declared
	// broken merely because they do not run bgpd or ospfd binaries.
	if d.Kind == model.KindRouter && d.EffectiveNOS() == model.DefaultNOS {
		if s.requiresFRRControl(d) {
			control := deploy.FRRControlContainer(d)
			sidecar, err := s.rt.Inspect(ctx, control)
			if err != nil {
				return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
					Reason: "FRR control sidecar inspect unreadable: " + err.Error()}
			}
			if !sidecar.State.Joinable() {
				return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches,
					Reason: "FRR control sidecar is absent or not running"}
			}
			if primary, err := s.primaryFRRDaemonCount(ctx, d); err != nil {
				return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
					Reason: "primary FRR daemon probe unreadable: " + err.Error()}
			} else if primary > 0 {
				return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches,
					Reason: fmt.Sprintf("primary router container still runs %d FRR daemon(s)", primary)}
			}
		}
		as := s.asOf(lab, d)
		if missing, probeErr := s.missingDaemonsResult(ctx, d, as); probeErr != nil {
			return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
				Reason: "routing-daemon probe unreadable: " + probeErr.Error()}
		} else if missing != "" {
			return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: daemonsDown + missing}
		}
		if dup, probeErr := s.duplicateDaemonsResult(ctx, d, as); probeErr != nil {
			return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
				Reason: "routing-daemon duplicate probe unreadable: " + probeErr.Error()}
		} else if dup != "" {
			return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches,
				Reason: daemonsDown + " duplicated: " + dup}
		}
	}
	if d.Kind == model.KindSwitch {
		if r, err := s.probeExec(ctx, d.Container, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "ovs-vsctl list-br 2>/dev/null | grep -c ."}}); err != nil {
			return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
				Reason: "switch bridge probe unreadable: " + err.Error()}
		} else if r.ExitCode != 0 {
			return deviceObservation{Health: healthUnknown, State: c.State, SpecMatches: specMatches,
				Reason: fmt.Sprintf("switch bridge probe exited %d", r.ExitCode)}
		} else if strings.TrimSpace(r.Stdout) == "0" {
			return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches, Reason: "it has no bridge"}
		}
	}
	if reason := s.semanticReason(ctx, lab, d); reason != "" {
		return deviceObservation{Health: healthBroken, State: c.State, SpecMatches: specMatches,
			Reason: "network semantics drifted: " + reason}
	}
	return deviceObservation{Health: healthHealthy, State: c.State, SpecMatches: specMatches}
}

// peerUnderlay returns the VTEP addresses recorded for a lab.
func (s *Server) finalSpecHash(lab string, d *model.Device) (string, error) {
	// Lightweight unit runtimes often embed a nil Runtime and expose no
	// concrete backend name. They cannot materialize a real OCI create
	// request, so retain the legacy hash only for that test/offline shape.
	// Docker/Podman agents always take the final-spec path below.
	if s.rt == nil || runtimeNameForReconcile(s.rt) == "" {
		return deploy.SpecHash(d), nil
	}
	s.mu.Lock()
	top := s.current[lab]
	mode := s.modes[lab]
	ungraded := s.ungraded[lab]
	s.mu.Unlock()
	if top == nil {
		return deploy.SpecHash(d), nil
	}
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, State: s.store,
		Renderer:        renderer(top, render.Mode(mode), ungraded),
		WritesReference: render.Mode(mode) == render.ModeSolve,
		UnderlayIP:      s.cfg.UnderlayIP,
		UnderlayDev:     s.cfg.UnderlayDev,
		PeerUnderlay:    s.peerUnderlay(top.Name),
	}
	return eng.FinalSpecHash(top, d)
}

func runtimeNameForReconcile(r rt.Runtime) (name string) {
	defer func() {
		if recover() != nil {
			name = ""
		}
	}()
	return r.Name()
}

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
	if s.requiresFRRControl(d) {
		control := deploy.FRRControlContainer(d)
		sidecar, err := s.rt.Inspect(ctx, control)
		if err != nil {
			return fmt.Errorf("inspect FRR control sidecar: %w", err)
		}
		if !sidecar.State.Joinable() {
			return fmt.Errorf("FRR control sidecar %s is not running; refusing to start daemons in primary", control)
		}
		if err := s.stopPrimaryFRRDaemons(ctx, d); err != nil {
			return fmt.Errorf("stop legacy primary FRR daemons: %w", err)
		}
	}
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
	if _, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{Cmd: []string{"sh", "-c", script}}); err != nil {
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
			duplicate, err := s.duplicateDaemonsResult(ctx, d, as)
			if err != nil {
				return err
			}
			if duplicate == "" {
				return nil
			}
			return fmt.Errorf("FRR control sidecar has duplicate daemons: %s", duplicate)
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
	dup, _ := s.duplicateDaemonsResult(ctx, d, as)
	return dup
}

func (s *Server) duplicateDaemonsResult(ctx context.Context, d *model.Device, as *model.AS) (string, error) {
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
		r, err := s.probeExec(ctx, s.frrContainer(ctx, d), rt.ExecCmd{Cmd: []string{"sh", "-c", script}})
		if err != nil || r.ExitCode != 0 {
			if err != nil {
				return "", err
			}
			return "", fmt.Errorf("duplicate daemon probe exited %d", r.ExitCode)
		}
		n, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
		if err != nil {
			return "", fmt.Errorf("parse duplicate daemon count: %w", err)
		}
		if n > 1 {
			dup = append(dup, fmt.Sprintf("%s (%d)", name, n))
		}
	}
	if len(dup) == 0 {
		return "", nil
	}
	sort.Strings(dup)
	return strings.Join(dup, " "), nil
}

// Failed repairs are retried with bounded exponential backoff. The old
// "three strikes forever" rule hid devices that became repairable later; a
// full audit or a lifecycle event now retries them when their next bounded
// window opens, and any healthy observation clears the history immediately.
const repairAttemptsBeforeGivingUp = 3

const (
	repairBackoffBase = time.Second
	repairBackoffMax  = 5 * time.Minute
)

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
	if s.repairFails[repairKey(lab, id)] < repairAttemptsBeforeGivingUp {
		return false
	}
	until := s.repairNext[repairKey(lab, id)]
	return !until.IsZero() && s.nowTime().Before(until)
}

func (s *Server) repairFailed(lab, id, what string, err error) {
	k := repairKey(lab, id)
	s.mu.Lock()
	if s.repairFails == nil {
		s.repairFails = map[string]int{}
	}
	if s.repairNext == nil {
		s.repairNext = map[string]time.Time{}
	}
	s.repairFails[k]++
	n := s.repairFails[k]
	delay := repairDelay(n)
	s.repairNext[k] = s.nowTime().Add(delay)
	s.mu.Unlock()

	slog.Error(what, "lab", lab, "device", id, "err", err, "attempt", n)
	s.metricRegistry().observeRepair("failed")
	s.queueReconcileAfter(lab, id, delay)
	if n >= repairAttemptsBeforeGivingUp {
		slog.Warn("repair is entering bounded exponential backoff; a later event or audit will retry",
			"lab", lab, "device", id, "attempts", n, "backoff", delay)
	}
}

func (s *Server) repairSucceeded(lab, id string) {
	s.mu.Lock()
	delete(s.repairFails, repairKey(lab, id))
	delete(s.repairNext, repairKey(lab, id))
	s.mu.Unlock()
}

func repairDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	shift := attempt - 1
	if shift > 8 {
		shift = 8
	}
	delay := repairBackoffBase << shift
	if delay > repairBackoffMax {
		return repairBackoffMax
	}
	return delay
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
	delete(s.holds, name)
	for k := range s.repairFails {
		if strings.HasPrefix(k, name+"|") {
			delete(s.repairFails, k)
		}
		for k := range s.repairNext {
			if strings.HasPrefix(k, name+"|") {
				delete(s.repairNext, k)
			}
		}
		for k := range s.health {
			if strings.HasPrefix(k, name+"|") {
				delete(s.health, k)
			}
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
	return s.partialCount(lab, id, true)
}

func (s *Server) partialCount(lab, id string, advance bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.partial == nil {
		s.partial = map[string]int{}
	}
	k := repairKey(lab, id)
	if advance {
		s.partial[k]++
	}
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
