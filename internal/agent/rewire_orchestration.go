package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
)

// A repair is not finished at the device it was asked about.
//
// Rewiring a router rebuilds the veth pairs that terminate on it, and a veth
// pair is rebuilt as a pair: the neighbour's end is deleted with it and comes
// back bare. The platform renders no address for an interface a student owns,
// so on a teaching deployment "bare" means the neighbour has a cable that is
// up, no address on it, and no adjacency across it -- and nothing observes
// that, because nothing asked for the neighbour to be repaired.
//
// This was found on a live three-node lab holding a restored, signed group
// submission. Killing one router's pid 1 rebuilt its own cables, replayed its
// own addresses and rebound its own control sidecar; the three routers on the
// far ends of those cables were left with bare interfaces, the router had no
// OSPF neighbours at all, and the agent logged "device repaired and its
// configuration put back". The deployment planner already knew this -- it
// expands a lost namespace to its one-hop neighbours before scheduling any
// work -- but automatic repair does not go through the planner. It calls
// Engine.RewireDevice directly, from four places, and every one of them
// repaired one device and quietly broke its neighbours.
//
// So there is one way to rewire, and it is this. It captures what the rewire
// is about to destroy before destroying it, refuses when what it is about to
// destroy cannot be saved, rewires the target, puts the neighbours' rendered
// configuration back, and replays the saved state of every device involved
// that holds a student's work rather than the reference answer.

// errRepairSuppressed reports that a durable transaction took ownership of the
// lab between the wiring and the replay. The caller stops its whole repair
// pass rather than continuing to the next device.
var errRepairSuppressed = errors.New("repair suppressed by an active recovery boundary")

// rewireStage names the part of a rewire that failed, so a caller can keep
// reporting them as distinctly as it did when it did the work itself.
type rewireStage string

const (
	// stagePreserve is a refusal: nothing has been mutated.
	stagePreserve rewireStage = "preserve"
	stageRewire   rewireStage = "rewire"
	stageReplay   rewireStage = "replay"
)

// rewireFailure carries the stage a rewire stopped at.
type rewireFailure struct {
	stage rewireStage
	err   error
}

func (f *rewireFailure) Error() string { return f.err.Error() }
func (f *rewireFailure) Unwrap() error { return f.err }

// rewireStageOf reports which part of a rewire produced an error.
func rewireStageOf(err error) rewireStage {
	var failure *rewireFailure
	if errors.As(err, &failure) {
		return failure.stage
	}
	if errors.Is(err, deploy.ErrRewireNotStarted) {
		// The engine refused before it deleted anything -- it could not
		// establish the durable marker that protects what it was about to
		// empty, or could not reach the record it would have to update
		// afterwards. Nothing was changed, so it is a refusal, not a break.
		return stagePreserve
	}
	return stageRewire
}

// rewireFailureLabel is what the repair loop records when a rewire fails, kept
// as distinct as it was when the loop performed each stage itself.
func rewireFailureLabel(err error) string {
	switch rewireStageOf(err) {
	case stagePreserve:
		return "the state a rewire would destroy could not be saved first"
	case stageReplay:
		return "configuration could not be put back after rewiring"
	default:
		return "rewiring failed"
	}
}

// rewireRequest is one bounded rewire of a single device.
type rewireRequest struct {
	engine rewireEngine
	top    *model.Topology
	device *model.Device
	// mode and ungraded are the deployed render mode of this lab. They are
	// passed rather than read from the server because a commit verifies the
	// mode it is installing, which is not yet the mode the server records.
	mode     render.Mode
	ungraded int
	// beforeReplay is consulted once, after the wiring is back and before any
	// saved state is replayed onto it. It exists for the automatic repair
	// loop, which must not replay a student's snapshot into a lab a rollback
	// has just taken ownership of.
	beforeReplay func() error
}

// rewireEngine is the deployment engine as a rewire orchestration uses it.
//
// It is an interface so that the order this file imposes -- save, wire,
// re-render, replay -- can be proven against a fake, which building a veth
// pair inside a unit test cannot be.
type rewireEngine interface {
	RewireDeviceAndPeers(ctx context.Context, top *model.Topology, d *model.Device,
		replay func(context.Context, *model.Device) error) error
}

// rewireWithPeers is the only production path to Engine.RewireDevice.
//
// Its order is the order the deployment planner uses for a device whose
// namespace was replaced -- wire, configure, then replay -- extended to the
// neighbours whose interfaces the wiring rebuilt.
func (s *Server) rewireWithPeers(ctx context.Context, req rewireRequest) error {
	if req.engine == nil || req.top == nil || req.device == nil {
		return &rewireFailure{stage: stagePreserve,
			err: errors.New("a rewire needs an engine, a topology, and a device")}
	}
	peers := deploy.LocalRewirePeers(req.top, s.cfg.Node, req.device)
	if err := s.preserveBeforeRewire(ctx, req, peers); err != nil {
		return &rewireFailure{stage: stagePreserve, err: err}
	}
	gated := false
	replay := func(ctx context.Context, d *model.Device) error {
		if !gated {
			gated = true
			if req.beforeReplay != nil {
				if err := req.beforeReplay(); err != nil {
					return err
				}
			}
		}
		// Never onto a lab deployed at the reference. Replaying a student's
		// snapshot over a solved router leaves the class being marked against
		// somebody's old work, and every check on it passes because it is a
		// converged network, just not the answer. The mode is asked per
		// device: a private grading harness is solved everywhere except the
		// one system under evaluation, which keeps its own state.
		if renderModeForDevice(req.mode, req.ungraded, d) == render.ModeSolve {
			return nil
		}
		if _, err := deploy.Restore(ctx, s.rt, d, req.top.Name, s.store); err != nil {
			return &rewireFailure{stage: stageReplay, err: fmt.Errorf(
				"configuration could not be put back after rewiring %s: %w", d.ID, err)}
		}
		return nil
	}
	if err := req.engine.RewireDeviceAndPeers(ctx, req.top, req.device, replay); err != nil {
		if errors.Is(err, errRepairSuppressed) {
			return err
		}
		var failure *rewireFailure
		if errors.As(err, &failure) {
			return err
		}
		return &rewireFailure{stage: stageRewire, err: err}
	}
	return nil
}

// preserveBeforeRewire saves what the rewire is about to destroy, and refuses
// the rewire when it cannot.
//
// The neighbours are the reason this exists. They were not reported broken, so
// nothing has looked at them, and the periodic capture may be minutes old --
// long enough for a student to have addressed an interface that is about to be
// deleted. Capturing them here costs one reading each and makes the difference
// between a repair that moves their work forward and one that rolls it back.
//
// It goes through the engine's capture API rather than reading the containers
// itself, so the namespace-identity guard decides what may be written: a
// device whose namespace was provably replaced has its bare namespace withheld
// and keeps the snapshot it already had, which is exactly what the target of
// this repair is.
//
// What is read is then replicated to the lab's policy before anything is
// unplugged. A capture that is only on this node's disk is not a copy of
// anything if this node is what fails next, and the whole point of taking it
// here is that the interfaces it describes are about to stop existing.
func (s *Server) preserveBeforeRewire(ctx context.Context, req rewireRequest,
	peers []*model.Device,
) error {
	if s.store == nil {
		// There is nothing durable to protect and nothing to replay. A lab
		// without a state store has never had its work saved anywhere.
		return nil
	}
	affected := append([]*model.Device{req.device}, peers...)
	var selected []string
	for _, d := range affected {
		if capturesStudentState(req.top, req.mode, req.ungraded, d) {
			selected = append(selected, d.ID)
		}
	}
	if len(selected) == 0 {
		// Every device this rewire touches is holding the reference answer.
		// Reading it would file the solution as somebody's work.
		return nil
	}
	sort.Strings(selected)
	// A capture engine, deliberately not the repair engine: a solve-mode
	// repair engine writes the reference and refuses to capture at all, which
	// would silently skip the one ungraded system in a private harness whose
	// state is the only thing being marked.
	guard := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(), State: s.store,
		Renderer:        renderer(req.top, render.ModePlatform, 0),
		ObservationRoot: s.observationRoot,
	}
	if _, err := guard.CaptureDevices(ctx, req.top, s.store, selected); err != nil {
		return fmt.Errorf("rewiring %s would rebuild the interfaces of %s, and what is on "+
			"them now could not be saved first: %w", req.device.ID,
			strings.Join(selected, ", "), err)
	}
	unproven := guard.UnprovenNamespaceDevices()
	var refused []string
	for _, d := range affected {
		// Every device the rewire touches, including the one it was called
		// about. "Unproven" is not "broken": it is a namespace nothing can
		// account for, which may hold work that was never saved and is about
		// to be deleted. The device that was reported broken is not a reason
		// to guess -- a namespace that is provably a replacement is a known
		// loss rather than an open question, and a known loss never lands
		// here, so refusing this set does not refuse the fault this repair
		// exists for.
		if reason, ok := unproven[d.ID]; ok {
			refused = append(refused, d.ID+": "+reason)
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("rewiring %s would rebuild the interfaces of %s, whose network state "+
			"this node cannot vouch for, so the repair is refused rather than taken out of "+
			"their namespaces: %s", req.device.ID, refusedDeviceList(refused),
			strings.Join(refused, "; "))
	}
	if err := s.replicateDurableState(ctx, req.top); err != nil {
		return fmt.Errorf("rewiring %s would rebuild the interfaces of %s, and what was just "+
			"read off them could not be copied to the other nodes this lab's policy requires, "+
			"so nothing was unplugged: %w", req.device.ID, strings.Join(selected, ", "), err)
	}
	return nil
}

func refusedDeviceList(refused []string) string {
	ids := make([]string, 0, len(refused))
	for _, r := range refused {
		ids = append(ids, strings.SplitN(r, ":", 2)[0])
	}
	return strings.Join(ids, ", ")
}
