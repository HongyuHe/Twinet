package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// RecoveryRequest asks a node to resume a durable rollback under the caller's
// current fence. The transaction's original fence is intentionally not reused:
// it became stale when the controller failed.
type RecoveryRequest struct {
	Lab      string `json:"lab"`
	Fence    Fence  `json:"fence"`
	Strategy string `json:"strategy,omitempty"`
	// Takeover permits a newly fenced operator to replace a recovery whose
	// persisted phase deadline has expired. It never steals healthy progress.
	Takeover bool `json:"takeover,omitempty"`
	// ForwardAcknowledged is required only for operator-selected forward
	// recovery: it records that unavailable historical replicas cannot be
	// reconstructed and the desired solve/reference transaction will win.
	ForwardAcknowledged bool `json:"forward_acknowledged,omitempty"`
}

// RecoveryResponse reports the verified state after a recovery attempt.
type RecoveryResponse struct {
	Status RecoveryStatus `json:"status"`
}

// transactionArtifact is a byte-exact rendered file or command set recorded
// before a transaction can replace its runtime.
type transactionArtifact struct {
	Path    string          `json:"path"`
	Content []byte          `json:"content,omitempty"`
	Mode    int64           `json:"mode,omitempty"`
	Digest  string          `json:"digest"`
	Command *deploy.Command `json:"command,omitempty"`
}

// transactionRuntimeSpec binds one topology device to the concrete OCI
// contract that existed before destructive work.
type transactionRuntimeSpec struct {
	DeviceID  string                `json:"device_id"`
	Spec      rt.Spec               `json:"spec"`
	Control   *rt.Spec              `json:"control,omitempty"`
	Artifacts []transactionArtifact `json:"artifacts,omitempty"`
}

const (
	overlayInventorySchema         = 3
	recoveryRetryEvery             = 5 * time.Second
	recoveryRetryBackoff           = 30 * time.Second
	defaultRecoveryPhaseTimeout    = 90 * time.Second
	defaultRecoveryArtifactTimeout = 4 * time.Minute
	// Exact rollback restores primary contracts, sidecars, artifacts,
	// readiness, and student snapshots one fenced target at a time. A
	// class-scale node legitimately needs longer than a single controller
	// lease, while every target remains independently deadline-bounded and
	// visible to a joining operator.
	defaultRecoveryTotalTimeout     = 30 * time.Minute
	forwardRecoverySLAMax           = 9*time.Minute + 30*time.Second
	defaultRecoveryLeaseTTL         = 90 * time.Second
	recoveryLeaseRenewEvery         = 15 * time.Second
	recoveryStatusObserveLimit      = 2 * time.Second
	recoveryReconcileHandoffTimeout = 5 * time.Second
	recoveryProgressPersistEvery    = 2 * time.Second
	// Recovering every primary and FRR sidecar at the normal apply worker
	// limit can saturate Docker precisely when it is already restarting
	// namespaces. Keep this intentionally small; the shared limiter can make
	// it smaller on constrained nodes.
	recoveryLifecycleWorkers = 4
)

func bindingVNIs(bindings []netx.LogicalBinding) []uint32 {
	seen := map[uint32]bool{}
	for _, binding := range bindings {
		if binding.VNI != 0 {
			seen[binding.VNI] = true
		}
	}
	out := make([]uint32, 0, len(seen))
	for vni := range seen {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type recoveryRunOptions struct {
	takeover            bool
	automatic           bool
	forwardAcknowledged bool
}

func (s *Server) recoveryPhaseLimit() time.Duration {
	if s.recoveryPhaseTimeout > 0 {
		return s.recoveryPhaseTimeout
	}
	return defaultRecoveryPhaseTimeout
}

func (s *Server) recoveryTotalLimit() time.Duration {
	if s.recoveryTotalTimeout > 0 {
		return s.recoveryTotalTimeout
	}
	return defaultRecoveryTotalTimeout
}

func (s *Server) recoveryLeaseLimit() time.Duration {
	if s.recoveryLeaseTTL > 0 {
		return s.recoveryLeaseTTL
	}
	return defaultRecoveryLeaseTTL
}

func (s *Server) recoveryStatusLimit() time.Duration {
	if s.recoveryStatusTimeout > 0 {
		return s.recoveryStatusTimeout
	}
	return recoveryStatusObserveLimit
}

func (s *Server) recoveryArtifactLimit() time.Duration {
	if s.recoveryPhaseTimeout > 0 {
		return s.recoveryPhaseTimeout
	}
	return defaultRecoveryArtifactTimeout
}

func (s *Server) recoveryWorkerCount() int {
	workers := s.workLimiter().ClampWorkers(limiter.Lifecycle, recoveryLifecycleWorkers)
	return s.workLimiter().ClampWorkers(limiter.Apply, workers)
}

func forwardDataLossScope(tx applyTransaction) []string {
	seen := map[string]bool{}
	for _, snapshot := range tx.Prestate.Snapshots {
		if snapshot.Device == "" || snapshot.Kind == "" {
			continue
		}
		seen[snapshot.Device+"/"+snapshot.Kind] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// forwardRecoveryLimit budgets the recorded desired apply from its actual
// node-local work set. Four lifecycle workers have measured roughly 12 seconds
// of worst-case create/wire/configure work per device under a saturated Docker
// daemon; the bound is deliberately below the operator-facing ten minute SLA.
func (s *Server) forwardRecoveryLimit(tx applyTransaction) time.Duration {
	var devices int
	var wire Wire
	if json.Unmarshal(tx.Requested, &wire) == nil {
		if top, err := wire.Rehydrate(); err == nil {
			devices = len(top.DevicesOnNode(s.cfg.Node))
		}
	}
	workers := s.recoveryWorkerCount()
	if workers < 1 {
		workers = 1
	}
	return forwardRecoveryBudget(devices, workers)
}

func forwardRecoveryBudget(devices, workers int) time.Duration {
	if workers < 1 {
		workers = 1
	}
	limit := 45*time.Second + time.Duration((devices+workers-1)/workers)*12*time.Second
	if limit < 6*time.Minute {
		limit = 6 * time.Minute
	}
	if limit > forwardRecoverySLAMax {
		limit = forwardRecoverySLAMax
	}
	return limit
}

func recoveredMode(tx applyTransaction, wire Wire) (render.Mode, int) {
	if tx.PreviousMode != "" || tx.PreviousUngraded != 0 {
		return render.Mode(tx.PreviousMode), tx.PreviousUngraded
	}
	if wire.Mode != "" || wire.Ungraded != 0 {
		return render.Mode(wire.Mode), wire.Ungraded
	}
	// Transactions written before previous-mode persistence cannot safely
	// infer "teaching" merely because the old wire omitted mode. The forward
	// request's solve/harness source is the only durable authority left; using
	// it prevents replaying stale student snapshots over a reference device.
	if tx.Mode != "" {
		return render.Mode(tx.Mode), tx.Ungraded
	}
	return render.ModePlatform, 0
}

func (s *Server) recoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(recoveryRetryEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.resumeRecoveries(ctx)
		}
	}
}

func (s *Server) resumeRecoveries(ctx context.Context) {
	s.mu.Lock()
	s.initCoordination()
	labs := make([]string, 0, len(s.transactions))
	for lab, tx := range s.transactions {
		if tx.Committed {
			continue
		}
		if tx.Phase == transactionRecovering && s.ops[lab] != nil {
			// The in-memory operation record is proof that this process still
			// owns a live runner. A persisted recovering phase without that
			// record means the agent restarted; reclaim it immediately under
			// a fresh fence instead of waiting for a now-dead phase deadline.
			continue
		}
		if lease := s.mutations[lab]; lease != nil && s.nowTime().Before(lease.until) {
			continue
		}
		if !tx.NextRecovery.IsZero() && s.nowTime().Before(tx.NextRecovery) {
			continue
		}
		labs = append(labs, lab)
	}
	s.mu.Unlock()
	sort.Strings(labs)
	for _, lab := range labs {
		lab := lab
		go s.runAutomaticRecovery(ctx, lab)
	}
}

func (s *Server) runAutomaticRecovery(ctx context.Context, lab string) {
	fence, err := s.acquireRecoveryFence(lab)
	if err != nil {
		return
	}
	defer func() {
		if err := s.releaseMutationLease(LeaseReleaseRequest{Lab: lab, Fence: fence}); err != nil {
			slog.Debug("releasing automatic recovery lease", "lab", lab, "err", err)
		}
	}()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenew := s.keepRecoveryFence(runCtx, lab, fence)
	defer stopRenew()
	s.mu.Lock()
	tx := s.transactions[lab]
	s.mu.Unlock()
	strategy := tx.RecoveryStrategy
	if strategy != "forward" {
		strategy = "rollback"
	}
	if _, err := s.recoverTransactionStrategyOptions(runCtx, lab, fence, strategy,
		recoveryRunOptions{takeover: true, automatic: true,
			forwardAcknowledged: tx.ForwardAcknowledged}); err != nil {
		slog.Warn("automatic transaction recovery failed; will retry",
			"lab", lab, "err", err)
	}
}

func (s *Server) acquireRecoveryFence(lab string) (Fence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if s.expireCoordinationLocked(now) {
		if err := s.saveCoordinationLocked(); err != nil {
			return Fence{}, err
		}
	}
	if held := s.mutations[lab]; held != nil {
		return Fence{}, fmt.Errorf("lab %q is still leased by %s", lab, held.holder)
	}
	token, err := opaqueFenceToken()
	if err != nil {
		return Fence{}, err
	}
	fence := Fence{Token: token, Generation: s.fenceHighWater[lab] + 1}
	s.fenceHighWater[lab] = fence.Generation
	s.mutations[lab] = &clusterLease{
		holder: "agent recovery", fence: fence, until: now.Add(s.recoveryLeaseLimit()),
	}
	if err := s.saveCoordinationLocked(); err != nil {
		delete(s.mutations, lab)
		return Fence{}, err
	}
	return fence, nil
}

// keepRecoveryFence renews only while the persisted phase deadline is still
// healthy. A stuck runtime call therefore loses its fence shortly after the
// deadline rather than monopolising recovery for the maximum controller TTL.
func (s *Server) keepRecoveryFence(ctx context.Context, lab string, fence Fence) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(recoveryLeaseRenewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
			}
			s.mu.Lock()
			tx, ok := s.transactions[lab]
			now := s.nowTime()
			expired := ok && !tx.RecoveryDeadline.IsZero() && !now.Before(tx.RecoveryDeadline)
			s.mu.Unlock()
			if expired {
				return
			}
			seconds := int(s.recoveryLeaseLimit().Round(time.Second).Seconds())
			if _, err := s.renewMutationLease(LeaseRenewRequest{
				Lab: lab, Fence: fence, TTLSeconds: seconds,
			}); err != nil {
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func (s *Server) recoveryOwner(lab string, fence Fence) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lease := s.mutations[lab]; lease != nil && lease.fence.Generation == fence.Generation &&
		subtle.ConstantTimeCompare([]byte(lease.fence.Token), []byte(fence.Token)) == 1 {
		return lease.holder
	}
	return "recovery"
}

func (s *Server) beginRecovery(lab string, fence Fence, generation, strategy string,
	totalDeadline time.Time, options recoveryRunOptions,
) (applyTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if err := s.fenceErrorLocked(lab, fence, now); err != nil {
		return applyTransaction{}, err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return applyTransaction{}, fmt.Errorf("generation %q of lab %q has no recovery transaction", generation, lab)
	}
	if _, err := RequireTransactionMode(tx.Mode); err != nil {
		return applyTransaction{}, fmt.Errorf("recovery desired mode invariant: %w", err)
	}
	if _, err := RequireTransactionMode(tx.PreviousMode); err != nil {
		return applyTransaction{}, fmt.Errorf("recovery previous mode invariant: %w", err)
	}
	active := tx.Phase == transactionRecovering && !tx.RecoveryDeadline.IsZero() &&
		now.Before(tx.RecoveryDeadline)
	if active {
		if tx.RecoveryStrategy != "" && tx.RecoveryStrategy != strategy {
			return applyTransaction{}, fmt.Errorf("recovery for lab %q is already running strategy %q", lab, tx.RecoveryStrategy)
		}
		if !options.takeover {
			return applyTransaction{}, fmt.Errorf("recovery for lab %q is already making progress as %q", lab, strategy)
		}
	}
	if tx.Phase == transactionRecovering && !options.takeover {
		return applyTransaction{}, fmt.Errorf("recovery for lab %q exceeded its deadline; retry with takeover", lab)
	}
	tx.Phase = transactionRecovering
	tx.Failure = ""
	tx.RecoveryAttempts++
	tx.LastRecovery = now
	tx.NextRecovery = time.Time{}
	tx.RecoveryOwner = s.recoveryOwnerLocked(lab, fence)
	tx.RecoveryStrategy = strategy
	if strategy == "forward" {
		if options.forwardAcknowledged {
			tx.ForwardAcknowledged = true
			tx.ForwardDataLossScope = forwardDataLossScope(tx)
		}
		if !tx.ForwardAcknowledged {
			return applyTransaction{}, errors.New(
				"forward recovery requires explicit acknowledgement that unavailable historical replicas may be lost")
		}
	}
	tx.RecoveryStarted = now
	tx.RecoveryProgress = now
	tx.RecoveryDeadline = now.Add(s.recoveryPhaseLimit())
	tx.RecoveryTotal = totalDeadline
	tx.RecoveryTarget = fmt.Sprintf("starting recovery %s/%d -> %s/%d",
		tx.PreviousMode, tx.PreviousUngraded, tx.Mode, tx.Ungraded)
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		return applyTransaction{}, err
	}
	s.stopPeriodicDurability(lab)
	return tx, nil
}

func (s *Server) recoveryOwnerLocked(lab string, fence Fence) string {
	if lease := s.mutations[lab]; lease != nil && lease.fence.Generation == fence.Generation &&
		subtle.ConstantTimeCompare([]byte(lease.fence.Token), []byte(fence.Token)) == 1 {
		return lease.holder
	}
	return "recovery"
}

func (s *Server) updateRecoveryProgress(lab string, fence Fence, generation, target string,
	deadline time.Time,
) error {
	return s.recordRecoveryProgress(lab, fence, generation, target, deadline, true)
}

func (s *Server) markForwardPhase(lab string, fence Fence, generation, phase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return fmt.Errorf("generation %q of lab %q has no forward transaction", generation, lab)
	}
	tx.ForwardPhase = phase
	tx.RecoveryProgress = s.nowTime()
	tx.RecoveryTarget = "forward: " + phase
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func (s *Server) recordForwardDataLoss(lab string, fence Fence, generation, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return fmt.Errorf("generation %q of lab %q has no forward transaction", generation, lab)
	}
	if detail != "" {
		tx.ForwardDataLossScope = append(tx.ForwardDataLossScope, detail)
		sort.Strings(tx.ForwardDataLossScope)
	}
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

// recordRecoveryProgress keeps live status current on every phase transition,
// but rate-limits journal fsyncs for rapid successful phases. The durable
// begin/failure/finalization records are sufficient to resume after a crash;
// repeatedly persisting "completed" bookkeeping made an otherwise idle
// automatic recovery exceed its lease while Docker was under load.
func (s *Server) recordRecoveryProgress(lab string, fence Fence, generation, target string,
	deadline time.Time, force bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if err := s.fenceErrorLocked(lab, fence, now); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return fmt.Errorf("generation %q of lab %q has no recovery transaction", generation, lab)
	}
	priorProgress, priorDeadline := tx.RecoveryProgress, tx.RecoveryDeadline
	persist := force || priorProgress.IsZero() ||
		now.Sub(priorProgress) >= recoveryProgressPersistEvery ||
		priorDeadline.IsZero() || deadline.After(priorDeadline.Add(recoveryProgressPersistEvery))
	tx.RecoveryTarget = target
	tx.RecoveryProgress = now
	tx.RecoveryDeadline = deadline
	s.transactions[lab] = tx
	if persist {
		if err := s.saveCoordinationLocked(); err != nil {
			return err
		}
	}
	slog.Info("recovery phase progress", "lab", lab, "generation", generation,
		"action_target", target, "deadline", deadline)
	return nil
}

func (s *Server) runRecoveryPhase(ctx context.Context, lab string, fence Fence,
	generation, action, target string, fn func(context.Context) error,
) error {
	return s.runRecoveryPhaseLimit(ctx, lab, fence, generation, action, target,
		s.recoveryPhaseLimit(), fn)
}

func (s *Server) runRecoveryPhaseLimit(ctx context.Context, lab string, fence Fence,
	generation, action, target string, limit time.Duration, fn func(context.Context) error,
) error {
	phaseCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	deadline := s.nowTime().Add(limit)
	if err := s.recordRecoveryProgress(lab, fence, generation, action+": "+target, deadline, false); err != nil {
		return err
	}
	if err := fn(phaseCtx); err != nil {
		if phaseCtx.Err() != nil {
			return fmt.Errorf("%s %s: %w", action, target, phaseCtx.Err())
		}
		return fmt.Errorf("%s %s: %w", action, target, err)
	}
	s.mu.Lock()
	tx, active := s.transactions[lab]
	s.mu.Unlock()
	if !active || tx.Generation != generation {
		// A successful commit/finalize removes the transaction atomically.
		// An old cancelled runner may also observe a newer takeover here; in
		// both cases it must not overwrite the newer persisted progress.
		return nil
	}
	// Completion is represented by the next in-memory phase transition or
	// terminal commit. Avoid a second coordination fsync for every successful
	// short phase: under a saturated Docker node those redundant writes made
	// automatic recovery spend seconds reporting completion rather than
	// restoring.
	return nil
}

// runRecoveryLongPhase is for a composite exact rollback. Its independent
// device operations use bounded per-device workers, while the aggregate stays
// fenced through the persisted total deadline.
func (s *Server) runRecoveryLongPhase(ctx context.Context, lab string, fence Fence,
	generation, action, target string, fn func(context.Context) error,
) error {
	s.mu.Lock()
	tx, ok := s.transactions[lab]
	s.mu.Unlock()
	deadline := tx.RecoveryTotal
	if !ok || deadline.IsZero() {
		deadline = s.nowTime().Add(s.recoveryTotalLimit())
	}
	if err := s.updateRecoveryProgress(lab, fence, generation, action+": "+target, deadline); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %s: %w", action, target, ctx.Err())
		}
		return fmt.Errorf("%s %s: %w", action, target, err)
	}
	s.mu.Lock()
	current, active := s.transactions[lab]
	s.mu.Unlock()
	if !active || current.Generation != generation {
		return nil
	}
	// See runRecoveryPhase: phase entry is durable progress; completion is
	// either followed by the next durable phase or terminal finalization.
	return nil
}

// runBoundedDeviceChecks runs independent device operations concurrently while
// preserving a per-device deadline and returning as soon as one systemic
// failure is known. Exact rollback used to process every device serially after
// the first rejected restore command, turning a bad dynamic snapshot into a
// tens-of-minutes recovery loop.
func runBoundedDeviceChecks[T any](ctx context.Context, workers int, items []T,
	limit time.Duration, label func(T) string, fn func(context.Context, T) error,
) error {
	if len(items) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan T)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error
	record := func(item T, err error) {
		if err == nil {
			return
		}
		once.Do(func() {
			firstErr = fmt.Errorf("%s: %w", label(item), err)
			cancel()
		})
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case item, ok := <-jobs:
					if !ok {
						return
					}
					if workCtx.Err() != nil {
						return
					}
					itemCtx, itemCancel := context.WithTimeout(workCtx, limit)
					err := fn(itemCtx, item)
					if err == nil && itemCtx.Err() != nil {
						err = itemCtx.Err()
					}
					itemCancel()
					record(item, err)
				}
			}
		}()
	}

feed:
	for _, item := range items {
		select {
		case <-workCtx.Done():
			break feed
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (s *Server) failRecovery(lab string, fence Fence, generation string, err error) {
	if err == nil {
		return
	}
	if markErr := s.markTransactionPhase(lab, fence, generation, transactionRollbackFailed, err.Error()); markErr != nil {
		slog.Warn("persisting recovery failure", "lab", lab, "err", markErr, "failure", err)
	}
}

func (s *Server) transactionFail(phase string) error {
	if s.transactionFailpoint == nil {
		return nil
	}
	return s.transactionFailpoint(phase)
}

func (s *Server) transactionFailpoints(p *plan.Plan) {
	if p == nil || s.transactionFailpoint == nil {
		return
	}
	for _, step := range p.Steps() {
		run := step.Run
		phase := string(step.Stage)
		step.Run = func(ctx context.Context) error {
			if err := s.transactionFail(phase); err != nil {
				return err
			}
			if run == nil {
				return nil
			}
			return run(ctx)
		}
	}
}

func (s *Server) recoveryContainerList(ctx context.Context, lab string) ([]rt.Container, error) {
	if s.recoveryContainers != nil {
		return s.recoveryContainers(ctx, lab)
	}
	if s.rt == nil {
		return nil, errors.New("no container runtime")
	}
	return s.rt.List(ctx, rt.Filter{All: true, Labels: map[string]string{
		deploy.LabelManaged: "true", deploy.LabelLab: lab,
	}})
}

func exactRuntimeSpecMatches(container rt.Container, spec *rt.Spec) bool {
	if spec == nil || container.Name != spec.Name || spec.Labels == nil {
		return false
	}
	wantSpec := spec.Labels[deploy.LabelSpec]
	if wantSpec == "" || container.Label(deploy.LabelSpec) != wantSpec {
		return false
	}
	if wantContract := spec.Labels[deploy.LabelRuntimeContract]; wantContract != "" &&
		container.Label(deploy.LabelRuntimeContract) != wantContract {
		return false
	}
	return true
}

// ensureExactRecoveryContainer resolves Docker's duplicate-name race by
// inspecting the object that owns the expected name. A matching running or
// exited container is reused/startable; only a known mismatching contract is
// removed. This makes an interrupted recovery converge instead of issuing a
// blind Create against a container another recovery phase already restored.
func (s *Server) ensureExactRecoveryContainer(ctx context.Context, spec *rt.Spec) error {
	if spec == nil || spec.Name == "" {
		return errors.New("exact recovery container has no name")
	}
	return s.workLimiter().Run(ctx, []limiter.Kind{limiter.Apply, limiter.Lifecycle}, func() error {
		var current rt.Container
		var lastCreateErr error
		for attempt := 0; attempt < 4; attempt++ {
			observed, err := s.rt.Inspect(ctx, spec.Name)
			if err != nil {
				return fmt.Errorf("inspect exact recovery container %s: %w", spec.Name, err)
			}
			if observed.State != rt.StateAbsent && !exactRuntimeSpecMatches(observed, spec) {
				if err := s.rt.Remove(ctx, spec.Name, true); err != nil {
					return fmt.Errorf("remove mismatching recovery container %s: %w", spec.Name, err)
				}
				if err := recoveryNameRetry(ctx); err != nil {
					return err
				}
				continue
			}
			if observed.State == rt.StateAbsent {
				if _, err := s.rt.Create(ctx, spec); err != nil {
					lastCreateErr = err
					// Docker can return a duplicate-name error after another
					// recovery attempt created the exact object. Re-inspect
					// and adopt it, or remove a known mismatch on the next
					// bounded iteration.
					if retryErr := recoveryNameRetry(ctx); retryErr != nil {
						return fmt.Errorf("create exact recovery container %s: %w", spec.Name, err)
					}
					continue
				}
				current = rt.Container{Name: spec.Name, State: rt.StateCreated}
			} else {
				current = observed
			}
			break
		}
		if current.Name == "" {
			if lastCreateErr == nil {
				return fmt.Errorf("exact recovery container %s remained in an unresolved runtime state", spec.Name)
			}
			return fmt.Errorf("exact recovery container %s remained in a duplicate-name conflict: %w",
				spec.Name, lastCreateErr)
		}
		switch current.State {
		case rt.StateRunning:
			return nil
		case rt.StatePaused:
			if err := s.rt.Unpause(ctx, spec.Name); err != nil {
				return fmt.Errorf("unpause exact recovery container %s: %w", spec.Name, err)
			}
			return nil
		case rt.StateRestarting:
			if err := s.rt.Stop(ctx, spec.Name, deploy.DefaultStopTimeout); err != nil {
				return fmt.Errorf("stop restarting recovery container %s: %w", spec.Name, err)
			}
			fallthrough
		case rt.StateCreated, rt.StateExited, rt.StateDead:
			if err := s.rt.Start(ctx, spec.Name); err != nil {
				return fmt.Errorf("start exact recovery container %s: %w", spec.Name, err)
			}
			return nil
		default:
			return fmt.Errorf("exact recovery container %s has unexpected state %q", spec.Name, current.State)
		}
	})
}

func recoveryNameRetry(ctx context.Context) error {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Server) removeRecoveryContainerIfPresent(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	return s.workLimiter().Run(ctx, []limiter.Kind{limiter.Apply, limiter.Lifecycle}, func() error {
		current, err := s.rt.Inspect(ctx, name)
		if err != nil {
			return fmt.Errorf("inspect recovery container %s: %w", name, err)
		}
		if current.State == rt.StateAbsent {
			return nil
		}
		if err := s.rt.Remove(ctx, name, true); err != nil {
			return fmt.Errorf("remove recovery container %s: %w", name, err)
		}
		return nil
	})
}

func (s *Server) recoveryOverlayList(lab string) ([]uint32, error) {
	if s.recoveryOverlays != nil {
		return s.recoveryOverlays(lab)
	}
	return netx.ListOverlaysOfLab(lab)
}

func (s *Server) snapshotTransactionInventory(ctx context.Context, lab string) (transactionInventory, error) {
	containers, err := s.recoveryContainerList(ctx, lab)
	if err != nil {
		return transactionInventory{}, fmt.Errorf("list pre-transaction containers: %w", err)
	}
	out := transactionInventory{CapturedAt: s.nowTime()}
	if s.recoveryOverlayInventory != nil {
		overlays, err := s.recoveryOverlayInventory(lab)
		if err != nil {
			return transactionInventory{}, fmt.Errorf("inspect pre-transaction overlays: %w", err)
		}
		out.Schema = overlayInventorySchema
		out.LogicalBindings = overlays.Bindings
		out.PhysicalTrunks = overlays.Trunks
		out.VNIs = bindingVNIs(overlays.Bindings)
	} else if s.recoveryOverlays != nil {
		vnis, err := s.recoveryOverlayList(lab)
		if err != nil {
			return transactionInventory{}, fmt.Errorf("list pre-transaction overlays: %w", err)
		}
		out.VNIs = append([]uint32(nil), vnis...)
	} else {
		overlays, err := netx.InspectOverlayInventory(lab)
		if err != nil {
			return transactionInventory{}, fmt.Errorf("inspect pre-transaction overlays: %w", err)
		}
		out.Schema = overlayInventorySchema
		out.LogicalBindings = overlays.Bindings
		out.PhysicalTrunks = overlays.Trunks
		out.VNIs = bindingVNIs(overlays.Bindings)
	}
	for _, container := range containers {
		if isInternalControlContainer(container) {
			continue
		}
		out.Containers = append(out.Containers, transactionContainer{
			Name:       container.Name,
			DeviceID:   container.Label(deploy.LabelDeviceID),
			Spec:       container.Label(deploy.LabelSpec),
			Generation: container.Label(deploy.LabelGen),
			State:      string(container.State),
		})
		if out.Generation == "" {
			out.Generation = container.Label(deploy.LabelGen)
		}
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	sort.Slice(out.VNIs, func(i, j int) bool { return out.VNIs[i] < out.VNIs[j] })
	return out, nil
}

func expectedTransactionInventory(top *model.Topology, node, generation string) transactionInventory {
	out := transactionInventory{Generation: generation, CapturedAt: time.Now()}
	if top == nil {
		return out
	}
	out.TopologyHash = top.Hash
	for _, device := range top.DevicesOnNode(node) {
		out.Containers = append(out.Containers, transactionContainer{
			Name:       device.Container,
			DeviceID:   device.ID,
			Spec:       deploy.SpecHash(device),
			Generation: generation,
			State:      string(rt.StateRunning),
		})
	}
	out.VNIs = overlayVNIsOnNode(top, node)
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	sort.Slice(out.VNIs, func(i, j int) bool { return out.VNIs[i] < out.VNIs[j] })
	return out
}

func expectedTransactionInventoryFinal(eng *deploy.Engine, top *model.Topology,
	node string, tx applyTransaction, observed transactionInventory,
) (transactionInventory, error) {
	out := transactionInventory{Generation: tx.Generation, CapturedAt: time.Now()}
	if top == nil {
		return out, nil
	}
	out.TopologyHash = top.Hash
	observedByDevice := map[string]transactionContainer{}
	for _, container := range observed.Containers {
		observedByDevice[container.DeviceID] = container
	}
	prestateByDevice := map[string]transactionContainer{}
	for _, container := range tx.Prestate.Containers {
		prestateByDevice[container.DeviceID] = container
	}
	for _, device := range top.DevicesOnNode(node) {
		spec, err := eng.FinalSpecHash(top, device)
		if err != nil {
			return transactionInventory{}, err
		}
		objectGeneration, err := expectedObjectGeneration(tx, device.ID, device.Container,
			spec, prestateByDevice, observedByDevice)
		if err != nil {
			return transactionInventory{}, err
		}
		out.Containers = append(out.Containers, transactionContainer{
			Name:       device.Container,
			DeviceID:   device.ID,
			Spec:       spec,
			Generation: objectGeneration,
			State:      string(rt.StateRunning),
		})
	}
	overlays, err := eng.ExpectedOverlayInventory(top)
	if err != nil {
		return transactionInventory{}, err
	}
	preserveLegacyTrunkPort(&overlays, observed)
	out.Schema = overlayInventorySchema
	out.LogicalBindings = overlays.Bindings
	out.PhysicalTrunks = overlays.Trunks
	out.VNIs = bindingVNIs(overlays.Bindings)
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	sort.Slice(out.VNIs, func(i, j int) bool { return out.VNIs[i] < out.VNIs[j] })
	return out, nil
}

func preserveLegacyTrunkPort(expected *netx.OverlayInventory, observed transactionInventory) {
	if expected == nil || observed.Schema < overlayInventorySchema {
		return
	}
	for i := range expected.Trunks {
		for _, actual := range observed.PhysicalTrunks {
			if actual.Legacy || actual.NodeA != expected.Trunks[i].NodeA ||
				actual.NodeB != expected.Trunks[i].NodeB || actual.Port != netx.VXLANPort ||
				actual.MTU != expected.Trunks[i].MTU {
				continue
			}
			expected.Trunks[i].Port = actual.Port
			for j := range expected.Bindings {
				if expected.Bindings[j].NodeA == actual.NodeA && expected.Bindings[j].NodeB == actual.NodeB {
					expected.Bindings[j].Port = actual.Port
					// A schema-v1/v2 record never carried this port fact.
					// Persist that the live standard-port carrier was
					// explicitly verified rather than synthesized.
					expected.Bindings[j].Legacy = true
				}
			}
			break
		}
	}
}

func expectedObjectGeneration(tx applyTransaction, deviceID, name, spec string,
	prestate, observed map[string]transactionContainer,
) (string, error) {
	touched := map[string]bool{}
	for _, id := range tx.Touched {
		touched[id] = true
	}
	if touched[deviceID] {
		return tx.Generation, nil
	}
	if tx.TouchedKnown {
		before, ok := prestate[deviceID]
		if !ok {
			return "", fmt.Errorf("%s was not in pre-state and was not marked recreated", deviceID)
		}
		if before.Name != name || before.Spec != spec {
			return "", fmt.Errorf("%s changed runtime identity without being marked recreated", deviceID)
		}
		return before.Generation, nil
	}
	// Transactions created before touched facts were persisted can still
	// complete only when their observed object exactly matches the desired
	// contract. validateInventoryLineage then rejects an unknown label rather
	// than adopting it as an ancestor.
	if prior, ok := observed[deviceID]; ok && prior.Name == name && prior.Spec == spec {
		return prior.Generation, nil
	}
	if before, ok := prestate[deviceID]; ok && before.Name == name && before.Spec == spec {
		return before.Generation, nil
	}
	return tx.Generation, nil
}

func artifactDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:])
}

func sortedStringMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) snapshotRollbackContracts(ctx context.Context, top *model.Topology,
	mode string, ungraded int, generation string, observed transactionInventory,
) ([]transactionRuntimeSpec, []netx.MultiplexOverlay, error) {
	if top == nil {
		return nil, nil, nil
	}
	engine := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(),
		Renderer:   renderer(top, render.Mode(mode), ungraded),
		UnderlayIP: s.cfg.UnderlayIP, UnderlayDev: s.cfg.UnderlayDev,
		PeerUnderlay: s.peerUnderlay(top.Name), Generation: generation,
	}
	if top.Lab != nil {
		engine.RequireImmutableImages = top.Lab.Images.RequiresImmutableImages()
	}
	actual, err := s.recoveryContainerList(ctx, top.Name)
	if err != nil {
		return nil, nil, err
	}
	byName := map[string]rt.Container{}
	for _, container := range actual {
		if !isInternalControlContainer(container) {
			byName[container.Name] = container
		}
	}
	var out []transactionRuntimeSpec
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		spec, err := engine.RuntimeSpec(ctx, top, device)
		if err != nil {
			return nil, nil, fmt.Errorf("derive pre-state runtime spec for %s: %w", device.ID, err)
		}
		if current, ok := byName[device.Container]; ok && len(current.Labels) > 0 {
			spec.Labels = map[string]string{}
			for key, value := range current.Labels {
				spec.Labels[key] = value
			}
		}
		files, err := engine.Renderer.Files(device)
		if err != nil {
			return nil, nil, fmt.Errorf("render pre-state artifacts for %s: %w", device.ID, err)
		}
		commands, err := engine.Renderer.Commands(device)
		if err != nil {
			return nil, nil, fmt.Errorf("render pre-state commands for %s: %w", device.ID, err)
		}
		entry := transactionRuntimeSpec{DeviceID: device.ID, Spec: *spec}
		control, err := engine.RuntimeControlSpec(top, device)
		if err != nil {
			return nil, nil, fmt.Errorf("derive pre-state control spec for %s: %w", device.ID, err)
		}
		if control != nil {
			copy := *control
			entry.Control = &copy
		}
		for _, path := range sortedStringMapKeys(files) {
			file := files[path]
			entry.Artifacts = append(entry.Artifacts, transactionArtifact{
				Path: path, Content: append([]byte(nil), file.Content...), Mode: file.Mode,
				Digest: artifactDigest(file.Content),
			})
		}
		for i := range commands {
			command := commands[i]
			raw, _ := json.Marshal(command)
			entry.Artifacts = append(entry.Artifacts, transactionArtifact{
				Path: fmt.Sprintf("command/%04d", i), Command: &command, Digest: artifactDigest(raw),
			})
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	overlays, err := netx.ListMultiplexOverlaysOfLab(top.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("capture pre-state multiplex overlays: %w", err)
	}
	_ = observed
	return out, overlays, nil
}

func inventoryMatches(want, got transactionInventory) error {
	if len(want.Containers) != len(got.Containers) {
		return fmt.Errorf("container inventory is %d, want %d", len(got.Containers), len(want.Containers))
	}
	for i := range want.Containers {
		a, b := want.Containers[i], got.Containers[i]
		// Transactions created before generation labels, and a rollback that
		// recreates only the missing subset, legitimately mix an unlabeled
		// surviving container with a replacement carrying the restored
		// generation. The persisted generation CAS remains authoritative.
		legacyGeneration := a.Generation == "" || b.Generation == ""
		if a.Name != b.Name || a.DeviceID != b.DeviceID || a.Spec != b.Spec ||
			(a.Generation != b.Generation && !legacyGeneration) {
			return fmt.Errorf("container %d is %+v, want %+v", i, b, a)
		}
		if a.State == string(rt.StateRunning) && !rt.State(b.State).Joinable() {
			return fmt.Errorf("container %s is %s, want a joinable service", b.Name, b.State)
		}
	}
	if want.Schema >= overlayInventorySchema && got.Schema >= overlayInventorySchema {
		if err := overlayInventoryMatches(want, got); err != nil {
			return err
		}
	} else {
		if len(want.VNIs) != len(got.VNIs) {
			return fmt.Errorf("overlay inventory is %d, want %d", len(got.VNIs), len(want.VNIs))
		}
		for i := range want.VNIs {
			if want.VNIs[i] != got.VNIs[i] {
				return fmt.Errorf("overlay VNI %d is %d, want %d", i, got.VNIs[i], want.VNIs[i])
			}
		}
	}
	return nil
}

func overlayInventoryMatches(want, got transactionInventory) error {
	if len(want.LogicalBindings) != len(got.LogicalBindings) {
		return fmt.Errorf("logical overlay bindings are %d, want %d",
			len(got.LogicalBindings), len(want.LogicalBindings))
	}
	for i := range want.LogicalBindings {
		a, b := want.LogicalBindings[i], got.LogicalBindings[i]
		if a.VNI != b.VNI || a.VLAN != b.VLAN || a.Peer != b.Peer ||
			a.MTU != b.MTU || a.Port != b.Port || a.NodeA != b.NodeA || a.NodeB != b.NodeB {
			return fmt.Errorf("logical binding %d is %+v, want %+v", i, b, a)
		}
	}
	wantTrunks := nonLegacyTrunks(want.PhysicalTrunks)
	gotTrunks := nonLegacyTrunks(got.PhysicalTrunks)
	if len(wantTrunks) != len(gotTrunks) {
		return fmt.Errorf("physical multiplex trunks are %d, want %d",
			len(gotTrunks), len(wantTrunks))
	}
	for i := range wantTrunks {
		a, b := wantTrunks[i], gotTrunks[i]
		if a.NodeA != b.NodeA || a.NodeB != b.NodeB || a.MTU != b.MTU || a.Port != b.Port {
			return fmt.Errorf("physical trunk %d is %+v, want %+v", i, b, a)
		}
	}
	return nil
}

func nonLegacyTrunks(in []netx.PhysicalTrunk) []netx.PhysicalTrunk {
	out := make([]netx.PhysicalTrunk, 0, len(in))
	for _, trunk := range in {
		if !trunk.Legacy {
			out = append(out, trunk)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeA != out[j].NodeA {
			return out[i].NodeA < out[j].NodeA
		}
		if out[i].NodeB != out[j].NodeB {
			return out[i].NodeB < out[j].NodeB
		}
		return out[i].Vxlan < out[j].Vxlan
	})
	return out
}

// inventoryMatchesCommitted additionally requires exact object labels. The
// generic recovery comparison accepts an unlabeled legacy object, but a
// current transaction with persisted touched facts must never turn that
// compatibility exception into an unrecorded recreation.
func inventoryMatchesCommitted(want, got transactionInventory) error {
	if err := inventoryMatches(want, got); err != nil {
		return err
	}
	for i := range want.Containers {
		if want.Containers[i].Generation != got.Containers[i].Generation {
			return fmt.Errorf("container %s generation is %q, want %q",
				got.Containers[i].Name, got.Containers[i].Generation, want.Containers[i].Generation)
		}
	}
	return nil
}

func (s *Server) validateInventoryLineage(lab string, inventory transactionInventory,
	current string,
) error {
	s.mu.Lock()
	state := s.generations[lab]
	overlayLineage := make(map[uint32]string, len(s.overlayLineage[lab]))
	for vni, generation := range s.overlayLineage[lab] {
		overlayLineage[vni] = generation
	}
	s.mu.Unlock()
	allowed := map[string]bool{current: true, state.Committed: true}
	for _, generation := range state.Ancestors {
		allowed[generation] = true
	}
	for _, container := range inventory.Containers {
		if container.Generation == "" {
			continue // legacy unlabeled object; spec/name still verify it.
		}
		if !allowed[container.Generation] {
			return fmt.Errorf("%s carries unrelated object generation %q", container.Name, container.Generation)
		}
	}
	for _, vni := range inventory.VNIs {
		if generation := overlayLineage[vni]; generation != "" && !allowed[generation] {
			return fmt.Errorf("VNI %d carries unrelated overlay generation %q", vni, generation)
		}
	}
	return nil
}

func (s *Server) markTransactionPhase(lab string, fence Fence, generation string,
	phase transactionPhase, failure string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return fmt.Errorf("generation %q of lab %q has no recovery transaction", generation, lab)
	}
	tx.Phase, tx.Failure = phase, failure
	if phase == transactionRecovering {
		tx.RecoveryAttempts++
		tx.LastRecovery = s.nowTime()
		tx.NextRecovery = time.Time{}
	}
	if phase == transactionRollbackFailed {
		// Leave a deterministic fenced window for an explicit operator
		// --strategy forward request before automatic rollback retries.
		tx.NextRecovery = s.nowTime().Add(recoveryRetryBackoff)
		tx.RecoveryProgress = s.nowTime()
		tx.RecoveryTarget = "failed"
	}
	if phase == transactionCommitted {
		tx.RecoveryProgress = s.nowTime()
		tx.RecoveryTarget = "committed"
	}
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func (s *Server) transactionInventoryStatus(ctx context.Context, lab string) RecoveryStatus {
	s.mu.Lock()
	s.initCoordination()
	tx, hasTx := s.transactions[lab]
	committed, hasCommitted := s.inventories[lab]
	committedGeneration := s.generations[lab].Committed
	leaseOwner := ""
	leaseUntil := time.Time{}
	if lease := s.mutations[lab]; lease != nil {
		leaseOwner, leaseUntil = lease.holder, lease.until
	}
	now := s.nowTime()
	s.mu.Unlock()

	status := RecoveryStatus{Lab: lab, Phase: "unknown"}
	var migrationErr error
	if hasCommitted && committed.Schema < overlayInventorySchema && s.canMigrateLegacyCommitted(lab) {
		migrated, err := s.migrateLegacyCommittedInventory(ctx, lab, committed)
		if err != nil {
			migrationErr = err
		} else {
			committed = migrated
		}
	}
	var want transactionInventory
	switch {
	case hasTx:
		status.Phase = string(tx.Phase)
		status.Generation = tx.Generation
		status.PreviousGeneration = tx.PreviousGen
		status.Mode, status.Ungraded = tx.Mode, tx.Ungraded
		status.PreviousMode, status.PreviousUngraded = tx.PreviousMode, tx.PreviousUngraded
		status.Attempts = tx.RecoveryAttempts
		status.RetryCount = tx.RecoveryAttempts
		status.Error = tx.Failure
		status.LastError = tx.Failure
		status.Owner = tx.RecoveryOwner
		status.Strategy = tx.RecoveryStrategy
		status.StartedAt = tx.RecoveryStarted
		status.LastProgressAt = tx.RecoveryProgress
		status.Deadline = tx.RecoveryDeadline
		status.TotalDeadline = tx.RecoveryTotal
		status.CurrentTarget = tx.RecoveryTarget
		status.ForwardAcknowledged = tx.ForwardAcknowledged
		status.ForwardPhase = tx.ForwardPhase
		status.DataLossScope = append([]string(nil), tx.ForwardDataLossScope...)
		if !leaseUntil.IsZero() {
			status.LeaseExpiresAt = leaseUntil
			if status.Owner == "" {
				status.Owner = leaseOwner
			}
		}
		status.TakeoverAllowed = tx.Phase == transactionRecovering &&
			(!tx.RecoveryDeadline.IsZero() && !now.Before(tx.RecoveryDeadline))
		if !tx.Committed {
			status.AllowedStrategies = []string{"rollback", "forward"}
		}
		if tx.Phase == transactionRollbackNeeded || tx.Phase == transactionRecovering ||
			tx.Phase == transactionRollbackFailed {
			want = tx.Prestate
		} else if hasCommitted {
			want = committed
		}
	case hasCommitted:
		status.Phase, status.Generation, want = "committed", committedGeneration, committed
		if status.Generation == "" {
			// Coordination records written before lab-generation lineage used
			// the inventory generation for both concepts.
			status.Generation = committed.Generation
		}
		s.mu.Lock()
		status.Mode, status.Ungraded = s.modes[lab], s.ungraded[lab]
		s.mu.Unlock()
	default:
		status.Phase = "idle"
		return status
	}
	status.ExpectedContainers, status.ExpectedVNIs = len(want.Containers), len(want.VNIs)
	status.ExpectedLogicalBindings = len(want.LogicalBindings)
	status.ExpectedPhysicalTrunks = len(want.PhysicalTrunks)
	observeCtx, cancel := context.WithTimeout(ctx, s.recoveryStatusLimit())
	defer cancel()
	got, err := s.snapshotTransactionInventory(observeCtx, lab)
	if err != nil {
		if status.Error == "" {
			status.Error = err.Error()
		}
		return status
	}
	status.ObservedContainers, status.ObservedVNIs = len(got.Containers), len(got.VNIs)
	status.ObservedLogicalBindings = len(got.LogicalBindings)
	status.ObservedPhysicalTrunks = len(got.PhysicalTrunks)
	if migrationErr != nil {
		status.Error = "migrate legacy committed overlay inventory: " + migrationErr.Error()
		return status
	}
	if err := inventoryMatches(want, got); err != nil {
		if status.Error == "" {
			status.Error = err.Error()
		}
		return status
	}
	// A matching partial inventory is recovery evidence, not a committed
	// cluster generation. Status must keep that distinction explicit so a
	// controller cannot mistake "HTTP answered" for atomic completion.
	status.Consistent = !hasTx || tx.Phase == transactionCommitted
	return status
}

func (s *Server) canMigrateLegacyCommitted(lab string) bool {
	s.mu.Lock()
	haveCurrent := s.current[lab] != nil
	store := s.store
	s.mu.Unlock()
	if haveCurrent {
		return true
	}
	if store == nil {
		return false
	}
	_, err := store.Topology(lab)
	return err == nil
}

// migrateLegacyCommittedInventory upgrades a schema-v1 committed count record
// only after reconstructing the topology's exact logical bindings and
// verifying them against live netlink state. A legacy count is never treated
// as proof that a shared trunk carries the right links.
func (s *Server) migrateLegacyCommittedInventory(ctx context.Context, lab string,
	committed transactionInventory,
) (transactionInventory, error) {
	top, peer, err := s.committedTopologyForInventory(lab)
	if err != nil {
		return transactionInventory{}, err
	}
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(),
		UnderlayIP: s.cfg.UnderlayIP, UnderlayDev: s.cfg.UnderlayDev,
		PeerUnderlay: peer, Generation: committed.Generation,
	}
	expected, err := eng.ExpectedOverlayInventory(top)
	if err != nil {
		return transactionInventory{}, fmt.Errorf("derive expected bindings: %w", err)
	}
	got, err := s.snapshotTransactionInventory(ctx, lab)
	if err != nil {
		return transactionInventory{}, err
	}
	if got.Schema < overlayInventorySchema {
		return transactionInventory{}, errors.New("live overlay inspection did not return schema-v2 bindings")
	}
	upgraded := committed
	upgraded.Schema = overlayInventorySchema
	upgraded.LogicalBindings = expected.Bindings
	upgraded.PhysicalTrunks = expected.Trunks
	upgraded.VNIs = bindingVNIs(expected.Bindings)
	if err := inventoryMatches(upgraded, got); err != nil {
		if s.rt == nil {
			// Focused inventory/restart tests may inject only an observed
			// inventory seam. A real agent always has a runtime and is the
			// only environment allowed to touch endpoint namespaces.
			return transactionInventory{}, err
		}
		repair, repairErr := eng.ReconcileOverlayBindings(ctx, top)
		if repairErr != nil {
			return transactionInventory{}, fmt.Errorf("inspect overlay drift: %w", repairErr)
		}
		if len(repair.Failed) > 0 {
			return transactionInventory{}, fmt.Errorf("repair logical bindings failed: %v", repair.Failed)
		}
		if len(repair.Extra) > 0 {
			return transactionInventory{}, fmt.Errorf("extra logical bindings require explicit prune: %v", repair.Extra)
		}
		got, repairErr = s.snapshotTransactionInventory(ctx, lab)
		if repairErr != nil {
			return transactionInventory{}, repairErr
		}
		if err := inventoryMatches(upgraded, got); err != nil {
			return transactionInventory{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	current, ok := s.inventories[lab]
	if !ok || current.Schema >= overlayInventorySchema {
		if ok {
			return current, nil
		}
		return transactionInventory{}, fmt.Errorf("committed inventory for %q disappeared during migration", lab)
	}
	previousInventory := current
	tx, hadTx := s.transactions[lab]
	state := s.generations[lab]
	previousState := state
	s.inventories[lab] = upgraded
	if hadTx && tx.Committed && tx.Generation == upgraded.Generation {
		delete(s.transactions, lab)
		if state.Prepared == tx.Generation {
			state.Prepared = ""
			s.generations[lab] = state
		}
	}
	if err := s.saveCoordinationLocked(); err != nil {
		s.inventories[lab] = previousInventory
		if hadTx {
			s.transactions[lab] = tx
		}
		s.generations[lab] = previousState
		return transactionInventory{}, fmt.Errorf("persist schema-v2 committed inventory: %w", err)
	}
	return upgraded, nil
}

func (s *Server) committedTopologyForInventory(lab string) (*model.Topology, map[string]string, error) {
	s.mu.Lock()
	top := s.current[lab]
	peer := map[string]string{}
	for node, address := range s.peers[lab] {
		peer[node] = address
	}
	s.mu.Unlock()
	if top != nil {
		if len(peer) == 0 && top.Lab != nil {
			for _, node := range top.Lab.Placement.Nodes {
				if node.UnderlayIP != "" {
					peer[node.Name] = node.UnderlayIP
				}
			}
		}
		return top, peer, nil
	}

	if s.store == nil {
		return nil, nil, fmt.Errorf("committed topology for %q is unavailable", lab)
	}
	raw, err := s.store.Topology(lab)
	if err != nil {
		return nil, nil, fmt.Errorf("read committed topology for %q: %w", lab, err)
	}
	var wire Wire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, nil, fmt.Errorf("decode committed topology for %q: %w", lab, err)
	}
	top, err = wire.Rehydrate()
	if err != nil {
		return nil, nil, fmt.Errorf("rehydrate committed topology for %q: %w", lab, err)
	}
	if len(peer) == 0 {
		for node, address := range wire.PeerUnderlay {
			peer[node] = address
		}
	}
	return top, peer, nil
}

// refreshCommittedOverlayInventory persists the post-repair schema-v3 facts.
// It is used by explicit overlay reconciliation so a repaired port/VNI is not
// immediately compared against the stale committed record on the next status
// or deploy.
func (s *Server) refreshCommittedOverlayInventory(ctx context.Context, lab string,
	top *model.Topology, eng *deploy.Engine,
) error {
	s.mu.Lock()
	committed, exists := s.inventories[lab]
	s.mu.Unlock()
	if !exists {
		return nil
	}
	expected, err := eng.ExpectedOverlayInventory(top)
	if err != nil {
		return err
	}
	got, err := s.snapshotTransactionInventory(ctx, lab)
	if err != nil {
		return err
	}
	if got.Schema < overlayInventorySchema {
		return errors.New("live overlay inspection did not return schema-v3 bindings")
	}
	upgraded := committed
	upgraded.Schema = overlayInventorySchema
	upgraded.LogicalBindings = expected.Bindings
	upgraded.PhysicalTrunks = expected.Trunks
	upgraded.VNIs = bindingVNIs(expected.Bindings)
	if err := inventoryMatches(upgraded, got); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	current, ok := s.inventories[lab]
	if !ok || current.Generation != committed.Generation {
		return fmt.Errorf("committed inventory for %q changed during overlay reconciliation", lab)
	}
	previous := current
	tx, hadTx := s.transactions[lab]
	state := s.generations[lab]
	previousState := state
	s.inventories[lab] = upgraded
	if hadTx && tx.Committed && tx.Generation == upgraded.Generation {
		delete(s.transactions, lab)
		if state.Prepared == tx.Generation {
			state.Prepared = ""
			s.generations[lab] = state
		}
	}
	if err := s.saveCoordinationLocked(); err != nil {
		s.inventories[lab] = previous
		if hadTx {
			s.transactions[lab] = tx
		}
		s.generations[lab] = previousState
		return err
	}
	return nil
}

func (s *Server) recoveryStatuses(ctx context.Context) map[string]RecoveryStatus {
	s.mu.Lock()
	s.initCoordination()
	labs := make(map[string]bool, len(s.transactions)+len(s.inventories))
	for lab := range s.transactions {
		labs[lab] = true
	}
	for lab := range s.inventories {
		labs[lab] = true
	}
	s.mu.Unlock()
	if len(labs) == 0 {
		return nil
	}
	out := make(map[string]RecoveryStatus, len(labs))
	for lab := range labs {
		out[lab] = s.transactionInventoryStatus(ctx, lab)
	}
	return out
}

// ordinaryMaintenanceSuppression is intentionally based on the persisted
// transaction journal, not the in-memory operation lease. A restart erases an
// ops lease before automatic recovery obtains a new one; event repair, audit,
// capture, or GC must not mistake that gap for permission to mutate a partially
// rolled-back lab. A transaction is released only when finalization deletes it.
func (s *Server) ordinaryMaintenanceSuppression(lab string) string {
	if lab == "" {
		return ""
	}
	s.mu.Lock()
	tx, active := s.transactions[lab]
	s.mu.Unlock()
	if !active {
		return ""
	}
	return fmt.Sprintf("durable transaction %q is %s", tx.Generation, tx.Phase)
}

func (s *Server) recoveryMutationRefusal(lab string) string {
	reason := s.ordinaryMaintenanceSuppression(lab)
	if reason == "" {
		return ""
	}
	return fmt.Sprintf("lab %q has %s; ordinary mutation is refused until the transaction is finalized",
		lab, reason)
}

func (s *Server) handleRecovery(w http.ResponseWriter, r *http.Request) {
	var req RecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	strategy := req.Strategy
	if strategy == "" {
		strategy = "rollback"
	}
	status, err := s.recoverTransactionStrategyOptions(r.Context(), req.Lab, req.Fence, strategy,
		recoveryRunOptions{takeover: req.Takeover, forwardAcknowledged: req.ForwardAcknowledged})
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, RecoveryResponse{Status: status})
}

func (s *Server) handleRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	lab := r.URL.Query().Get("lab")
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	writeJSON(w, s.transactionInventoryStatus(r.Context(), lab))
}

// recoverTransaction restores the last durable inventory. It never deletes a
// live lab as a shortcut: the rollback engine first recreates the old
// topology, restores student state, verifies exact service/VNI inventory, and
// only then considers cleanup.
func (s *Server) recoverTransaction(ctx context.Context, lab string, fence Fence) (RecoveryStatus, error) {
	return s.recoverTransactionStrategy(ctx, lab, fence, "rollback")
}

func recoveryPreviousTopology(lab string, tx applyTransaction) (*model.Topology, error) {
	if len(tx.Previous) == 0 {
		return nil, nil
	}
	var wire Wire
	if err := json.Unmarshal(tx.Previous, &wire); err != nil {
		return nil, fmt.Errorf("read recovery pre-state topology: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return nil, fmt.Errorf("rehydrate recovery pre-state topology: %w", err)
	}
	if top.Name != lab {
		return nil, fmt.Errorf("recovery pre-state topology belongs to %q, not %q", top.Name, lab)
	}
	return top, nil
}

func peerHandshakePermanent(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "bad certificate") ||
		strings.Contains(message, "certificate") ||
		strings.Contains(message, "unauthorized") ||
		strings.Contains(message, "forbidden") ||
		strings.Contains(message, "peer-state")
}

// waitForRecoveryPeerQuorum keeps one recovery attempt active while peers are
// rolling back/restarting. The old design returned after one periodic-ack
// miss, so three recovering nodes incremented retry counters every five
// seconds without ever giving their read-only peer APIs time to form quorum.
func (s *Server) waitForRecoveryPeerQuorum(ctx context.Context, top *model.Topology) error {
	if top == nil || top.Lab == nil || top.Lab.State.ReplicationFactor < 2 {
		return nil
	}
	delay := peerRetryMin
	var last error
	for {
		if err := s.ensurePeerQuorumReachable(ctx, top); err == nil {
			return nil
		} else {
			last = err
			if peerHandshakePermanent(err) {
				return err
			}
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			if last != nil {
				return fmt.Errorf("live peer quorum did not form: %w", last)
			}
			return ctx.Err()
		case <-timer.C:
		}
		delay *= 2
		if delay > peerRetryMax {
			delay = peerRetryMax
		}
	}
}

// fetchRecoveryReplicas reconstructs only the exact snapshot digests recorded
// before the failed transaction. It never substitutes a newer-looking peer
// snapshot, and it runs after live peer authentication but before rollback can
// replace the runtime carrying the old state.
func (s *Server) fetchRecoveryReplicas(ctx context.Context, top *model.Topology, tx applyTransaction) error {
	if len(tx.Prestate.Snapshots) == 0 {
		return nil
	}
	if s.store == nil {
		return errors.New("recovery snapshot manifest exists but the state store is unavailable")
	}
	if top == nil {
		return errors.New("recovery has snapshot evidence but no previous topology for peer lookup")
	}
	missing := map[string]transactionSnapshot{}
	for _, expected := range tx.Prestate.Snapshots {
		snapshot, err := s.store.Current(top.Name, expected.Device, state.Kind(expected.Kind))
		if err == nil && snapshot.Digest == expected.Digest {
			continue
		}
		missing[expected.Device+"/"+expected.Kind] = expected
	}
	if len(missing) == 0 {
		return nil
	}
	targets, err := s.replicaTargets(top)
	if err != nil {
		return err
	}
	for _, target := range targets {
		var response PeerStateReadResponse
		peerErr, nextRetry := retryPeer(ctx, func() error {
			peer, err := s.peerFor(ctx, target)
			if err != nil {
				return fmt.Errorf("dial recovery replica %s: %w", target.Name, err)
			}
			response, err = peer.Read(ctx, top.Name)
			if err != nil {
				return fmt.Errorf("read recovery replica %s: %w", target.Name, err)
			}
			if response.Lab != top.Name {
				return fmt.Errorf("read recovery replica %s returned lab %q, want %q",
					target.Name, response.Lab, top.Name)
			}
			return nil
		})
		if peerErr != nil {
			s.recordPeerReplication(top.Name, target.Name, peerErr, nextRetry)
			continue
		}
		s.recordPeerReplication(top.Name, target.Name, nil, time.Time{})
		for _, wire := range response.Snapshots {
			key := wire.Snapshot.Device + "/" + string(wire.Snapshot.Kind)
			expected, needed := missing[key]
			if !needed || wire.Snapshot.Lab != top.Name || wire.Snapshot.Digest != expected.Digest {
				continue
			}
			snapshot := wire.Snapshot
			snapshot.Content = wire.Content
			if _, err := s.store.Put(snapshot); err != nil {
				return fmt.Errorf("store verified replica %s/%s from %s: %w",
					snapshot.Device, snapshot.Kind, target.Name, err)
			}
			current, err := s.store.Current(top.Name, expected.Device, state.Kind(expected.Kind))
			if err == nil && current.Digest == expected.Digest {
				delete(missing, key)
			}
		}
		if len(missing) == 0 {
			return nil
		}
	}
	if len(missing) == 0 {
		return nil
	}
	keys := make([]string, 0, len(missing))
	for key := range missing {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Errorf("verified recovery replica is missing required snapshot digest(s): %s",
		strings.Join(keys, ", "))
}

func (s *Server) recoverTransactionStrategy(ctx context.Context, lab string, fence Fence,
	strategy string,
) (RecoveryStatus, error) {
	return s.recoverTransactionStrategyOptions(ctx, lab, fence, strategy, recoveryRunOptions{})
}

func (s *Server) recoverTransactionStrategyOptions(ctx context.Context, lab string, fence Fence,
	strategy string, options recoveryRunOptions,
) (RecoveryStatus, error) {
	if strategy != "rollback" && strategy != "forward" {
		return RecoveryStatus{}, fmt.Errorf("unknown recovery strategy %q", strategy)
	}
	if err := s.requireMutationFence(lab, fence); err != nil {
		return RecoveryStatus{}, err
	}
	s.mu.Lock()
	s.initCoordination()
	tx, ok := s.transactions[lab]
	s.mu.Unlock()
	if !ok {
		status := s.transactionInventoryStatus(ctx, lab)
		if !status.Consistent && status.Phase != "idle" {
			return status, fmt.Errorf("lab %q inventory is not consistent: %s", lab, status.Error)
		}
		return status, nil
	}
	if tx.Prestate.CapturedAt.IsZero() && len(tx.Prestate.Containers) == 0 && len(tx.Previous) > 0 {
		var wire Wire
		if err := json.Unmarshal(tx.Previous, &wire); err != nil {
			return RecoveryStatus{}, fmt.Errorf("read legacy transaction pre-state: %w", err)
		}
		oldTop, err := wire.Rehydrate()
		if err != nil {
			return RecoveryStatus{}, fmt.Errorf("rehydrate legacy transaction pre-state: %w", err)
		}
		// Legacy transactions predate per-container generation labels. Keep
		// the committed generation at the transaction level, but do not
		// invent labels that an otherwise intact old container cannot acquire
		// without destructive replacement.
		prestate := expectedTransactionInventory(oldTop, s.cfg.Node, "")
		prestate.Generation = tx.PreviousGen
		prestate.CapturedAt = s.nowTime()
		prestate.StateSafe = s.store != nil && s.store.Healthy() == nil
		s.mu.Lock()
		current := s.transactions[lab]
		if current.Generation == tx.Generation {
			current.Prestate = prestate
			s.transactions[lab] = current
			_ = s.saveCoordinationLocked()
			tx = current
		}
		s.mu.Unlock()
	}
	if tx.Committed {
		status := s.transactionInventoryStatus(ctx, lab)
		if !status.Consistent {
			_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
				"committed inventory drift: "+status.Error)
			return status, fmt.Errorf("committed generation %q inventory drift: %s", tx.Generation, status.Error)
		}
		return status, nil
	}
	recoveryLimit := s.recoveryTotalLimit()
	if strategy == "forward" {
		recoveryLimit = s.forwardRecoveryLimit(tx)
	}
	totalCtx, totalCancel := context.WithTimeout(ctx, recoveryLimit)
	defer totalCancel()
	totalDeadline := s.nowTime().Add(recoveryLimit)
	fencedCtx, stopFence := s.fencedContext(totalCtx, lab, fence)
	defer stopFence()
	opID, err := s.acquireRecoveryOperation(lab, totalDeadline, totalCancel, options.takeover)
	if err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	defer s.releaseRecoveryOperation(lab, opID)
	tx, err = s.beginRecovery(lab, fence, tx.Generation, strategy, totalDeadline, options)
	if err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if strategy == "forward" {
		if err := s.runRecoveryLongPhase(fencedCtx, lab, fence, tx.Generation,
			"forward", "recorded desired transaction", func(phaseCtx context.Context) error {
				if s.recoveryForward != nil {
					return s.recoveryForward(phaseCtx, lab, fence, tx)
				}
				_, err := s.forwardTransaction(phaseCtx, lab, fence, tx)
				return err
			}); err != nil {
			s.failRecovery(lab, fence, tx.Generation, err)
			return s.transactionInventoryStatus(ctx, lab), err
		}
		return s.transactionInventoryStatus(ctx, lab), nil
	}
	if len(tx.Prestate.Containers) > 0 && !tx.Prestate.StateSafe {
		err := errors.New("refusing recovery before durable student state capture")
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), errors.New(
			"refusing recovery before durable student state capture")
	}
	previousTop, err := recoveryPreviousTopology(lab, tx)
	if err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if previousTop != nil {
		if err := s.runRecoveryPhaseLimit(fencedCtx, lab, fence, tx.Generation,
			"peer", "authenticated live peer quorum", s.recoveryArtifactLimit(),
			func(phaseCtx context.Context) error {
				return s.waitForRecoveryPeerQuorum(phaseCtx, previousTop)
			}); err != nil {
			s.failRecovery(lab, fence, tx.Generation, err)
			return s.transactionInventoryStatus(ctx, lab), err
		}
		if err := s.runRecoveryPhaseLimit(fencedCtx, lab, fence, tx.Generation,
			"replica", "verify and fetch durable replicas", s.recoveryArtifactLimit(),
			func(phaseCtx context.Context) error {
				return s.fetchRecoveryReplicas(phaseCtx, previousTop, tx)
			}); err != nil {
			s.failRecovery(lab, fence, tx.Generation, err)
			return s.transactionInventoryStatus(ctx, lab), err
		}
	}
	rollback := s.rollbackPreparedApply
	if s.recoveryRollback != nil {
		rollback = s.recoveryRollback
	}
	runRollback := s.runRecoveryPhase
	if s.recoveryRollback == nil && len(tx.Prestate.RuntimeSpecs) > 0 {
		runRollback = s.runRecoveryLongPhase
	}
	if err := runRollback(fencedCtx, lab, fence, tx.Generation,
		"rollback", "restore prior runtime inventory", func(phaseCtx context.Context) error {
			if err := s.transactionFail("rollback"); err != nil {
				return err
			}
			return rollback(phaseCtx, lab, fence, tx)
		}); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	restore := func(context.Context) error { return s.restoreRecoveredTopology(lab, tx) }
	if s.recoveryRestore != nil {
		restore = func(phaseCtx context.Context) error {
			return s.recoveryRestore(phaseCtx, lab, tx)
		}
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"restore", "persist previous topology", restore); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	verify := func(phaseCtx context.Context) error { return s.verifyRecoveredStudentState(phaseCtx, tx) }
	if s.recoveryVerify != nil {
		verify = func(phaseCtx context.Context) error { return s.recoveryVerify(phaseCtx, tx) }
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"verify", "restored student state and runtime semantics", verify); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"verify", "expected FRR control sidecars", func(phaseCtx context.Context) error {
			return s.verifyRecoveredControls(phaseCtx, tx)
		}); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	replicate := func(phaseCtx context.Context) error { return s.replicateRecoveredDurability(phaseCtx, tx) }
	if s.recoveryReplicate != nil {
		replicate = func(phaseCtx context.Context) error { return s.recoveryReplicate(phaseCtx, tx) }
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"replicate", "durable peer quorum", replicate); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"verify", "exact prior inventory", func(phaseCtx context.Context) error {
			got, err := s.snapshotTransactionInventory(phaseCtx, lab)
			if err != nil {
				return err
			}
			return inventoryMatches(tx.Prestate, got)
		}); err != nil {
		err = fmt.Errorf("rollback inventory verification failed: %w", err)
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
		"commit", "persist recovered generation", func(context.Context) error {
			return s.finishRecoveredGeneration(lab, fence, tx.Generation)
		}); err != nil {
		s.failRecovery(lab, fence, tx.Generation, err)
		return s.transactionInventoryStatus(ctx, lab), err
	}
	return s.transactionInventoryStatus(ctx, lab), nil
}

// restoreRecoveredTopology makes the old mode/ungarded policy authoritative
// before semantic verification and peer replication. Exact-contract rollback
// used to recreate containers but leave the agent believing the failed forward
// mode was still current, so a solved host could be recaptured as reference
// state or an ungraded submission could be skipped entirely.
func (s *Server) restoreRecoveredTopology(lab string, tx applyTransaction) error {
	if len(tx.Previous) == 0 {
		return nil
	}
	var wire Wire
	if err := json.Unmarshal(tx.Previous, &wire); err != nil {
		return fmt.Errorf("read recovered topology: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return fmt.Errorf("rehydrate recovered topology: %w", err)
	}
	if top.Name != lab {
		return fmt.Errorf("recovered topology belongs to %q, not %q", top.Name, lab)
	}
	if s.store != nil {
		if err := s.store.PutTopology(lab, tx.Previous); err != nil {
			return fmt.Errorf("persist recovered topology: %w", err)
		}
	}
	s.mu.Lock()
	if s.current == nil {
		s.current = map[string]*model.Topology{}
	}
	s.current[lab] = top
	mode, ungraded := recoveredMode(tx, wire)
	s.rememberHow(lab, string(mode), ungraded)
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	s.peers[lab] = wire.PeerUnderlay
	s.mu.Unlock()
	return nil
}

// replicateRecoveredDurability makes recovery completion contingent on the
// same peer quorum as a forward destructive boundary. A locally repaired
// namespace is not a completed recovery if the sole durable copy still lives
// on the recovering node.
func (s *Server) replicateRecoveredDurability(ctx context.Context, tx applyTransaction) error {
	if s.store == nil || len(tx.Previous) == 0 {
		return nil
	}
	var wire Wire
	if err := json.Unmarshal(tx.Previous, &wire); err != nil {
		return fmt.Errorf("read recovered topology for durability replication: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return fmt.Errorf("rehydrate recovered topology for durability replication: %w", err)
	}
	if _, err := s.captureAndReplicate(ctx, top); err != nil {
		return fmt.Errorf("recovery peer quorum: %w", err)
	}
	return nil
}

func (s *Server) verifyRecoveredControls(ctx context.Context, tx applyTransaction) error {
	var controls []transactionRuntimeSpec
	for _, entry := range tx.Prestate.RuntimeSpecs {
		if entry.Control != nil {
			controls = append(controls, entry)
		}
	}
	if len(controls) == 0 {
		return nil
	}
	if s.rt == nil {
		return errors.New("no runtime for recovered control verification")
	}
	return runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(), controls, s.recoveryArtifactLimit(),
		func(entry transactionRuntimeSpec) string { return "FRR control " + entry.DeviceID },
		func(checkCtx context.Context, entry transactionRuntimeSpec) error {
			control := entry.Control
			var current rt.Container
			err := s.workLimiter().Run(checkCtx, []limiter.Kind{limiter.Apply, limiter.Lifecycle}, func() error {
				var inspectErr error
				current, inspectErr = s.rt.Inspect(checkCtx, control.Name)
				return inspectErr
			})
			if err != nil {
				return fmt.Errorf("inspect expected control %s: %w", control.Name, err)
			}
			if current.State != rt.StateRunning {
				return fmt.Errorf("expected control %s is %s, want running", control.Name, current.State)
			}
			if !exactRuntimeSpecMatches(current, control) {
				return fmt.Errorf("expected control %s does not match its recovered runtime contract", control.Name)
			}
			return nil
		})
}

func (s *Server) verifyRecoveredStudentState(ctx context.Context, tx applyTransaction) error {
	if s.rt == nil || len(tx.Previous) == 0 {
		return nil
	}

	var wire Wire
	if err := json.Unmarshal(tx.Previous, &wire); err != nil {
		return fmt.Errorf("read pre-state topology for restore verification: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return fmt.Errorf("rehydrate pre-state topology for restore verification: %w", err)
	}
	expectedByDevice := map[string][]state.Snapshot{}
	if len(tx.Prestate.Snapshots) > 0 {
		if s.store == nil {
			return errors.New("recovery snapshot manifest exists but the state store is unavailable")
		}
		for _, expected := range tx.Prestate.Snapshots {
			snapshot, err := s.store.Current(top.Name, expected.Device, state.Kind(expected.Kind))
			if err != nil {
				return fmt.Errorf("recovery snapshot %s/%s is missing: %w", expected.Device, expected.Kind, err)
			}
			if snapshot.Digest != expected.Digest {
				return fmt.Errorf("recovery snapshot %s/%s digest is %s, want captured %s",
					expected.Device, expected.Kind, snapshot.Digest, expected.Digest)
			}
			expectedByDevice[expected.Device] = append(expectedByDevice[expected.Device], snapshot)
		}
	}
	mode, ungraded := recoveredMode(tx, wire)
	var restoreDevices []*model.Device
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if renderModeForDevice(mode, ungraded, device) != render.ModeSolve {
			restoreDevices = append(restoreDevices, device)
		}
	}
	if err := runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(),
		restoreDevices, s.recoveryArtifactLimit(),
		func(device *model.Device) string { return "verify restored student state " + device.ID },
		func(verifyCtx context.Context, device *model.Device) error {
			if s.store != nil {
				expected := expectedByDevice[device.ID]
				if len(tx.Prestate.Snapshots) == 0 {
					for _, kind := range state.AllKinds {
						snapshot, err := s.store.Current(top.Name, device.ID, kind)
						if err == nil {
							expected = append(expected, snapshot)
						}
					}
				}
				if len(expected) > 0 {
					if _, err := verifyRestoredState(verifyCtx, s.rt, device, top.Name, top.Hash, expected); err != nil {
						return fmt.Errorf("verify restored student state for %s: %w", device.ID, err)
					}
				}
			}
			return nil
		}); err != nil {
		return err
	}
	if err := s.verifyRecoveredSemantics(ctx, top, mode, ungraded,
		tx.Prestate.RuntimeSpecs); err != nil {
		return fmt.Errorf("verify recovered rendered/network semantics: %w", err)
	}
	return nil
}

// forwardTransaction is deliberately explicit: it resumes the persisted
// desired wire only after an operator selected --strategy forward. Automatic
// recovery always uses rollback, because a newer contract may intentionally
// obsolete the old runtime.
func (s *Server) forwardTransaction(ctx context.Context, lab string, fence Fence,
	tx applyTransaction,
) (RecoveryStatus, error) {
	var wire Wire
	if err := json.Unmarshal(tx.Requested, &wire); err != nil {
		return RecoveryStatus{}, fmt.Errorf("read desired forward transaction: %w", err)
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return RecoveryStatus{}, fmt.Errorf("rehydrate desired forward transaction: %w", err)
	}
	if top.Name != lab {
		return RecoveryStatus{}, errors.New("recorded desired topology belongs to another lab")
	}
	if len(tx.StateProofs) > 0 && !tx.StateVerified && !tx.ForwardAcknowledged {
		return RecoveryStatus{}, errors.New("forward recovery requires verified restored student state")
	}
	if err := s.markForwardPhase(lab, fence, tx.Generation, "reserve desired overlays"); err != nil {
		return RecoveryStatus{}, err
	}
	if _, err := s.reserveOverlays(OverlayReservationRequest{
		Lab: lab, Fence: fence, VNIs: overlayVNIsOnNode(top, s.cfg.Node),
	}); err != nil {
		return s.transactionInventoryStatus(ctx, lab), fmt.Errorf("forward reserve overlays: %w", err)
	}
	s.mu.Lock()
	current := s.transactions[lab]
	if current.Generation != tx.Generation {
		s.mu.Unlock()
		return RecoveryStatus{}, errors.New("transaction changed while forward recovery was starting")
	}
	current.FenceGeneration = fence.Generation
	current.Phase, current.Failure = transactionApplying, ""
	s.transactions[lab] = current
	if err := s.saveCoordinationLocked(); err != nil {
		s.mu.Unlock()
		return RecoveryStatus{}, err
	}
	previous := s.current[lab]
	s.mu.Unlock()
	if err := s.markForwardPhase(lab, fence, tx.Generation, "capture current durable state"); err != nil {
		return RecoveryStatus{}, err
	}
	if previous != nil && s.store != nil {
		if _, err := s.captureAndReplicate(ctx, previous); err != nil {
			if !current.ForwardAcknowledged {
				_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
					"forward pre-state capture failed: "+err.Error())
				return s.transactionInventoryStatus(ctx, lab), err
			}
			if auditErr := s.recordForwardDataLoss(lab, fence, tx.Generation,
				"current-state-capture-unavailable: "+err.Error()); auditErr != nil {
				return s.transactionInventoryStatus(ctx, lab), auditErr
			}
		}
	}
	eng, err := s.transactionEngine(top, current)
	if err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.markForwardPhase(lab, fence, tx.Generation, "build observed desired diff"); err != nil {
		return RecoveryStatus{}, err
	}
	p, err := eng.Build(top)
	if err != nil {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.recordGenerationTouched(lab, fence, tx.Generation,
		eng.DirtyCreateDevices(), eng.DirtyOverlayVNIs(top), current.TouchedKnown); err != nil {
		return s.transactionInventoryStatus(ctx, lab), fmt.Errorf("persist forward recovery touched set: %w", err)
	}
	if err := s.recordGenerationSemantic(lab, fence, tx.Generation, eng.DirtySemanticDevices()); err != nil {
		return s.transactionInventoryStatus(ctx, lab), fmt.Errorf("persist forward recovery semantic set: %w", err)
	}
	s.mu.Lock()
	current = s.transactions[lab]
	s.mu.Unlock()
	if err := s.markForwardPhase(lab, fence, tx.Generation, "apply remaining desired work"); err != nil {
		return RecoveryStatus{}, err
	}
	s.transactionFailpoints(p)
	rep, err := p.Execute(ctx, plan.Options{
		Workers: s.recoveryWorkerCount(), ContinueOnError: true,
	})
	if err != nil || rep.Failed() {
		failure := "forward recovery failed"
		if err != nil {
			failure += ": " + err.Error()
		} else {
			failure += ": " + rep.Err().Error()
		}
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, failure)
		return s.transactionInventoryStatus(ctx, lab), errors.New(failure)
	}
	if err := s.markGenerationApplied(lab, fence, tx.Generation); err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.markForwardPhase(lab, fence, tx.Generation, "verify and commit desired inventory"); err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	resp, err := s.commitAppliedTopology(ctx, top, &wire, fence, current)
	if err != nil {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
			"forward commit failed: "+err.Error())
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if len(resp.Failures) > 0 {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
			"forward commit reported failures")
		return s.transactionInventoryStatus(ctx, lab), errors.New("forward commit reported failures")
	}
	if err := s.finalizeCommittedGeneration(lab, fence, tx.Generation); err != nil {
		return s.transactionInventoryStatus(ctx, lab), err
	}
	return s.transactionInventoryStatus(ctx, lab), nil
}

// rollbackExactContracts restores the runtime contract captured before the
// transaction. It deliberately does not call ensureContainer/configure: those
// functions derive today's hardening and renderer output, precisely the drift
// a rollback must avoid.
func (s *Server) rollbackExactContracts(ctx context.Context, lab string, fence Fence,
	tx applyTransaction, top *model.Topology,
) error {
	if s.rt == nil {
		return errors.New("no runtime for exact rollback")
	}
	byDevice := map[string]*model.Device{}
	var oldWire Wire
	if err := json.Unmarshal(tx.Previous, &oldWire); err != nil {
		return fmt.Errorf("read exact rollback topology: %w", err)
	}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		byDevice[device.ID] = device
	}
	rollback := tx
	rollback.Generation, rollback.Prune = tx.PreviousGen, false
	// Exact artifacts were captured from the previous wire. Rewiring through
	// the failed forward mode can leave a solved host without its reference
	// address/default route (or install one on an ungraded submission AS)
	// before the persisted commands are replayed.
	previousMode, previousUngraded := recoveredMode(tx, oldWire)
	rollback.Mode = string(previousMode)
	rollback.Ungraded = previousUngraded
	rollback.PeerUnderlay = oldWire.PeerUnderlay
	eng, err := s.transactionEngine(top, rollback)
	if err != nil {
		return err
	}
	keepWiring, err := s.rollbackCanKeepWiring(ctx, tx, top)
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		expected[entry.Spec.Name] = true
	}
	if err := runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(),
		tx.Prestate.RuntimeSpecs, s.recoveryArtifactLimit(),
		func(entry transactionRuntimeSpec) string { return "exact runtime contract " + entry.DeviceID },
		func(phaseCtx context.Context, entry transactionRuntimeSpec) error {
			device := byDevice[entry.DeviceID]
			if device == nil {
				return fmt.Errorf("rollback contract references unknown device %q", entry.DeviceID)
			}
			current, err := s.rt.Inspect(phaseCtx, entry.Spec.Name)
			if err != nil {
				return fmt.Errorf("inspect rollback primary %s: %w", entry.Spec.Name, err)
			}
			// A split FRR control sidecar joins the primary container's
			// network namespace. Remove it only when the primary genuinely
			// needs replacement. Retrying a timeout must never tear down a
			// healthy restored control merely because another object stalled.
			replacePrimary := current.State == rt.StateAbsent || !exactRuntimeSpecMatches(current, &entry.Spec)
			if replacePrimary && entry.Control != nil {
				if err := s.removeRecoveryContainerIfPresent(phaseCtx, entry.Control.Name); err != nil {
					return fmt.Errorf("remove rollback control %s before primary replacement: %w",
						entry.Control.Name, err)
				}
			}
			if err := eng.PrepareRuntimeSpec(top, device); err != nil {
				return fmt.Errorf("prepare rollback runtime paths for %s: %w", entry.DeviceID, err)
			}
			spec := entry.Spec
			if err := s.ensureExactRecoveryContainer(phaseCtx, &spec); err != nil {
				return err
			}
			return nil
		}); err != nil {
		return err
	}
	if !keepWiring {
		if err := s.runRecoveryPhaseLimit(ctx, lab, fence, tx.Generation,
			"rollback", "rewire prior topology", s.recoveryArtifactLimit(), func(phaseCtx context.Context) error {
				return s.workLimiter().Run(phaseCtx, []limiter.Kind{limiter.Apply, limiter.Netlink}, func() error {
					if err := eng.RewireTopology(phaseCtx, top); err != nil {
						return fmt.Errorf("rewire exact rollback topology: %w", err)
					}
					return nil
				})
			}); err != nil {
			return err
		}
	}
	if err := runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(),
		tx.Prestate.RuntimeSpecs, s.recoveryArtifactLimit(),
		func(entry transactionRuntimeSpec) string { return "exact rendered artifacts " + entry.DeviceID },
		func(phaseCtx context.Context, entry transactionRuntimeSpec) error {
			device := byDevice[entry.DeviceID]
			if device == nil {
				return fmt.Errorf("rollback artifacts reference unknown device %q", entry.DeviceID)
			}
			for _, artifact := range entry.Artifacts {
				if artifact.Command != nil {
					continue
				}
				if artifact.Digest != artifactDigest(artifact.Content) {
					return fmt.Errorf("rollback artifact %s for %s digest mismatch", artifact.Path, entry.DeviceID)
				}
				if err := s.workLimiter().Run(phaseCtx, []limiter.Kind{limiter.Apply, limiter.ExecProbe}, func() error {
					return s.rt.CopyTo(phaseCtx, entry.Spec.Name, artifact.Path, artifact.Mode, artifact.Content)
				}); err != nil {
					return fmt.Errorf("restore rollback artifact %s to %s: %w",
						artifact.Path, entry.Spec.Name, err)
				}
			}
			if entry.Control != nil {
				control := *entry.Control
				if err := s.ensureExactRecoveryContainer(phaseCtx, &control); err != nil {
					return err
				}
			} else if err := s.workLimiter().Run(phaseCtx, []limiter.Kind{limiter.Apply, limiter.Lifecycle}, func() error {
				return eng.EnsureRuntimeSupport(phaseCtx, top, device)
			}); err != nil {
				return fmt.Errorf("restore rollback support for %s: %w", entry.DeviceID, err)
			}
			runCommand := func(artifact transactionArtifact) error {
				raw, _ := json.Marshal(*artifact.Command)
				if artifact.Digest != artifactDigest(raw) {
					return fmt.Errorf("rollback command for %s digest mismatch", entry.DeviceID)
				}
				container := entry.Spec.Name
				if artifact.Command.FRRControl && deploy.UsesFRRControl(device) {
					container = deploy.FRRControlContainer(device)
				}
				var result rt.ExecResult
				err := s.workLimiter().Run(phaseCtx, []limiter.Kind{limiter.Apply, limiter.ExecProbe}, func() error {
					var execErr error
					result, execErr = s.rt.Exec(phaseCtx, container, rt.ExecCmd{Cmd: artifact.Command.Args})
					return execErr
				})
				if err != nil {
					return fmt.Errorf("run rollback command for %s: %w", entry.DeviceID, err)
				}
				if err := result.Err(); err != nil && !artifact.Command.IgnoreError {
					return fmt.Errorf("run rollback command for %s: %w", entry.DeviceID, err)
				}
				return nil
			}

			var daemonChecks []transactionArtifact
			for _, artifact := range entry.Artifacts {
				if artifact.Command == nil {
					continue
				}
				if artifact.Command.FRRControl &&
					strings.Contains(artifact.Command.Describe, "check the routing daemons are running") {
					daemonChecks = append(daemonChecks, artifact)
					continue
				}
				if err := runCommand(artifact); err != nil {
					return err
				}
			}
			// The persisted command list checks daemons before a later
			// frrinit start command. During exact rollback the control
			// namespace was deliberately recreated, so perform that check
			// after the recorded starter and retain its final validation.
			for _, artifact := range daemonChecks {
				if err := runCommand(artifact); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}
	if err := runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(),
		tx.Prestate.RuntimeSpecs, s.recoveryPhaseLimit(),
		func(entry transactionRuntimeSpec) string { return "exact rollback readiness " + entry.DeviceID },
		func(phaseCtx context.Context, entry transactionRuntimeSpec) error {
			device := byDevice[entry.DeviceID]
			if device == nil {
				return fmt.Errorf("rollback readiness references unknown device %q", entry.DeviceID)
			}
			if waiter := eng.Renderer.Ready(device, s.rt); waiter != nil {
				if err := plan.Wait(phaseCtx, *waiter); err != nil {
					return fmt.Errorf("verify exact rollback readiness for %s: %w", entry.DeviceID, err)
				}
			}
			return nil
		}); err != nil {
		return err
	}
	// A restored FRR snapshot is applied through vtysh. The private FRR
	// control namespace can be running while its socket is not yet usable by
	// the primary container; applying state before readiness caused retries to
	// fail with transient "Failure to communicate to zebra" errors. Runtime
	// contracts and rendered artifacts are already exact at this point, so
	// waiting does not recompute or weaken the rollback contract.
	var studentEntries []transactionRuntimeSpec
	for _, entry := range tx.Prestate.RuntimeSpecs {
		device := byDevice[entry.DeviceID]
		if device != nil && renderModeForDevice(previousMode, previousUngraded, device) != render.ModeSolve {
			studentEntries = append(studentEntries, entry)
		}
	}
	if err := runBoundedDeviceChecks(ctx, s.recoveryWorkerCount(),
		studentEntries, s.recoveryArtifactLimit(),
		func(entry transactionRuntimeSpec) string { return "exact student state " + entry.DeviceID },
		func(phaseCtx context.Context, entry transactionRuntimeSpec) error {
			device := byDevice[entry.DeviceID]
			if device == nil {
				return fmt.Errorf("student state references unknown device %q", entry.DeviceID)
			}
			if err := s.workLimiter().Run(phaseCtx, []limiter.Kind{limiter.Apply, limiter.ExecProbe}, func() error {
				_, err := deploy.Restore(phaseCtx, s.rt, device, lab, s.store)
				return err
			}); err != nil {
				return fmt.Errorf("restore student state for %s: %w", entry.DeviceID, err)
			}
			return nil
		}); err != nil {
		return err
	}
	if err := s.runRecoveryPhase(ctx, lab, fence, tx.Generation,
		"prune", "forward-only runtime objects and overlays", func(phaseCtx context.Context) error {
			containers, err := s.recoveryContainerList(phaseCtx, lab)
			if err != nil {
				return err
			}
			for _, container := range containers {
				if isInternalControlContainer(container) || expected[container.Name] {
					continue
				}
				if err := s.rt.Remove(phaseCtx, container.Name, true); err != nil {
					return fmt.Errorf("remove forward-only rollback container %s: %w", container.Name, err)
				}
			}
			if err := s.transactionFail("prune"); err != nil {
				return fmt.Errorf("exact rollback prune failpoint: %w", err)
			}
			if _, err := eng.PruneOverlaysContext(phaseCtx, top); err != nil {
				return fmt.Errorf("prune exact rollback overlays: %w", err)
			}
			return nil
		}); err != nil {
		return err
	}
	return nil
}
