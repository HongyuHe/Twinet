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
	recoveryRetryEvery             = 5 * time.Second
	recoveryRetryBackoff           = 30 * time.Second
	defaultRecoveryPhaseTimeout    = 90 * time.Second
	defaultRecoveryArtifactTimeout = 4 * time.Minute
	// Exact rollback restores primary contracts, sidecars, artifacts,
	// readiness, and student snapshots one fenced target at a time. A
	// class-scale node legitimately needs longer than a single controller
	// lease, while every target remains independently deadline-bounded and
	// visible to a joining operator.
	defaultRecoveryTotalTimeout = 30 * time.Minute
	defaultRecoveryLeaseTTL     = 90 * time.Second
	recoveryLeaseRenewEvery     = 15 * time.Second
	recoveryStatusObserveLimit  = 2 * time.Second
)

type recoveryRunOptions struct {
	takeover  bool
	automatic bool
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
	if _, err := s.recoverTransactionStrategyOptions(runCtx, lab, fence, "rollback",
		recoveryRunOptions{takeover: true, automatic: true}); err != nil {
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
	tx.RecoveryStarted = now
	tx.RecoveryProgress = now
	tx.RecoveryDeadline = now.Add(s.recoveryPhaseLimit())
	tx.RecoveryTotal = totalDeadline
	tx.RecoveryTarget = "starting recovery"
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		return applyTransaction{}, err
	}
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
	tx.RecoveryTarget = target
	tx.RecoveryProgress = s.nowTime()
	tx.RecoveryDeadline = deadline
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		return err
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
	if err := s.updateRecoveryProgress(lab, fence, generation, action+": "+target, deadline); err != nil {
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
	return s.updateRecoveryProgress(lab, fence, generation, "completed "+action+": "+target, deadline)
}

// runRecoveryLongPhase is for a composite exact rollback. Each device inside
// it is still run through runRecoveryPhase, so one blocked container/exec has
// a bounded deadline; the aggregate may legitimately span more than one
// device deadline on a class-sized node.
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
	return s.updateRecoveryProgress(lab, fence, generation, "completed "+action+": "+target, deadline)
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
	vnis, err := s.recoveryOverlayList(lab)
	if err != nil {
		return transactionInventory{}, fmt.Errorf("list pre-transaction overlays: %w", err)
	}
	out := transactionInventory{CapturedAt: s.nowTime(), VNIs: append([]uint32(nil), vnis...)}
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
	out.VNIs = overlayVNIsOnNode(top, node)
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].Name < out.Containers[j].Name })
	sort.Slice(out.VNIs, func(i, j int) bool { return out.VNIs[i] < out.VNIs[j] })
	return out, nil
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
	if len(want.VNIs) != len(got.VNIs) {
		return fmt.Errorf("overlay inventory is %d, want %d", len(got.VNIs), len(want.VNIs))
	}
	for i := range want.VNIs {
		if want.VNIs[i] != got.VNIs[i] {
			return fmt.Errorf("overlay VNI %d is %d, want %d", i, got.VNIs[i], want.VNIs[i])
		}
	}
	return nil
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

func (s *Server) recoveryMutationRefusal(lab string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	tx, ok := s.transactions[lab]
	if !ok || tx.Committed {
		return ""
	}
	return fmt.Sprintf("lab %q is %s for failed generation %q; ordinary mutation is refused until recovery verifies the prior inventory",
		lab, tx.Phase, tx.Generation)
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
		recoveryRunOptions{takeover: req.Takeover})
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
	totalCtx, totalCancel := context.WithTimeout(ctx, s.recoveryTotalLimit())
	defer totalCancel()
	totalDeadline := s.nowTime().Add(s.recoveryTotalLimit())
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
		if err := s.runRecoveryPhase(fencedCtx, lab, fence, tx.Generation,
			"forward", "recorded desired transaction", func(phaseCtx context.Context) error {
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
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if renderModeForDevice(mode, ungraded, device) == render.ModeSolve {
			// A solved reference device intentionally does not replay student
			// snapshots. An ungraded AS in a private harness reaches the
			// platform path above and is preserved normally.
			continue
		}
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
				if _, err := verifyRestoredState(ctx, s.rt, device, top.Name, top.Hash, expected); err != nil {
					return fmt.Errorf("verify restored student state for %s: %w", device.ID, err)
				}
			}
		}
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
	if len(tx.StateProofs) > 0 && !tx.StateVerified {
		return RecoveryStatus{}, errors.New("forward recovery requires verified restored student state")
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
	if previous != nil && s.store != nil {
		if _, err := s.captureAndReplicate(ctx, previous); err != nil {
			_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
				"forward pre-state capture failed: "+err.Error())
			return s.transactionInventoryStatus(ctx, lab), err
		}
	}
	eng := s.transactionEngine(top, current)
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
	s.transactionFailpoints(p)
	rep, err := p.Execute(ctx, plan.Options{
		Workers: s.workLimiter().ClampWorkers(limiter.Apply, 0), ContinueOnError: true,
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
	eng := s.transactionEngine(top, rollback)
	expected := map[string]bool{}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		entry := entry
		if err := s.runRecoveryPhase(ctx, lab, fence, tx.Generation,
			"rollback", "exact runtime contract: "+entry.DeviceID, func(phaseCtx context.Context) error {
				device := byDevice[entry.DeviceID]
				if device == nil {
					return fmt.Errorf("rollback contract references unknown device %q", entry.DeviceID)
				}
				expected[entry.Spec.Name] = true
				// A split FRR control sidecar joins the primary container's
				// network namespace. It must be removed before replacing that
				// primary: retaining the old namespace holder can leave Docker
				// Start blocked with the replacement stuck in Created.
				if entry.Control != nil {
					control, err := s.rt.Inspect(phaseCtx, entry.Control.Name)
					if err != nil {
						return fmt.Errorf("inspect rollback control %s: %w", entry.Control.Name, err)
					}
					if control.State != rt.StateAbsent {
						if err := s.rt.Remove(phaseCtx, entry.Control.Name, true); err != nil {
							return fmt.Errorf("remove rollback control %s before primary replacement: %w",
								entry.Control.Name, err)
						}
					}
				}
				current, err := s.rt.Inspect(phaseCtx, entry.Spec.Name)
				if err != nil {
					return fmt.Errorf("inspect rollback container %s: %w", entry.Spec.Name, err)
				}
				if current.State != rt.StateAbsent {
					if err := s.rt.Remove(phaseCtx, entry.Spec.Name, true); err != nil {
						return fmt.Errorf("remove dirty rollback container %s: %w", entry.Spec.Name, err)
					}
				}
				if err := eng.PrepareRuntimeSpec(top, device); err != nil {
					return fmt.Errorf("prepare rollback runtime paths for %s: %w", entry.DeviceID, err)
				}
				spec := entry.Spec
				if _, err := s.rt.Create(phaseCtx, &spec); err != nil {
					return fmt.Errorf("create exact rollback container %s: %w", spec.Name, err)
				}
				if err := s.rt.Start(phaseCtx, spec.Name); err != nil {
					return fmt.Errorf("start exact rollback container %s: %w", spec.Name, err)
				}
				return nil
			}); err != nil {
			return err
		}
	}
	if err := s.runRecoveryPhase(ctx, lab, fence, tx.Generation,
		"rollback", "rewire prior topology", func(phaseCtx context.Context) error {
			if err := eng.RewireTopology(phaseCtx, top); err != nil {
				return fmt.Errorf("rewire exact rollback topology: %w", err)
			}
			return nil
		}); err != nil {
		return err
	}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		entry := entry
		if err := s.runRecoveryPhaseLimit(ctx, lab, fence, tx.Generation,
			"restore", "exact rendered artifacts: "+entry.DeviceID, s.recoveryArtifactLimit(),
			func(phaseCtx context.Context) error {
				device := byDevice[entry.DeviceID]
				for _, artifact := range entry.Artifacts {
					if artifact.Command != nil {
						continue
					}
					if artifact.Digest != artifactDigest(artifact.Content) {
						return fmt.Errorf("rollback artifact %s for %s digest mismatch", artifact.Path, entry.DeviceID)
					}
					if err := s.rt.CopyTo(phaseCtx, entry.Spec.Name, artifact.Path, artifact.Mode, artifact.Content); err != nil {
						return fmt.Errorf("restore rollback artifact %s to %s: %w",
							artifact.Path, entry.Spec.Name, err)
					}
				}
				if entry.Control != nil {
					current, err := s.rt.Inspect(phaseCtx, entry.Control.Name)
					if err != nil {
						return fmt.Errorf("inspect exact rollback control %s: %w", entry.Control.Name, err)
					}
					if current.State != rt.StateAbsent {
						if err := s.rt.Remove(phaseCtx, entry.Control.Name, true); err != nil {
							return fmt.Errorf("remove dirty rollback control %s: %w", entry.Control.Name, err)
						}
					}
					control := *entry.Control
					if _, err := s.rt.Create(phaseCtx, &control); err != nil {
						return fmt.Errorf("create exact rollback control %s: %w", control.Name, err)
					}
					if err := s.rt.Start(phaseCtx, control.Name); err != nil {
						return fmt.Errorf("start exact rollback control %s: %w", control.Name, err)
					}
				} else if err := eng.EnsureRuntimeSupport(phaseCtx, top, device); err != nil {
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
					result, err := s.rt.Exec(phaseCtx, container, rt.ExecCmd{Cmd: artifact.Command.Args})
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
	}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		entry := entry
		if err := s.runRecoveryPhase(ctx, lab, fence, tx.Generation,
			"verify", "exact rollback readiness: "+entry.DeviceID, func(phaseCtx context.Context) error {
				device := byDevice[entry.DeviceID]
				if waiter := eng.Renderer.Ready(device, s.rt); waiter != nil {
					if err := plan.Wait(phaseCtx, *waiter); err != nil {
						return fmt.Errorf("verify exact rollback readiness for %s: %w", entry.DeviceID, err)
					}
				}
				return nil
			}); err != nil {
			return err
		}
	}
	// A restored FRR snapshot is applied through vtysh. The private FRR
	// control namespace can be running while its socket is not yet usable by
	// the primary container; applying state before readiness caused retries to
	// fail with transient "Failure to communicate to zebra" errors. Runtime
	// contracts and rendered artifacts are already exact at this point, so
	// waiting does not recompute or weaken the rollback contract.
	for _, entry := range tx.Prestate.RuntimeSpecs {
		entry := entry
		device := byDevice[entry.DeviceID]
		if renderModeForDevice(previousMode, previousUngraded, device) == render.ModeSolve {
			continue
		}
		if err := s.runRecoveryPhase(ctx, lab, fence, tx.Generation,
			"restore", "exact student state: "+entry.DeviceID, func(phaseCtx context.Context) error {
				if _, err := deploy.Restore(phaseCtx, s.rt, device, lab, s.store); err != nil {
					return fmt.Errorf("restore student state for %s: %w", entry.DeviceID, err)
				}
				return nil
			}); err != nil {
			return err
		}
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
