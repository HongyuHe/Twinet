package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
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

const recoveryRetryEvery = 5 * time.Second
const recoveryRetryBackoff = 30 * time.Second

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
		fence, err := s.acquireRecoveryFence(lab)
		if err != nil {
			continue
		}
		_, err = s.recoverTransaction(ctx, lab, fence)
		if err != nil {
			slog.Warn("automatic transaction recovery failed; will retry",
				"lab", lab, "err", err)
		}
		_ = s.releaseMutationLease(LeaseReleaseRequest{Lab: lab, Fence: fence})
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
		// Recovery can replay a full class topology and wait for daemon
		// readiness. Give the internal fenced owner the documented maximum;
		// expiring half way through would turn a safe rollback into a second
		// partial mutation.
		holder: "agent recovery", fence: fence, until: now.Add(leaseTTL(maxMutationLeaseSeconds)),
	}
	if err := s.saveCoordinationLocked(); err != nil {
		delete(s.mutations, lab)
		return Fence{}, err
	}
	return fence, nil
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
	}
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func (s *Server) transactionInventoryStatus(ctx context.Context, lab string) RecoveryStatus {
	s.mu.Lock()
	s.initCoordination()
	tx, hasTx := s.transactions[lab]
	committed, hasCommitted := s.inventories[lab]
	s.mu.Unlock()

	status := RecoveryStatus{Lab: lab, Phase: "unknown"}
	var want transactionInventory
	switch {
	case hasTx:
		status.Phase = string(tx.Phase)
		status.Generation = tx.Generation
		status.PreviousGeneration = tx.PreviousGen
		status.Attempts = tx.RecoveryAttempts
		status.Error = tx.Failure
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
		status.Phase, status.Generation, want = "committed", committed.Generation, committed
	default:
		status.Phase = "idle"
		return status
	}
	status.ExpectedContainers, status.ExpectedVNIs = len(want.Containers), len(want.VNIs)
	got, err := s.snapshotTransactionInventory(ctx, lab)
	if err != nil {
		status.Error = err.Error()
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
	status, err := s.recoverTransactionStrategy(r.Context(), req.Lab, req.Fence, strategy)
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
	if strategy == "forward" {
		return s.forwardTransaction(ctx, lab, fence, tx)
	}
	if len(tx.Prestate.Containers) > 0 && !tx.Prestate.StateSafe {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed,
			"pre-state snapshots were not durably captured")
		return s.transactionInventoryStatus(ctx, lab), errors.New(
			"refusing recovery before durable student state capture")
	}
	if err := s.markTransactionPhase(lab, fence, tx.Generation, transactionRecovering, ""); err != nil {
		return RecoveryStatus{}, err
	}
	if err := s.acquire(lab, "recovery"); err != nil {
		return RecoveryStatus{}, err
	}
	defer s.release(lab)
	if err := s.transactionFail("rollback"); err != nil {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
		return s.transactionInventoryStatus(ctx, lab), err
	}
	rollback := s.rollbackPreparedApply
	if s.recoveryRollback != nil {
		rollback = s.recoveryRollback
	}
	if err := rollback(ctx, lab, fence, tx); err != nil {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if s.recoveryRollback == nil {
		if err := s.restoreRecoveredTopology(lab, tx); err != nil {
			_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
			return s.transactionInventoryStatus(ctx, lab), err
		}
		if err := s.verifyRecoveredStudentState(ctx, tx); err != nil {
			_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
			return s.transactionInventoryStatus(ctx, lab), err
		}
		if err := s.replicateRecoveredDurability(ctx, tx); err != nil {
			_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
			return s.transactionInventoryStatus(ctx, lab), err
		}
	}
	got, verifyErr := s.snapshotTransactionInventory(ctx, lab)
	if verifyErr == nil {
		verifyErr = inventoryMatches(tx.Prestate, got)
	}

	if verifyErr != nil {
		err := fmt.Errorf("rollback inventory verification failed: %v", verifyErr)
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
		return s.transactionInventoryStatus(ctx, lab), err
	}
	if err := s.finishRecoveredGeneration(lab, fence, tx.Generation); err != nil {
		_ = s.markTransactionPhase(lab, fence, tx.Generation, transactionRollbackFailed, err.Error())
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
	s.rememberHow(lab, wire.Mode, wire.Ungraded)
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
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if renderModeForDevice(render.Mode(wire.Mode), wire.Ungraded, device) == render.ModeSolve {
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
	if err := s.verifyRecoveredSemantics(ctx, top, render.Mode(wire.Mode), wire.Ungraded,
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
	if err := s.acquire(lab, "forward recovery"); err != nil {
		return RecoveryStatus{}, err
	}
	defer s.release(lab)
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
func (s *Server) rollbackExactContracts(ctx context.Context, lab string,
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
	rollback.Mode = oldWire.Mode
	rollback.Ungraded = oldWire.Ungraded
	rollback.PeerUnderlay = oldWire.PeerUnderlay
	eng := s.transactionEngine(top, rollback)
	expected := map[string]bool{}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		device := byDevice[entry.DeviceID]
		if device == nil {
			return fmt.Errorf("rollback contract references unknown device %q", entry.DeviceID)
		}
		expected[entry.Spec.Name] = true
		current, err := s.rt.Inspect(ctx, entry.Spec.Name)
		if err != nil {
			return fmt.Errorf("inspect rollback container %s: %w", entry.Spec.Name, err)
		}
		if current.State != rt.StateAbsent {
			if err := s.rt.Remove(ctx, entry.Spec.Name, true); err != nil {
				return fmt.Errorf("remove dirty rollback container %s: %w", entry.Spec.Name, err)
			}
		}
		if err := eng.PrepareRuntimeSpec(top, device); err != nil {
			return fmt.Errorf("prepare rollback runtime paths for %s: %w", entry.DeviceID, err)
		}
		spec := entry.Spec
		if _, err := s.rt.Create(ctx, &spec); err != nil {
			return fmt.Errorf("create exact rollback container %s: %w", spec.Name, err)
		}
		if err := s.rt.Start(ctx, spec.Name); err != nil {
			return fmt.Errorf("start exact rollback container %s: %w", spec.Name, err)
		}
	}
	if err := eng.RewireTopology(ctx, top); err != nil {
		return fmt.Errorf("rewire exact rollback topology: %w", err)
	}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		device := byDevice[entry.DeviceID]
		for _, artifact := range entry.Artifacts {
			if artifact.Command != nil {
				continue
			}
			if artifact.Digest != artifactDigest(artifact.Content) {
				return fmt.Errorf("rollback artifact %s for %s digest mismatch", artifact.Path, entry.DeviceID)
			}
			if err := s.rt.CopyTo(ctx, entry.Spec.Name, artifact.Path, artifact.Mode, artifact.Content); err != nil {
				return fmt.Errorf("restore rollback artifact %s to %s: %w",
					artifact.Path, entry.Spec.Name, err)
			}
		}
		if entry.Control != nil {
			current, err := s.rt.Inspect(ctx, entry.Control.Name)
			if err != nil {
				return fmt.Errorf("inspect exact rollback control %s: %w", entry.Control.Name, err)
			}
			if current.State != rt.StateAbsent {
				if err := s.rt.Remove(ctx, entry.Control.Name, true); err != nil {
					return fmt.Errorf("remove dirty rollback control %s: %w", entry.Control.Name, err)
				}
			}
			control := *entry.Control
			if _, err := s.rt.Create(ctx, &control); err != nil {
				return fmt.Errorf("create exact rollback control %s: %w", control.Name, err)
			}
			if err := s.rt.Start(ctx, control.Name); err != nil {
				return fmt.Errorf("start exact rollback control %s: %w", control.Name, err)
			}
		} else if err := eng.EnsureRuntimeSupport(ctx, top, device); err != nil {
			return fmt.Errorf("restore rollback support for %s: %w", entry.DeviceID, err)
		}
		for _, artifact := range entry.Artifacts {
			if artifact.Command == nil {
				continue
			}
			raw, _ := json.Marshal(*artifact.Command)
			if artifact.Digest != artifactDigest(raw) {
				return fmt.Errorf("rollback command for %s digest mismatch", entry.DeviceID)
			}
			container := entry.Spec.Name
			if artifact.Command.FRRControl && deploy.UsesFRRControl(device) {
				container = deploy.FRRControlContainer(device)
			}
			result, err := s.rt.Exec(ctx, container, rt.ExecCmd{Cmd: artifact.Command.Args})
			if err != nil {
				return fmt.Errorf("run rollback command for %s: %w", entry.DeviceID, err)
			}
			if err := result.Err(); err != nil && !artifact.Command.IgnoreError {
				return fmt.Errorf("run rollback command for %s: %w", entry.DeviceID, err)
			}
		}
		if renderModeForDevice(render.Mode(oldWire.Mode), oldWire.Ungraded, device) != render.ModeSolve {
			if _, err := deploy.Restore(ctx, s.rt, device, lab, s.store); err != nil {
				return fmt.Errorf("restore student state for %s: %w", entry.DeviceID, err)
			}
		}
	}
	for _, entry := range tx.Prestate.RuntimeSpecs {
		device := byDevice[entry.DeviceID]
		if waiter := eng.Renderer.Ready(device, s.rt); waiter != nil {
			if err := plan.Wait(ctx, *waiter); err != nil {
				return fmt.Errorf("verify exact rollback readiness for %s: %w", entry.DeviceID, err)
			}
		}
	}
	containers, err := s.recoveryContainerList(ctx, lab)
	if err != nil {
		return err
	}
	for _, container := range containers {
		if isInternalControlContainer(container) || expected[container.Name] {
			continue
		}
		if err := s.rt.Remove(ctx, container.Name, true); err != nil {
			return fmt.Errorf("remove forward-only rollback container %s: %w", container.Name, err)
		}
	}
	if err := s.transactionFail("prune"); err != nil {
		return fmt.Errorf("exact rollback prune failpoint: %w", err)
	}
	if _, err := eng.PruneOverlaysContext(ctx, top); err != nil {
		return fmt.Errorf("prune exact rollback overlays: %w", err)
	}
	return nil
}
