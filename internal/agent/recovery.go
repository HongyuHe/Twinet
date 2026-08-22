package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
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
	Lab   string `json:"lab"`
	Fence Fence  `json:"fence"`
}

// RecoveryResponse reports the verified state after a recovery attempt.
type RecoveryResponse struct {
	Status RecoveryStatus `json:"status"`
}

const recoveryRetryEvery = 5 * time.Second

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
	status, err := s.recoverTransaction(r.Context(), req.Lab, req.Fence)
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
		if err := s.verifyRecoveredStudentState(ctx, tx); err != nil {
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

func (s *Server) verifyRecoveredStudentState(ctx context.Context, tx applyTransaction) error {
	if s.store == nil || s.rt == nil || len(tx.Previous) == 0 {
		return nil
	}
	var wire Wire
	if err := json.Unmarshal(tx.Previous, &wire); err != nil {
		return fmt.Errorf("read pre-state topology for restore verification: %w", err)
	}
	if wire.Mode == string(render.ModeSolve) {
		// A solved reference/harness intentionally does not replay stored
		// student snapshots over the reference answer.
		return nil
	}
	top, err := wire.Rehydrate()
	if err != nil {
		return fmt.Errorf("rehydrate pre-state topology for restore verification: %w", err)
	}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		var expected []state.Snapshot
		for _, kind := range state.AllKinds {
			snapshot, err := s.store.Current(top.Name, device.ID, kind)
			if err == nil {
				expected = append(expected, snapshot)
			}
		}
		if len(expected) == 0 {
			continue
		}
		if _, err := verifyRestoredState(ctx, s.rt, device, top.Name, top.Hash, expected); err != nil {
			return fmt.Errorf("verify restored student state for %s: %w", device.ID, err)
		}
	}
	return nil
}
