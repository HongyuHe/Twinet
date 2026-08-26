package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
)

// A successful Cluster.Apply has this invariant:
//
//   1. every node persisted the same prepared generation;
//   2. every node finished the apply phase; and
//   3. every node acknowledged commit.
//
// If prepare, apply, or commit cannot meet that condition, the coordinator
// reports failure and asks every prepared node to roll back. Finalization only
// discards rollback material after every commit acknowledgement; a failure
// there is reported and remains fail-closed. A node that restarts with an
// unfinished transaction refuses later generations rather than guessing
// whether an old controller's partial work was committed.

func reportFailures(rep *plan.Report) map[string][]string {
	if rep == nil || !rep.Failed() {
		return nil
	}
	out := map[string][]string{}
	for _, scope := range rep.FailedScopes() {
		for _, err := range rep.ScopeErrors[scope] {
			out[scope] = append(out[scope], err.Error())
		}
	}
	return out
}

func (s *Server) handleApplyPrepare(w http.ResponseWriter, r *http.Request, req ApplyRequest) {
	mode, err := requiredTransactionMode(req.Mode)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Topology == nil {
		httpError(w, http.StatusBadRequest, errors.New("no topology supplied"))
		return
	}
	wireMode, err := requiredTransactionMode(req.Topology.Mode)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("topology mode invariant: %w", err))
		return
	}
	if wireMode != mode || req.Topology.Ungraded != req.Ungraded {
		httpError(w, http.StatusBadRequest, fmt.Errorf(
			"topology mode %s/%d does not match request mode %s/%d",
			wireMode, req.Topology.Ungraded, mode, req.Ungraded))
		return
	}
	// A disposable lab must say so in both the request and the topology that
	// is persisted from it. Accepting a request that claims one and a wire
	// that claims the other would let a restart rehydrate a harness as durable
	// -- or, far worse, a teaching lab as collectable.
	if req.Topology.Ephemeral != req.Ephemeral {
		httpError(w, http.StatusBadRequest, fmt.Errorf(
			"topology ephemeral=%t does not match request ephemeral=%t",
			req.Topology.Ephemeral, req.Ephemeral))
		return
	}
	top, err := req.Topology.Rehydrate()
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("rehydrate topology: %w", err))
		return
	}
	if err := validateApplyAssignment(req, top, s.cfg.Node); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if req.Lab != "" && req.Lab != top.Name {
		httpError(w, http.StatusBadRequest, errors.New("apply lab does not match its topology"))
		return
	}
	var durableStoreErr error
	if s.store == nil {
		durableStoreErr = errors.New("node has no state store")
	} else if err := s.store.Healthy(); err != nil {
		durableStoreErr = fmt.Errorf("node state store is unavailable: %w", err)
	}
	if top.Lab.State.ReplicationFactor > 1 && durableStoreErr != nil {
		if top.Lab.State.FailClosedEnabled() {
			httpError(w, http.StatusServiceUnavailable, errors.New(
				"clustered durable state requires a healthy node state store; refusing an apply that could acknowledge only one copy: "+
					durableStoreErr.Error()))
			return
		}
		slog.Error("AUDIT: applying clustered lab without a durable node state store because fail_closed=false",
			"lab", top.Name, "node", s.cfg.Node, "err", durableStoreErr)
	}
	if err := s.ensurePeerQuorumReachable(r.Context(), top); err != nil {
		if top.Lab.State.FailClosedEnabled() {
			httpError(w, http.StatusServiceUnavailable,
				fmt.Errorf("refusing destructive transaction before apply because durability peer quorum is unavailable: %w", err))
			return
		}
		slog.Error("AUDIT: applying while durability peer quorum is unavailable because fail_closed=false",
			"lab", top.Name, "node", s.cfg.Node, "err", err)
	}
	if why := s.refuseMutationIfHeld(top.Name, req.Hold, "this deployment"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	if err := s.requireMutationFence(top.Name, req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if why := s.recoveryMutationRefusal(top.Name); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	prestate, err := s.snapshotTransactionInventory(r.Context(), top.Name)
	if err != nil {
		httpError(w, http.StatusConflict, fmt.Errorf("capture pre-transaction inventory: %w", err))
		return
	}
	s.mu.Lock()
	previous := s.current[top.Name]
	s.mu.Unlock()
	dirtyCapture := []string(nil)
	semanticDirty := []string(nil)
	if previous != nil {
		observed := &deploy.Engine{
			Runtime:                s.rt,
			Node:                   s.cfg.Node,
			Limiter:                s.workLimiter(),
			Renderer:               renderer(top, mode, req.Ungraded),
			WritesReference:        mode == render.ModeSolve,
			Authoritative:          mode == render.ModeSolve && req.Ungraded == 0,
			UnderlayIP:             s.cfg.UnderlayIP,
			UnderlayDev:            s.cfg.UnderlayDev,
			PeerUnderlay:           req.PeerUnderlay,
			State:                  s.store,
			Generation:             req.Generation,
			ModeKey:                rendererModeKey(mode, req.Ungraded),
			RequireImmutableImages: top.Lab.Images.RequiresImmutableImages(),
			RetainLegacyOverlays:   true,
			SemanticProbe: func(ctx context.Context, device *model.Device) error {
				if err := s.semanticProbe(ctx, top, mode, req.Ungraded, device); err != nil {
					return err
				}
				return auditedDriftError(s.auditedDriftReason(ctx, top.Name, device))
			},
		}
		if _, err := observed.BuildContext(r.Context(), top); err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("observe prepared deployment: %w", err))
			return
		}
		dirtyCapture = observed.DirtyCaptureDevices()
		semanticDirty = observed.DirtySemanticDevices()
	}
	if previous != nil {
		prestate.TopologyHash = previous.Hash
	}
	if len(prestate.Containers) == 0 {
		prestate.StateSafe = true
	} else {
		if previous == nil || s.store == nil {
			httpError(w, http.StatusConflict, errors.New(
				"refusing a destructive transaction without the previous topology and durable student state"))
			return
		}
		if len(dirtyCapture) == 0 {
			// A no-change/delay-only request has no destructive container
			// boundary. Periodic durability remains responsible for the full
			// class snapshot; prepare records inventory but does not spend a
			// minute recapturing every router.
			prestate.StateSafe = true
		} else if _, captureErr := s.captureAndReplicateDirty(r.Context(), previous, dirtyCapture); captureErr != nil {
			if boundaryErr := s.durableBoundary(previous, "preparing a destructive transaction", captureErr); boundaryErr != nil {
				httpError(w, http.StatusConflict, boundaryErr)
				return
			}
			// An explicitly fail-open policy may let the forward request
			// continue, but it may never call rollback "recovered" without
			// proof that the prior student state was actually durable.
			prestate.StateSafe = false
		} else {
			prestate.StateSafe = true
		}
	}
	if previous != nil && prestate.StateSafe && len(dirtyCapture) > 0 {
		snapshots, err := s.durableSnapshotManifest(previous.Name, dirtyCapture)
		if err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("record durable snapshot manifest: %w", err))
			return
		}
		prestate.Snapshots = snapshots
	}
	if previous != nil {
		s.mu.Lock()
		previousMode, previousUngraded := s.modes[top.Name], s.ungraded[top.Name]
		s.mu.Unlock()
		specs, overlays, err := s.snapshotRollbackContracts(r.Context(), previous,
			previousMode, previousUngraded, prestate.Generation, prestate)
		if err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("capture exact rollback contracts: %w", err))
			return
		}
		prestate.RuntimeSpecs, prestate.OverlayState = specs, overlays
	}
	raw, err := json.Marshal(req.Topology)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("encode topology: %w", err))
		return
	}
	if err := s.prepareGeneration(top.Name, req.Fence, req.ExpectedGeneration, req.Generation,
		raw, string(mode), req.Ungraded, req.PeerUnderlay, req.Prune, req.OnlySteps, req.StateProofs,
		prestate); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	s.mu.Lock()
	prepared := s.transactions[top.Name]
	s.mu.Unlock()
	s.recordEvent(top.Name, req.Generation, "coordination", s.requestCorrelation(r),
		"transaction_mode", "success", fmt.Sprintf("previous=%s/%d desired=%s/%d",
			prepared.PreviousMode, prepared.PreviousUngraded, prepared.Mode, prepared.Ungraded))
	if err := s.recordGenerationDirtyCapture(top.Name, req.Fence, req.Generation, dirtyCapture); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if err := s.recordGenerationSemantic(top.Name, req.Fence, req.Generation, semanticDirty); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, ApplyResponse{
		Node: s.cfg.Node, AgentVersion: Version, ControllerVersion: req.ControllerVersion,
		Generation: req.Generation, Phase: "prepare",
	})
}

func (s *Server) handleApplyCommit(w http.ResponseWriter, r *http.Request, req ApplyRequest) {
	lab := req.Lab
	if lab == "" && req.Topology != nil {
		lab = req.Topology.Lab
	}
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	if why := s.refuseMutationIfHeld(lab, req.Hold, "committing this deployment"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	tx, err := s.transactionForCommit(lab, req.Fence, req.Generation)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}

	var wire Wire
	if err := json.Unmarshal(tx.Requested, &wire); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("read prepared topology: %w", err))
		return
	}
	top, err := wire.Rehydrate()
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("rehydrate prepared topology: %w", err))
		return
	}
	if err := validateApplyAssignment(req, top, s.cfg.Node); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if top.Name != lab {
		httpError(w, http.StatusConflict, errors.New("prepared topology belongs to another lab"))
		return
	}
	if err := s.acquire(lab, "commit"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(lab)
	if tx.Committed {
		writeJSON(w, ApplyResponse{
			Node: s.cfg.Node, AgentVersion: Version, ControllerVersion: req.ControllerVersion,
			Generation: tx.Generation, Phase: "commit",
		})
		return
	}
	fenced, stopFence := s.fencedContext(r.Context(), lab, req.Fence)
	defer stopFence()

	resp, err := s.commitAppliedTopology(fenced, top, &wire, req.Fence, tx)
	if err != nil {
		_ = s.markTransactionPhase(lab, req.Fence, req.Generation,
			transactionRollbackNeeded, "commit failed: "+err.Error())
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if len(resp.Failures) > 0 {
		_ = s.markTransactionPhase(lab, req.Fence, req.Generation,
			transactionRollbackNeeded, "commit reported failures")
	}
	writeJSON(w, resp)
}

func (s *Server) handleApplyFinalize(w http.ResponseWriter, r *http.Request, req ApplyRequest) {
	lab := req.Lab
	if lab == "" && req.Topology != nil {
		lab = req.Topology.Lab
	}
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	if err := s.finalizeCommittedGeneration(lab, req.Fence, req.Generation); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: req.Generation, Phase: "finalize"})
}

func (s *Server) commitAppliedTopology(ctx context.Context, top *model.Topology, wire *Wire,
	fence Fence, tx applyTransaction,
) (ApplyResponse, error) {
	recordStart := time.Now()
	authoritative := len(tx.OnlySteps) == 0
	wire.Generation = tx.Generation
	wire.PeerUnderlay = tx.PeerUnderlay

	desiredMode, err := requiredTransactionMode(tx.Mode)
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("committed desired mode invariant: %w", err)
	}
	previousMode, err := requiredTransactionMode(tx.PreviousMode)
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("committed previous mode invariant: %w", err)
	}
	slog.Info("committing transaction mode invariant", "lab", top.Name, "generation", tx.Generation,
		"previous_mode", previousMode, "previous_ungraded", tx.PreviousUngraded,
		"desired_mode", desiredMode, "desired_ungraded", tx.Ungraded)
	wire.Mode, wire.Ungraded = modeToPersist(authoritative, string(desiredMode), tx.Ungraded,
		string(previousMode), tx.PreviousUngraded)
	raw, err := json.Marshal(wire)
	if err != nil {
		return ApplyResponse{}, fmt.Errorf("encode committed topology: %w", err)
	}
	if s.store != nil {
		if err := s.store.PutTopology(top.Name, raw); err != nil {
			return ApplyResponse{}, fmt.Errorf("record committed topology: %w", err)
		}
	}

	s.mu.Lock()
	if s.current == nil {
		s.current = map[string]*model.Topology{}
	}
	s.current[top.Name] = top
	if authoritative {
		s.rememberHow(top.Name, string(desiredMode), tx.Ungraded)
	}
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	s.peers[top.Name] = tx.PeerUnderlay
	s.mu.Unlock()

	// The lifetime is recorded after the topology, so a crash between the two
	// leaves an ephemeral topology whose deadline rehydration re-derives under
	// a bounded restart grace rather than a durable lab with a deadline.
	if authoritative {
		if wire.Ephemeral {
			if err := s.noteEphemeralLease(top.Name, wire.EphemeralOwner,
				wire.EphemeralTTLSeconds, tx.Generation); err != nil {
				return ApplyResponse{}, err
			}
		} else if err := s.forgetEphemeralLease(top.Name); err != nil {
			return ApplyResponse{}, err
		}
	}

	resp := ApplyResponse{
		Node: s.cfg.Node, AgentVersion: Version,
		Generation: tx.Generation, Phase: "commit",
	}
	addPhaseTiming(&resp, "record", time.Since(recordStart))
	eng, err := s.transactionEngine(top, tx)
	if err != nil {
		return ApplyResponse{}, err
	}
	// Capture and replicate before any prune. A commit that removes the old
	// placement before its current state and topology record have a verified
	// failure-domain-separated quorum is not a successful migration.
	if s.store != nil {
		captureStart := time.Now()
		var (
			n          int
			captureErr error
		)
		if tx.DirtyCaptureKnown {
			n, captureErr = s.captureAndReplicateDirty(ctx, top, tx.DirtyCapture)
		} else {
			// Transactions prepared by an older agent lack a dirty set; keep
			// the conservative full capture compatibility path.
			n, captureErr = s.captureAndReplicate(ctx, top)
		}
		if captureErr != nil {
			if err := s.durableBoundary(top, "committing this deployment", captureErr); err != nil {
				return ApplyResponse{}, err
			}
		} else {
			resp.Snapshots = n
		}
		captureElapsed := time.Since(captureStart)
		addCaptureTiming(&resp, captureElapsed)
		s.metricRegistry().observePhase("capture", captureElapsed, metricResult(captureErr))
	}
	// Semantic proof is deliberately before pruning. A matching OCI
	// inventory is insufficient evidence that a recreated host has its
	// reference address/default route or that a service loaded its rendered
	// files; if this fails the old placement remains intact for rollback.
	// An explicit forward recovery converges each node under the same fenced
	// desired transaction. Cross-node BGP/reference routes cannot be proven
	// until every node has committed its local inventory, so requiring the
	// distributed semantic probe here creates a circular commit deadlock.
	// Inventory, rendered contracts, readiness, and control sidecars remain
	// verified; normal deploys retain the stricter pre-prune semantic gate.
	if !tx.ForwardAcknowledged {
		if touched := semanticCommitDevices(top, s.cfg.Node, tx, render.Mode(desiredMode)); len(touched) > 0 {
			if err := s.verifyCommittedSemantics(ctx, top, render.Mode(desiredMode), tx.Ungraded, touched); err != nil {
				return ApplyResponse{}, fmt.Errorf("commit semantic verification failed: %w", err)
			}
		}
	}
	// A semantic address repair may recreate one cross-node endpoint. Linux
	// can discard that VLAN/VNI's external FDB binding while the host veth is
	// replaced, so re-prove and restore the complete logical carrier set
	// before snapshotting committed inventory.
	if err := s.reconcileCommitOverlays(ctx, eng, top, desiredMode, tx.Ungraded); err != nil {
		return ApplyResponse{}, err
	}
	if err := s.verifyKnownStudentState(ctx, top, previousMode, tx.PreviousUngraded, desiredMode, tx.Ungraded); err != nil {
		return ApplyResponse{}, err
	}
	if tx.Prune {
		if err := s.transactionFail("prune"); err != nil {
			return ApplyResponse{}, fmt.Errorf("commit prune failpoint: %w", err)
		}
		gone, err := eng.PruneOrphans(ctx, top)
		if err != nil {
			addApplyFailure(&resp, "prune", err)
		} else {
			resp.Pruned = append(resp.Pruned, gone...)
		}
		if overlays, err := eng.PruneOverlays(top); err != nil {
			addApplyFailure(&resp, "prune", err)
		} else {
			resp.Pruned = append(resp.Pruned, overlays...)
		}
	}
	vnis := overlayVNIsOnNode(top, s.cfg.Node)
	if len(vnis) > 0 {
		if err := s.promoteOverlayReservations(top.Name, fence, vnis); err != nil {
			addApplyFailure(&resp, "overlay", err)
		}
	}
	if len(resp.Failures) > 0 {
		return resp, nil
	}
	var actual, inventory transactionInventory
	err = retryMissingDesiredVNI(ctx, 3, func() error {
		var snapshotErr error
		actual, snapshotErr = s.snapshotTransactionInventory(ctx, top.Name)
		if snapshotErr != nil {
			return fmt.Errorf("verify committed inventory: %w", snapshotErr)
		}
		inventory, snapshotErr = expectedTransactionInventoryFinal(eng, top, s.cfg.Node, tx, actual)
		if snapshotErr != nil {
			return fmt.Errorf("derive committed runtime inventory: %w", snapshotErr)
		}
		if !tx.Prune {
			// An explicitly non-pruning deployment preserves deliberate extra
			// objects, but desired objects still use their expected lineage.
			// Recording actual labels for desired objects would let an unrecorded
			// recreate appear committed merely because pruning was disabled.
			inventory, snapshotErr = mergePreservedInventory(inventory, actual)
			if snapshotErr != nil {
				return fmt.Errorf("verify non-pruning committed inventory: %w", snapshotErr)
			}
		}
		return nil
	}, func() error {
		return s.reconcileCommitOverlays(ctx, eng, top, desiredMode, tx.Ungraded)
	})
	if err != nil {
		return ApplyResponse{}, err
	}
	if err := s.validateInventoryLineage(top.Name, inventory, tx.Generation); err != nil {
		return ApplyResponse{}, fmt.Errorf("commit inventory lineage: %w", err)
	}
	if err := inventoryMatchesCommitted(inventory, actual); err != nil {
		return ApplyResponse{}, fmt.Errorf("commit inventory is incomplete: %w", err)
	}
	if err := s.transactionFail("commit"); err != nil {
		return ApplyResponse{}, fmt.Errorf("commit failpoint: %w", err)
	}
	if err := s.finishCommittedGeneration(top.Name, fence, tx.Generation, inventory); err != nil {
		return ApplyResponse{}, err
	}
	s.beginSemanticConvergenceGrace(top)
	return resp, nil
}

func mergePreservedInventory(expected, actual transactionInventory) (transactionInventory, error) {
	out := actual
	out.Containers = append([]transactionContainer(nil), actual.Containers...)
	out.VNIs = append([]uint32(nil), actual.VNIs...)
	out.Generation, out.TopologyHash = expected.Generation, expected.TopologyHash
	desired := make(map[string]transactionContainer, len(expected.Containers))
	for _, container := range expected.Containers {
		desired[container.DeviceID] = container
	}
	seen := map[string]bool{}
	for i, container := range out.Containers {
		want, isDesired := desired[container.DeviceID]
		if !isDesired {
			continue
		}
		if seen[container.DeviceID] {
			return transactionInventory{}, fmt.Errorf("duplicate desired object %q", container.DeviceID)
		}
		seen[container.DeviceID] = true
		if container.Name != want.Name || container.Spec != want.Spec {
			return transactionInventory{}, fmt.Errorf("desired object %q is %+v, want %+v",
				container.DeviceID, container, want)
		}
		out.Containers[i] = want
	}
	for id := range desired {
		if !seen[id] {
			return transactionInventory{}, fmt.Errorf("desired object %q is absent", id)
		}
	}
	wantVNIs := map[uint32]bool{}
	for _, vni := range expected.VNIs {
		wantVNIs[vni] = true
	}
	haveVNIs := map[uint32]bool{}
	for _, vni := range actual.VNIs {
		haveVNIs[vni] = true
	}
	for vni := range wantVNIs {
		if !haveVNIs[vni] {
			return transactionInventory{}, &desiredVNIAbsentError{VNI: vni}
		}
	}
	return out, nil
}

type desiredVNIAbsentError struct {
	VNI uint32
}

func (e *desiredVNIAbsentError) Error() string {
	return fmt.Sprintf("desired VNI %d is absent", e.VNI)
}

func retryMissingDesiredVNI(ctx context.Context, attempts int, verify, repair func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = verify()
		if last == nil {
			return nil
		}
		var missing *desiredVNIAbsentError
		if !errors.As(last, &missing) || attempt+1 == attempts {
			return last
		}
		if err := repair(); err != nil {
			return fmt.Errorf("%w; targeted overlay reconciliation failed: %v", last, err)
		}
	}
	return last
}

func (s *Server) reconcileCommitOverlays(ctx context.Context, eng *deploy.Engine, top *model.Topology,
	mode render.Mode, ungraded int,
) error {
	report, err := eng.ReconcileOverlayBindings(ctx, top)
	if err != nil {
		return fmt.Errorf("reconcile overlays after semantic repair: %w", err)
	}
	if len(report.Failed) == 0 {
		for _, device := range repairedLocalDevices(top, eng.Node, report.Repaired) {
			// Recreating a missing host veth also recreates its container-side
			// interface. The wire is healthy but its solved/student address is
			// gone until the device contract is replayed.
			if err := eng.ReconfigureDevice(ctx, device); err != nil {
				return fmt.Errorf("reconfigure %s after overlay endpoint repair: %w", device.ID, err)
			}
			if renderModeForDevice(mode, ungraded, device) != render.ModeSolve && s.store != nil {
				if _, err := deploy.Restore(ctx, s.rt, device, top.Name, s.store); err != nil {
					return fmt.Errorf("restore %s after overlay endpoint repair: %w", device.ID, err)
				}
			}
		}
		return nil
	}
	keys := make([]string, 0, len(report.Failed))
	for key := range report.Failed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	failures := make([]string, 0, len(keys))
	for _, key := range keys {
		failures = append(failures, key+": "+report.Failed[key])
	}
	return fmt.Errorf("reconcile overlays after semantic repair: %s", strings.Join(failures, "; "))
}

func repairedLocalDevices(top *model.Topology, node string, repaired []string) []*model.Device {
	if top == nil || len(repaired) == 0 {
		return nil
	}
	repairedSet := make(map[string]bool, len(repaired))
	for _, id := range repaired {
		repairedSet[id] = true
	}
	byID := map[string]*model.Device{}
	for _, link := range top.Links {
		if link == nil || !link.CrossNode() || !repairedSet[fmt.Sprintf("vni:%d", link.VNI)] {
			continue
		}
		switch node {
		case link.A.Device.Node:
			byID[link.A.Device.ID] = link.A.Device
		case link.B.Device.Node:
			byID[link.B.Device.ID] = link.B.Device
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*model.Device, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out
}

func addApplyFailure(resp *ApplyResponse, scope string, err error) {
	if resp.Failures == nil {
		resp.Failures = map[string][]string{}
	}
	resp.Failures[scope] = append(resp.Failures[scope], err.Error())
}

func (s *Server) transactionEngine(top *model.Topology, tx applyTransaction) (*deploy.Engine, error) {
	mode, err := requiredTransactionMode(tx.Mode)
	if err != nil {
		return nil, fmt.Errorf("transaction desired mode invariant: %w", err)
	}
	previousMode, err := requiredTransactionMode(tx.PreviousMode)
	if err != nil {
		return nil, fmt.Errorf("transaction previous mode invariant: %w", err)
	}
	forceStudentReset := needsStudentReset(string(previousMode), mode)
	return &deploy.Engine{
		Runtime:                s.rt,
		Node:                   s.cfg.Node,
		Limiter:                s.workLimiter(),
		Renderer:               renderer(top, mode, tx.Ungraded),
		WritesReference:        mode == render.ModeSolve,
		Authoritative:          mode == render.ModeSolve && tx.Ungraded == 0,
		UnderlayIP:             s.cfg.UnderlayIP,
		UnderlayDev:            s.cfg.UnderlayDev,
		PeerUnderlay:           tx.PeerUnderlay,
		State:                  s.store,
		Prune:                  tx.Prune,
		Generation:             tx.Generation,
		ModeKey:                rendererModeKey(mode, tx.Ungraded),
		ForceStudentReset:      forceStudentReset,
		RestoreStudentState:    forceStudentReset,
		PreviousMode:           string(previousMode),
		PreviousUngraded:       tx.PreviousUngraded,
		RequireImmutableImages: top.Lab.Images.RequiresImmutableImages(),
		RetainLegacyOverlays:   true,
		SemanticProbe: func(ctx context.Context, device *model.Device) error {
			if s.isExempt(top.Name, device.ID) {
				return nil
			}
			if err := s.semanticProbe(ctx, top, mode, tx.Ungraded, device); err != nil {
				return err
			}
			return auditedDriftError(s.auditedDriftReason(ctx, top.Name, device))
		},
	}, nil
}

func overlayVNIsOnNode(top *model.Topology, node string) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, link := range top.Links {
		if link.VNI == 0 || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil ||
			link.A.Device.Node == link.B.Device.Node ||
			(link.A.Device.Node != node && link.B.Device.Node != node) {
			continue
		}
		if !seen[link.VNI] {
			seen[link.VNI] = true
			out = append(out, link.VNI)
		}
	}
	return out
}

func validateApplyAssignment(req ApplyRequest, top *model.Topology, node string) error {
	if !req.AssignmentKnown {
		return nil
	}
	if req.TargetNode != node {
		return fmt.Errorf("apply placement target %q reached agent %q", req.TargetNode, node)
	}
	got := make([]string, 0)
	for _, device := range top.DevicesOnNode(node) {
		got = append(got, device.ID)
	}
	want := append([]string(nil), req.AssignedDevices...)
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("apply placement for node %q contains devices %v, controller assigned %v",
			node, got, want)
	}
	return nil
}

func validatePreparedPlacement(tx applyTransaction, top *model.Topology) error {
	var prepared Wire
	if err := json.Unmarshal(tx.Requested, &prepared); err != nil {
		return fmt.Errorf("decode prepared topology placement: %w", err)
	}
	want := make(map[string]string, len(prepared.Devices))
	for _, device := range prepared.Devices {
		want[device.ID] = device.Node
	}
	if len(want) != len(top.Devices) {
		return fmt.Errorf("apply topology has %d devices, prepared placement has %d",
			len(top.Devices), len(want))
	}
	for id, device := range top.Devices {
		node, ok := want[id]
		if !ok {
			return fmt.Errorf("apply topology device %q was not in the prepared placement", id)
		}
		if device.Node != node {
			return fmt.Errorf("apply topology moved device %q from prepared node %q to %q",
				id, node, device.Node)
		}
	}
	return nil
}

func (s *Server) handleApplyAbort(w http.ResponseWriter, r *http.Request, req ApplyRequest) {
	lab := req.Lab
	if lab == "" && req.Topology != nil {
		lab = req.Topology.Lab
	}
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	status, err := s.recoverTransaction(r.Context(), lab, req.Fence)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: status.Generation, Phase: "abort"})
}

func (s *Server) rollbackPreparedApply(ctx context.Context, lab string, fence Fence,
	tx applyTransaction,
) error {
	if len(tx.Previous) == 0 {
		eng := &deploy.Engine{
			Runtime: s.rt, Node: s.cfg.Node, State: s.store, Limiter: s.workLimiter(),
			Workers: s.recoveryWorkerCount(),
		}
		if err := eng.Destroy(ctx, lab); err != nil {
			return fmt.Errorf("removing partially applied lab %q: %w", lab, err)
		}
		owned, err := s.recoveryOverlayList(lab)
		if err != nil {
			return fmt.Errorf("listing partially applied overlays: %w", err)
		}
		if err := eng.DestroyOverlaysContext(ctx, owned); err != nil {
			return fmt.Errorf("removing partially applied overlays: %w", err)
		}
		if err := s.releaseOverlayClaims(lab, nil); err != nil {
			return fmt.Errorf("releasing partially applied overlay claims: %w", err)
		}
		s.mu.Lock()
		delete(s.current, lab)
		delete(s.semanticGraceUntil, lab)
		delete(s.modes, lab)
		delete(s.ungraded, lab)
		delete(s.peers, lab)
		s.mu.Unlock()
		if s.store != nil {
			if err := s.store.ForgetTopology(lab); err != nil {
				return fmt.Errorf("clearing partially applied topology: %w", err)
			}
		}
		return nil
	}

	var oldWire Wire
	if err := json.Unmarshal(tx.Previous, &oldWire); err != nil {
		return fmt.Errorf("decode previous topology for rollback: %w", err)
	}
	oldTop, err := oldWire.Rehydrate()
	if err != nil {
		return fmt.Errorf("rehydrate previous topology for rollback: %w", err)
	}
	if len(tx.Prestate.RuntimeSpecs) > 0 {
		return s.rollbackExactContracts(ctx, lab, fence, tx, oldTop)
	}
	rollback := tx
	rollback.Generation = tx.PreviousGen
	previousMode, previousUngraded := recoveredMode(tx, oldWire)
	slog.Info("rolling back transaction mode invariant", "lab", lab, "generation", tx.Generation,
		"previous_mode", previousMode, "previous_ungraded", previousUngraded,
		"desired_mode", tx.Mode, "desired_ungraded", tx.Ungraded)
	rollback.Mode = string(previousMode)
	rollback.Ungraded = previousUngraded
	rollback.PeerUnderlay = oldWire.PeerUnderlay
	// The old topology is rebuilt first. Pruning happens only after every old
	// device has its interfaces and restored student state back, never as the
	// mechanism that tries to make a failed forward apply disappear.
	rollback.Prune = false
	eng, err := s.transactionEngine(oldTop, rollback)
	if err != nil {
		return err
	}
	eng.RecoveryCompatibility = true
	p, err := eng.BuildContext(ctx, oldTop)
	if err != nil {
		return fmt.Errorf("build rollback plan: %w", err)
	}
	rep, err := p.Execute(ctx, plan.Options{
		Workers: s.recoveryWorkerCount(), ContinueOnError: true,
	})
	if err != nil {
		return fmt.Errorf("run rollback plan: %w", err)
	}
	if rep.Failed() {
		return fmt.Errorf("rollback plan failed: %w", rep.Err())
	}
	if err := s.transactionFail("prune"); err != nil {
		return fmt.Errorf("rollback prune failpoint: %w", err)
	}
	if _, err := eng.PruneOrphans(ctx, oldTop); err != nil {
		return fmt.Errorf("prune after rollback: %w", err)
	}
	if _, err := eng.PruneOverlays(oldTop); err != nil {
		return fmt.Errorf("prune overlays after rollback: %w", err)
	}
	if s.store != nil {
		if err := s.store.PutTopology(lab, tx.Previous); err != nil {
			return fmt.Errorf("restore previous topology record: %w", err)
		}
	}
	s.mu.Lock()
	if s.current == nil {
		s.current = map[string]*model.Topology{}
	}
	s.current[lab] = oldTop
	s.rememberHow(lab, string(previousMode), previousUngraded)
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	s.peers[lab] = oldWire.PeerUnderlay
	s.mu.Unlock()
	if err := s.restoreOverlayClaims(lab, fence, overlayVNIsOnNode(oldTop, s.cfg.Node)); err != nil {
		return err
	}
	s.beginSemanticConvergenceGrace(oldTop)
	return nil
}

func (s *Server) restoreOverlayClaims(lab string, fence Fence, oldVNIs []uint32) error {
	want := map[uint32]bool{}
	for _, vni := range oldVNIs {
		want[vni] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	for vni, claim := range s.overlayClaims {
		if claim.Lab == lab && !claim.Live && claim.Generation == fence.Generation && !want[vni] {
			delete(s.overlayClaims, vni)
		}
	}
	for vni := range want {
		s.overlayClaims[vni] = overlayClaim{Lab: lab, Generation: fence.Generation, Live: true}
	}
	return s.saveCoordinationLocked()
}
