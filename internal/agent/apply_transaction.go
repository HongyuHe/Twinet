package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
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
	if req.Topology == nil {
		httpError(w, http.StatusBadRequest, errors.New("no topology supplied"))
		return
	}
	top, err := req.Topology.Rehydrate()
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("rehydrate topology: %w", err))
		return
	}
	if req.Lab != "" && req.Lab != top.Name {
		httpError(w, http.StatusBadRequest, errors.New("apply lab does not match its topology"))
		return
	}
	if why := s.refuseMutationIfHeld(top.Name, req.Hold, "this deployment"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	if err := s.requireMutationFence(top.Name, req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	raw, err := json.Marshal(req.Topology)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("encode topology: %w", err))
		return
	}
	if err := s.prepareGeneration(top.Name, req.Fence, req.ExpectedGeneration, req.Generation,
		raw, req.Mode, req.Ungraded, req.PeerUnderlay, req.Prune, req.OnlySteps); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: req.Generation, Phase: "prepare"})
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
		writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: tx.Generation, Phase: "commit"})
		return
	}
	fenced, stopFence := s.fencedContext(r.Context(), lab, req.Fence)
	defer stopFence()

	resp, err := s.commitAppliedTopology(fenced, top, &wire, req.Fence, tx)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
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
	authoritative := len(tx.OnlySteps) == 0
	wire.Generation = tx.Generation
	wire.PeerUnderlay = tx.PeerUnderlay

	s.mu.Lock()
	s.initCoordination()
	prevMode, prevUngraded := s.modes[top.Name], s.ungraded[top.Name]
	s.mu.Unlock()
	wire.Mode, wire.Ungraded = modeToPersist(authoritative, tx.Mode, tx.Ungraded,
		prevMode, prevUngraded)
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
		s.rememberHow(top.Name, tx.Mode, tx.Ungraded)
	}
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	s.peers[top.Name] = tx.PeerUnderlay
	s.mu.Unlock()

	resp := ApplyResponse{Node: s.cfg.Node, Generation: tx.Generation, Phase: "commit"}
	eng := s.transactionEngine(top, tx)
	if tx.Prune {
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
	if err := s.finishCommittedGeneration(top.Name, fence, tx.Generation); err != nil {
		return ApplyResponse{}, err
	}
	if s.store != nil && tx.Mode != string(render.ModeSolve) {
		if n, err := eng.CaptureAll(ctx, top, s.store); err != nil {
			slog.Warn("capturing student configuration after commit", "err", err, "saved", n)
		} else {
			resp.Snapshots = n
		}
	}
	return resp, nil
}

func addApplyFailure(resp *ApplyResponse, scope string, err error) {
	if resp.Failures == nil {
		resp.Failures = map[string][]string{}
	}
	resp.Failures[scope] = append(resp.Failures[scope], err.Error())
}

func (s *Server) transactionEngine(top *model.Topology, tx applyTransaction) *deploy.Engine {
	mode := render.Mode(tx.Mode)
	if mode == "" {
		mode = render.ModePlatform
	}
	return &deploy.Engine{
		Runtime:         s.rt,
		Node:            s.cfg.Node,
		Renderer:        renderer(top, mode, tx.Ungraded),
		WritesReference: mode == render.ModeSolve,
		Authoritative:   mode == render.ModeSolve && tx.Ungraded == 0,
		UnderlayIP:      s.cfg.UnderlayIP,
		UnderlayDev:     s.cfg.UnderlayDev,
		PeerUnderlay:    tx.PeerUnderlay,
		State:           s.store,
		Prune:           tx.Prune,
		Generation:      tx.Generation,
	}
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

func (s *Server) handleApplyAbort(w http.ResponseWriter, r *http.Request, req ApplyRequest) {
	lab := req.Lab
	if lab == "" && req.Topology != nil {
		lab = req.Topology.Lab
	}
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	tx, err := s.transactionForAbort(lab, req.Fence, req.Generation)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if tx.Generation == "" {
		writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: req.Generation, Phase: "abort"})
		return
	}
	if err := s.acquire(lab, "rollback"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(lab)
	fenced, stopFence := s.fencedContext(r.Context(), lab, req.Fence)
	defer stopFence()
	if err := s.rollbackPreparedApply(fenced, lab, req.Fence, tx); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.finishAbortedGeneration(lab, req.Fence, tx.Generation); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, ApplyResponse{Node: s.cfg.Node, Generation: tx.Generation, Phase: "abort"})
}

func (s *Server) rollbackPreparedApply(ctx context.Context, lab string, fence Fence,
	tx applyTransaction,
) error {
	if len(tx.Previous) == 0 {
		eng := &deploy.Engine{Runtime: s.rt, Node: s.cfg.Node, State: s.store}
		if err := eng.Destroy(ctx, lab); err != nil {
			return fmt.Errorf("removing partially applied lab %q: %w", lab, err)
		}
		owned, err := netx.ListOverlaysOfLab(lab)
		if err != nil {
			return fmt.Errorf("listing partially applied overlays: %w", err)
		}
		if err := eng.DestroyOverlays(owned); err != nil {
			return fmt.Errorf("removing partially applied overlays: %w", err)
		}
		if err := s.releaseOverlayClaims(lab, nil); err != nil {
			return fmt.Errorf("releasing partially applied overlay claims: %w", err)
		}
		s.mu.Lock()
		delete(s.current, lab)
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
	rollback := tx
	rollback.Generation = tx.PreviousGen
	rollback.Mode = oldWire.Mode
	rollback.Ungraded = oldWire.Ungraded
	rollback.PeerUnderlay = oldWire.PeerUnderlay
	rollback.Prune = true
	eng := s.transactionEngine(oldTop, rollback)
	p, err := eng.Build(oldTop)
	if err != nil {
		return fmt.Errorf("build rollback plan: %w", err)
	}
	rep, err := p.Execute(ctx, plan.Options{Workers: 0, ContinueOnError: true})
	if err != nil {
		return fmt.Errorf("run rollback plan: %w", err)
	}
	if rep.Failed() {
		return fmt.Errorf("rollback plan failed: %w", rep.Err())
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
	s.rememberHow(lab, oldWire.Mode, oldWire.Ungraded)
	if s.peers == nil {
		s.peers = map[string]map[string]string{}
	}
	s.peers[lab] = oldWire.PeerUnderlay
	s.mu.Unlock()
	return s.restoreOverlayClaims(lab, fence, overlayVNIsOnNode(oldTop, s.cfg.Node))
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
