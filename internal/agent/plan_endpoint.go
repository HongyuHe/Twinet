package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
)

// PlanRequest is a read-only desired/observed preflight request.
type PlanRequest struct {
	Lab          string            `json:"lab"`
	Topology     *Wire             `json:"topology"`
	Mode         string            `json:"mode,omitempty"`
	Ungraded     int               `json:"ungraded_as,omitempty"`
	PeerUnderlay map[string]string `json:"peer_underlay,omitempty"`
}

// PlanResponse is a bounded no-op eligibility report. Token is a read-only
// compare-and-swap witness checked immediately before the controller returns
// a no-op result.
type PlanResponse struct {
	Node            string                 `json:"node"`
	Generation      string                 `json:"generation,omitempty"`
	FenceGeneration uint64                 `json:"fence_generation,omitempty"`
	Hash            string                 `json:"hash,omitempty"`
	Mode            string                 `json:"mode,omitempty"`
	Token           string                 `json:"token,omitempty"`
	Noop            bool                   `json:"noop"`
	Stats           deploy.DeploymentStats `json:"stats"`
	Reason          string                 `json:"reason,omitempty"`
	// SemanticHealth is this node's audited convergence state for the lab.
	// It is the same evidence `node status` publishes, carried here so that a
	// controller cannot accept a zero-change deployment against a node that
	// is simultaneously reporting drifted devices.
	SemanticHealth SemanticHealth `json:"semantic_health"`
}

type PlanVerifyRequest struct {
	Lab   string `json:"lab"`
	Token string `json:"token"`
}

type PlanVerifyResponse struct {
	Node  string `json:"node"`
	Valid bool   `json:"valid"`
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	var req PlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" || req.Topology == nil {
		httpError(w, http.StatusBadRequest, errors.New("a lab and topology are required"))
		return
	}
	top, err := req.Topology.Rehydrate()
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if top.Name != req.Lab {
		httpError(w, http.StatusConflict, errors.New("preflight topology belongs to another lab"))
		return
	}
	mode, err := RequireTransactionMode(req.Mode)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	current := s.current[req.Lab]
	committed := s.generations[req.Lab].Committed
	fenceGeneration := s.fenceHighWater[req.Lab]
	currentMode, currentUngraded := s.modes[req.Lab], s.ungraded[req.Lab]
	_, activeTx := s.transactions[req.Lab]
	s.mu.Unlock()
	resp := PlanResponse{
		Node: s.cfg.Node, Generation: committed, FenceGeneration: fenceGeneration,
		Hash: top.Hash, Mode: mode, SemanticHealth: s.labSemanticHealth(req.Lab),
	}
	if current == nil || current.Hash != top.Hash {
		resp.Reason = "committed topology hash differs"
		writeJSON(w, resp)
		return
	}
	if canonicalMode(currentMode) != mode || currentUngraded != req.Ungraded {
		resp.Reason = "committed renderer mode differs"
		writeJSON(w, resp)
		return
	}
	if activeTx {
		resp.Reason = "transaction is active"
		writeJSON(w, resp)
		return
	}
	eng := &deploy.Engine{
		Runtime:                s.rt,
		Node:                   s.cfg.Node,
		Limiter:                s.workLimiter(),
		Renderer:               renderer(top, render.Mode(mode), req.Ungraded),
		WritesReference:        render.Mode(mode) == render.ModeSolve,
		Authoritative:          render.Mode(mode) == render.ModeSolve && req.Ungraded == 0,
		UnderlayIP:             s.cfg.UnderlayIP,
		UnderlayDev:            s.cfg.UnderlayDev,
		PeerUnderlay:           req.PeerUnderlay,
		State:                  s.store,
		ModeKey:                rendererModeKey(render.Mode(mode), req.Ungraded),
		RequireImmutableImages: top.Lab.Images.RequiresImmutableImages(),
		ObservationReadOnly:    true,
		SemanticProbe: func(ctx context.Context, device *model.Device) error {
			if err := s.semanticProbe(ctx, top, render.Mode(mode), req.Ungraded, device); err != nil {
				return err
			}
			// The audit sees what a rendered-hash diff cannot: a container
			// with no interfaces, a router with no routing daemons, a dead
			// FRR sidecar. A preflight that ignored it answered "no changes"
			// for a lab whose own node was publishing a hundred drifted
			// devices at the same moment.
			return auditedDriftError(s.auditedDriftReason(ctx, req.Lab, device))
		},
	}
	plan, err := eng.BuildContext(r.Context(), top)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	resp.Stats = eng.DeploymentStats(nil)
	// The plan is re-read after the probes above, which refresh the audited
	// observations they consult.
	resp.SemanticHealth = s.labSemanticHealth(req.Lab)
	resp.Noop = plan.Len() == 0 && eng.LastBuildDiff().Empty()
	// Zero work and degraded health are mutually exclusive answers, and the
	// health is the more useful of the two: it names the device an operator
	// has to look at. The deployment falls through to the ordinary fenced
	// path, which can repair what the preflight refused to ignore.
	if reason := noopRefusalReason(resp.SemanticHealth); reason != "" {
		resp.Noop = false
		resp.Reason = reason
	} else if resp.Noop {
		resp.Token = planToken(committed, fenceGeneration, top.Hash, mode, req.Ungraded)
	} else {
		resp.Reason = "desired/observed dirty set is non-empty"
	}
	writeJSON(w, resp)
}

func (s *Server) handlePlanVerify(w http.ResponseWriter, r *http.Request) {
	var req PlanVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	current := s.current[req.Lab]
	committed := s.generations[req.Lab].Committed
	fenceGeneration := s.fenceHighWater[req.Lab]
	mode, ungraded := s.modes[req.Lab], s.ungraded[req.Lab]
	_, activeTx := s.transactions[req.Lab]
	s.mu.Unlock()
	valid := current != nil && !activeTx &&
		req.Token == planToken(committed, fenceGeneration, current.Hash, canonicalMode(mode), ungraded)
	writeJSON(w, PlanVerifyResponse{Node: s.cfg.Node, Valid: valid})
}

func planToken(generation string, fenceGeneration uint64, hash, mode string, ungraded int) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		generation, strconv.FormatUint(fenceGeneration, 10), hash, mode, strconv.Itoa(ungraded),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
