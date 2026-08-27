package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/HongyuHe/twinet/internal/deploy"
)

// ReconcileRequest asks an agent to schedule targeted desired/observed checks.
// An empty Devices list means every primary device hosted on this node.
type ReconcileRequest struct {
	Lab     string   `json:"lab"`
	Devices []string `json:"devices,omitempty"`
	// Overlay repairs missing VNI/VLAN bindings without recreating endpoint
	// containers. It is implicit when all local devices are reconciled.
	Overlay bool `json:"overlay,omitempty"`
	// Force clears automatic-repair backoff, including a terminal state a
	// bounded distributed repair has already given up on, before queuing the
	// selected check. It never bypasses a hold, fault exemption, recovery
	// fence, or authorization policy.
	Force bool `json:"force,omitempty"`
}

type ReconcileResponse struct {
	Node            string            `json:"node"`
	Scheduled       []string          `json:"scheduled"`
	OverlayRepaired []string          `json:"overlay_repaired,omitempty"`
	OverlayFailed   map[string]string `json:"overlay_failed,omitempty"`
	OverlayExtra    []string          `json:"overlay_extra,omitempty"`
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	var req ReconcileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	s.mu.Lock()
	top := s.current[req.Lab]
	s.mu.Unlock()
	if top == nil {
		httpError(w, http.StatusNotFound, errors.New("this node does not host the lab"))
		return
	}
	want := map[string]bool{}
	for _, id := range req.Devices {
		want[id] = true
	}
	if req.Force && len(want) == 0 && !req.Overlay {
		httpError(w, http.StatusBadRequest, errors.New("forced reconciliation requires one or more device IDs"))
		return
	}
	resp := ReconcileResponse{Node: s.cfg.Node}
	if req.Overlay || len(want) == 0 {
		if reason := s.ordinaryMaintenanceSuppression(req.Lab); reason != "" {
			httpError(w, http.StatusConflict, errors.New(reason))
			return
		}
		if who := s.heldBy(req.Lab); who != "" {
			httpError(w, http.StatusConflict, errors.New("lab is held by "+who))
			return
		}
		if err := s.acquire(req.Lab, "overlay-reconcile"); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		repair := (&deploy.Engine{
			Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(),
			UnderlayIP: s.cfg.UnderlayIP, UnderlayDev: s.cfg.UnderlayDev,
			PeerUnderlay: s.peerUnderlay(req.Lab), ForceOverlayReconcile: true,
			ObservationRoot: s.observationRoot,
		})
		report, err := repair.ReconcileOverlayBindings(r.Context(), top)
		s.release(req.Lab)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		resp.OverlayRepaired = report.Repaired
		resp.OverlayFailed = report.Failed
		resp.OverlayExtra = report.Extra
		if len(report.Failed) == 0 && len(report.Extra) == 0 {
			if err := s.refreshCommittedOverlayInventory(r.Context(), req.Lab, top, repair); err != nil {
				resp.OverlayFailed = map[string]string{"inventory": err.Error()}
			}
		}
	}
	scheduled := []string{}
	for _, device := range top.SortedDevices() {
		if device.Node != s.cfg.Node || (len(want) > 0 && !want[device.ID]) {
			continue
		}
		if req.Force {
			s.repairSucceeded(req.Lab, device.ID)
			if err := s.forceRewireDevice(r.Context(), top, device); err != nil {
				httpError(w, http.StatusConflict, err)
				return
			}
		} else {
			s.queueReconcile(r.Context(), req.Lab, device.ID)
		}
		scheduled = append(scheduled, device.ID)
	}
	sort.Strings(scheduled)
	s.recordEvent(req.Lab, "", "reconcile", s.requestCorrelation(r),
		"reconcile_requested", "scheduled", joinControlIDs(scheduled))
	resp.Scheduled = scheduled
	writeJSON(w, resp)
}
