package agent

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
)

// ReconcileRequest asks an agent to schedule targeted desired/observed checks.
// An empty Devices list means every primary device hosted on this node.
type ReconcileRequest struct {
	Lab     string   `json:"lab"`
	Devices []string `json:"devices,omitempty"`
	// Force clears only automatic-repair backoff before queuing the selected
	// check. It never bypasses a hold, fault exemption, recovery fence, or
	// authorization policy.
	Force bool `json:"force,omitempty"`
}

type ReconcileResponse struct {
	Node      string   `json:"node"`
	Scheduled []string `json:"scheduled"`
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
	if req.Force && len(want) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("forced reconciliation requires one or more device IDs"))
		return
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
	writeJSON(w, ReconcileResponse{Node: s.cfg.Node, Scheduled: scheduled})
}
