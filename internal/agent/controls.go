package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// ControlStatus is one private FRR control-sidecar audit result. It never
// exposes a student router shell as a control target.
type ControlStatus struct {
	Node      string            `json:"node"`
	Lab       string            `json:"lab"`
	Device    string            `json:"device"`
	Container string            `json:"container"`
	State     rt.State          `json:"state"`
	Daemons   map[string]int    `json:"daemons,omitempty"`
	VTY       bool              `json:"vty"`
	Namespace *ControlNamespace `json:"namespace,omitempty"`
	Healthy   bool              `json:"healthy"`
	Reason    string            `json:"reason,omitempty"`
}

// ControlAuditResponse is a stable node-local sidecar inventory.
type ControlAuditResponse struct {
	Node     string          `json:"node"`
	Controls []ControlStatus `json:"controls"`
}

// ControlReconcileRequest asks the agent to enqueue bounded automatic repair
// for unhealthy sidecars. It does not bypass holds, fences, or backoff.
type ControlReconcileRequest struct {
	Lab string `json:"lab"`
}

func (s *Server) handleControls(w http.ResponseWriter, r *http.Request) {
	lab := r.URL.Query().Get("lab")
	controls := s.auditControls(r.Context(), lab)
	writeJSON(w, ControlAuditResponse{Node: s.cfg.Node, Controls: controls})
}

func (s *Server) handleControlReconcile(w http.ResponseWriter, r *http.Request) {
	var req ControlReconcileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	controls := s.auditControls(r.Context(), req.Lab)
	scheduled := make([]string, 0, len(controls))
	for _, control := range controls {
		if control.Healthy {
			continue
		}
		s.queueReconcile(r.Context(), req.Lab, control.Device)
		scheduled = append(scheduled, control.Device)
	}
	sort.Strings(scheduled)
	s.recordEvent(req.Lab, "", "reconcile", s.requestCorrelation(r),
		"control_audit_reconcile", "scheduled", joinControlIDs(scheduled))
	writeJSON(w, map[string]any{"node": s.cfg.Node, "scheduled": scheduled})
}

func (s *Server) auditControls(ctx context.Context, lab string) []ControlStatus {
	s.mu.Lock()
	tops := make([]*model.Topology, 0, len(s.current))
	for name, top := range s.current {
		if lab == "" || lab == name {
			tops = append(tops, top)
		}
	}
	s.mu.Unlock()
	sort.Slice(tops, func(i, j int) bool { return tops[i].Name < tops[j].Name })
	var out []ControlStatus
	for _, top := range tops {
		if top == nil {
			continue
		}
		for _, device := range top.SortedDevices() {
			if device.Node != s.cfg.Node || !s.requiresFRRControl(device) {
				continue
			}
			out = append(out, s.auditControl(ctx, top, device))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Lab != out[j].Lab {
			return out[i].Lab < out[j].Lab
		}
		return out[i].Device < out[j].Device
	})
	return out
}

func (s *Server) auditControl(ctx context.Context, top *model.Topology, device *model.Device) ControlStatus {
	status := ControlStatus{
		Node: s.cfg.Node, Lab: top.Name, Device: device.ID,
		Container: deploy.FRRControlContainer(device),
	}
	sidecar, err := s.rt.Inspect(ctx, status.Container)
	if err != nil {
		status.Reason = "inspect control sidecar: " + err.Error()
		return status
	}
	status.State = sidecar.State
	if !sidecar.State.Joinable() {
		status.Reason = "control sidecar is absent or not running"
		return status
	}
	// Where the sidecar is, before what is running inside it. A sidecar left
	// in the namespace of a router that has since restarted runs the complete
	// daemon set, answers on its vty, and is attached to a namespace with a
	// loopback and no cables. Counting its daemons is how this audit used to
	// certify exactly that device as healthy.
	proof := s.proveControlNamespace(ctx, device)
	status.Namespace = proof.wire()
	if !proof.OK() {
		status.Reason = proof.Reason
		return status
	}
	as := top.ASes[device.ASN]
	counts, err := s.controlDaemonCounts(ctx, device, as)
	if err != nil {
		status.Reason = "count control daemons: " + err.Error()
		return status
	}
	status.Daemons = counts
	if err := s.verifyControlDaemonSet(ctx, device, as); err != nil {
		status.Reason = err.Error()
		return status
	}
	status.VTY = true
	status.Healthy = true
	return status
}

func joinControlIDs(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	out := ids[0]
	for _, id := range ids[1:] {
		out += "," + id
	}
	return out
}
