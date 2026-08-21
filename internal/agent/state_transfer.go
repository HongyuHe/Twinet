package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/state"
)

// Moving an autonomous system to another node used to lose the work in it.
//
// Preserved student configuration is held in a store on the node that captured
// it. Placement is not fixed: adding a machine, or a manifest that grows,
// re-partitions the lab and moves systems between nodes. When that happened the
// source node captured the device's configuration before removing it -- which
// is right -- and the destination node then built the device from the manifest,
// because the snapshot was in a directory on a machine it never asks.
//
// Both nodes reported success. The class's work was not deleted; it was
// stranded on a machine that no longer runs the device, which is
// indistinguishable from deleted to everyone except someone who knows to go
// looking. Rebalancing a cluster is an operator action with no warning attached,
// so this was reachable by doing something entirely reasonable.
//
// These two endpoints let the controller carry a device's snapshots from the
// node that holds them to the node that will run it. Export and import rather
// than node-to-node transfer, because the nodes authenticate to the controller
// and not to each other, and giving them a mutual credential so a file can move
// is a much larger change than the problem needs.

// StateExportResponse carries a device's snapshots off the node holding them.
type StateExportResponse struct {
	Lab       string          `json:"lab"`
	Snapshots []WireSnapshot  `json:"snapshots"`
	Missing   []string        `json:"missing,omitempty"`
	Extra     json.RawMessage `json:"extra,omitempty"`
}

// WireSnapshot is a snapshot with its body, which state.Snapshot omits from
// JSON because the store keeps the two in separate files.
type WireSnapshot struct {
	state.Snapshot
	Content []byte `json:"content"`
}

// StateImportRequest installs snapshots taken on another node.
type StateImportRequest struct {
	Lab       string         `json:"lab"`
	Hold      string         `json:"hold,omitempty"`
	Fence     Fence          `json:"fence"`
	Snapshots []WireSnapshot `json:"snapshots"`
}

// StateImportResponse says how many were new.
type StateImportResponse struct {
	Stored int `json:"stored"`
}

func (s *Server) handleStateExport(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		httpError(w, http.StatusServiceUnavailable,
			fmt.Errorf("this node keeps no state store, so it has nothing to hand over"))
		return
	}
	lab := r.URL.Query().Get("lab")
	if lab == "" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("no lab was named"))
		return
	}
	devices := r.URL.Query()["device"]
	if len(devices) == 0 {
		var err error
		devices, err = s.store.Devices(lab)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}

	// The freshest copy of a student's work is in the running container, not
	// in the store.
	//
	// A device only gets captured when something removes it, and on a move
	// that happens during the deploy that is asking for this -- after it, not
	// before. Exporting the store alone therefore handed over whatever was
	// last written, which for a device nobody had removed yet was nothing at
	// all, and the transfer succeeded while carrying an empty set.
	s.captureBeforeExport(r.Context(), lab, devices)

	resp := StateExportResponse{Lab: lab}
	for _, d := range devices {
		found := false
		for _, k := range state.AllKinds {
			snap, err := s.store.Current(lab, d, k)
			if err != nil {
				continue
			}
			resp.Snapshots = append(resp.Snapshots,
				WireSnapshot{Snapshot: snap, Content: snap.Content})
			found = true
		}
		if !found {
			// Reported rather than silently omitted. A caller migrating a
			// device needs to tell "this node had nothing for it" from "this
			// node was not asked", and only one of those is safe to ignore.
			resp.Missing = append(resp.Missing, d)
		}
	}
	writeJSON(w, resp)
}

func (s *Server) handleStateImport(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		httpError(w, http.StatusServiceUnavailable,
			fmt.Errorf("this node keeps no state store, so imported work would be dropped"))
		return
	}
	var req StateImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, fmt.Errorf("no lab was named"))
		return
	}
	if err := s.requireMutationFence(req.Lab, req.Fence); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	if why := s.refuseMutationIfHeld(req.Lab, req.Hold, "importing preserved state"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	if err := s.acquire(req.Lab, "state import"); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	defer s.release(req.Lab)
	stored := 0
	for _, ws := range req.Snapshots {
		if err := s.requireMutationFence(req.Lab, req.Fence); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		snap := ws.Snapshot
		snap.Content = ws.Content
		if len(snap.Content) == 0 {
			continue
		}
		// The digest is recomputed by Put, so a snapshot whose body was
		// truncated in transit stores under its real digest rather than
		// claiming to be the original.
		isNew, err := s.store.Put(snap)
		if err != nil {
			httpError(w, http.StatusInternalServerError,
				fmt.Errorf("storing %s/%s: %w", snap.Device, snap.Kind, err))
			return
		}
		if isNew {
			stored++
		}
	}
	writeJSON(w, StateImportResponse{Stored: stored})
}

// captureBeforeExport snapshots any of the named devices this node is still
// running, so that what is handed over is current rather than historical.
//
// Failures are not fatal: a device that cannot be captured falls back to
// whatever the store already holds, which is the situation that existed before
// this ran. Refusing the whole export because one container was mid-restart
// would deny the caller the snapshots it could have had.
func (s *Server) captureBeforeExport(ctx context.Context, lab string, devices []string) {
	if s.rt == nil || s.store == nil {
		return
	}
	s.mu.Lock()
	top := s.current[lab]
	s.mu.Unlock()
	if top == nil {
		return
	}
	want := map[string]bool{}
	for _, d := range devices {
		want[d] = true
	}
	for _, d := range top.Devices {
		if !want[d.ID] || d.Node != s.cfg.Node {
			continue
		}
		snaps, err := deploy.Capture(ctx, s.rt, d, lab, top.Hash)
		if err != nil {
			slog.Debug("capturing before export", "device", d.ID, "err", err)
			continue
		}
		for _, sn := range snaps {
			if _, err := s.store.Put(sn); err != nil {
				slog.Warn("storing a snapshot taken for export", "device", d.ID, "err", err)
			}
		}
	}
}
