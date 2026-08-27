package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
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
	Lab       string         `json:"lab"`
	Snapshots []WireSnapshot `json:"snapshots"`
	Records   []WireRecord   `json:"records,omitempty"`
	Missing   []string       `json:"missing,omitempty"`
	// FreshAt is set only after the source completed a capture and durable
	// replication quorum. A migration must not treat an old store read as a
	// fresh boundary capture.
	FreshAt time.Time       `json:"fresh_at,omitempty"`
	Extra   json.RawMessage `json:"extra,omitempty"`
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
	Records   []WireRecord   `json:"records,omitempty"`
}

// StateImportResponse says how many were new.
type StateImportResponse struct {
	Stored int        `json:"stored"`
	Acks   []StateAck `json:"acks,omitempty"`
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
	if r.URL.Query().Get("fresh") != "false" {
		if err := s.captureBeforeExport(r.Context(), lab, devices); err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("fresh state capture: %w", err))
			return
		}
	}

	resp := StateExportResponse{Lab: lab}
	for _, d := range devices {
		if !s.exportsStudentState(lab, d) {
			// Solve-mode reference devices are recreated from their persisted
			// renderer contract, never from a stale student snapshot. The
			// ungraded AS of a private harness remains exportable.
			continue
		}
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
	records, err := s.store.CurrentRecords(lab)
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("reading durable records: %w", err))
		return
	}
	for _, record := range records {
		resp.Records = append(resp.Records, WireRecord{Record: record, Content: record.Content})
	}
	if r.URL.Query().Get("fresh") != "false" {
		resp.FreshAt = time.Now().UTC()
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
	acks := make([]StateAck, 0, len(req.Snapshots)+len(req.Records))
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
		acks = append(acks, StateAck{Key: snapshotStateKey(snap), Digest: snap.Digest})
	}
	for _, wire := range req.Records {
		if err := s.requireMutationFence(req.Lab, req.Fence); err != nil {
			httpError(w, http.StatusConflict, err)
			return
		}
		record := wire.Record
		record.Content = wire.Content
		if record.Lab != req.Lab {
			httpError(w, http.StatusBadRequest, fmt.Errorf("record %s belongs to lab %q, not %q",
				record.Kind, record.Lab, req.Lab))
			return
		}
		isNew, err := s.store.PutRecord(record)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("storing %s record: %w", record.Kind, err))
			return
		}
		if isNew {
			stored++
		}
		if err := s.installImportedRecord(record); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		acks = append(acks, StateAck{Key: recordStateKey(record), Digest: record.Digest})
	}

	sort.Slice(acks, func(i, j int) bool { return acks[i].Key < acks[j].Key })
	writeJSON(w, StateImportResponse{Stored: stored, Acks: acks})
}

// installImportedRecord restores the local repair metadata represented by a
// durable record. Topology remains replica-only until the fenced apply commits
// it, but exemptions and active holds must take effect before a repair loop can
// undo a deliberately broken or externally managed lab.
func (s *Server) installImportedRecord(record state.Record) error {
	switch record.Kind {
	case state.RecordExemptions:
		if err := s.store.PutExemptions(record.Lab, record.Content); err != nil {
			return fmt.Errorf("install imported exemptions: %w", err)
		}
		s.loadExemptions(record.Lab)
	case state.RecordHolds:
		if err := s.store.PutHolds(record.Lab, record.Content); err != nil {
			return fmt.Errorf("install imported holds: %w", err)
		}
		s.loadHolds(record.Lab)
	}
	return nil
}

// captureBeforeExport snapshots any of the named devices this node is still
// running, so that what is handed over is current rather than historical.
//
// Failures are fatal for a fresh export. Falling back to an older store entry
// while the source is reachable is precisely the stale-state migration failure
// this boundary prevents; an explicit recovery path may request fresh=false
// only after a source-loss decision is audited.
//
// It goes through the engine's capture API rather than reading the containers
// itself, because that API is where a capture is checked against the namespace
// the device's saved state came out of. Reading them here meant a device that
// had restarted was exported as the empty namespace it came back into -- a
// fresh capture is exactly the operation that overwrites the old one -- and the
// destination then received that as the student's work. Selecting through the
// same predicate periodic durability uses is part of it: what a fresh export
// hands over must be what a capture is allowed to store.
func (s *Server) captureBeforeExport(ctx context.Context, lab string, devices []string) error {
	if s.rt == nil || s.store == nil {
		return errors.New("this node cannot capture durable state")
	}
	s.mu.Lock()
	top := s.current[lab]
	mode := render.Mode(s.modes[lab])
	ungraded := s.ungraded[lab]
	s.mu.Unlock()
	if top == nil {
		return fmt.Errorf("this node has no topology record for %q", lab)
	}
	want := map[string]bool{}
	for _, d := range devices {
		want[d] = true
	}
	selected := make([]string, 0, len(want))
	for id := range want {
		d, ok := top.Device(id)
		if !ok {
			return fmt.Errorf("source topology has no device %q", id)
		}
		if d.Node != s.cfg.Node {
			return fmt.Errorf("device %s is placed on %s, not source %s", id, d.Node, s.cfg.Node)
		}
		if !capturesStudentState(top, mode, ungraded, d) {
			continue
		}
		current, err := s.rt.Inspect(ctx, d.Container)
		if err != nil {
			return fmt.Errorf("inspect %s before fresh capture: %w", d.ID, err)
		}
		if current.State == rt.StateAbsent {
			return fmt.Errorf("device %s is absent, so its state cannot be freshly captured", d.ID)
		}
		selected = append(selected, id)
	}
	sort.Strings(selected)
	if len(selected) > 0 {
		eng := &deploy.Engine{
			Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(), State: s.store,
			Renderer:        renderer(top, render.ModePlatform, 0),
			ObservationRoot: s.observationRoot,
		}
		if _, err := eng.CaptureDevices(ctx, top, s.store, selected); err != nil {
			return fmt.Errorf("capture %s: %w", lab, err)
		}
	}
	if err := s.replicateDurableState(ctx, top); err != nil {
		return err
	}
	return nil
}

func (s *Server) exportsStudentState(lab, id string) bool {
	s.mu.Lock()
	top := s.current[lab]
	mode := render.Mode(s.modes[lab])
	ungraded := s.ungraded[lab]
	s.mu.Unlock()
	if top == nil {
		return true
	}
	device, ok := top.Device(id)
	if !ok {
		return false
	}
	return renderModeForDevice(mode, ungraded, device) != render.ModeSolve
}
