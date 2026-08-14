package agent

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
)

// An exemption says a device is broken on purpose and must not be repaired.
//
// The nodes run a loop that repairs devices which have stopped working, and it
// cannot tell a fault somebody injected from a fault that happened. Stopping
// FRR on a router is a supported fault, and the loop restarted it within the
// minute -- so an episode kept open for an agent to diagnose lost its fault
// while the recorded ground truth went on saying it was live. Every answer
// graded against that truth is wrong, and nothing reports it.
//
// It is recorded here, on the node, and deliberately not inside the container.
// A marker file in the device under test tells an agent being evaluated on
// root-cause analysis both that a fault was injected and, if it names the
// fault, what the answer is. That is the whole benchmark, readable with `cat`.
//
// It is persisted because a fault outlives the command that injected it: an
// episode held open for diagnosis, or a fault injected by hand for a class
// exercise, must survive an agent restart. It is not a lease, for the same
// reason -- there is no process left running to renew one.
type exemptions struct {
	// Devices maps a device ID to the opaque injection identifiers currently
	// exempting it. Identifiers rather than fault names, so that nothing here
	// is the answer even to somebody who can read this node's disk.
	Devices map[string][]string `json:"devices"`
}

// ExemptRequest adds or removes one exemption.
type ExemptRequest struct {
	Lab    string `json:"lab"`
	Device string `json:"device"`
	// ID is an opaque injection identifier.
	ID string `json:"id"`
	// On adds the exemption; false removes it.
	On bool `json:"on"`
}

func (s *Server) handleExempt(w http.ResponseWriter, r *http.Request) {
	var req ExemptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" || req.Device == "" || req.ID == "" {
		httpError(w, http.StatusBadRequest,
			errors.New("a lab, a device and an injection identifier are all required"))
		return
	}
	if err := s.setExempt(req); err != nil {
		// Reported, not logged and forgotten. An injection whose exemption
		// could not be recorded will be undone by the repair loop within the
		// minute, and the caller has to know that before it tells anybody the
		// fault is live.
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) setExempt(req ExemptRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.exempt == nil {
		s.exempt = map[string]*exemptions{}
	}
	ex := s.exempt[req.Lab]
	if ex == nil {
		ex = &exemptions{Devices: map[string][]string{}}
		s.exempt[req.Lab] = ex
	}
	ids := ex.Devices[req.Device]
	have := false
	kept := ids[:0:0]
	for _, id := range ids {
		if id == req.ID {
			have = true
			if !req.On {
				continue
			}
		}
		kept = append(kept, id)
	}
	if req.On && !have {
		kept = append(kept, req.ID)
	}
	sort.Strings(kept)
	if len(kept) == 0 {
		delete(ex.Devices, req.Device)
	} else {
		ex.Devices[req.Device] = kept
	}
	return s.saveExemptLocked(req.Lab)
}

// saveExemptLocked persists a lab's exemptions. The caller holds s.mu.
func (s *Server) saveExemptLocked(lab string) error {
	if s.store == nil {
		return nil
	}
	raw, err := json.Marshal(s.exempt[lab])
	if err != nil {
		return err
	}
	return s.store.PutExemptions(lab, raw)
}

// loadExemptions restores a lab's exemptions after a restart.
func (s *Server) loadExemptions(lab string) {
	if s.store == nil {
		return
	}
	raw, err := s.store.Exemptions(lab)
	if err != nil {
		return
	}
	var ex exemptions
	if err := json.Unmarshal(raw, &ex); err != nil {
		slog.Warn("reading which devices are broken on purpose", "lab", lab, "err", err)
		return
	}
	if ex.Devices == nil {
		ex.Devices = map[string][]string{}
	}
	s.mu.Lock()
	if s.exempt == nil {
		s.exempt = map[string]*exemptions{}
	}
	s.exempt[lab] = &ex
	s.mu.Unlock()
}

// isExempt reports whether a device is broken on purpose.
func (s *Server) isExempt(lab, device string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ex := s.exempt[lab]
	return ex != nil && len(ex.Devices[device]) > 0
}
