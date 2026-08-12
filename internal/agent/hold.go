package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// A hold asks this node's repair loop to leave a lab alone for a while.
//
// Grading manipulates a lab from outside the agent: it flushes addresses,
// reloads routing configuration and, between submissions, deliberately puts an
// autonomous system back to the state a student starts from. Every one of those
// steps makes a device look, for a moment, exactly like a device that has lost
// its wiring.
//
// The repair loop believed that appearance and acted on it. Mid-run it rewired
// thirteen devices of a lab that was being graded; rewiring removes an
// interface and adds it back, so the submission being loaded at that instant
// failed with "Cannot find device port_BOS" and its owner was quarantined. In a
// solved lab the repair also re-renders configuration, which is the reference
// solution being written over a student's work while their marks are counted.
//
// A hold is deliberately a lease with a deadline rather than a flag. A grader
// that crashes, is killed, or loses the network stops renewing, and the node
// resumes looking after the lab by itself within the minute. Nothing has to be
// cleaned up by hand, and no failure of the grader can leave repairs switched
// off permanently -- which is the failure mode that a plain on/off switch has
// and that nobody notices until something else breaks months later.
type hold struct {
	holder string
	// token is proof of ownership. Without one, any caller could renew or drop
	// a hold another grading run is relying on -- and the second caller would
	// be told it had succeeded. Two graders on one lab is a mistake, but it
	// must be a loud one.
	token string
	until time.Time
}

// HoldRequest asks for, renews, or drops a hold.
type HoldRequest struct {
	Lab string `json:"lab"`
	// Holder names what is asking, so the log and any conflict message can say
	// who to go and look at.
	Holder string `json:"holder"`
	// Seconds is how long the hold should last from now. Zero drops it.
	Seconds int `json:"seconds"`
	// Token identifies the holder across calls.
	Token string `json:"token,omitempty"`
}

// maxHoldSeconds bounds a single lease. A caller that wants longer renews,
// which is what proves it is still alive.
const maxHoldSeconds = 600

func (s *Server) handleHold(w http.ResponseWriter, r *http.Request) {
	var req HoldRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	if err := s.applyHold(req); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, struct{}{})
}

// applyHold takes, renews or drops a hold, and refuses if somebody else has it.
//
// The cap lives here rather than in the handler so it cannot be bypassed by a
// future second caller.
func (s *Server) applyHold(req HoldRequest) error {
	if req.Seconds > maxHoldSeconds {
		req.Seconds = maxHoldSeconds
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if cur, ok := s.holds[req.Lab]; ok && time.Now().Before(cur.until) &&
		cur.token != "" && cur.token != req.Token {
		return fmt.Errorf("lab %q is already held by %s for another %s; two operations "+
			"grading or repairing the same lab at once would each undo the other's work",
			req.Lab, cur.holder, time.Until(cur.until).Round(time.Second))
	}
	if req.Seconds <= 0 {
		delete(s.holds, req.Lab)
		return nil
	}
	s.holds[req.Lab] = &hold{
		holder: req.Holder,
		token:  req.Token,
		until:  time.Now().Add(time.Duration(req.Seconds) * time.Second),
	}
	return nil
}

// heldBy names what is holding a lab, or "" if the repair loop may proceed.
func (s *Server) heldBy(lab string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.holds[lab]
	if !ok {
		return ""
	}
	if time.Now().After(h.until) {
		delete(s.holds, lab)
		return ""
	}
	if h.holder == "" {
		return "an external operation"
	}
	return h.holder
}
