package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

// persistedHold is deliberately separate from hold: the in-memory fields are
// unexported, so marshaling hold directly would write `{}` and a replicated
// restart would silently forget the repair pause it was meant to preserve.
type persistedHold struct {
	Holder string    `json:"holder"`
	Token  string    `json:"token"`
	Until  time.Time `json:"until"`
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
	if top, _, ok := s.durabilityTopology(req.Lab); ok && s.store != nil {
		if err := s.ensureDurableState(r.Context(), top); err != nil {
			if boundaryErr := s.durableBoundary(top, "recording a repair hold", err); boundaryErr != nil {
				// The local hold remains active. Returning an error rather than
				// claiming cluster-wide safety tells the caller to retry, while
				// retaining the safer local state instead of reopening repair.
				httpError(w, http.StatusServiceUnavailable, boundaryErr)
				return
			}
		}
	}
	action, result := "hold_set", "success"
	if req.Seconds <= 0 {
		action = "hold_released"
	}
	s.recordEvent(req.Lab, "", "grading", s.requestCorrelation(r), action, result,
		"holder="+boundedEventText(req.Holder, 96))
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
	if s.holds == nil {
		s.holds = map[string]*hold{}
	}
	previous := cloneHold(s.holds[req.Lab])

	if cur, ok := s.holds[req.Lab]; ok && time.Now().Before(cur.until) &&
		cur.token != "" && cur.token != req.Token {
		return fmt.Errorf("lab %q is already held by %s for another %s; two operations "+
			"grading or repairing the same lab at once would each undo the other's work",
			req.Lab, cur.holder, time.Until(cur.until).Round(time.Second))
	}
	if req.Seconds <= 0 {
		delete(s.holds, req.Lab)
	} else {
		s.holds[req.Lab] = &hold{
			holder: req.Holder,
			token:  req.Token,
			until:  time.Now().Add(time.Duration(req.Seconds) * time.Second),
		}
	}
	if err := s.saveHoldsLocked(req.Lab); err != nil {
		if previous == nil {
			delete(s.holds, req.Lab)
		} else {
			s.holds[req.Lab] = previous
		}
		return err
	}
	return nil
}

func cloneHold(in *hold) *hold {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

// saveHoldsLocked persists active holds so a restart or a node repair does not
// mistake a deliberately paused lab for an abandoned one. The caller holds
// s.mu.
func (s *Server) saveHoldsLocked(lab string) error {
	if s.store == nil {
		return nil
	}
	now := time.Now()
	if h := s.holds[lab]; h != nil && !now.Before(h.until) {
		delete(s.holds, lab)
	}
	var saved *persistedHold
	if h := s.holds[lab]; h != nil {
		saved = &persistedHold{Holder: h.holder, Token: h.token, Until: h.until}
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return s.store.PutHolds(lab, raw)
}

// loadHolds restores an unexpired hold after the agent restarts. An expired
// hold is deliberately discarded: a dead grader must never stop repair
// forever merely because its state was replicated.
func (s *Server) loadHolds(lab string) {
	if s.store == nil {
		return
	}
	raw, err := s.store.Holds(lab)
	if err != nil {
		return
	}
	var saved *persistedHold
	if err := json.Unmarshal(raw, &saved); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holds == nil {
		s.holds = map[string]*hold{}
	}
	if saved == nil || !time.Now().Before(saved.Until) {
		delete(s.holds, lab)
		return
	}
	s.holds[lab] = &hold{holder: saved.Holder, token: saved.Token, until: saved.Until}
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

// labOfContainer recovers the lab a container belongs to from its name.
//
// Containers are named "twinet-<lab>-<...>", and every lab this node hosts is
// known, so the longest matching lab name is the owner. Matching the longest is
// what tells "cos461" from "cos461-g3-groupX".
func (s *Server) labOfContainer(name string) string {
	const prefix = "twinet-"
	if !strings.HasPrefix(name, prefix) {
		return ""
	}
	rest := name[len(prefix):]
	s.mu.Lock()
	defer s.mu.Unlock()
	best := ""
	for lab := range s.current {
		if strings.HasPrefix(rest, lab+"-") && len(lab) > len(best) {
			best = lab
		}
	}
	return best
}

// refuseIfHeldByAnother reports why an interactive request must be refused, or
// "" if it may proceed.
//
// A hold is how a grading run says "leave this lab to me". It stopped the
// node's own repair loop and nothing else, so while a class was being marked a
// student could still open a shell on a router -- read the reference solution
// off their neighbours, change the submission that was about to be graded, or
// break a system somebody else's mark depended on. None of that would appear
// anywhere in the marks.
//
// The holder is exempt: grading reaches the containers through this same door.
func (s *Server) refuseIfHeldByAnother(container, token string) string {
	lab := s.labOfContainer(container)
	if lab == "" {
		return ""
	}
	s.mu.Lock()
	h, ok := s.holds[lab]
	if ok && time.Now().After(h.until) {
		delete(s.holds, lab)
		ok = false
	}
	s.mu.Unlock()
	if !ok || h.token == "" || h.token == token {
		return ""
	}
	return fmt.Sprintf("lab %q is being graded by %s; interactive access is refused until "+
		"that finishes, because a change made now would land in somebody's marks",
		lab, h.holder)
}

// refuseMutationIfHeld reports why an operation on a named lab must be refused,
// or "" if it may proceed.
//
// The hold stopped the repair loop, and then interactive access, and left every
// other way of changing a lab open. A second `twinet deploy --solve` run by
// anybody, a destroy, a container restart -- each could overwrite a submission
// with the reference while it was being marked, and none of them closes the
// grader's lease, so the run would go on and release the marks.
//
// The holder is exempt: grading restores each system between submissions
// through this same door.
func (s *Server) refuseMutationIfHeld(lab, token, what string) string {
	if lab == "" {
		return ""
	}
	s.mu.Lock()
	h, ok := s.holds[lab]
	if ok && time.Now().After(h.until) {
		delete(s.holds, lab)
		ok = false
	}
	s.mu.Unlock()
	if !ok || h.token == "" || h.token == token {
		return ""
	}
	return fmt.Sprintf("lab %q is being graded by %s, so %s is refused: a change made now "+
		"would land in somebody's marks with nothing in the report able to say so",
		lab, h.holder, what)
}
