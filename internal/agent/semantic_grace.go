package agent

import (
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

const (
	smallTopologySemanticGrace = 2 * time.Minute
	largeTopologySemanticGrace = 10 * time.Minute
)

func semanticConvergenceGraceFor(top *model.Topology) time.Duration {
	if top != nil && len(top.Devices) > 256 {
		return largeTopologySemanticGrace
	}
	return smallTopologySemanticGrace
}

func (s *Server) beginSemanticConvergenceGrace(top *model.Topology) {
	if s == nil || top == nil || top.Name == "" {
		return
	}
	s.mu.Lock()
	if s.semanticGraceUntil == nil {
		s.semanticGraceUntil = map[string]time.Time{}
	}
	s.semanticGraceUntil[top.Name] = s.nowTime().Add(semanticConvergenceGraceFor(top))
	// A new committed generation gets its own bounded convergence budget.
	// Failure history from the previous generation cannot terminalize it.
	for key := range s.semanticCycles {
		if repairKeyLab(key) == top.Name {
			delete(s.semanticCycles, key)
			delete(s.repairTerminal, key)
			delete(s.repairFails, key)
			delete(s.repairNext, key)
		}
	}
	s.mu.Unlock()
}

func (s *Server) semanticDriftActionable(lab, reason string) bool {
	// Missing local addressing, VLANs, or switch state is never normal BGP
	// convergence and remains repairable immediately.
	if locallyRepairableDrift(reason) {
		return true
	}
	s.mu.Lock()
	until := s.semanticGraceUntil[lab]
	s.mu.Unlock()
	return until.IsZero() || !s.nowTime().Before(until)
}

func repairKeyLab(key string) string {
	for i := range len(key) {
		if key[i] == '|' {
			return key[:i]
		}
	}
	return ""
}
