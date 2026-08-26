package agent

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/HongyuHe/twinet/internal/netx"
)

// Collection decisions are made from a scan and acted on afterwards. Between
// those two moments a deploy can legitimately claim exactly the object the
// scan decided was abandoned: it reserves the VNI, the reservation succeeds
// because at that instant nothing said otherwise, and the collector then
// deletes the overlay the new lab has just been wired into. The lab comes up
// with a cable missing and nothing anywhere records why.
//
// The fix is a fence rather than a longer grace period. A collector must
// re-prove ownership under the same lock the reservation path takes, and must
// hold a visible claim on the object while it acts, so a reservation arriving
// mid-collection is refused with a retryable conflict instead of racing.
// Grace windows make the race rarer; only mutual exclusion makes it absent.

// labProtectedLocked re-derives whether a lab's objects may be collected. The
// caller holds s.mu. It deliberately mirrors gcProtectedLabs' control-plane
// sources: a deploy always claims a lab through one of them before it creates
// any host object, so this is the complete set as of this instant.
func (s *Server) labProtectedLocked(lab string, now time.Time) bool {
	if lab == "" {
		return false
	}
	if _, active := s.current[lab]; active {
		return true
	}
	if _, active := s.transactions[lab]; active {
		return true
	}
	if held := s.ops[lab]; held != nil && held.kind != "gc" {
		return true
	}
	if hold := s.holds[lab]; hold != nil && now.Before(hold.until) {
		return true
	}
	if lease := s.mutations[lab]; lease != nil && now.Before(lease.until) {
		return true
	}
	if state := s.generations[lab]; state.Prepared != "" {
		return true
	}
	for _, claim := range s.overlayClaims {
		if claim.Lab != lab {
			continue
		}
		if claim.Live || claim.Until.IsZero() || now.Before(claim.Until) {
			return true
		}
	}
	return false
}

// beginOverlayCollection fences one overlay identifier for removal.
//
// It returns false whenever anything has changed since the scan: the owner
// became protected, the identifier acquired a reservation or a live claim, or
// another collection already owns it. Marking and proving happen under one
// lock, which is what makes the reservation path's refusal below meaningful.
func (s *Server) beginOverlayCollection(vni uint32, owner string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if s.gcCollecting[vni] {
		return false
	}
	now := s.nowTime()
	if s.labProtectedLocked(owner, now) {
		return false
	}
	if claim, claimed := s.overlayClaims[vni]; claimed {
		// Any claim at all stops the collection. An expired reservation is
		// dropped by expireCoordinationLocked on the next mutation; acting on
		// one here would mean deciding a deploy's fate from a stale read.
		if claim.Live || claim.Until.IsZero() || now.Before(claim.Until) {
			return false
		}
		return false
	}
	s.gcCollecting[vni] = true
	return true
}

// endOverlayCollection drops the fence and releases the collected object's
// ownership record under the same lock hold.
//
// The order matters. Releasing after the fence is dropped opens a window in
// which a deployment blocked on s.mu is admitted, legitimately reserves the
// identifier, and then has that fresh reservation deleted by the collector
// that no longer owns the object. The owner check is a second guard: a claim
// naming a different lab is never this collection's to remove.
func (s *Server) endOverlayCollection(vni uint32, owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.gcCollecting, vni)
	claim, claimed := s.overlayClaims[vni]
	if !claimed {
		return
	}
	if owner != "" && claim.Lab != owner {
		return
	}
	delete(s.overlayClaims, vni)
	if err := s.saveCoordinationLocked(); err != nil {
		slog.Warn("persist collected overlay claim", "vni", vni, "err", err)
	}
}

// collectingOverlayLocked reports whether a collection currently owns a VNI.
// The caller holds s.mu.
func (s *Server) collectingOverlayLocked(vni uint32) bool {
	return s.gcCollecting[vni]
}

// beginLabRecordCollection fences a lab's local records by taking the lab's
// ordinary operation lease, which is the same exclusion a deploy takes. It
// refuses rather than waiting: a lab that just became busy is not a lab whose
// records should be removed.
func (s *Server) beginLabRecordCollection(lab string) (uint64, bool) {
	id, _, err := s.acquireOperation(lab, "gc", nil)
	if err != nil {
		return 0, false
	}
	s.mu.Lock()
	protected := s.labProtectedLocked(lab, s.nowTime())
	s.mu.Unlock()
	if protected {
		s.releaseOperation(lab, id, nil)
		return 0, false
	}
	if !s.gcGenerationProven(lab) {
		s.releaseOperation(lab, id, nil)
		return 0, false
	}
	return id, true
}

func (s *Server) endLabRecordCollection(lab string, id uint64) {
	s.releaseOperation(lab, id, nil)
}

// gcOrphanBridgeHooks returns the discovery and removal seams for unaliased
// Twinet bridges, defaulting to netx.
func (s *Server) gcOrphanBridgeHooks(live map[string]bool) (
	func(map[string]bool) ([]netx.OrphanBridge, error),
	func(string) error,
) {
	s.gcMu.Lock()
	find := s.gcFindOrphanBridges
	remove := s.gcRemoveOrphanBridge
	s.gcMu.Unlock()
	if find == nil {
		find = netx.FindOrphanBridges
	}
	if remove == nil {
		remove = func(name string) error { return netx.RemoveOrphanBridge(name, live) }
	}
	return find, remove
}

func (s *Server) collectOrphanBridges(protected map[string]bool, now time.Time,
	summary *GCSummary,
) error {
	find, remove := s.gcOrphanBridgeHooks(protected)
	bridges, err := find(protected)
	if err != nil {
		// Fail closed: an unreadable link table means an object that looks
		// absent might be carrying a lab.
		return fmt.Errorf("list orphan bridges before garbage collection: %w", err)
	}
	for _, bridge := range bridges {
		if bridge.Owner != "" && protected[bridge.Owner] {
			continue
		}
		if bridge.Ports > 0 {
			continue
		}
		if !s.gcEligible("bridge:"+bridge.Name, now) {
			continue
		}
		if bridge.Owner != "" {
			s.mu.Lock()
			stillProtected := s.labProtectedLocked(bridge.Owner, s.nowTime())
			s.mu.Unlock()
			if stillProtected {
				continue
			}
		}
		if bridge.VNI != 0 {
			if !s.beginOverlayCollection(bridge.VNI, bridge.Owner) {
				continue
			}
		}
		removeErr := remove(bridge.Name)
		if bridge.VNI != 0 {
			s.endOverlayCollection(bridge.VNI, bridge.Owner)
		}
		if removeErr != nil {
			slog.Debug("leaving a Twinet bridge in place", "bridge", bridge.Name, "err", removeErr)
			continue
		}
		summary.RemovedBridges = append(summary.RemovedBridges, bridge.Name)
		s.recordEvent(bridge.Owner, "", "gc", "", "orphan_bridge_removed", "success", bridge.Name)
	}
	return nil
}
