package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/netx"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

const (
	defaultGCGrace    = 15 * time.Minute
	defaultGCInterval = 5 * time.Minute
)

// GCSummary reports a single conservative collection pass. It is kept small
// enough for event and metric detail; object identifiers remain in the event
// stream rather than metric labels.
type GCSummary struct {
	RemovedOverlays []uint32 `json:"removed_overlays,omitempty"`
	RemovedPairs    []string `json:"removed_pairs,omitempty"`
	RemovedRecords  int      `json:"removed_records,omitempty"`
	ExpiredClaims   int      `json:"expired_claims,omitempty"`
	Protected       int      `json:"protected_labs,omitempty"`
}

func (s *Server) gcGrace() time.Duration {
	if s.cfg.GCGrace > 0 {
		return s.cfg.GCGrace
	}
	return defaultGCGrace
}

func (s *Server) gcInterval() time.Duration {
	if s.cfg.GCInterval > 0 {
		return s.cfg.GCInterval
	}
	return defaultGCInterval
}

func (s *Server) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(s.gcInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			summary, err := s.gcOnce(ctx)
			s.metricRegistry().observeOperation("gc", time.Since(start), err)
			if err != nil {
				s.recordEvent("", "", "gc", "", "garbage_collect", "error", err.Error())
				continue
			}
			if len(summary.RemovedOverlays) > 0 || len(summary.RemovedPairs) > 0 ||
				summary.RemovedRecords > 0 || summary.ExpiredClaims > 0 {
				s.recordEvent("", "", "gc", "", "garbage_collect", "success",
					fmt.Sprintf("overlays=%d pairs=%d records=%d reservations=%d",
						len(summary.RemovedOverlays), len(summary.RemovedPairs),
						summary.RemovedRecords, summary.ExpiredClaims))
			}
		}
	}
}

// gcOnce is fail-closed: an unreadable runtime, unknown lab activity, a hold,
// a local operation, or a still-valid mutation fence keeps an object. The
// first observation only starts its grace timer; no current absence is enough
// to remove a host object.
func (s *Server) gcOnce(ctx context.Context) (GCSummary, error) {
	now := s.nowTime()
	protected, expired, err := s.gcProtectedLabs(ctx, now)
	if err != nil {
		return GCSummary{}, err
	}
	summary := GCSummary{ExpiredClaims: expired, Protected: len(protected)}
	summary.ExpiredClaims += s.gcReleaseStaleLiveClaims(protected, now)

	findOrphans, removeOverlay, deleteHost, listMultiplex, removeEmpty := s.gcHooks()
	orphans, err := findOrphans(protected)
	if err != nil {
		return summary, err
	}
	for _, orphan := range orphans {
		if orphan.Owner != "" && protected[orphan.Owner] {
			continue
		}
		key := fmt.Sprintf("legacy:%d", orphan.VNI)
		if !s.gcEligible(key, now) {
			continue
		}
		if orphan.Ports > 0 {
			// A stale cross-node host port has a deterministic twp<VNI> name.
			// Remove only that Twinet-owned name, then re-observe before
			// deleting a bridge. An arbitrary port keeps the bridge protected.
			if err := deleteHost(gcHostSideName(orphan.VNI)); err != nil {
				continue
			}
			fresh, freshErr := findOrphans(protected)
			if freshErr != nil || orphanHasPorts(fresh, orphan.VNI) {
				continue
			}
		}
		if err := removeOverlay(orphan.VNI); err != nil {
			continue
		}
		s.releaseGCOverlayClaim(orphan.VNI)
		summary.RemovedOverlays = append(summary.RemovedOverlays, orphan.VNI)
		s.recordEvent(orphan.Owner, "", "gc", "", "overlay_removed", "success",
			fmt.Sprintf("legacy VNI %d", orphan.VNI))
	}

	// Multiplex pairs can retain VNI FDB bindings without a legacy twvx
	// device. Each binding is collected under its own grace key, then the
	// pair is removed only when no binding and no host-side port remains.
	multiplex, err := listMultiplex("")
	if err != nil {
		return summary, err
	}
	for _, overlay := range multiplex {
		if protected[overlay.Lab] {
			continue
		}
		for _, vni := range overlay.VNIs {
			key := fmt.Sprintf("multiplex:%s:%d", overlay.Vxlan, vni)
			if !s.gcEligible(key, now) {
				continue
			}
			_ = deleteHost(gcHostSideName(vni))
			if err := removeOverlay(vni); err != nil {
				continue
			}
			s.releaseGCOverlayClaim(vni)
			summary.RemovedOverlays = append(summary.RemovedOverlays, vni)
			s.recordEvent(overlay.Lab, "", "gc", "", "overlay_removed", "success",
				fmt.Sprintf("multiplex VNI %d", vni))
		}
		if len(overlay.VNIs) == 0 && s.gcEligible("multiplex-pair:"+overlay.Vxlan, now) {
			removed, removeErr := removeEmpty(overlay.Lab)
			if removeErr == nil {
				summary.RemovedPairs = append(summary.RemovedPairs, removed...)
			}
		}
	}

	if s.store != nil {
		labs, listErr := s.store.KnownLabs()
		if listErr != nil {
			return summary, listErr
		}
		for _, lab := range labs {
			if protected[lab] || !s.gcGenerationProven(lab) {
				continue
			}
			if !s.gcEligible("records:"+lab, now) {
				continue
			}
			removed, removeErr := s.store.GarbageCollectLabRecords(lab, now.Add(-s.gcGrace()), true)
			if removeErr != nil {
				continue
			}
			if removed > 0 {
				summary.RemovedRecords += removed
				s.recordEvent(lab, "", "gc", "", "lab_records_removed", "success",
					fmt.Sprintf("records=%d", removed))
			}
		}
	}
	sort.Slice(summary.RemovedOverlays, func(i, j int) bool {
		return summary.RemovedOverlays[i] < summary.RemovedOverlays[j]
	})
	sort.Strings(summary.RemovedPairs)
	return summary, nil
}

func (s *Server) gcHooks() (
	func(map[string]bool) ([]netx.Orphan, error),
	func(uint32) error,
	func(string) error,
	func(string) ([]netx.MultiplexOverlay, error),
	func(string) ([]string, error),
) {
	s.gcMu.Lock()
	defer s.gcMu.Unlock()
	find := s.gcFindOrphans
	if find == nil {
		find = netx.FindOrphans
	}
	remove := s.gcRemoveOverlay
	if remove == nil {
		remove = netx.RemoveOverlay
	}
	deleteHost := s.gcDeleteHostLink
	if deleteHost == nil {
		deleteHost = netx.DeleteHostLink
	}
	list := s.gcListMultiplex
	if list == nil {
		list = netx.ListMultiplexOverlaysOfLab
	}
	removeEmpty := s.gcRemoveEmptyMultiplex
	if removeEmpty == nil {
		removeEmpty = netx.RemoveEmptyMultiplexOverlays
	}
	return find, remove, deleteHost, list, removeEmpty
}

func orphanHasPorts(orphans []netx.Orphan, vni uint32) bool {
	for _, orphan := range orphans {
		if orphan.VNI == vni {
			return orphan.Ports > 0
		}
	}
	return false
}

// gcHostSideName mirrors deploy's deterministic host-side cross-node veth
// naming without giving netx or agent a dependency on deployment internals.
func gcHostSideName(vni uint32) string { return fmt.Sprintf("twp%d", vni) }

func (s *Server) gcEligible(key string, now time.Time) bool {
	s.gcMu.Lock()
	defer s.gcMu.Unlock()
	if s.gcSeen == nil {
		s.gcSeen = map[string]time.Time{}
	}
	first, found := s.gcSeen[key]
	if !found {
		s.gcSeen[key] = now
		return false
	}
	return !now.Before(first.Add(s.gcGrace()))
}

func (s *Server) gcProtectedLabs(ctx context.Context, now time.Time) (map[string]bool, int, error) {
	// Listing managed containers is a generation proof boundary. If it cannot
	// be read, a live lab might look absent; automatic collection must stop.
	if s.rt == nil {
		return nil, 0, errors.New("cannot garbage-collect without a runtime")
	}
	containers, err := s.rt.List(ctx, rt.Filter{
		All: true, Labels: map[string]string{deploy.LabelManaged: "true"},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list managed containers before garbage collection: %w", err)
	}
	protected := map[string]bool{}
	for _, container := range containers {
		if lab := container.Label(deploy.LabelLab); lab != "" {
			protected[lab] = true
		}
	}
	s.mu.Lock()
	s.initCoordination()
	before := len(s.overlayClaims)
	changed := s.expireCoordinationLocked(now)
	after := len(s.overlayClaims)
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			s.mu.Unlock()
			return nil, 0, fmt.Errorf("persist expired overlay reservations: %w", err)
		}
	}
	for lab := range s.current {
		protected[lab] = true
	}
	for lab := range s.ops {
		protected[lab] = true
	}
	for lab, hold := range s.holds {
		if hold != nil && now.Before(hold.until) {
			protected[lab] = true
		}
	}
	for lab, lease := range s.mutations {
		if lease != nil && now.Before(lease.until) {
			protected[lab] = true
		}
	}
	for _, claim := range s.overlayClaims {
		if !claim.Live && !claim.Until.IsZero() && now.Before(claim.Until) {
			protected[claim.Lab] = true
		}
	}
	s.mu.Unlock()
	return protected, before - after, nil
}

func (s *Server) gcReleaseStaleLiveClaims(protected map[string]bool, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed, removed := false, 0
	for vni, claim := range s.overlayClaims {
		if !claim.Live || protected[claim.Lab] || !s.gcEligible("claim:"+fmt.Sprint(vni), now) {
			continue
		}
		delete(s.overlayClaims, vni)
		changed, removed = true, removed+1
	}
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			slog.Warn("persist stale overlay claim cleanup", "err", err)
		}
	}
	return removed
}

func (s *Server) releaseGCOverlayClaim(vni uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.overlayClaims[vni]; !exists {
		return
	}
	delete(s.overlayClaims, vni)
	if err := s.saveCoordinationLocked(); err != nil {
		slog.Warn("persist collected overlay claim", "vni", vni, "err", err)
	}
}

// gcGenerationProven requires there to be no active or prepared generation
// for the lab. It is intentionally separate from a name/age check: a stale
// record may be old but still be the only evidence an interrupted controller
// needs to finish safely.
func (s *Server) gcGenerationProven(lab string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, active := s.current[lab]; active {
		return false
	}
	if _, active := s.ops[lab]; active {
		return false
	}
	if _, active := s.transactions[lab]; active {
		return false
	}
	if state := s.generations[lab]; state.Prepared != "" {
		return false
	}
	return true
}
