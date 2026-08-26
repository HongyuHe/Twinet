package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/netx"
)

// A grading harness is a lab that only a running controller wants.
//
// The failure this exists for: `twinet grade batch` deploys a private harness
// per submission, marks it, and destroys it in a deferred function. Kill the
// controller -- Ctrl-C, an OOM, a lost SSH session -- and that deferred
// function never runs. What is left behind is indistinguishable from a
// teaching lab: its containers are running, so garbage collection protects it
// by design; its topology record is on disk, so every agent restart rehydrates
// it; reconciliation repairs it forever; and its own reconcile operation lease
// answers a later `twinet destroy` with 409. One abandoned 2664-container
// harness exhausted a cluster, after which every unrelated lab failed strict
// admission for a reason that had nothing to do with it.
//
// The contract here is deliberately the smallest one that makes "forever"
// impossible: a lab may be marked ephemeral, an ephemeral lab has a durable
// deadline, only a live controller heartbeat moves that deadline, no heartbeat
// can move it past an absolute ceiling, and once it passes the node reclaims
// the lab on its own authority. Nothing about a durable teaching lab changes:
// a lab with no ephemeral lease is never touched by any of this.
const (
	// defaultEphemeralTTLSeconds is the lifetime granted when a caller asks
	// for none. It is long enough that a heartbeat may be missed several
	// times over a busy cluster and short enough that an abandoned harness is
	// reclaimed inside one lab session.
	defaultEphemeralTTLSeconds = 900
	// maxEphemeralTTLSeconds caps a single grant or renewal.
	maxEphemeralTTLSeconds = 3600
	// maxEphemeralLifetime is the absolute ceiling from first deployment. A
	// heartbeat loop that is itself stuck -- or a caller that keeps renewing a
	// harness it has forgotten about -- cannot push a disposable lab past it.
	maxEphemeralLifetime = 8 * time.Hour
	// ephemeralSweepEvery is how often expiry is evaluated.
	ephemeralSweepEvery = 30 * time.Second
	// ephemeralRestartGrace is how long a rehydrated ephemeral lab whose
	// durable deadline was lost is given before it is reclaimed. It exists so
	// an agent restart cannot delete a harness a live controller is mid-way
	// through marking, and it is bounded rather than absent.
	ephemeralRestartGrace = 15 * time.Minute
)

// ephemeralLease is the durable side of the contract. It is node-local: each
// node reclaims what it is holding without needing to agree with any other
// node, because a half-reclaimed harness is still a reclaimed harness and no
// student state is involved.
type ephemeralLease struct {
	Lab   string `json:"lab"`
	Owner string `json:"owner,omitempty"`
	// TTLSeconds is the clamped lifetime each heartbeat grants.
	TTLSeconds int `json:"ttl_seconds"`
	// Generation is the deployment that created or last refreshed the lease.
	// It is audit provenance; expiry never depends on it.
	Generation string    `json:"generation,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// HardExpiresAt is the ceiling no renewal may pass.
	HardExpiresAt time.Time `json:"hard_expires_at"`
	// Restored marks a lease this node synthesised after finding an ephemeral
	// topology with no durable deadline beside it.
	Restored bool `json:"restored,omitempty"`
}

func (l ephemeralLease) deadline() time.Time {
	if !l.HardExpiresAt.IsZero() && l.HardExpiresAt.Before(l.ExpiresAt) {
		return l.HardExpiresAt
	}
	return l.ExpiresAt
}

func (l ephemeralLease) expired(now time.Time) bool {
	deadline := l.deadline()
	return !deadline.IsZero() && !now.Before(deadline)
}

// EphemeralRequest renews or releases a disposable lab's lifetime. It is a
// liveness signal, not a mutation of the lab: it deliberately does not carry a
// mutation fence, because a controller that grades for an hour holds no
// cluster lease between its individual operations, and requiring one would
// mean the heartbeat could only be sent while the lab was already locked.
type EphemeralRequest struct {
	Lab   string `json:"lab"`
	Owner string `json:"owner,omitempty"`
	// TTLSeconds is the requested lifetime; the node clamps it.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Release ends the lease immediately, which is what an orderly teardown
	// does before it destroys the lab.
	Release bool `json:"release,omitempty"`
}

// EphemeralResponse reports the lifetime this node is actually holding.
type EphemeralResponse struct {
	Lab           string    `json:"lab"`
	Ephemeral     bool      `json:"ephemeral"`
	Owner         string    `json:"owner,omitempty"`
	TTLSeconds    int       `json:"ttl_seconds,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	HardExpiresAt time.Time `json:"hard_expires_at,omitempty"`
}

// EphemeralStatus is the observable form used by node status and tests.
type EphemeralStatus struct {
	Lab           string    `json:"lab"`
	Owner         string    `json:"owner,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	HardExpiresAt time.Time `json:"hard_expires_at"`
	Restored      bool      `json:"restored,omitempty"`
}

func clampEphemeralTTL(seconds int) time.Duration {
	if seconds <= 0 {
		seconds = defaultEphemeralTTLSeconds
	}
	if seconds > maxEphemeralTTLSeconds {
		seconds = maxEphemeralTTLSeconds
	}
	return time.Duration(seconds) * time.Second
}

// noteEphemeralLease records or refreshes a disposable lab's lifetime at
// commit. The caller must not hold s.mu.
func (s *Server) noteEphemeralLease(lab, owner string, ttlSeconds int, generation string) error {
	if lab == "" {
		return errors.New("an ephemeral lease must name its lab")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	ttl := clampEphemeralTTL(ttlSeconds)
	previous, had := s.ephemeral[lab]
	lease := ephemeralLease{
		Lab: lab, Owner: owner, TTLSeconds: int(ttl.Seconds()), Generation: generation,
		CreatedAt: now, ExpiresAt: now.Add(ttl), HardExpiresAt: now.Add(maxEphemeralLifetime),
	}
	if had && !previous.CreatedAt.IsZero() && !previous.HardExpiresAt.IsZero() {
		// A redeploy of the same disposable name renews the lifetime but must
		// not reset the ceiling: a warm harness reused for submission after
		// submission would otherwise be immortal by construction.
		lease.CreatedAt = previous.CreatedAt
		lease.HardExpiresAt = previous.HardExpiresAt
	}
	s.ephemeral[lab] = lease
	if err := s.saveCoordinationLocked(); err != nil {
		if had {
			s.ephemeral[lab] = previous
		} else {
			delete(s.ephemeral, lab)
		}
		return fmt.Errorf("persisting ephemeral lab lease: %w", err)
	}
	return nil
}

// clearEphemeralLeaseLocked drops a lease as part of a destroy. The caller
// holds s.mu and is responsible for persisting.
func (s *Server) clearEphemeralLeaseLocked(lab string) (ephemeralLease, bool) {
	previous, had := s.ephemeral[lab]
	delete(s.ephemeral, lab)
	return previous, had
}

func (s *Server) renewEphemeralLease(req EphemeralRequest) (EphemeralResponse, error) {
	if req.Lab == "" {
		return EphemeralResponse{}, errors.New("a lab name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	lease, ok := s.ephemeral[req.Lab]
	if !ok {
		// Fail closed rather than creating a lease from a heartbeat. A lease
		// is created only by a deployment that said the lab was disposable;
		// letting a heartbeat mint one would let a caller mark somebody's
		// teaching lab collectable.
		return EphemeralResponse{Lab: req.Lab}, fmt.Errorf(
			"lab %q is not an ephemeral lab on this node", req.Lab)
	}
	if lease.Owner != "" && req.Owner != "" && lease.Owner != req.Owner {
		return EphemeralResponse{Lab: req.Lab}, fmt.Errorf(
			"lab %q is held by %q, not %q", req.Lab, lease.Owner, req.Owner)
	}
	before := lease
	if req.Release {
		delete(s.ephemeral, req.Lab)
		if err := s.saveCoordinationLocked(); err != nil {
			s.ephemeral[req.Lab] = before
			return EphemeralResponse{}, fmt.Errorf("persisting released ephemeral lease: %w", err)
		}
		return EphemeralResponse{Lab: req.Lab, Ephemeral: false}, nil
	}
	now := s.nowTime()
	if lease.expired(now) {
		// An expired lease is reclamation work already owed. Renewing it would
		// let a controller that returned after its harness was scheduled for
		// removal keep it alive indefinitely.
		return EphemeralResponse{Lab: req.Lab, Ephemeral: true, Owner: lease.Owner,
				ExpiresAt: lease.ExpiresAt, HardExpiresAt: lease.HardExpiresAt},
			fmt.Errorf("the ephemeral lease for lab %q expired at %s and is being reclaimed",
				req.Lab, lease.deadline().UTC().Format(time.RFC3339))
	}
	ttl := clampEphemeralTTL(req.TTLSeconds)
	if req.TTLSeconds <= 0 && lease.TTLSeconds > 0 {
		ttl = clampEphemeralTTL(lease.TTLSeconds)
	}
	lease.TTLSeconds = int(ttl.Seconds())
	lease.ExpiresAt = now.Add(ttl)
	if !lease.HardExpiresAt.IsZero() && lease.ExpiresAt.After(lease.HardExpiresAt) {
		lease.ExpiresAt = lease.HardExpiresAt
	}
	lease.Restored = false
	s.ephemeral[req.Lab] = lease
	if err := s.saveCoordinationLocked(); err != nil {
		s.ephemeral[req.Lab] = before
		return EphemeralResponse{}, fmt.Errorf("persisting renewed ephemeral lease: %w", err)
	}
	return EphemeralResponse{
		Lab: req.Lab, Ephemeral: true, Owner: lease.Owner, TTLSeconds: lease.TTLSeconds,
		ExpiresAt: lease.ExpiresAt, HardExpiresAt: lease.HardExpiresAt,
	}, nil
}

func (s *Server) handleEphemeral(w http.ResponseWriter, r *http.Request) {
	var req EphemeralRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.renewEphemeralLease(req)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, resp)
}

// ephemeralStatuses reports every disposable lab this node is holding.
func (s *Server) ephemeralStatuses() []EphemeralStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	out := make([]EphemeralStatus, 0, len(s.ephemeral))
	for lab, lease := range s.ephemeral {
		out = append(out, EphemeralStatus{
			Lab: lab, Owner: lease.Owner, ExpiresAt: lease.ExpiresAt,
			HardExpiresAt: lease.HardExpiresAt, Restored: lease.Restored,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lab < out[j].Lab })
	return out
}

// ephemeralExpired reports whether ordinary maintenance should leave a lab
// alone because it is owed reclamation. Repairing a lab that is about to be
// removed wastes the very capacity the removal is trying to return.
func (s *Server) ephemeralExpired(lab string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	lease, ok := s.ephemeral[lab]
	return ok && lease.expired(s.nowTime())
}

// restoreEphemeralLeaseLocked gives a rehydrated ephemeral topology a bounded
// deadline. The caller holds s.mu.
//
// The ambiguous case is an agent that crashed between writing topology.json
// and updating its coordination journal. The topology says the lab is
// disposable but no deadline survived. Deleting it immediately would be a
// destructive guess; leaving it unbounded would reintroduce exactly the bug
// this file exists for. A fresh bounded grace is the only answer that is
// neither.
func (s *Server) restoreEphemeralLeaseLocked(lab string, ttlSeconds int, generation string) bool {
	if _, ok := s.ephemeral[lab]; ok {
		return false
	}
	now := s.nowTime()
	ttl := clampEphemeralTTL(ttlSeconds)
	if ttl < ephemeralRestartGrace {
		ttl = ephemeralRestartGrace
	}
	s.ephemeral[lab] = ephemeralLease{
		Lab: lab, TTLSeconds: int(ttl.Seconds()), Generation: generation,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
		HardExpiresAt: now.Add(maxEphemeralLifetime), Restored: true,
	}
	slog.Warn("AUDIT: rehydrated an ephemeral lab with no durable deadline; "+
		"granting a bounded restart grace instead of holding it forever",
		"lab", lab, "grace", ttl)
	return true
}

// EphemeralReapSummary reports one reclamation pass.
type EphemeralReapSummary struct {
	Reclaimed []string `json:"reclaimed,omitempty"`
	Deferred  []string `json:"deferred,omitempty"`
	Problems  []string `json:"problems,omitempty"`
}

func (s *Server) ephemeralLoop(ctx context.Context) {
	ticker := time.NewTicker(ephemeralSweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			summary := s.reapExpiredEphemeralLabs(ctx)
			if len(summary.Reclaimed) > 0 || len(summary.Problems) > 0 {
				s.metricRegistry().observeOperation("ephemeral_reap", time.Since(start), nil)
			}
		}
	}
}

// expiredEphemeralLabs lists labs whose bounded lifetime has passed, in a
// stable order so a sweep is deterministic.
func (s *Server) expiredEphemeralLabs(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	var out []string
	for lab, lease := range s.ephemeral {
		if lease.expired(now) {
			out = append(out, lab)
		}
	}
	sort.Strings(out)
	return out
}

// reapExpiredEphemeralLabs removes every disposable lab whose lifetime has
// passed. It is exported to the loop and to tests as one deterministic pass so
// expiry can be proved on an injected clock rather than by waiting.
//
// Labs are reclaimed one at a time and nothing node-wide is held while a
// reclamation runs: an unrelated lab remains deployable throughout, which
// matters because the whole point is to return a cluster to service.
func (s *Server) reapExpiredEphemeralLabs(ctx context.Context) EphemeralReapSummary {
	var summary EphemeralReapSummary
	for _, lab := range s.expiredEphemeralLabs(s.nowTime()) {
		if ctx.Err() != nil {
			return summary
		}
		switch err := s.reclaimEphemeralLab(ctx, lab); {
		case err == nil:
			summary.Reclaimed = append(summary.Reclaimed, lab)
		case errors.Is(err, errEphemeralReapDeferred):
			summary.Deferred = append(summary.Deferred, lab)
		default:
			summary.Problems = append(summary.Problems, lab+": "+err.Error())
		}
	}
	return summary
}

// errEphemeralReapDeferred means the node could not safely act this pass and
// will try again. It is not a failure: deferring is how this stays fail-closed
// while remaining bounded, because every reason to defer is itself bounded.
var errEphemeralReapDeferred = errors.New("ephemeral reclamation deferred")

func (s *Server) reclaimEphemeralLab(ctx context.Context, lab string) error {
	// A live controller lease means somebody is mid-operation on this lab.
	// Mutation leases are capped at ten minutes and require active renewal, so
	// waiting for one is bounded; destroying underneath one is not safe.
	if holder := s.mutationLeaseHolder(lab); holder != "" {
		slog.Info("deferring ephemeral reclamation while a controller holds the lab",
			"lab", lab, "holder", holder)
		return errEphemeralReapDeferred
	}
	if holder := s.heldBy(lab); holder != "" {
		slog.Info("deferring ephemeral reclamation while a grading hold is live",
			"lab", lab, "holder", holder)
		return errEphemeralReapDeferred
	}

	// The node acts on its own authority here, but through the ordinary fenced
	// path rather than around it: the fence excludes a controller that arrives
	// mid-reclamation, and every existing destroy invariant keeps applying.
	fence, err := s.acquireRecoveryFence(lab)
	if err != nil {
		return errEphemeralReapDeferred
	}
	defer func() {
		if err := s.releaseMutationLease(LeaseReleaseRequest{Lab: lab, Fence: fence}); err != nil {
			slog.Debug("releasing ephemeral reclamation lease", "lab", lab, "err", err)
		}
	}()

	reapCtx, cancel := context.WithTimeout(ctx, s.ephemeralReapLimit(lab))
	defer cancel()
	stopRenew := s.keepEphemeralFence(reapCtx, lab, fence)
	defer stopRenew()

	s.recordEvent(lab, "", "ephemeral", "", "lease_expired", "scheduled",
		"reclaiming an abandoned ephemeral lab")

	// Reconciliation and any in-flight apply are cancellable and must yield:
	// the reconcile lease is precisely what answered an operator's destroy
	// with 409 while the harness sat there. A recovery that has already blown
	// its own deadline yields too; one that has not is left alone.
	opID, opDone, err := s.acquireForcedOperation(reapCtx, lab, "ephemeral_reap", true)
	if err != nil {
		slog.Info("deferring ephemeral reclamation until the current operation yields",
			"lab", lab, "err", err)
		return errEphemeralReapDeferred
	}
	defer s.releaseOperation(lab, opID, opDone)

	// Ephemeral means the state is worthless by construction, so no capture
	// runs. That is the same contract `destroy --ephemeral` already has, and
	// it is the reason this is safe to do without a person present.
	//
	// Host objects come down first and the records only afterwards. A
	// reclamation that failed halfway must keep every record it has -- above
	// all its own lease -- or the lab silently becomes durable again and the
	// containers it could not remove are back to living forever.
	problems := s.destroyEphemeralObjects(reapCtx, lab)
	if len(problems) == 0 {
		if s.store != nil {
			if err := s.store.Forget(lab); err != nil {
				problems = append(problems, "discard ephemeral lab state: "+err.Error())
			}
		}
		// Reservations, generations and the durable transaction journal go
		// with it. A leftover claim keeps a VNI allocated, which is the other
		// half of how an abandoned harness starves a cluster.
		if err := s.finishDestroyedLab(lab, fence); err != nil {
			problems = append(problems, "commit empty destroyed state: "+err.Error())
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		s.recordEvent(lab, "", "ephemeral", "", "lease_reclaim", "error", joinProblems(problems))
		return fmt.Errorf("reclaiming ephemeral lab %q: %s", lab, joinProblems(problems))
	}
	s.dropEphemeralLease(lab)
	s.recordEvent(lab, "", "ephemeral", "", "lease_reclaim", "success",
		"an abandoned ephemeral lab and its reservations were reclaimed")
	slog.Warn("reclaimed an abandoned ephemeral lab whose controller stopped renewing it",
		"lab", lab, "node", s.cfg.Node)
	return nil
}

// destroyEphemeralObjects removes the lab's containers and the overlays it
// owns. It is a seam so the reclamation decision can be proved without a host
// runtime or a netlink namespace.
func (s *Server) destroyEphemeralObjects(ctx context.Context, lab string) []string {
	if s.ephemeralDestroy != nil {
		if err := s.ephemeralDestroy(ctx, lab); err != nil {
			return []string{err.Error()}
		}
		return nil
	}
	var problems []string
	eng := &deploy.Engine{Runtime: s.rt, Node: s.cfg.Node, State: s.store, Limiter: s.workLimiter()}
	if err := eng.Destroy(ctx, lab); err != nil {
		problems = append(problems, "containers: "+err.Error())
	}
	// Overlays are removed by ownership rather than by the identifiers a
	// manifest derives, for the same reason destroy does it that way: a lab
	// that moved its identifiers to avoid a collision would otherwise leak the
	// tunnels it has and delete the ones belonging to whatever it collided
	// with.
	owned, err := netx.ListOverlaysOfLab(lab)
	if err != nil {
		problems = append(problems, "list overlays: "+err.Error())
		return problems
	}
	if len(owned) > 0 {
		if err := eng.DestroyOverlays(owned); err != nil {
			problems = append(problems, fmt.Sprintf("%d overlay(s) left behind: %v", len(owned), err))
		}
	}
	return problems
}

func joinProblems(problems []string) string {
	out := ""
	for i, problem := range problems {
		if i > 0 {
			out += "; "
		}
		out += problem
	}
	return out
}

// dropEphemeralLease removes the lease record after the lab is gone. It is
// separate from finishDestroyedLab so a partially failed reclamation keeps its
// lease and is retried, rather than silently becoming a durable lab again.
func (s *Server) dropEphemeralLease(lab string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if _, had := s.clearEphemeralLeaseLocked(lab); !had {
		return
	}
	if err := s.saveCoordinationLocked(); err != nil {
		slog.Warn("persisting reclaimed ephemeral lease", "lab", lab, "err", err)
	}
}

// forgetEphemeralLease drops a lease and reports a persistence failure. A lab
// redeployed without the ephemeral marker is durable from that generation on.
func (s *Server) forgetEphemeralLease(lab string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	previous, had := s.clearEphemeralLeaseLocked(lab)
	if !had {
		return nil
	}
	if err := s.saveCoordinationLocked(); err != nil {
		s.ephemeral[lab] = previous
		return fmt.Errorf("persisting durable lab lifetime: %w", err)
	}
	slog.Info("a lab that was ephemeral was redeployed as durable", "lab", lab)
	return nil
}

// ephemeralReapLimit bounds one reclamation by the work it has to do. A
// 2664-container harness cannot be removed in the time a small one takes, and
// an unbounded destroy would hold the lab's operation lease indefinitely.
func (s *Server) ephemeralReapLimit(lab string) time.Duration {
	s.mu.Lock()
	devices := 0
	if top := s.current[lab]; top != nil {
		devices = len(top.DevicesOnNode(s.cfg.Node))
	}
	s.mu.Unlock()
	limit := 5*time.Minute + time.Duration(devices)*time.Second
	if limit > MaximumRecoveryTotalTimeout {
		limit = MaximumRecoveryTotalTimeout
	}
	return limit
}

func (s *Server) keepEphemeralFence(ctx context.Context, lab string, fence Fence) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(recoveryLeaseRenewEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
			}
			seconds := int(s.recoveryLeaseLimit().Round(time.Second).Seconds())
			if _, err := s.renewMutationLease(LeaseRenewRequest{
				Lab: lab, Fence: fence, TTLSeconds: seconds,
			}); err != nil {
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}
