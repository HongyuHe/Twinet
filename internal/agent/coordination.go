package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/render"
)

// Fence identifies one issued mutation lease. Token is deliberately opaque:
// generation orders leases, while the unguessable token proves that a caller
// owns that particular generation.
type Fence struct {
	Token      string `json:"token,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}

// LeaseAcquireRequest asks one node to issue a mutation fence for a lab.
type LeaseAcquireRequest struct {
	Lab        string `json:"lab"`
	Holder     string `json:"holder,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// LeaseRenewRequest extends an existing mutation lease.
type LeaseRenewRequest struct {
	Lab        string `json:"lab"`
	Fence      Fence  `json:"fence"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// LeaseReleaseRequest drops an existing mutation lease.
type LeaseReleaseRequest struct {
	Lab   string `json:"lab"`
	Fence Fence  `json:"fence"`
}

// LeaseResponse describes an issued or renewed lease.
type LeaseResponse struct {
	Lab       string    `json:"lab"`
	Fence     Fence     `json:"fence"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OverlayReservationRequest atomically claims the supplied VNIs on one node.
// The claim is tied to the mutation fence, so an expired controller cannot
// create an overlay after a newer controller has taken over the lab.
type OverlayReservationRequest struct {
	Lab   string   `json:"lab"`
	Hold  string   `json:"hold,omitempty"`
	Fence Fence    `json:"fence"`
	VNIs  []uint32 `json:"vnis"`
}

// OverlayReservationResponse reports the claimed VNIs.
type OverlayReservationResponse struct {
	Lab       string    `json:"lab"`
	VNIs      []uint32  `json:"vnis"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	defaultMutationLeaseSeconds = 90
	maxMutationLeaseSeconds     = 600
)

// clusterLease is intentionally in-memory. A process restart invalidates every
// token; persisted high-water marks ensure that the next token has a newer
// generation and stale callers cannot become valid again.
type clusterLease struct {
	holder string
	fence  Fence
	until  time.Time
}

// overlayClaim is either a short-lived reservation or the durable record of a
// live overlay. Live claims are released only after normal overlay destruction.
type overlayClaim struct {
	Lab        string    `json:"lab"`
	Generation uint64    `json:"generation"`
	Until      time.Time `json:"until,omitempty"`
	Live       bool      `json:"live"`
}

type overlayClaimBefore struct {
	claim overlayClaim
	have  bool
}

type legacyOverlayAdoption struct {
	vni    uint32
	revert func() error
}

type generationState struct {
	Committed string   `json:"committed,omitempty"`
	Prepared  string   `json:"prepared,omitempty"`
	Ancestors []string `json:"ancestors,omitempty"`
}

// transactionPhase is persisted before any destructive work. A transaction
// never disappears merely because a controller lost its request: recovery can
// resume from this durable phase record after an agent restart.
type transactionPhase string

const (
	transactionPrepared       transactionPhase = "prepared"
	transactionApplying       transactionPhase = "applying"
	transactionApplied        transactionPhase = "applied"
	transactionRollbackNeeded transactionPhase = "rollback_needed"
	transactionRecovering     transactionPhase = "recovering"
	transactionRollbackFailed transactionPhase = "rollback_failed"
	transactionCommitted      transactionPhase = "committed"
)

// transactionContainer is the observed service inventory of one managed
// workload before a transaction may replace it.
type transactionContainer struct {
	Name       string `json:"name"`
	DeviceID   string `json:"device_id,omitempty"`
	Spec       string `json:"spec,omitempty"`
	Generation string `json:"generation,omitempty"`
	State      string `json:"state"`
}

// transactionSnapshot is the immutable state evidence captured before a
// destructive transaction. Recovery must find the exact digest again; merely
// finding any newer-looking snapshot is stale-state substitution.
type transactionSnapshot struct {
	Device string `json:"device"`
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

// transactionInventory is both rollback evidence and the post-recovery
// verifier. Overlay VNIs cover legacy and multiplex objects uniformly.
type transactionInventory struct {
	Schema          int                      `json:"schema,omitempty"`
	TopologyHash    string                   `json:"topology_hash,omitempty"`
	Generation      string                   `json:"generation,omitempty"`
	Containers      []transactionContainer   `json:"containers,omitempty"`
	VNIs            []uint32                 `json:"vnis,omitempty"`
	LogicalBindings []netx.LogicalBinding    `json:"logical_bindings,omitempty"`
	PhysicalTrunks  []netx.PhysicalTrunk     `json:"physical_trunks,omitempty"`
	CapturedAt      time.Time                `json:"captured_at"`
	StateSafe       bool                     `json:"state_safe"`
	Snapshots       []transactionSnapshot    `json:"snapshots,omitempty"`
	RuntimeSpecs    []transactionRuntimeSpec `json:"runtime_specs,omitempty"`
	OverlayState    []netx.MultiplexOverlay  `json:"overlay_state,omitempty"`
}

// RecoveryStatus is safe to expose in node status and recovery responses. It
// names a phase and inventory counts, never student configuration content.
type RecoveryStatus struct {
	Lab                string    `json:"lab"`
	Phase              string    `json:"phase"`
	Generation         string    `json:"generation,omitempty"`
	PreviousGeneration string    `json:"previous_generation,omitempty"`
	Mode               string    `json:"mode,omitempty"`
	Ungraded           int       `json:"ungraded_as,omitempty"`
	PreviousMode       string    `json:"previous_mode,omitempty"`
	PreviousUngraded   int       `json:"previous_ungraded_as,omitempty"`
	Owner              string    `json:"owner,omitempty"`
	Strategy           string    `json:"strategy,omitempty"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	LastProgressAt     time.Time `json:"last_progress_at,omitempty"`
	Deadline           time.Time `json:"deadline,omitempty"`
	TotalDeadline      time.Time `json:"total_deadline,omitempty"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at,omitempty"`
	CurrentTarget      string    `json:"current_target,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
	RetryCount         int       `json:"retry_count,omitempty"`
	TakeoverAllowed    bool      `json:"takeover_allowed,omitempty"`
	// CommittedPending marks a generation this node committed but has not
	// finalized. Its rollback material still exists, which is what makes a
	// split cluster commit recoverable instead of permanent.
	CommittedPending        bool     `json:"committed_pending,omitempty"`
	ForwardAcknowledged     bool     `json:"forward_acknowledged,omitempty"`
	ForwardPhase            string   `json:"forward_phase,omitempty"`
	DataLossScope           []string `json:"data_loss_scope,omitempty"`
	ExpectedContainers      int      `json:"expected_containers"`
	ObservedContainers      int      `json:"observed_containers"`
	ExpectedVNIs            int      `json:"expected_vnis"`
	ObservedVNIs            int      `json:"observed_vnis"`
	ExpectedLogicalBindings int      `json:"expected_logical_bindings"`
	ObservedLogicalBindings int      `json:"observed_logical_bindings"`
	ExpectedPhysicalTrunks  int      `json:"expected_physical_trunks"`
	ObservedPhysicalTrunks  int      `json:"observed_physical_trunks"`
	Consistent              bool     `json:"consistent"`
	Attempts                int      `json:"attempts,omitempty"`
	Error                   string   `json:"error,omitempty"`
	AllowedStrategies       []string `json:"allowed_strategies,omitempty"`
}

// applyTransaction persists enough information to fail closed after a crashed
// coordinator. It intentionally excludes the opaque token: after restart no
// old caller can continue or finish this transaction.
type applyTransaction struct {
	Generation      string          `json:"generation"`
	Expected        string          `json:"expected,omitempty"`
	FenceGeneration uint64          `json:"fence_generation"`
	Requested       json.RawMessage `json:"requested"`
	Previous        json.RawMessage `json:"previous,omitempty"`
	PreviousGen     string          `json:"previous_generation,omitempty"`
	// PreviousMode and PreviousUngraded are persisted independently of the
	// legacy topology blob. Recovery must know whether old runtime state was
	// reference/solve, a harness submission AS, or teaching mode before it
	// decides whether a student snapshot may be replayed.
	PreviousMode         string               `json:"previous_mode"`
	PreviousUngraded     int                  `json:"previous_ungraded_as,omitempty"`
	Mode                 string               `json:"mode"`
	Ungraded             int                  `json:"ungraded_as,omitempty"`
	PeerUnderlay         map[string]string    `json:"peer_underlay,omitempty"`
	Prune                bool                 `json:"prune,omitempty"`
	OnlySteps            []string             `json:"only_steps,omitempty"`
	StateProofs          []StateProof         `json:"state_proofs,omitempty"`
	DirtyCapture         []string             `json:"dirty_capture,omitempty"`
	DirtyCaptureKnown    bool                 `json:"dirty_capture_known,omitempty"`
	Semantic             []string             `json:"semantic_devices,omitempty"`
	SemanticKnown        bool                 `json:"semantic_known,omitempty"`
	Touched              []string             `json:"touched_objects,omitempty"`
	TouchedVNIs          []uint32             `json:"touched_vnis,omitempty"`
	TouchedKnown         bool                 `json:"touched_known,omitempty"`
	StateVerified        bool                 `json:"state_verified,omitempty"`
	Phase                transactionPhase     `json:"phase,omitempty"`
	Prestate             transactionInventory `json:"prestate,omitempty"`
	Failure              string               `json:"failure,omitempty"`
	RecoveryAttempts     int                  `json:"recovery_attempts,omitempty"`
	LastRecovery         time.Time            `json:"last_recovery,omitempty"`
	NextRecovery         time.Time            `json:"next_recovery,omitempty"`
	RecoveryOwner        string               `json:"recovery_owner,omitempty"`
	RecoveryStrategy     string               `json:"recovery_strategy,omitempty"`
	RecoveryStarted      time.Time            `json:"recovery_started,omitempty"`
	RecoveryProgress     time.Time            `json:"recovery_progress,omitempty"`
	RecoveryDeadline     time.Time            `json:"recovery_deadline,omitempty"`
	RecoveryTotal        time.Time            `json:"recovery_total_deadline,omitempty"`
	RecoveryTarget       string               `json:"recovery_target,omitempty"`
	ForwardAcknowledged  bool                 `json:"forward_acknowledged,omitempty"`
	ForwardPhase         string               `json:"forward_phase,omitempty"`
	ForwardDataLossScope []string             `json:"forward_data_loss_scope,omitempty"`
	Applied              bool                 `json:"applied"`
	Committed            bool                 `json:"committed"`
}

type coordinationState struct {
	FenceHighWater map[string]uint64               `json:"fence_high_water,omitempty"`
	Overlays       map[uint32]overlayClaim         `json:"overlays,omitempty"`
	Generations    map[string]generationState      `json:"generations,omitempty"`
	Transactions   map[string]applyTransaction     `json:"transactions,omitempty"`
	Inventories    map[string]transactionInventory `json:"inventories,omitempty"`
	OverlayLineage map[string]map[uint32]string    `json:"overlay_lineage,omitempty"`
	// Ephemeral is absent from every record written before disposable labs
	// had a bounded lifetime. An absent map means every lab on this node is
	// durable, which is exactly the old behaviour, so no migration step is
	// required to read an older journal.
	Ephemeral map[string]ephemeralLease `json:"ephemeral,omitempty"`
}

func (s *Server) initCoordination() {
	if s.mutations == nil {
		s.mutations = map[string]*clusterLease{}
	}
	if s.fenceHighWater == nil {
		s.fenceHighWater = map[string]uint64{}
	}
	if s.overlayClaims == nil {
		s.overlayClaims = map[uint32]overlayClaim{}
	}
	if s.generations == nil {
		s.generations = map[string]generationState{}
	}
	if s.transactions == nil {
		s.transactions = map[string]applyTransaction{}
	}
	if s.inventories == nil {
		s.inventories = map[string]transactionInventory{}
	}
	if s.overlayLineage == nil {
		s.overlayLineage = map[string]map[uint32]string{}
	}
	if s.ephemeral == nil {
		s.ephemeral = map[string]ephemeralLease{}
	}
	if s.gcCollecting == nil {
		s.gcCollecting = map[uint32]bool{}
	}
}

func (s *Server) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func leaseTTL(seconds int) time.Duration {
	if seconds <= 0 {
		seconds = defaultMutationLeaseSeconds
	}
	if seconds > maxMutationLeaseSeconds {
		seconds = maxMutationLeaseSeconds
	}
	return time.Duration(seconds) * time.Second
}

func opaqueFenceToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s *Server) loadCoordination() {
	if s.store == nil {
		return
	}
	raw, err := s.store.Coordination()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("reading coordination state", "err", err)
		}
		return
	}
	var disk coordinationState
	if err := json.Unmarshal(raw, &disk); err != nil {
		slog.Warn("reading coordination state", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	migrated := false
	for lab, generation := range disk.FenceHighWater {
		if generation > s.fenceHighWater[lab] {
			s.fenceHighWater[lab] = generation
		}
	}
	for vni, claim := range disk.Overlays {
		s.overlayClaims[vni] = claim
	}
	for lab, generation := range disk.Generations {
		s.generations[lab] = generation
	}
	for lab, transaction := range disk.Transactions {
		if transaction.Phase == "" {
			// Older prepared records were never safe to resume forward after a
			// restart. Treat them as rollback work rather than guessing.
			transaction.Phase = transactionRollbackNeeded
		}
		updated, changed, migrationErr := migrateLegacyTransactionModes(transaction)
		if migrationErr != nil {
			updated.Phase = transactionRollbackFailed
			updated.Failure = "legacy transaction mode migration refused: " + migrationErr.Error()
			slog.Error("AUDIT: refusing ambiguous legacy transaction mode",
				"lab", lab, "generation", transaction.Generation, "err", migrationErr)
			changed = true
		} else if changed {
			slog.Warn("AUDIT: migrated legacy transaction mode fields",
				"lab", lab, "generation", transaction.Generation,
				"previous_mode", updated.PreviousMode, "desired_mode", updated.Mode)
		}
		transaction = updated
		migrated = migrated || changed
		s.transactions[lab] = transaction
	}
	for lab, inventory := range disk.Inventories {
		s.inventories[lab] = inventory
	}
	for lab, lineage := range disk.OverlayLineage {
		s.overlayLineage[lab] = lineage
	}
	for lab, lease := range disk.Ephemeral {
		if lease.Lab == "" {
			lease.Lab = lab
		}
		if lease.HardExpiresAt.IsZero() {
			// A record written before the absolute ceiling existed would
			// otherwise be renewable forever. Anchor it to its creation, or to
			// now if that is missing too, so the ceiling always applies.
			anchor := lease.CreatedAt
			if anchor.IsZero() {
				anchor = s.nowTime()
			}
			lease.HardExpiresAt = anchor.Add(maxEphemeralLifetime)
			migrated = true
		}
		s.ephemeral[lab] = lease
	}
	_ = s.expireCoordinationLocked(s.nowTime())
	if migrated {
		if err := s.saveCoordinationLocked(); err != nil {
			slog.Error("persisting legacy transaction mode migration", "err", err)
		}
	}
}

// migrateLegacyTransactionModes is the only compatibility bridge for records
// written before Mode became mandatory. Desired mode may be recovered from the
// requested wire; an absent desired mode is ambiguous and fails closed rather
// than silently becoming platform. A pre-mode committed topology explicitly
// migrates its previous mode to platform.
func migrateLegacyTransactionModes(tx applyTransaction) (applyTransaction, bool, error) {
	changed := false
	if tx.Mode == "" {
		var requested Wire
		if len(tx.Requested) == 0 || json.Unmarshal(tx.Requested, &requested) != nil {
			return tx, false, errors.New("desired mode is absent from both transaction and requested topology")
		}
		if requested.Mode == "" {
			// This branch is only for records already on disk from before
			// mode was mandatory. Future prepare requests are rejected above.
			tx.Mode, tx.Ungraded, changed = string(render.ModePlatform), 0, true
		} else {
			mode, err := RequireTransactionMode(requested.Mode)
			if err != nil {
				return tx, false, fmt.Errorf("requested topology desired mode: %w", err)
			}
			tx.Mode, tx.Ungraded, changed = mode, requested.Ungraded, true
		}
	}
	if _, err := RequireTransactionMode(tx.Mode); err != nil {
		return tx, false, fmt.Errorf("desired mode: %w", err)
	}
	if tx.PreviousMode == "" {
		var previous Wire
		if len(tx.Previous) > 0 && json.Unmarshal(tx.Previous, &previous) == nil && previous.Mode != "" {
			mode, err := RequireTransactionMode(previous.Mode)
			if err != nil {
				return tx, false, fmt.Errorf("previous topology mode: %w", err)
			}
			tx.PreviousMode, tx.PreviousUngraded = mode, previous.Ungraded
		} else {
			// A transaction with no previous topology is an initial platform
			// baseline. A topology that predates the field has the same
			// explicit migration; the audit caller records it above.
			tx.PreviousMode, tx.PreviousUngraded = string(render.ModePlatform), 0
		}
		changed = true
	}
	if _, err := RequireTransactionMode(tx.PreviousMode); err != nil {
		return tx, false, fmt.Errorf("previous mode: %w", err)
	}
	return tx, changed, nil
}

// saveCoordinationLocked persists fencing high-water marks, live overlay
// ownership, and unfinished transactions. The caller holds s.mu.
func (s *Server) saveCoordinationLocked() error {
	if s.store == nil {
		return nil
	}
	disk := coordinationState{
		FenceHighWater: s.fenceHighWater,
		Overlays:       s.overlayClaims,
		Generations:    s.generations,
		Transactions:   s.transactions,
		Inventories:    s.inventories,
		OverlayLineage: s.overlayLineage,
		Ephemeral:      s.ephemeral,
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	return s.store.PutCoordination(raw)
}

// expireCoordinationLocked drops expired in-memory leases and their
// reservations. The caller holds s.mu.
func (s *Server) expireCoordinationLocked(now time.Time) bool {
	changed := false
	for lab, lease := range s.mutations {
		if !now.Before(lease.until) {
			delete(s.mutations, lab)
			changed = true
		}
	}
	for vni, claim := range s.overlayClaims {
		if !claim.Live && !claim.Until.IsZero() && !now.Before(claim.Until) {
			delete(s.overlayClaims, vni)
			changed = true
		}
	}
	return changed
}

func (s *Server) fenceErrorLocked(lab string, fence Fence, now time.Time) error {
	if lab == "" {
		return errors.New("a mutation must name its lab")
	}
	if fence.Token == "" || fence.Generation == 0 {
		return errors.New("a valid mutation fence is required")
	}
	lease := s.mutations[lab]
	if lease == nil || !now.Before(lease.until) {
		return fmt.Errorf("the mutation lease for lab %q has expired or was released; its fence is stale", lab)
	}
	if lease.fence.Generation != fence.Generation ||
		subtle.ConstantTimeCompare([]byte(lease.fence.Token), []byte(fence.Token)) != 1 {
		return fmt.Errorf("the mutation fence for lab %q is stale", lab)
	}
	return nil
}

func (s *Server) requireMutationFence(lab string, fence Fence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	changed := s.expireCoordinationLocked(s.nowTime())
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			return fmt.Errorf("persisting expired coordination state: %w", err)
		}
	}
	return s.fenceErrorLocked(lab, fence, s.nowTime())
}

// requireOverlayReservations proves that every cross-node VNI this node is
// about to attach was atomically reserved by the same fenced controller. The
// bridge/VXLAN names include the lab, but VXLAN demultiplexing uses the VNI on
// the wire: accepting an unreserved collision would still let two labs receive
// one another's frames.
func (s *Server) requireOverlayReservations(top *model.Topology, fence Fence) error {
	if top == nil {
		return errors.New("overlay reservation needs a topology")
	}
	vnis := overlayVNIsOnNode(top, s.cfg.Node)
	if len(vnis) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	changed := s.expireCoordinationLocked(now)
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			return fmt.Errorf("persist expired overlay reservations: %w", err)
		}
	}
	for _, vni := range vnis {
		claim, ok := s.overlayClaims[vni]
		if !ok || claim.Lab != top.Name || claim.Generation != fence.Generation {
			return fmt.Errorf("cross-node VNI %d for lab %q is not reserved by this mutation fence", vni, top.Name)
		}
		if !claim.Live && !claim.Until.IsZero() && !now.Before(claim.Until) {
			return fmt.Errorf("cross-node VNI %d reservation for lab %q expired", vni, top.Name)
		}
	}
	return nil
}

// fencedContext stops an in-flight plan as soon as its fence expires or is
// superseded. Plan steps receive this context, so no not-yet-started Docker or
// netlink mutation can run under a stale controller.
func (s *Server) fencedContext(parent context.Context, lab string, fence Fence) (
	context.Context, func(),
) {
	ctx, cancel := context.WithCancel(parent)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.requireMutationFence(lab, fence); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() {
		close(stop)
		cancel()
		<-done
	}
}

func (s *Server) acquireMutationLease(req LeaseAcquireRequest) (LeaseResponse, error) {
	if req.Lab == "" {
		return LeaseResponse{}, errors.New("a lab name is required")
	}
	token, err := opaqueFenceToken()
	if err != nil {
		return LeaseResponse{}, fmt.Errorf("generate fencing token: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	changed := s.expireCoordinationLocked(now)
	if held := s.mutations[req.Lab]; held != nil {
		if tx, recovering := s.transactions[req.Lab]; recovering && tx.Phase == transactionRecovering {
			return LeaseResponse{}, fmt.Errorf(
				"lab %q is already leased by %s for another %s; recovery strategy=%q target=%q last_progress=%s deadline=%s",
				req.Lab, held.holder, time.Until(held.until).Round(time.Second),
				tx.RecoveryStrategy, tx.RecoveryTarget,
				tx.RecoveryProgress.Format(time.RFC3339), tx.RecoveryDeadline.Format(time.RFC3339))
		}
		return LeaseResponse{}, fmt.Errorf("lab %q is already leased by %s for another %s",
			req.Lab, held.holder, time.Until(held.until).Round(time.Second))
	}
	generation := s.fenceHighWater[req.Lab] + 1
	s.fenceHighWater[req.Lab] = generation
	until := now.Add(leaseTTL(req.TTLSeconds))
	lease := &clusterLease{
		holder: req.Holder,
		fence:  Fence{Token: token, Generation: generation},
		until:  until,
	}
	s.mutations[req.Lab] = lease
	if changed || s.store != nil {
		if err := s.saveCoordinationLocked(); err != nil {
			delete(s.mutations, req.Lab)
			return LeaseResponse{}, fmt.Errorf("persisting fence generation: %w", err)
		}
	}
	return LeaseResponse{Lab: req.Lab, Fence: lease.fence, ExpiresAt: until}, nil
}

func (s *Server) renewMutationLease(req LeaseRenewRequest) (LeaseResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	changed := s.expireCoordinationLocked(now)
	if err := s.fenceErrorLocked(req.Lab, req.Fence, now); err != nil {
		if changed {
			_ = s.saveCoordinationLocked()
		}
		return LeaseResponse{}, err
	}
	lease := s.mutations[req.Lab]
	lease.until = now.Add(leaseTTL(req.TTLSeconds))
	for vni, claim := range s.overlayClaims {
		if !claim.Live && claim.Lab == req.Lab && claim.Generation == req.Fence.Generation {
			claim.Until = lease.until
			s.overlayClaims[vni] = claim
			changed = true
		}
	}
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			return LeaseResponse{}, fmt.Errorf("persisting renewed reservation: %w", err)
		}
	}
	return LeaseResponse{Lab: req.Lab, Fence: lease.fence, ExpiresAt: lease.until}, nil
}

func (s *Server) releaseMutationLease(req LeaseReleaseRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	changed := s.expireCoordinationLocked(now)
	if err := s.fenceErrorLocked(req.Lab, req.Fence, now); err != nil {
		if changed {
			_ = s.saveCoordinationLocked()
		}
		return err
	}
	delete(s.mutations, req.Lab)
	for vni, claim := range s.overlayClaims {
		if !claim.Live && claim.Lab == req.Lab && claim.Generation == req.Fence.Generation {
			delete(s.overlayClaims, vni)
			changed = true
		}
	}
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			return fmt.Errorf("persisting released reservation: %w", err)
		}
	}
	return nil
}

func (s *Server) overlayOwnersNow() (map[uint32]string, error) {
	if s.overlayOwners != nil {
		return s.overlayOwners()
	}
	return netx.OverlayOwners()
}

func (s *Server) adoptLegacyOverlayOwner(vni uint32, lab string) (func() error, error) {
	if s.overlayAdopter != nil {
		if err := s.overlayAdopter(vni, lab); err != nil {
			return nil, err
		}
		return func() error {
			if s.overlayReverter == nil {
				return errors.New("no legacy overlay adoption reverter is configured")
			}
			return s.overlayReverter(vni, lab)
		}, nil
	}
	adoption, err := netx.AdoptLegacyOverlayOwner(vni, lab)
	if err != nil {
		return nil, err
	}
	return adoption.Revert, nil
}

// legacyOwnerlessOverlayProofLocked permits adoption only for the exact
// cross-node VNI the agent still records as active for this lab. The caller
// holds s.mu, which makes this proof and the reservation claim one decision.
func (s *Server) legacyOwnerlessOverlayProofLocked(lab string, vni uint32) error {
	top := s.current[lab]
	if top == nil {
		if s.store == nil {
			return fmt.Errorf("VNI %d is ownerless and lab %q has no current or persisted topology",
				vni, lab)
		}
		raw, err := s.store.Topology(lab)
		if err != nil {
			return fmt.Errorf("VNI %d is ownerless and lab %q has no persisted topology: %w",
				vni, lab, err)
		}
		var wire Wire
		if err := json.Unmarshal(raw, &wire); err != nil {
			return fmt.Errorf("VNI %d is ownerless and lab %q has unreadable persisted topology: %w",
				vni, lab, err)
		}
		top, err = wire.Rehydrate()
		if err != nil {
			return fmt.Errorf("VNI %d is ownerless and lab %q has invalid persisted topology: %w",
				vni, lab, err)
		}
	}
	if top.Name != lab {
		return fmt.Errorf("VNI %d is ownerless and lab %q has a mismatched topology for %q",
			vni, lab, top.Name)
	}

	if n := crossNodeVNIClaims(top, s.cfg.Node, vni); n != 1 {
		switch n {
		case 0:
			return fmt.Errorf("VNI %d is ownerless but is not an active cross-node link of lab %q",
				vni, lab)
		default:
			return fmt.Errorf("VNI %d is ownerless but lab %q has %d active cross-node claims",
				vni, lab, n)
		}
	}
	for otherLab, other := range s.current {
		if otherLab == lab || other == nil {
			continue
		}
		if n := crossNodeVNIClaims(other, s.cfg.Node, vni); n > 0 {
			return fmt.Errorf("VNI %d is ownerless but current lab %q also claims it",
				vni, otherLab)
		}
	}
	return nil
}

func crossNodeVNIClaims(top *model.Topology, node string, vni uint32) int {
	if top == nil {
		return 0
	}
	count := 0
	for _, link := range top.Links {
		if link == nil || link.VNI != vni || link.A == nil || link.B == nil ||
			link.A.Device == nil || link.B.Device == nil ||
			link.A.Device.Node == link.B.Device.Node {
			continue
		}
		if link.A.Device.Node == node || link.B.Device.Node == node {
			count++
		}
	}
	return count
}

func sortedVNIs(vnis []uint32) ([]uint32, error) {
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(vnis))
	for _, vni := range vnis {
		if vni == 0 {
			return nil, errors.New("overlay VNI must be non-zero")
		}
		if !seen[vni] {
			seen[vni] = true
			out = append(out, vni)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *Server) reserveOverlays(req OverlayReservationRequest) (OverlayReservationResponse, error) {
	vnis, err := sortedVNIs(req.VNIs)
	if err != nil {
		return OverlayReservationResponse{}, err
	}
	if req.Lab == "" {
		return OverlayReservationResponse{}, errors.New("a lab name is required")
	}
	owners, err := s.overlayOwnersNow()
	if err != nil {
		return OverlayReservationResponse{}, fmt.Errorf("listing live overlay ownership: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	changed := s.expireCoordinationLocked(now)
	if err := s.fenceErrorLocked(req.Lab, req.Fence, now); err != nil {
		if changed {
			_ = s.saveCoordinationLocked()
		}
		return OverlayReservationResponse{}, err
	}
	lease := s.mutations[req.Lab]
	legacy := make([]uint32, 0, len(vnis))
	for _, vni := range vnis {
		// A collection pass that has already proved this identifier abandoned
		// is mid-deletion. Granting the reservation would hand the lab an
		// overlay that is about to be removed underneath it; refusing is
		// retryable and takes at most one collection pass.
		if s.collectingOverlayLocked(vni) {
			return OverlayReservationResponse{}, fmt.Errorf(
				"VNI %d is being collected on this node; retry the deployment", vni)
		}
		if owner, exists := owners[vni]; exists && owner != req.Lab {
			if owner == "" {
				if err := s.legacyOwnerlessOverlayProofLocked(req.Lab, vni); err != nil {
					return OverlayReservationResponse{}, err
				}
				legacy = append(legacy, vni)
			} else {
				return OverlayReservationResponse{}, fmt.Errorf(
					"VNI %d is already owned by lab %q on this node", vni, owner)
			}
		}
		if claim, exists := s.overlayClaims[vni]; exists {
			switch {
			case claim.Lab != req.Lab:
				return OverlayReservationResponse{}, fmt.Errorf(
					"VNI %d is reserved or live for lab %q on this node", vni, claim.Lab)
			case claim.Live:
				continue // an idempotent apply of the owning lab
			case claim.Generation != req.Fence.Generation:
				return OverlayReservationResponse{}, fmt.Errorf(
					"VNI %d is reserved by an older fence for lab %q", vni, req.Lab)
			}
		}
	}

	before := make(map[uint32]overlayClaimBefore, len(vnis))
	for _, vni := range vnis {
		claim, have := s.overlayClaims[vni]
		before[vni] = overlayClaimBefore{claim: claim, have: have}
	}
	for _, vni := range vnis {
		claim := s.overlayClaims[vni]
		if claim.Live {
			// A redeploy of the owning lab keeps the live tunnel, but its
			// ownership is now guarded by the newer mutation fence.
			if claim.Generation != req.Fence.Generation {
				claim.Generation = req.Fence.Generation
				s.overlayClaims[vni] = claim
				changed = true
			}
			continue
		}
		s.overlayClaims[vni] = overlayClaim{
			Lab: req.Lab, Generation: req.Fence.Generation, Until: lease.until,
		}
		changed = true
	}
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			restoreOverlayClaimsLocked(s.overlayClaims, before)
			return OverlayReservationResponse{}, fmt.Errorf("persisting overlay reservation: %w", err)
		}
	}

	// A legacy per-link tunnel is already carrying live traffic. Once the
	// persisted/current topology proves it belongs to this lab, stamp only its
	// aliases; never replace the tunnel, bridge, FDB, or attached ports.
	adopted := make([]legacyOverlayAdoption, 0, len(legacy))
	for _, vni := range legacy {
		revert, err := s.adoptLegacyOverlayOwner(vni, req.Lab)
		if err != nil {
			rollbackErrs := s.rollbackLegacyAdoptionsLocked(req.Lab, adopted, before)
			if len(rollbackErrs) > 0 {
				return OverlayReservationResponse{}, fmt.Errorf(
					"adopting legacy VNI %d: %w; rollback: %s", vni, err,
					strings.Join(rollbackErrs, "; "))
			}
			return OverlayReservationResponse{}, fmt.Errorf("adopting legacy VNI %d: %w", vni, err)
		}
		adopted = append(adopted, legacyOverlayAdoption{vni: vni, revert: revert})
		claim := s.overlayClaims[vni]
		claim.Lab = req.Lab
		claim.Generation = req.Fence.Generation
		claim.Live = true
		claim.Until = time.Time{}
		s.overlayClaims[vni] = claim
	}
	if len(adopted) > 0 {
		if err := s.saveCoordinationLocked(); err != nil {
			// The kernel aliases are now the safety boundary. Keep the live
			// in-memory claims rather than rolling aliases back after a
			// persistence failure; the caller sees failure and no other lab
			// can reserve the VNI through either authority.
			return OverlayReservationResponse{}, fmt.Errorf(
				"persisting adopted legacy overlay ownership: %w", err)
		}
	}
	return OverlayReservationResponse{Lab: req.Lab, VNIs: vnis, ExpiresAt: lease.until}, nil
}

func restoreOverlayClaimsLocked(claims map[uint32]overlayClaim, before map[uint32]overlayClaimBefore) {
	for vni, prior := range before {
		if prior.have {
			claims[vni] = prior.claim
			continue
		}
		delete(claims, vni)
	}
}

func (s *Server) rollbackLegacyAdoptionsLocked(lab string, adopted []legacyOverlayAdoption,
	before map[uint32]overlayClaimBefore,
) []string {
	var errs []string
	kept := map[uint32]bool{}
	for i := len(adopted) - 1; i >= 0; i-- {
		adoption := adopted[i]
		if err := adoption.revert(); err != nil {
			vni := adoption.vni
			errs = append(errs, fmt.Sprintf("VNI %d: %v", vni, err))
			kept[vni] = true
			// The alias still owns the live tunnel, so preserve its claim.
			claim := s.overlayClaims[vni]
			claim.Lab, claim.Live = lab, true
			claim.Until = time.Time{}
			s.overlayClaims[vni] = claim
		}
	}
	for vni, prior := range before {
		if kept[vni] {
			continue
		}
		if prior.have {
			s.overlayClaims[vni] = prior.claim
		} else {
			delete(s.overlayClaims, vni)
		}
	}
	if err := s.saveCoordinationLocked(); err != nil {
		errs = append(errs, fmt.Sprintf("persisting rollback: %v", err))
	}
	return errs
}

func (s *Server) promoteOverlayReservations(lab string, fence Fence, vnis []uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if err := s.fenceErrorLocked(lab, fence, now); err != nil {
		return err
	}
	changed := false
	for _, vni := range vnis {
		claim, ok := s.overlayClaims[vni]
		if !ok || claim.Lab != lab || claim.Generation != fence.Generation {
			return fmt.Errorf("VNI %d was not reserved by this mutation fence", vni)
		}
		if !claim.Live {
			claim.Live = true
			claim.Until = time.Time{}
			s.overlayClaims[vni] = claim
			changed = true
		}
	}
	if changed {
		if err := s.saveCoordinationLocked(); err != nil {
			return fmt.Errorf("persisting live overlay ownership: %w", err)
		}
	}
	return nil
}

func (s *Server) releaseOverlayClaims(lab string, vnis []uint32) error {
	want := map[uint32]bool{}
	for _, vni := range vnis {
		want[vni] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	changed := false
	for vni, claim := range s.overlayClaims {
		if claim.Lab != lab || (len(want) > 0 && !want[vni]) {
			continue
		}
		delete(s.overlayClaims, vni)
		changed = true
	}
	if changed {
		return s.saveCoordinationLocked()
	}
	return nil
}

// finishDestroyedLab removes every durable coordination record that could
// make an empty lab look like a committed deployment. Runtime and topology
// cleanup happen first; this is the terminal, fenced commit for destroy.
func (s *Server) finishDestroyedLab(lab string, fence Fence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}

	generation, hadGeneration := s.generations[lab]
	tx, hadTransaction := s.transactions[lab]
	inventory, hadInventory := s.inventories[lab]
	lineage, hadLineage := s.overlayLineage[lab]
	lifetime, hadLifetime := s.clearEphemeralLeaseLocked(lab)
	claims := map[uint32]overlayClaim{}
	for vni, claim := range s.overlayClaims {
		if claim.Lab == lab {
			claims[vni] = claim
			delete(s.overlayClaims, vni)
		}
	}
	delete(s.generations, lab)
	delete(s.transactions, lab)
	delete(s.inventories, lab)
	delete(s.overlayLineage, lab)
	if err := s.saveCoordinationLocked(); err != nil {
		if hadGeneration {
			s.generations[lab] = generation
		}
		if hadTransaction {
			s.transactions[lab] = tx
		}
		if hadInventory {
			s.inventories[lab] = inventory
		}
		if hadLineage {
			s.overlayLineage[lab] = lineage
		}
		if hadLifetime {
			s.ephemeral[lab] = lifetime
		}
		for vni, claim := range claims {
			s.overlayClaims[vni] = claim
		}
		return fmt.Errorf("persisting destroyed lab coordination: %w", err)
	}

	delete(s.current, lab)
	delete(s.modes, lab)
	delete(s.ungraded, lab)
	delete(s.peers, lab)
	for key := range s.repairFails {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.repairFails, key)
		}
	}
	for key := range s.repairNext {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.repairNext, key)
		}
	}
	for key := range s.partial {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.partial, key)
		}
	}
	return nil
}

func (s *Server) prepareGeneration(lab string, fence Fence, expected, generation string,
	requested json.RawMessage, mode string, ungraded int, peers map[string]string, prune bool,
	onlySteps []string, stateProofs []StateProof, prestate ...transactionInventory,
) error {
	if generation == "" {
		return errors.New("a deployment generation is required")
	}
	desiredMode, err := RequireTransactionMode(mode)
	if err != nil {
		return err
	}
	if ungraded < 0 {
		return errors.New("transaction ungraded AS must not be negative")
	}
	var requestedWire Wire
	if len(requested) == 0 || json.Unmarshal(requested, &requestedWire) != nil {
		return errors.New("prepared transaction requires a valid topology wire with an explicit mode")
	}
	requestedMode, err := RequireTransactionMode(requestedWire.Mode)
	if err != nil {
		return fmt.Errorf("requested topology mode invariant: %w", err)
	}
	if requestedMode != desiredMode || requestedWire.Ungraded != ungraded {
		return fmt.Errorf("requested topology mode %s/%d does not match desired transaction mode %s/%d",
			requestedMode, requestedWire.Ungraded, desiredMode, ungraded)
	}

	var previous json.RawMessage
	if s.store != nil {
		if raw, err := s.store.Topology(lab); err == nil {
			previous = append(json.RawMessage(nil), raw...)
		}
	}
	if len(previous) == 0 {
		s.mu.Lock()
		if top := s.current[lab]; top != nil {
			if raw, err := json.Marshal(Serialise(top)); err == nil {
				previous = raw
			}
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	now := s.nowTime()
	if err := s.fenceErrorLocked(lab, fence, now); err != nil {
		return err
	}
	state := s.generations[lab]
	if tx, active := s.transactions[lab]; active {
		if tx.Generation == generation && tx.FenceGeneration == fence.Generation {
			return nil
		}
		return fmt.Errorf("lab %q has an unfinished deployment transaction for generation %q; "+
			"refusing a new generation until it is recovered", lab, tx.Generation)
	}
	if state.Committed != expected {
		return fmt.Errorf("generation compare-and-swap for lab %q failed: expected %q, node has %q",
			lab, expected, state.Committed)
	}
	before := transactionInventory{}
	if len(prestate) > 0 {
		before = prestate[0]
	}
	previousMode, previousUngraded := "", 0
	legacyPrevious := false
	if len(previous) > 0 {
		var previousWire Wire
		if json.Unmarshal(previous, &previousWire) == nil {
			previousMode, previousUngraded = previousWire.Mode, previousWire.Ungraded
		}
	}
	if previousMode == "" {
		// A committed topology predating explicit mode fields is a legacy
		// platform deployment. Make that migration explicit in the prepared
		// record and audit logs; do not use a mutable in-memory ApplyRequest
		// default to infer a desired mode.
		if len(previous) > 0 {
			previousMode, legacyPrevious = string(render.ModePlatform), true
		} else {
			// A first deployment has no committed topology. In that one
			// case the already-rehydrated committed mode is the only durable
			// source available to this process (and preserves harness state
			// in tests/offline bootstrap).
			previousMode, previousUngraded = s.modes[lab], s.ungraded[lab]
			if previousMode == "" {
				previousMode, previousUngraded = string(render.ModePlatform), 0
			}
		}
	}
	if _, err := RequireTransactionMode(previousMode); err != nil {
		return fmt.Errorf("persisted previous mode for lab %q: %w", lab, err)
	}
	s.transactions[lab] = applyTransaction{
		Generation: generation, Expected: expected, FenceGeneration: fence.Generation,
		Requested: append(json.RawMessage(nil), requested...), Previous: previous,
		PreviousGen:  state.Committed,
		PreviousMode: previousMode, PreviousUngraded: previousUngraded,
		Mode: desiredMode, Ungraded: ungraded,
		PeerUnderlay: peers, Prune: prune, OnlySteps: append([]string(nil), onlySteps...),
		StateProofs: append([]StateProof(nil), stateProofs...),
		Phase:       transactionPrepared, Prestate: before,
	}
	state.Prepared = generation
	s.generations[lab] = state
	if err := s.saveCoordinationLocked(); err != nil {
		delete(s.transactions, lab)
		state.Prepared = ""
		s.generations[lab] = state
		return fmt.Errorf("persisting prepared generation: %w", err)
	}
	slog.Info("prepared transaction mode invariant", "lab", lab, "generation", generation,
		"previous_mode", previousMode, "previous_ungraded", previousUngraded,
		"desired_mode", desiredMode, "desired_ungraded", ungraded,
		"legacy_previous_mode_migrated", legacyPrevious)
	// A periodic capture that began before prepare can otherwise keep running
	// against containers this fenced transaction is about to replace. The
	// transaction's own boundary capture remains responsible for durability.
	s.stopPeriodicDurability(lab)
	return nil
}

func (s *Server) checkPreparedGeneration(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	return nil
}

// transactionForApply returns the durable mode contract for an apply phase.
// Request fields are checked by the handler but never become the authority:
// a controller retry must not reinterpret an empty/default Mode after prepare.
func (s *Server) transactionForApply(lab string, fence Fence, generation string) (applyTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return applyTransaction{}, err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return applyTransaction{}, fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	if _, err := RequireTransactionMode(tx.Mode); err != nil {
		return applyTransaction{}, fmt.Errorf("prepared desired mode invariant: %w", err)
	}
	if _, err := RequireTransactionMode(tx.PreviousMode); err != nil {
		return applyTransaction{}, fmt.Errorf("prepared previous mode invariant: %w", err)
	}
	return tx, nil
}

func (s *Server) markGenerationApplying(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	tx.Phase, tx.Failure = transactionApplying, ""
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func (s *Server) markGenerationApplied(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}

	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	tx.Applied, tx.Phase, tx.Failure = true, transactionApplied, ""
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		return fmt.Errorf("persisting applied generation: %w", err)
	}
	return nil
}

// recordGenerationDirtyCapture persists the narrow destructive set produced
// by the apply plan so commit capture does not fall back to a class-wide
// CaptureAll on an otherwise no-change deployment.
func (s *Server) recordGenerationDirtyCapture(lab string, fence Fence, generation string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}

	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	tx.DirtyCapture = append([]string(nil), ids...)
	tx.DirtyCaptureKnown = true
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

// recordGenerationSemantic persists dynamic-state drift discovered by the
// observed deployment pass. These devices must be semantically verified at
// commit even when their OCI spec was reused and no student snapshot was
// needed.
func (s *Server) recordGenerationSemantic(lab string, fence Fence, generation string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	tx.Semantic = append([]string(nil), ids...)
	tx.SemanticKnown = true
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func (s *Server) recordGenerationTouched(lab string, fence Fence, generation string,
	ids []string, vnis []uint32, known bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation {
		return fmt.Errorf("generation %q of lab %q was not prepared by this fence", generation, lab)
	}
	tx.Touched = appendTouchedStrings(tx.Touched, ids)
	tx.TouchedVNIs = appendTouchedVNIs(tx.TouchedVNIs, vnis)
	tx.TouchedKnown = tx.TouchedKnown || known
	s.transactions[lab] = tx
	return s.saveCoordinationLocked()
}

func appendTouchedStrings(existing, added []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(added))
	for _, id := range append(append([]string(nil), existing...), added...) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func appendTouchedVNIs(existing, added []uint32) []uint32 {
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(existing)+len(added))
	for _, vni := range append(append([]uint32(nil), existing...), added...) {
		if vni == 0 || seen[vni] {
			continue
		}
		seen[vni] = true
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Server) transactionForCommit(lab string, fence Fence, generation string) (applyTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return applyTransaction{}, err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation || !tx.Applied ||
		tx.Phase == transactionRollbackNeeded || tx.Phase == transactionRecovering ||
		tx.Phase == transactionRollbackFailed {
		return applyTransaction{}, fmt.Errorf("generation %q of lab %q was not fully applied by this fence",
			generation, lab)
	}
	if len(tx.StateProofs) > 0 && !tx.StateVerified {
		return applyTransaction{}, fmt.Errorf("generation %q of lab %q has restored state that was not verified; refusing source prune",
			generation, lab)
	}
	if _, err := RequireTransactionMode(tx.Mode); err != nil {
		return applyTransaction{}, fmt.Errorf("generation %q desired mode invariant: %w", generation, err)
	}
	if _, err := RequireTransactionMode(tx.PreviousMode); err != nil {
		return applyTransaction{}, fmt.Errorf("generation %q previous mode invariant: %w", generation, err)
	}
	return tx, nil
}

// transactionForStateVerify reads an applied transaction before it is
// committed. It intentionally does not require StateVerified yet; this is the
// only transition allowed to establish that fact.
func (s *Server) transactionForStateVerify(lab string, fence Fence, generation string) (applyTransaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return applyTransaction{}, err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation || !tx.Applied {
		return applyTransaction{}, fmt.Errorf("generation %q of lab %q was not fully applied by this fence",
			generation, lab)
	}
	return tx, nil
}

func (s *Server) markStateVerified(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation || !tx.Applied {
		return fmt.Errorf("generation %q of lab %q was not fully applied by this fence",
			generation, lab)
	}
	tx.StateVerified = true
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		return fmt.Errorf("persisting state restore verification: %w", err)
	}
	return nil
}

func (s *Server) finishCommittedGeneration(lab string, fence Fence, generation string,
	inventory ...transactionInventory,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation || !tx.Applied {
		return fmt.Errorf("generation %q of lab %q cannot be committed by this fence", generation, lab)
	}
	state := s.generations[lab]
	oldState := state
	previousCommitted := state.Committed
	state.Committed, state.Prepared = generation, ""
	state.Ancestors = appendGenerationLineage(state.Ancestors, previousCommitted, generation)
	s.generations[lab] = state
	previousInventory, hadInventory := s.inventories[lab]
	previousLineage := s.overlayLineage[lab]
	if len(inventory) > 0 {
		s.inventories[lab] = inventory[0]
		lineage := map[uint32]string{}
		touchedVNIs := map[uint32]bool{}
		for _, vni := range tx.TouchedVNIs {
			touchedVNIs[vni] = true
		}
		for _, vni := range inventory[0].VNIs {
			if tx.TouchedKnown && touchedVNIs[vni] {
				lineage[vni] = generation
			} else if previous := s.overlayLineage[lab][vni]; previous != "" {
				lineage[vni] = previous
			} else {
				lineage[vni] = generation
			}
		}
		s.overlayLineage[lab] = lineage
	}
	tx.Committed, tx.Phase, tx.Failure = true, transactionCommitted, ""
	s.transactions[lab] = tx
	if err := s.saveCoordinationLocked(); err != nil {
		tx.Committed = false
		s.transactions[lab] = tx
		s.generations[lab] = oldState
		if hadInventory {
			s.inventories[lab] = previousInventory
		} else {
			delete(s.inventories, lab)
		}
		if previousLineage != nil {
			s.overlayLineage[lab] = previousLineage
		} else {
			delete(s.overlayLineage, lab)
		}
		return fmt.Errorf("persisting committed generation: %w", err)
	}
	return nil
}

func appendGenerationLineage(existing []string, previous, current string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+2)
	values := append([]string(nil), existing...)
	values = append(values, previous, current)
	for _, generation := range values {
		if generation == "" || seen[generation] {
			continue
		}
		seen[generation] = true
		out = append(out, generation)
	}
	return out
}

// finalizeCommittedGeneration drops rollback material only after the
// coordinator has received a commit acknowledgement from every node. Until
// then an ambiguous response can still be aborted safely.
func (s *Server) finalizeCommittedGeneration(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation || tx.FenceGeneration != fence.Generation || !tx.Committed {
		return fmt.Errorf("generation %q of lab %q is not awaiting finalization by this fence",
			generation, lab)
	}
	delete(s.transactions, lab)
	if err := s.saveCoordinationLocked(); err != nil {
		s.transactions[lab] = tx
		return fmt.Errorf("persisting finalized generation: %w", err)
	}
	return nil
}

// finishRecoveredGeneration is deliberately less strict than normal abort:
// an agent restart or controller loss invalidates the original fence, so the
// newer recovery fence is the only authority that can finish restoring the
// pre-state.
func (s *Server) finishRecoveredGeneration(lab string, fence Fence, generation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	if err := s.fenceErrorLocked(lab, fence, s.nowTime()); err != nil {
		return err
	}
	tx, ok := s.transactions[lab]
	if !ok || tx.Generation != generation {
		return fmt.Errorf("generation %q of lab %q has no recovery transaction", generation, lab)
	}
	state := s.generations[lab]
	state.Committed, state.Prepared = tx.PreviousGen, ""
	s.generations[lab] = state
	s.inventories[lab] = tx.Prestate
	delete(s.transactions, lab)
	// A completed semantic recovery supersedes every failed targeted repair
	// observation from the interrupted generation. Leaving those entries
	// behind makes status report a recovered lab as still retrying and can
	// immediately rewire a device that the rollback just proved healthy.
	for key := range s.repairFails {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.repairFails, key)
		}
	}
	for key := range s.repairNext {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.repairNext, key)
		}
	}
	for key := range s.partial {
		if strings.HasPrefix(key, lab+"|") {
			delete(s.partial, key)
		}
	}
	if err := s.saveCoordinationLocked(); err != nil {
		s.transactions[lab] = tx
		return fmt.Errorf("persisting recovered generation: %w", err)
	}
	return nil
}

func (s *Server) committedGenerations() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	out := make(map[string]string, len(s.generations))
	for lab, state := range s.generations {
		if state.Committed != "" {
			out[lab] = state.Committed
		}

	}
	return out
}

func (s *Server) committedModes() map[string]LabModeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]LabModeStatus{}
	for lab, mode := range s.modes {
		out[lab] = LabModeStatus{Mode: mode, Ungraded: s.ungraded[lab]}
	}
	return out
}

func (s *Server) mutationLeaseHolder(lab string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initCoordination()
	_ = s.expireCoordinationLocked(s.nowTime())
	if lease := s.mutations[lab]; lease != nil {
		if lease.holder != "" {
			return lease.holder
		}
		return "a fenced cluster operation"
	}
	return ""
}

func (s *Server) handleLeaseAcquire(w http.ResponseWriter, r *http.Request) {
	var req LeaseAcquireRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.acquireMutationLease(req)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleLeaseRenew(w http.ResponseWriter, r *http.Request) {
	var req LeaseRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := s.renewMutationLease(req)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) handleLeaseRelease(w http.ResponseWriter, r *http.Request) {
	var req LeaseReleaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.releaseMutationLease(req); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, struct{}{})
}

func (s *Server) handleOverlayReserve(w http.ResponseWriter, r *http.Request) {
	var req OverlayReservationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if why := s.refuseMutationIfHeld(req.Lab, req.Hold, "reserving overlay identifiers"); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}
	resp, err := s.reserveOverlays(req)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, resp)
}
