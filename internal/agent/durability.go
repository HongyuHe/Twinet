package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// WireRecord carries a content-addressed control-plane record. Like
// WireSnapshot it carries its body explicitly because state.Record keeps bodies
// out of ordinary JSON metadata.
type WireRecord struct {
	state.Record
	Content []byte `json:"content"`
}

// StateAck proves that a receiver recomputed and accepted an object digest.
type StateAck struct {
	Key    string `json:"key"`
	Digest string `json:"digest"`
}

// PeerStateRequest is the peer-only write protocol. It deliberately has no
// fence: peer credentials are not controller credentials and may only append
// verified durable objects, never mutate runtime state or topology placement.
type PeerStateRequest struct {
	Lab       string         `json:"lab"`
	Source    string         `json:"source"`
	Snapshots []WireSnapshot `json:"snapshots,omitempty"`
	Records   []WireRecord   `json:"records,omitempty"`
}

// PeerStateResponse returns a digest acknowledgement for every received
// object. An acknowledgement is not inferred from HTTP success.
type PeerStateResponse struct {
	Lab  string     `json:"lab"`
	Acks []StateAck `json:"acks"`
}

// PeerStateInventoryResponse lets a sender avoid retransmitting unchanged
// content while still verifying the peer has the expected current digest.
type PeerStateInventoryResponse struct {
	Lab       string               `json:"lab"`
	Artifacts []state.ArtifactMeta `json:"artifacts"`
}

// PeerStateReadResponse carries verified current artifact bodies to a
// recovering peer. It is peer-authenticated and read-only: recovery may fetch
// a lost local replica without granting a node controller authority.
type PeerStateReadResponse struct {
	Lab       string         `json:"lab"`
	Snapshots []WireSnapshot `json:"snapshots,omitempty"`
	Records   []WireRecord   `json:"records,omitempty"`
}

// PeerReplicationStatus is a bounded, operator-visible replication health
// record. It deliberately reports no state content: the actionable fact is
// whether a failure-domain peer acknowledged the current digest quorum.
type PeerReplicationStatus struct {
	Lab     string `json:"lab"`
	Peer    string `json:"peer"`
	Healthy bool   `json:"healthy"`
	// Fresh means this process completed a live authenticated inventory
	// handshake. Persisted acknowledgements survive restart as LastSuccess but
	// are deliberately not called fresh until the peer is reachable again.
	Fresh               bool      `json:"fresh"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	LastFailure         time.Time `json:"last_failure,omitempty"`
	NextRetry           time.Time `json:"next_retry,omitempty"`
	Error               string    `json:"error,omitempty"`
}

type peerStateClient interface {
	Inventory(context.Context, string) (PeerStateInventoryResponse, error)
	Read(context.Context, string) (PeerStateReadResponse, error)
	Import(context.Context, PeerStateRequest) (PeerStateResponse, error)
}

type peerDialer func(context.Context, model.NodeSpec) (peerStateClient, error)

const (
	peerRetryMin      = 100 * time.Millisecond
	peerRetryMax      = 2 * time.Second
	peerRetryAttempts = 5
	peerHealthEvery   = 5 * time.Second
	peerHealthTimeout = 15 * time.Second
)

type httpPeerStateClient struct {
	base string
	http *http.Client
}

func (c *httpPeerStateClient) request(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusBadRequest {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var problem struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &problem)
		if problem.Error == "" {
			problem.Error = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("%s: %s", resp.Status, problem.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *httpPeerStateClient) Inventory(ctx context.Context, lab string) (PeerStateInventoryResponse, error) {
	var out PeerStateInventoryResponse
	err := c.request(ctx, http.MethodGet, "/v1/peer/state/inventory?lab="+url.QueryEscape(lab), nil, &out)
	return out, err
}

func (c *httpPeerStateClient) Read(ctx context.Context, lab string) (PeerStateReadResponse, error) {
	var out PeerStateReadResponse
	err := c.request(ctx, http.MethodGet, "/v1/peer/state?lab="+url.QueryEscape(lab), nil, &out)
	return out, err
}

func (c *httpPeerStateClient) Import(ctx context.Context, req PeerStateRequest) (PeerStateResponse, error) {
	var out PeerStateResponse
	err := c.request(ctx, http.MethodPost, "/v1/peer/state", req, &out)
	return out, err
}

// peerAuth admits only a node certificate carrying the peer-state scope. It
// does not accept the shared bearer token: possessing a node key must never
// make a compromised node a controller.
func (s *Server) peerAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "a mutually authenticated peer certificate is required", http.StatusUnauthorized)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		id, err := authz.FromCertificate(cert)
		if err != nil || id.Role != authz.RolePeer || !id.Allows("*", authz.ActionPeerState) {
			http.Error(w, "this certificate is not permitted to use the peer replication API", http.StatusForbidden)
			return
		}
		if cert.Subject.CommonName == "" {
			http.Error(w, "peer certificate has no node identity", http.StatusForbidden)
			return
		}
		scope, err := peerRequestScope(r)
		if err != nil {
			http.Error(w, "a valid peer-state lab scope is required", http.StatusBadRequest)
			return
		}
		principal := requestPrincipal{
			Identity: id, Name: cert.Subject.CommonName,
			CertificateSerial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		}
		ctx := context.WithValue(r.Context(), requestPrincipalKey{}, principal)
		ctx = context.WithValue(ctx, requestScopeKey{}, scope)
		r = r.WithContext(ctx)
		if r.Method != http.MethodPost {
			h(w, r)
			return
		}
		observed := &authorizationResponseWriter{ResponseWriter: w}
		h(observed, r)
		result := "success"
		if observed.status >= http.StatusBadRequest {
			result = "error"
		}
		s.recordAuthorizationAudit(r, scope, principal, result, "")
	}
}

func peerRequestScope(r *http.Request) (requestScope, error) {
	lab := strings.TrimSpace(r.URL.Query().Get("lab"))
	if r.Method == http.MethodPost {
		values, err := requestJSONObject(r)
		if err != nil {
			return requestScope{}, err
		}
		lab = jsonString(values["lab"])
	}
	if !labNameRE.MatchString(lab) {
		return requestScope{}, errors.New("lab is required")
	}
	return requestScope{Lab: lab, Action: authz.ActionPeerState, Target: lab}, nil
}

func peerNodeName(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

func (s *Server) handlePeerStateInventory(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		httpError(w, http.StatusServiceUnavailable, errors.New("this node has no durable state store"))
		return
	}
	lab := r.URL.Query().Get("lab")
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	artifacts, err := s.store.CurrentArtifactMeta(lab)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, PeerStateInventoryResponse{Lab: lab, Artifacts: artifacts})
}

func (s *Server) handlePeerStateRead(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		httpError(w, http.StatusServiceUnavailable, errors.New("this node has no durable state store"))
		return
	}
	lab := r.URL.Query().Get("lab")
	if lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	snapshots, err := s.store.CurrentSnapshots(lab)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	records, err := s.store.CurrentRecords(lab)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := PeerStateReadResponse{Lab: lab}
	for _, snapshot := range snapshots {
		out.Snapshots = append(out.Snapshots, WireSnapshot{Snapshot: snapshot, Content: snapshot.Content})
	}
	for _, record := range records {
		out.Records = append(out.Records, WireRecord{Record: record, Content: record.Content})
	}
	writeJSON(w, out)
}

func (s *Server) handlePeerStateImport(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		httpError(w, http.StatusServiceUnavailable, errors.New("this node has no durable state store"))
		return
	}
	var req PeerStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab name is required"))
		return
	}
	if req.Source == "" || req.Source != peerNodeName(r) {
		httpError(w, http.StatusForbidden, errors.New("peer source does not match its authenticated node identity"))
		return
	}
	acks := make([]StateAck, 0, len(req.Snapshots)+len(req.Records))
	for _, wire := range req.Snapshots {
		snapshot := wire.Snapshot
		snapshot.Content = wire.Content
		if snapshot.Lab != req.Lab {
			httpError(w, http.StatusBadRequest, fmt.Errorf("snapshot %s belongs to lab %q, not %q",
				snapshot.Device, snapshot.Lab, req.Lab))
			return
		}
		if _, err := s.store.Put(snapshot); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("verify snapshot %s/%s: %w",
				snapshot.Device, snapshot.Kind, err))
			return
		}
		acks = append(acks, StateAck{Key: snapshotStateKey(snapshot), Digest: snapshot.Digest})
	}
	for _, wire := range req.Records {
		record := wire.Record
		record.Content = wire.Content
		if record.Lab != req.Lab {
			httpError(w, http.StatusBadRequest, fmt.Errorf("record %s belongs to lab %q, not %q",
				record.Kind, record.Lab, req.Lab))
			return
		}
		if _, err := s.store.PutRecord(record); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("verify %s record: %w", record.Kind, err))
			return
		}
		if err := s.installImportedRecord(record); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		acks = append(acks, StateAck{Key: recordStateKey(record), Digest: record.Digest})
	}
	sort.Slice(acks, func(i, j int) bool { return acks[i].Key < acks[j].Key })
	writeJSON(w, PeerStateResponse{Lab: req.Lab, Acks: acks})
}

func snapshotStateKey(snapshot state.Snapshot) string {
	return "snapshot/" + snapshot.Device + "/" + string(snapshot.Kind)
}

func recordStateKey(record state.Record) string {
	return "record/" + string(record.Kind)
}

// durabilityLoop keeps capture and replication alive inside the node agent;
// it is intentionally unrelated to a CLI process's lifetime.
func (s *Server) durabilityLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.captureDueState(ctx)
		}
	}
}

func (s *Server) captureDueState(ctx context.Context) {
	s.mu.Lock()
	labs := make([]string, 0, len(s.current))
	for lab := range s.current {
		labs = append(labs, lab)
	}
	sort.Strings(labs)
	s.mu.Unlock()
	for _, lab := range labs {
		if reason := s.ordinaryMaintenanceSuppression(lab); reason != "" {
			continue
		}
		top, policy, ok := s.durabilityTopology(lab)
		mode, ungraded := s.modeAndUngraded(lab)
		if !ok || top == nil || !hasCapturableStudentDevice(top, mode, ungraded, s.cfg.Node) {
			continue
		}
		interval, err := time.ParseDuration(policy.CaptureInterval)
		if err != nil || interval <= 0 {
			slog.Error("invalid active durability policy", "lab", lab, "interval", policy.CaptureInterval)
			continue
		}
		s.durabilityMu.Lock()
		last := s.lastCapture[lab]
		s.durabilityMu.Unlock()
		captureDue := last.IsZero() || time.Since(last) >= interval
		retryDue := s.peerReplicationRetryDue(lab)
		if !captureDue && !retryDue {
			continue
		}
		periodicCtx, ok := s.beginPeriodicDurability(ctx, lab)
		if !ok {
			continue
		}
		go func(periodicCtx context.Context, lab string, top *model.Topology, policy model.StatePolicy, captureDue bool) {
			defer s.endDurability(lab)
			// A transaction may have become durable after this periodic task
			// was scheduled. Do not race rollback by capturing a half-restored
			// namespace or attempting peer replication with its canceled
			// context; recovery itself owns the next durable boundary.
			if s.ordinaryMaintenanceSuppression(lab) != "" {
				return
			}
			var err error
			if captureDue {
				_, err = s.captureAndReplicate(periodicCtx, top)
			} else {
				err = s.replicateDurableState(periodicCtx, top)
			}
			if err != nil {
				if periodicCtx.Err() != nil && s.ordinaryMaintenanceSuppression(lab) != "" {
					// Expected cancellation: a newly persisted transaction
					// owns the next capture/replication boundary.
					return
				}
				slog.Error("periodic durable replication failed", "lab", lab, "err", err,
					"fail_closed", policy.FailClosedEnabled())
			}
		}(periodicCtx, lab, top, policy, captureDue)
	}
}

func (s *Server) durabilityTopology(lab string) (*model.Topology, model.StatePolicy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	top := s.current[lab]
	if top == nil || top.Lab == nil {
		return nil, model.StatePolicy{}, false
	}
	return top, top.Lab.State, true
}

func (s *Server) modeAndUngraded(lab string) (render.Mode, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return render.Mode(s.modes[lab]), s.ungraded[lab]
}

func hasCapturableStudentDevice(top *model.Topology, mode render.Mode, ungraded int, node string) bool {
	for _, device := range top.DevicesOnNode(node) {
		if capturesStudentState(top, mode, ungraded, device) {
			return true
		}
	}
	return false
}

func (s *Server) beginPeriodicDurability(parent context.Context, lab string) (context.Context, bool) {
	s.durabilityMu.Lock()
	defer s.durabilityMu.Unlock()
	if s.durabilityBusy == nil {
		s.durabilityBusy = map[string]bool{}
	}
	if s.durabilityBusy[lab] {
		return nil, false
	}
	if s.durabilityCancel == nil {
		s.durabilityCancel = map[string]context.CancelFunc{}
	}
	ctx, cancel := context.WithCancel(parent)
	s.durabilityBusy[lab] = true
	s.durabilityCancel[lab] = cancel
	return ctx, true
}

func (s *Server) endDurability(lab string) {
	s.durabilityMu.Lock()
	if s.durabilityBusy == nil {
		s.durabilityBusy = map[string]bool{}
	}
	delete(s.durabilityBusy, lab)
	if cancel := s.durabilityCancel[lab]; cancel != nil {
		cancel()
	}
	delete(s.durabilityCancel, lab)
	s.durabilityMu.Unlock()
}

// stopPeriodicDurability cancels only agent-scheduled work. It is invoked as
// soon as a transaction is persisted so a stale capture cannot race rollback
// or turn its expected peer quorum into a noisy canceled failure.
func (s *Server) stopPeriodicDurability(lab string) {
	s.durabilityMu.Lock()
	cancel := s.durabilityCancel[lab]
	s.durabilityMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// captureAndReplicate takes a bounded capture and confirms every current
// object has the policy's required number of independent copies.
func (s *Server) captureAndReplicate(ctx context.Context, top *model.Topology) (int, error) {
	return s.captureAndReplicateSelected(ctx, top, nil)
}

// captureAndReplicateDirty is used at a deployment boundary. Periodic
// durability calls captureAndReplicate and therefore still captures the full
// student-owned set independently of deploy reconciliation.
func (s *Server) captureAndReplicateDirty(ctx context.Context, top *model.Topology, ids []string) (int, error) {
	return s.captureAndReplicateSelected(ctx, top, ids)
}

func (s *Server) captureAndReplicateSelected(ctx context.Context, top *model.Topology, ids []string) (int, error) {
	if top == nil || top.Lab == nil {
		return 0, errors.New("durability needs a topology with a lab policy")
	}
	if s.store == nil {
		return 0, errors.New("this node has no state store")
	}
	mode, ungraded := s.modeAndUngraded(top.Name)
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(), State: s.store,
		Renderer: renderer(top, render.ModePlatform, 0),
	}
	eligible := map[string]bool{}
	for _, device := range top.DevicesOnNode(s.cfg.Node) {
		if capturesStudentState(top, mode, ungraded, device) {
			eligible[device.ID] = true
		}
	}
	if ids != nil {
		asked := map[string]bool{}
		for _, id := range ids {
			if eligible[id] {
				asked[id] = true
			}
		}
		eligible = asked
	}
	if len(eligible) == 0 {
		// A solved reference has no student-owned state, but its topology,
		// mode, holds, and exemptions still need peer durability.
		return 0, s.replicateDurableState(ctx, top)
	}
	selected := make([]string, 0, len(eligible))
	for id := range eligible {
		selected = append(selected, id)
	}
	sort.Strings(selected)
	n, err := eng.CaptureDevices(ctx, top, s.store, selected)
	if err != nil {
		return n, fmt.Errorf("capture current student state: %w", err)
	}
	if err := s.replicateDurableState(ctx, top); err != nil {
		return n, err
	}
	s.durabilityMu.Lock()
	if s.lastCapture == nil {
		s.lastCapture = map[string]time.Time{}
	}
	s.lastCapture[top.Name] = time.Now()
	s.durabilityMu.Unlock()
	return n, nil
}

// ensureDurableState replicates topology/mode/exemption/hold records even when
// no local device was captured. It is used at commit boundaries.
func (s *Server) ensureDurableState(ctx context.Context, top *model.Topology) error {
	if s.store == nil {
		return errors.New("this node has no state store")
	}

	return s.replicateDurableState(ctx, top)
}

func (s *Server) durableSnapshotManifest(lab string, ids []string) ([]transactionSnapshot, error) {
	if s.store == nil {
		return nil, errors.New("this node has no state store")
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		allowed[id] = true
	}
	snapshots, err := s.store.CurrentSnapshots(lab)
	if err != nil {
		return nil, err
	}
	out := make([]transactionSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if len(allowed) > 0 && !allowed[snapshot.Device] {
			continue
		}
		out = append(out, transactionSnapshot{
			Device: snapshot.Device, Kind: string(snapshot.Kind), Digest: snapshot.Digest,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

func (s *Server) replicaTargets(top *model.Topology) ([]model.NodeSpec, error) {
	if top == nil || top.Lab == nil {
		return nil, errors.New("durability needs a topology with a lab policy")
	}

	policy := top.Lab.State
	if policy.ReplicationFactor < 1 {
		return nil, fmt.Errorf("invalid replication factor %d", policy.ReplicationFactor)
	}
	if policy.ReplicationFactor == 1 {
		return nil, nil
	}
	var local model.NodeSpec
	found := false
	for _, node := range top.Lab.Placement.Nodes {
		if node.Name == s.cfg.Node {
			local, found = node, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("this agent %q is not declared in the lab placement", s.cfg.Node)
	}
	used := map[string]bool{local.Domain(): true}
	nodes := append([]model.NodeSpec(nil), top.Lab.Placement.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	want := policy.ReplicationFactor - 1
	var out []model.NodeSpec
	for _, node := range nodes {
		if node.Name == s.cfg.Node || used[node.Domain()] {
			continue
		}
		out = append(out, node)
		used[node.Domain()] = true
		if len(out) == want {
			return out, nil
		}
	}
	return nil, fmt.Errorf("replication factor %d requires %d peer failure domains beyond %q, but only %d are available",
		policy.ReplicationFactor, want, local.Domain(), len(out))
}

// ensurePeerQuorumReachable proves a live authenticated peer quorum before a
// transaction creates or replaces anything. This is intentionally an
// inventory-only handshake: it establishes transport/auth freshness without
// waiting for the periodic replication loop to run.
func (s *Server) ensurePeerQuorumReachable(ctx context.Context, top *model.Topology) error {
	targets, err := s.replicaTargets(top)
	if err != nil {
		return err
	}
	for _, target := range targets {
		var inventory PeerStateInventoryResponse
		err, nextRetry := retryPeer(ctx, func() error {
			peer, err := s.peerFor(ctx, target)
			if err != nil {
				return fmt.Errorf("dial durable peer %s: %w", target.Name, err)
			}
			inventory, err = peer.Inventory(ctx, top.Name)
			if err != nil {
				return fmt.Errorf("probe durable peer %s: %w", target.Name, err)
			}
			if inventory.Lab != top.Name {
				return fmt.Errorf("probe durable peer %s returned inventory for %q, want %q",
					target.Name, inventory.Lab, top.Name)
			}
			return nil
		})
		if err != nil {
			s.recordPeerReplication(top.Name, target.Name, err, nextRetry)
			return err
		}
		s.recordPeerReplication(top.Name, target.Name, nil, time.Time{})
	}
	return nil
}

func (s *Server) peerFor(ctx context.Context, node model.NodeSpec) (peerStateClient, error) {
	if s.peerDial != nil {
		return s.peerDial(ctx, node)
	}
	return s.dialPeer(ctx, node)
}

func peerHealthKey(lab, peer string) string { return lab + "/" + peer }

func (s *Server) recordPeerReplication(lab, peer string, err error, nextRetry time.Time) {
	s.peerHealthMu.Lock()
	defer s.peerHealthMu.Unlock()
	if s.peerHealth == nil {
		s.peerHealth = map[string]PeerReplicationStatus{}
	}
	key := peerHealthKey(lab, peer)
	status := s.peerHealth[key]
	status.Lab, status.Peer = lab, peer
	if err == nil {
		status.Healthy = true
		status.Fresh = true
		status.ConsecutiveFailures = 0
		status.LastSuccess = time.Now().UTC()
		status.Error = ""
		status.NextRetry = time.Time{}
	} else {
		status.Healthy = false
		status.Fresh = false
		status.ConsecutiveFailures++
		status.LastFailure = time.Now().UTC()
		status.NextRetry = nextRetry.UTC()
		status.Error = err.Error()
	}
	s.peerHealth[key] = status
}

func (s *Server) peerReplicationStatuses() map[string]PeerReplicationStatus {
	s.peerHealthMu.Lock()
	out := make(map[string]PeerReplicationStatus, len(s.peerHealth))
	for key, status := range s.peerHealth {
		out[key] = status
	}
	s.peerHealthMu.Unlock()

	// A missing acknowledgement is not health. Report required peers for
	// every active lab explicitly rather than making an empty map look like a
	// healthy quorum immediately after a restart.
	s.mu.Lock()
	tops := make([]*model.Topology, 0, len(s.current))
	for _, top := range s.current {
		tops = append(tops, top)
	}
	s.mu.Unlock()
	for _, top := range tops {
		targets, err := s.replicaTargets(top)
		if err != nil {
			key := peerHealthKey(top.Name, "<quorum>")
			if _, exists := out[key]; !exists {
				out[key] = PeerReplicationStatus{Lab: top.Name, Peer: "<quorum>", Error: err.Error()}
			}
			continue
		}
		for _, target := range targets {
			key := peerHealthKey(top.Name, target.Name)
			if _, exists := out[key]; !exists {
				out[key] = PeerReplicationStatus{
					Lab: top.Name, Peer: target.Name,
					Error: "no peer replication acknowledgement recorded",
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadPersistedPeerReplicationHealth retains the last verified acknowledgement
// across an agent restart without falsely treating it as a live connection.
// A fresh inventory handshake is required before Healthy becomes true.
func (s *Server) loadPersistedPeerReplicationHealth(top *model.Topology) {
	if s.store == nil || top == nil {
		return
	}
	replicas, err := s.store.ReplicaStatus(top.Name)
	if err != nil {
		return
	}
	targets, err := s.replicaTargets(top)
	if err != nil {
		return
	}
	s.peerHealthMu.Lock()
	defer s.peerHealthMu.Unlock()
	if s.peerHealth == nil {
		s.peerHealth = map[string]PeerReplicationStatus{}
	}
	for _, target := range targets {
		var last time.Time
		for _, acks := range replicas.Acks {
			for _, ack := range acks {
				if ack.Node == target.Name && ack.Acknowledged.After(last) {
					last = ack.Acknowledged
				}
			}
		}
		if last.IsZero() {
			continue
		}
		key := peerHealthKey(top.Name, target.Name)
		if live := s.peerHealth[key]; live.Fresh {
			continue
		}
		s.peerHealth[key] = PeerReplicationStatus{
			Lab: top.Name, Peer: target.Name, LastSuccess: last,
			Error: "persisted acknowledgement awaiting live peer handshake",
		}
	}
}

// peerHealthLoop establishes authenticated inventory handshakes independently
// of periodic capture. It intentionally includes recovering labs: peer read
// APIs are safe during recovery and simultaneous node restarts must be able to
// form a quorum before any node restores destructively.
func (s *Server) peerHealthLoop(ctx context.Context) {
	s.bootstrapPeerHealth(ctx)
	ticker := time.NewTicker(peerHealthEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.bootstrapPeerHealth(ctx)
		}
	}
}

func (s *Server) bootstrapPeerHealth(ctx context.Context) {
	s.mu.Lock()
	tops := make([]*model.Topology, 0, len(s.current))
	for _, top := range s.current {
		tops = append(tops, top)
	}
	s.mu.Unlock()
	for _, top := range tops {
		if top == nil || top.Lab == nil || top.Lab.State.ReplicationFactor < 2 {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, peerHealthTimeout)
		_ = s.ensurePeerQuorumReachable(probeCtx, top)
		cancel()
	}
}

func (s *Server) peerReplicationRetryDue(lab string) bool {
	now := time.Now()
	s.peerHealthMu.Lock()
	defer s.peerHealthMu.Unlock()
	for _, status := range s.peerHealth {
		if status.Lab != lab || status.Healthy {
			continue
		}
		if status.NextRetry.IsZero() || !now.Before(status.NextRetry) {
			return true
		}
	}
	return false
}

func retryPeer(ctx context.Context, fn func() error) (error, time.Time) { //nolint:staticcheck // callers branch on the error before scheduling its retry time
	delay := peerRetryMin
	var last error
	for attempt := 0; attempt < peerRetryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err, time.Now().UTC()
		}
		if err := fn(); err == nil {
			return nil, time.Time{}
		} else {
			last = err
		}
		if attempt+1 == peerRetryAttempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err(), time.Now().UTC()
		case <-timer.C:
		}
		delay *= 2
		if delay > peerRetryMax {
			delay = peerRetryMax
		}
	}
	if last == nil {
		last = errors.New("peer replication failed without an error")
	}
	return last, time.Now().Add(delay).UTC()
}

func (s *Server) dialPeer(_ context.Context, node model.NodeSpec) (peerStateClient, error) {
	addr := node.Addr
	if addr == "" {
		addr = net.JoinHostPort(node.Name, "7200")
	}
	scheme := "http"
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		scheme, addr = u.Scheme, u.Host
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConnsPerHost: 4,
	}
	if s.cfg.TLSCert != "" || s.cfg.TLSKey != "" || s.cfg.ClientCA != "" {
		if s.cfg.TLSCert == "" || s.cfg.TLSKey == "" || s.cfg.ClientCA == "" {
			return nil, errors.New("peer replication requires complete mutual TLS material")
		}
		certPath, keyPath, _, credentialErr := s.peerTLSPaths(time.Now())
		if credentialErr != nil {
			return nil, credentialErr
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load node peer certificate: %w", err)
		}
		pem, err := os.ReadFile(s.cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read peer CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("peer CA %s has no certificate", s.cfg.ClientCA)
		}
		transport.TLSClientConfig = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			// Bind peer replication to the manifest node identity rather than
			// whichever underlay alias happened to be dialled. Generate always
			// includes NodeSpec.Name in the listener SANs; a mismatch is a
			// fail-closed rollout error, not a reason to disable verification.
			ServerName: node.Name,
		}
		scheme = "https"
	} else if !s.insecureLoopbackMode() {
		return nil, errors.New("peer replication requires mutual TLS; insecure loopback mode must be explicit")
	}
	return &httpPeerStateClient{
		base: scheme + "://" + strings.TrimRight(addr, "/"),
		http: &http.Client{Timeout: 2 * time.Minute, Transport: transport},
	}, nil
}

func (s *Server) peerTLSPaths(now time.Time) (certPath, keyPath string, legacy bool, err error) {
	if (s.cfg.PeerTLSCert == "") != (s.cfg.PeerTLSKey == "") {
		return "", "", false, errors.New("peer replication requires -peer-tls-cert and -peer-tls-key together")
	}
	if s.cfg.PeerTLSCert != "" {
		return s.cfg.PeerTLSCert, s.cfg.PeerTLSKey, false, nil
	}
	if s.cfg.LegacyPeerCertUntil.IsZero() || !now.Before(s.cfg.LegacyPeerCertUntil) {
		return "", "", false, errors.New(
			"peer replication requires a separate peer certificate; the explicit legacy migration deadline is absent or expired")
	}
	if s.cfg.TLSCert == "" || s.cfg.TLSKey == "" {
		return "", "", false, errors.New("legacy peer migration has no listener certificate")
	}
	return s.cfg.TLSCert, s.cfg.TLSKey, true, nil
}

func validatePeerTLSIdentity(node, certPath, keyPath, caPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load peer TLS credential: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("peer TLS credential has no leaf certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse peer TLS leaf: %w", err)
	}
	identity, err := authz.FromCertificate(leaf)
	if err != nil {
		return fmt.Errorf("peer TLS certificate identity: %w", err)
	}
	if identity.Role != authz.RolePeer || !identity.Allows("*", authz.ActionPeerState) {
		return errors.New("peer TLS certificate is not limited to peer-state")
	}
	if leaf.Subject.CommonName != node {
		return fmt.Errorf("peer TLS certificate belongs to node %q, not %q", leaf.Subject.CommonName, node)
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read peer CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("peer CA %s contains no certificate", caPath)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("peer TLS certificate is not trusted for client authentication: %w", err)
	}
	return nil
}

func (s *Server) replicateDurableState(ctx context.Context, top *model.Topology) error {
	targets, err := s.replicaTargets(top)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}
	snapshots, err := s.store.CurrentSnapshots(top.Name)
	if err != nil {
		return err
	}
	records, err := s.store.CurrentRecords(top.Name)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for _, snapshot := range snapshots {
		expected[snapshotStateKey(snapshot)] = snapshot.Digest
	}
	for _, record := range records {
		expected[recordStateKey(record)] = record.Digest
	}
	if len(expected) == 0 {
		return nil
	}
	status := state.ReplicaStatus{Lab: top.Name, Acks: map[string][]state.ReplicaAck{}}
	if old, err := s.store.ReplicaStatus(top.Name); err == nil {
		status = old
	}
	status.Updated = time.Now().UTC()
	if status.Acks == nil {
		status.Acks = map[string][]state.ReplicaAck{}
	}

	for _, target := range targets {
		var inventory PeerStateInventoryResponse
		err, nextRetry := retryPeer(ctx, func() error {
			peer, err := s.peerFor(ctx, target)
			if err != nil {
				return fmt.Errorf("dial durable peer %s: %w", target.Name, err)
			}
			inventory, err = peer.Inventory(ctx, top.Name)
			if err != nil {
				return fmt.Errorf("read durable inventory from %s: %w", target.Name, err)
			}
			return nil
		})
		if err != nil {
			s.recordPeerReplication(top.Name, target.Name, err, nextRetry)
			return err
		}
		have := map[string]string{}
		for _, meta := range inventory.Artifacts {
			have[meta.Key] = meta.Digest
		}
		request := PeerStateRequest{Lab: top.Name, Source: s.cfg.Node}
		for _, snapshot := range snapshots {
			if have[snapshotStateKey(snapshot)] == snapshot.Digest {
				continue
			}
			request.Snapshots = append(request.Snapshots,
				WireSnapshot{Snapshot: snapshot, Content: snapshot.Content})
		}
		for _, record := range records {
			if have[recordStateKey(record)] == record.Digest {
				continue
			}
			request.Records = append(request.Records, WireRecord{Record: record, Content: record.Content})
		}
		acked := have
		if len(request.Snapshots) > 0 || len(request.Records) > 0 {
			var response PeerStateResponse
			err, nextRetry = retryPeer(ctx, func() error {
				peer, err := s.peerFor(ctx, target)
				if err != nil {
					return fmt.Errorf("dial durable peer %s: %w", target.Name, err)
				}
				response, err = peer.Import(ctx, request)
				if err != nil {
					return fmt.Errorf("replicate durable state to %s: %w", target.Name, err)
				}
				return nil
			})
			if err != nil {
				s.recordPeerReplication(top.Name, target.Name, err, nextRetry)
				return err
			}
			for _, ack := range response.Acks {
				acked[ack.Key] = ack.Digest
			}
		}
		now := time.Now().UTC()
		for key, digest := range expected {
			if acked[key] != digest {
				err := fmt.Errorf("peer %s did not acknowledge durable %s digest %s", target.Name, key, digest)
				s.recordPeerReplication(top.Name, target.Name, err, time.Now().Add(peerRetryMin))
				return err
			}
			status.Acks[key] = appendAck(status.Acks[key], state.ReplicaAck{
				Node: target.Name, FailureDomain: target.Domain(), Digest: digest, Acknowledged: now,
			})
		}
		s.recordPeerReplication(top.Name, target.Name, nil, time.Time{})
	}
	if err := s.store.PutReplicaStatus(status); err != nil {
		return fmt.Errorf("persist durable replica acknowledgements: %w", err)
	}
	retention, err := time.ParseDuration(top.Lab.State.ReplicaRetention)
	if err == nil && retention > 0 {
		if _, err := s.store.PruneRetained(top.Name, time.Now().Add(-retention), true); err != nil {
			return fmt.Errorf("garbage collect durable history: %w", err)
		}
	}
	return nil
}

func appendAck(existing []state.ReplicaAck, next state.ReplicaAck) []state.ReplicaAck {
	out := existing[:0]
	for _, old := range existing {
		if old.Node == next.Node {
			continue
		}
		out = append(out, old)
	}
	out = append(out, next)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Digest < out[j].Digest
	})
	return out
}

// durableBoundary turns a failed capture/replication proof into either a hard
// refusal or intentionally loud data-loss audit evidence, according to the
// manifest policy.
func (s *Server) durableBoundary(top *model.Topology, boundary string, err error) error {
	if err == nil {
		return nil
	}
	if top == nil || top.Lab == nil || top.Lab.State.FailClosedEnabled() {
		return fmt.Errorf("%s requires a fresh durable replica quorum: %w", boundary, err)
	}
	slog.Error("AUDIT: durability failure bypassed by fail_closed=false",
		"lab", top.Name, "boundary", boundary, "err", err)
	return nil
}

// StateVerification is the controller-visible result of comparing the
// destination's restored state with the freshly captured source digest.
type StateVerification struct {
	Lab      string   `json:"lab"`
	Device   string   `json:"device"`
	Verified []string `json:"verified"`
}

// StateProof binds the fresh source capture a destination must restore. It is
// persisted with the apply transaction so a controller crash cannot turn a
// later commit into an unverified source prune.
type StateProof struct {
	Device    string         `json:"device"`
	Snapshots []WireSnapshot `json:"snapshots"`
}

// StateVerifyRequest asks an agent to verify every persisted state proof for a
// prepared generation.
type StateVerifyRequest struct {
	Lab        string `json:"lab"`
	Fence      Fence  `json:"fence"`
	Generation string `json:"generation"`
}

// StateVerifyResponse records each device whose restore was verified.
type StateVerifyResponse struct {
	Lab      string              `json:"lab"`
	Verified []StateVerification `json:"verified"`
}

func (s *Server) handleStateVerify(w http.ResponseWriter, r *http.Request) {
	var req StateVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Lab == "" || req.Generation == "" {
		httpError(w, http.StatusBadRequest, errors.New("a lab and generation are required"))
		return
	}
	tx, err := s.transactionForStateVerify(req.Lab, req.Fence, req.Generation)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	var wire Wire
	if err := json.Unmarshal(tx.Requested, &wire); err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("read prepared topology: %w", err))
		return
	}
	top, err := wire.Rehydrate()
	if err != nil {
		httpError(w, http.StatusInternalServerError, fmt.Errorf("rehydrate prepared topology: %w", err))
		return
	}
	response := StateVerifyResponse{Lab: req.Lab}
	for _, proof := range tx.StateProofs {
		device, ok := top.Device(proof.Device)
		if !ok {
			httpError(w, http.StatusConflict, fmt.Errorf("state proof references unknown device %q", proof.Device))
			return
		}
		expected := make([]state.Snapshot, 0, len(proof.Snapshots))
		for _, wireSnapshot := range proof.Snapshots {
			snapshot := wireSnapshot.Snapshot
			snapshot.Content = wireSnapshot.Content
			if snapshot.Lab != req.Lab || snapshot.Device != device.ID {
				httpError(w, http.StatusConflict, fmt.Errorf("state proof for %s does not match this lab/device", proof.Device))
				return
			}
			expected = append(expected, snapshot)
		}
		verified, err := verifyRestoredState(r.Context(), s.rt, device, req.Lab, top.Hash, expected)
		if err != nil {
			httpError(w, http.StatusConflict, fmt.Errorf("verify restored %s: %w", device.ID, err))
			return
		}
		response.Verified = append(response.Verified, StateVerification{
			Lab: req.Lab, Device: device.ID, Verified: verified,
		})
	}
	if err := s.markStateVerified(req.Lab, req.Fence, req.Generation); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, response)
}

// verifyRestoredState captures the destination after restore. Stable files use
// their content digest; dynamic network state uses deploy's typed canonical
// facts so kernel indices, lifetimes, and ordering cannot reject an exact
// restore while a real missing or extra address, route, tunnel, or VLAN does.
func verifyRestoredState(ctx context.Context, r rt.Runtime, device *model.Device,
	lab, topology string, expected []state.Snapshot,
) ([]string, error) {
	got, err := deploy.Capture(ctx, r, device, lab, topology)
	if err != nil {
		return nil, err
	}
	byKind := map[state.Kind]state.Snapshot{}
	for _, snapshot := range got {
		byKind[snapshot.Kind] = snapshot
	}
	var verified []string
	for _, want := range expected {
		have, ok := byKind[want.Kind]
		if !ok {
			return nil, fmt.Errorf("%s restored no %s state", device.ID, want.Kind)
		}
		if want.Kind == state.KindAddrs || want.Kind == state.KindTunnels || want.Kind == state.KindOVS {
			gotCanonical := deploy.CanonicalDynamicSnapshot(want.Kind, string(have.Content))
			wantCanonical := deploy.CanonicalDynamicSnapshot(want.Kind, string(want.Content))
			if gotCanonical == wantCanonical {
				verified = append(verified, string(want.Kind))
				continue
			}
			return nil, fmt.Errorf("%s restored %s dynamic facts differ from captured state",
				device.ID, want.Kind)
		}
		haveDigest := have.Digest
		if haveDigest == "" {
			sum := sha256.Sum256(have.Content)
			haveDigest = hex.EncodeToString(sum[:])
		}
		if haveDigest == want.Digest || equivalentState(have.Content, want.Content) {
			verified = append(verified, string(want.Kind))
			continue
		}
		if (want.Kind == state.KindFRR || want.Kind == state.KindBIRD) &&
			restoredConfigContains(have.Content, want.Content) {
			verified = append(verified, string(want.Kind))
			continue
		}
		return nil, fmt.Errorf("%s restored %s digest %s, expected %s",
			device.ID, want.Kind, haveDigest, want.Digest)
	}
	sort.Strings(verified)
	return verified, nil
}

// restoredAddressesPresent compares the student-replayable address facts, not
// iproute's unstable interface indices, flags, and platform-owned addresses.
// Recovery still requires every saved non-kernel address to be present.
func restoredAddressesPresent(have, want []byte) bool {
	parse := func(raw []byte) map[string]bool {
		out := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line == "---" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			iface := strings.TrimSuffix(fields[1], ":")
			iface, _, _ = strings.Cut(iface, "@")
			for i := 2; i+1 < len(fields); i++ {
				if fields[i] != "inet" && fields[i] != "inet6" {
					continue
				}
				addr := fields[i+1]
				if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "::1") ||
					strings.HasPrefix(addr, "fe80:") {
					continue
				}
				out[iface+"\x00"+addr] = true
			}
		}
		return out
	}
	got, expected := parse(have), parse(want)
	if len(got) != len(expected) {
		return false
	}
	for key := range expected {
		if !got[key] {
			return false
		}
	}
	return true
}

func restoredTunnelsPresent(have, want []byte) bool {
	parse := func(raw []byte) map[string]bool {
		out := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.Contains(line, "remote ") && strings.Contains(line, "local ") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				name := strings.TrimSuffix(fields[0], ":")
				remote, local := "", ""
				for i := range fields {
					if fields[i] == "remote" && i+1 < len(fields) {
						remote = fields[i+1]
					}
					if fields[i] == "local" && i+1 < len(fields) {
						local = fields[i+1]
					}
				}
				if name != "" && remote != "" && local != "" && remote != "any" && local != "any" {
					out["tunnel\x00"+name+"\x00"+remote+"\x00"+local] = true
				}
				continue
			}
			if strings.HasPrefix(line, "default") || strings.Contains(line, " via ") {
				route := strings.Join(strings.Fields(line), " ")
				if before, _, ok := strings.Cut(route, " pref "); ok {
					route = before
				}
				out["route\x00"+route] = true
			}
		}
		return out
	}
	got, expected := parse(have), parse(want)
	if len(got) != len(expected) {
		return false
	}
	for key := range expected {
		if !got[key] {
			return false
		}
	}
	return true
}

// restoredConfigContains accepts daemon reordering and platform-owned extra
// lines while requiring every saved student configuration statement to remain
// present after recovery.
func restoredConfigContains(have, want []byte) bool {
	lines := func(raw []byte) map[string]bool {
		out := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line == "!" || strings.HasPrefix(line, "!") ||
				strings.HasPrefix(line, "Building configuration") ||
				strings.HasPrefix(line, "Current configuration") {
				continue
			}
			line = strings.Join(strings.Fields(line), " ")
			// IPv6 forwarding is restored by the persisted runtime sysctl
			// contract rather than the student snapshot. Legacy FRR captures
			// include this platform-owned line, but recovery intentionally
			// filters it before vtysh replay because current mgmtd rejects the
			// duplicate directive.
			if line == "ipv6 forwarding" || line == "no ipv6 forwarding" ||
				strings.HasPrefix(line, "hostname ") ||
				strings.HasPrefix(line, "frr version ") ||
				strings.HasPrefix(line, "frr defaults ") ||
				line == "service integrated-vtysh-config" ||
				line == "end" {
				continue
			}
			out[line] = true
		}
		return out
	}
	got, expected := lines(have), lines(want)
	for line := range expected {
		if !got[line] {
			return false
		}
	}
	return true
}

func equivalentState(a, b []byte) bool {
	canonical := func(raw []byte) string {
		lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || line == "!" {
				continue
			}
			out = append(out, strings.Join(strings.Fields(line), " "))
		}
		return strings.Join(out, "\n")
	}
	return canonical(a) == canonical(b)
}
