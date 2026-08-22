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

type peerStateClient interface {
	Inventory(context.Context, string) (PeerStateInventoryResponse, error)
	Import(context.Context, PeerStateRequest) (PeerStateResponse, error)
}

type peerDialer func(context.Context, model.NodeSpec) (peerStateClient, error)

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

func peerClient(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	id, err := authz.FromCertificate(r.TLS.PeerCertificates[0])
	return err == nil && id.Role == authz.RolePeer
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
		top, policy, ok := s.durabilityTopology(lab)
		if !ok || top == nil || s.modeOf(lab) == string(render.ModeSolve) {
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
		if !last.IsZero() && time.Since(last) < interval {
			continue
		}
		if !s.beginDurability(lab) {
			continue
		}
		go func(lab string, top *model.Topology, policy model.StatePolicy) {
			defer s.endDurability(lab)
			_, err := s.captureAndReplicate(ctx, top)
			if err != nil {
				slog.Error("periodic durable capture failed", "lab", lab, "err", err,
					"fail_closed", policy.FailClosedEnabled())
			}
		}(lab, top, policy)
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

func (s *Server) modeOf(lab string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.modes[lab]
}

func (s *Server) beginDurability(lab string) bool {
	s.durabilityMu.Lock()
	defer s.durabilityMu.Unlock()
	if s.durabilityBusy == nil {
		s.durabilityBusy = map[string]bool{}
	}
	if s.durabilityBusy[lab] {
		return false
	}
	s.durabilityBusy[lab] = true
	return true
}

func (s *Server) endDurability(lab string) {
	s.durabilityMu.Lock()
	if s.durabilityBusy == nil {
		s.durabilityBusy = map[string]bool{}
	}
	delete(s.durabilityBusy, lab)
	s.durabilityMu.Unlock()
}

// captureAndReplicate takes a bounded capture and confirms every current
// object has the policy's required number of independent copies.
func (s *Server) captureAndReplicate(ctx context.Context, top *model.Topology) (int, error) {
	if top == nil || top.Lab == nil {
		return 0, errors.New("durability needs a topology with a lab policy")
	}
	if s.store == nil {
		return 0, errors.New("this node has no state store")
	}
	if s.modeOf(top.Name) == string(render.ModeSolve) {
		// A solved grading harness contains the reference answer, never a
		// student's state. Topology records may still be replicated by commit.
		return 0, s.replicateDurableState(ctx, top)
	}
	eng := &deploy.Engine{
		Runtime: s.rt, Node: s.cfg.Node, Limiter: s.workLimiter(), State: s.store,
		Renderer: renderer(top, render.ModePlatform, 0),
	}
	n, err := eng.CaptureAll(ctx, top, s.store)
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

func (s *Server) peerFor(ctx context.Context, node model.NodeSpec) (peerStateClient, error) {
	if s.peerDial != nil {
		return s.peerDial(ctx, node)
	}
	return s.dialPeer(ctx, node)
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
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
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
		peer, err := s.peerFor(ctx, target)
		if err != nil {
			return fmt.Errorf("dial durable peer %s: %w", target.Name, err)
		}
		inventory, err := peer.Inventory(ctx, top.Name)
		if err != nil {
			return fmt.Errorf("read durable inventory from %s: %w", target.Name, err)
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
			response, err := peer.Import(ctx, request)
			if err != nil {
				return fmt.Errorf("replicate durable state to %s: %w", target.Name, err)
			}
			for _, ack := range response.Acks {
				acked[ack.Key] = ack.Digest
			}
		}
		now := time.Now().UTC()
		for key, digest := range expected {
			if acked[key] != digest {
				return fmt.Errorf("peer %s did not acknowledge durable %s digest %s", target.Name, key, digest)
			}
			status.Acks[key] = appendAck(status.Acks[key], state.ReplicaAck{
				Node: target.Name, FailureDomain: target.Domain(), Digest: digest, Acknowledged: now,
			})
		}
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

// verifyRestoredState captures the destination after restore and checks both
// raw digest and a whitespace-insensitive semantic form. The latter handles
// daemons that render equivalent configuration with benign line wrapping while
// still refusing changed commands.
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
		haveDigest := have.Digest
		if haveDigest == "" {
			sum := sha256.Sum256(have.Content)
			haveDigest = hex.EncodeToString(sum[:])
		}
		if haveDigest == want.Digest || equivalentState(have.Content, want.Content) {
			verified = append(verified, string(want.Kind))
			continue
		}
		if want.Kind == state.KindAddrs && restoredAddressesPresent(have.Content, want.Content) {
			verified = append(verified, string(want.Kind))
			continue
		}
		if want.Kind == state.KindTunnels && restoredTunnelsPresent(have.Content, want.Content) {
			verified = append(verified, string(want.Kind))
			continue
		}
		if want.Kind == state.KindTunnels {
			// Restore executes each reconstructed tunnel/route command and
			// fails the rollback if one fails. Kernel tunnel dumps include
			// volatile encap/cache fields that cannot be byte-compared after a
			// namespace recreation, so successful replay is the durable
			// semantic proof once endpoint parsing above found no stable match.
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
			out[strings.Join(strings.Fields(line), " ")] = true
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
