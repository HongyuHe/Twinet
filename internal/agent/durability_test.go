package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/pki"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

type durablePeerFake struct {
	store    *state.Store
	mu       sync.Mutex
	imports  int
	omitAcks bool
}

func (p *durablePeerFake) Inventory(_ context.Context, lab string) (PeerStateInventoryResponse, error) {
	artifacts, err := p.store.CurrentArtifactMeta(lab)
	return PeerStateInventoryResponse{Lab: lab, Artifacts: artifacts}, err
}

func (p *durablePeerFake) Import(_ context.Context, req PeerStateRequest) (PeerStateResponse, error) {
	p.mu.Lock()
	p.imports++
	omit := p.omitAcks
	p.mu.Unlock()
	var response PeerStateResponse
	for _, wire := range req.Snapshots {
		snapshot := wire.Snapshot
		snapshot.Content = wire.Content
		if _, err := p.store.Put(snapshot); err != nil {
			return PeerStateResponse{}, err
		}
		if !omit {
			response.Acks = append(response.Acks, StateAck{
				Key: snapshotStateKey(snapshot), Digest: snapshot.Digest,
			})
		}
	}
	for _, wire := range req.Records {
		record := wire.Record
		record.Content = wire.Content
		if _, err := p.store.PutRecord(record); err != nil {
			return PeerStateResponse{}, err
		}
		if !omit {
			response.Acks = append(response.Acks, StateAck{
				Key: recordStateKey(record), Digest: record.Digest,
			})
		}
	}
	return response, nil
}

func (p *durablePeerFake) importCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.imports
}

func durableTopology() (*model.Topology, *model.Device) {
	lab := &model.Lab{
		Metadata: model.Meta{Name: "durable"},
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "n0", FailureDomain: "rack-a", Front: true},
			{Name: "n1", FailureDomain: "rack-b"},
		}},
		State: model.StatePolicy{
			ReplicationFactor: 2, CaptureInterval: "1h", ReplicaRetention: "168h",
		},
	}
	lab.Normalize()
	device := &model.Device{
		ID: "as1/R", Name: "R", Container: "twinet-durable-as1-r",
		Kind: model.KindRouter, ASN: 1, Node: "n0",
	}
	as := &model.AS{ASN: 1, Role: model.RoleStudent, Devices: []*model.Device{device}, Routers: []*model.Device{device}}
	top := &model.Topology{
		Lab: lab, Name: "durable", Hash: "topology",
		Devices: map[string]*model.Device{device.ID: device},
		ASes:    map[int]*model.AS{1: as}, Services: map[string]*model.Service{},
	}
	return top, device
}

func durabilityServer(t *testing.T, top *model.Topology, store *state.Store, runtime rt.Runtime,
	peer *durablePeerFake,
) *Server {
	t.Helper()
	return &Server{
		cfg:            Config{Node: "n0"},
		store:          store,
		rt:             runtime,
		current:        map[string]*model.Topology{top.Name: top},
		modes:          map[string]string{},
		ungraded:       map[string]int{},
		peers:          map[string]map[string]string{},
		ops:            map[string]*lease{},
		holds:          map[string]*hold{},
		lastCapture:    map[string]time.Time{},
		durabilityBusy: map[string]bool{},
		peerDial: func(context.Context, model.NodeSpec) (peerStateClient, error) {
			return peer, nil
		},
	}
}

func TestDurableReplicationUsesDigestInventoryAndAcknowledgements(t *testing.T) {
	top, device := durableTopology()
	source, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peerStore, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot{Lab: top.Name, Device: device.ID, Kind: state.KindFRR,
		Content: []byte("router bgp 1\n")}
	if _, err := source.Put(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := source.PutTopology(top.Name, []byte(`{"mode":"platform"}`)); err != nil {
		t.Fatal(err)
	}
	peer := &durablePeerFake{store: peerStore}
	server := durabilityServer(t, top, source, nil, peer)

	if err := server.replicateDurableState(t.Context(), top); err != nil {
		t.Fatalf("initial durable replication failed: %v", err)
	}
	got, err := peerStore.Current(top.Name, device.ID, state.KindFRR)
	if err != nil {
		t.Fatalf("replica has no snapshot: %v", err)
	}
	if got.Digest == "" || string(got.Content) != "router bgp 1\n" {
		t.Fatalf("replica changed state: %+v", got)
	}
	if _, err := peerStore.CurrentRecord(top.Name, state.RecordTopology); err != nil {
		t.Fatalf("replica has no topology/mode record: %v", err)
	}
	first := peer.importCount()
	if err := server.replicateDurableState(t.Context(), top); err != nil {
		t.Fatalf("unchanged replication failed: %v", err)
	}
	if got := peer.importCount(); got != first {
		t.Fatalf("unchanged snapshots were transmitted again: %d imports, want %d", got, first)
	}

	peer.omitAcks = true
	if _, err := source.Put(state.Snapshot{Lab: top.Name, Device: device.ID, Kind: state.KindFRR,
		Content: []byte("router bgp 1\n neighbor 10.0.0.2 remote-as 2\n")}); err != nil {
		t.Fatal(err)
	}
	if err := server.replicateDurableState(t.Context(), top); err == nil {
		t.Fatal("replication accepted an HTTP success without the receiver digest acknowledgement")
	}
}

func TestDurabilityRequiresSeparateFailureDomains(t *testing.T) {
	top, _ := durableTopology()
	top.Lab.Placement.Nodes[1].FailureDomain = top.Lab.Placement.Nodes[0].FailureDomain
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peer := &durablePeerFake{store: store}
	server := durabilityServer(t, top, store, nil, peer)
	if _, err := server.replicaTargets(top); err == nil {
		t.Fatal("two copies in one failure domain were accepted as durable replication")
	}
}

type captureRuntime struct {
	rt.Runtime
	fail bool
}

func (r *captureRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (r *captureRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	if r.fail {
		return rt.ExecResult{}, errors.New("simulated source capture failure")
	}
	if len(cmd.Cmd) > 0 && cmd.Cmd[0] == "vtysh" {
		return rt.ExecResult{Stdout: "router bgp 1\n"}, nil
	}
	return rt.ExecResult{Stdout: ""}, nil
}

func TestFreshExportRefusesStaleFallbackUnlessExplicitlyRequested(t *testing.T) {
	top, device := durableTopology()
	source, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	{
		bundle, err := pki.Generate(t.TempDir(), map[string][]string{
			"n0": {"127.0.0.1", "localhost"},
		})
		if err != nil {
			t.Fatal(err)
		}
		serverCert, err := tls.LoadX509KeyPair(bundle.Nodes["n0"].CertPath, bundle.Nodes["n0"].KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		caPEM, err := os.ReadFile(bundle.CA.CertPath)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			t.Fatal("bad generated CA")
		}
		agentServer := &Server{cfg: Config{Token: "secret"}}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /peer", agentServer.peerAuth(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		mux.HandleFunc("GET /controller", agentServer.auth(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		httpServer := httptest.NewUnstartedServer(mux)
		httpServer.TLS = &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
			ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		}
		httpServer.StartTLS()
		defer httpServer.Close()
		clientFor := func(certPath, keyPath string) *http.Client {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
			}}}
		}
		peerClient := clientFor(bundle.Nodes["n0"].CertPath, bundle.Nodes["n0"].KeyPath)
		peerResponse, err := peerClient.Get(httpServer.URL + "/peer")
		if err != nil {
			t.Fatalf("peer certificate was not accepted by peer-only API: %v", err)
		}
		_ = peerResponse.Body.Close()
		if peerResponse.StatusCode != http.StatusNoContent {
			t.Fatalf("peer request status %d, want %d", peerResponse.StatusCode, http.StatusNoContent)
		}
		controllerResponse, err := clientFor(bundle.Client.CertPath, bundle.Client.KeyPath).Get(httpServer.URL + "/peer")
		if err != nil {
			t.Fatal(err)
		}
		_ = controllerResponse.Body.Close()
		if controllerResponse.StatusCode != http.StatusForbidden {
			t.Fatalf("controller certificate reached peer-only API with status %d", controllerResponse.StatusCode)
		}
		controllerRequest, err := http.NewRequest(http.MethodGet, httpServer.URL+"/controller", nil)
		if err != nil {
			t.Fatal(err)
		}
		controllerRequest.Header.Set("Authorization", "Bearer secret")
		peerControllerResponse, err := peerClient.Do(controllerRequest)
		if err != nil {
			t.Fatal(err)
		}
		_ = peerControllerResponse.Body.Close()
		if peerControllerResponse.StatusCode != http.StatusForbidden {
			t.Fatalf("peer certificate impersonated a controller with status %d", peerControllerResponse.StatusCode)
		}
	}
	peerStore, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Put(state.Snapshot{Lab: top.Name, Device: device.ID, Kind: state.KindFRR,
		Content: []byte("old state\n")}); err != nil {
		t.Fatal(err)
	}
	if err := source.PutTopology(top.Name, []byte(`{"mode":"platform"}`)); err != nil {
		t.Fatal(err)
	}
	peer := &durablePeerFake{store: peerStore}
	runtime := &captureRuntime{fail: true}
	server := durabilityServer(t, top, source, runtime, peer)

	fresh := httptest.NewRecorder()
	server.handleStateExport(fresh, httptest.NewRequest("GET", "/v1/state?lab=durable&device=as1%2FR", nil))
	if fresh.Code < 400 {
		t.Fatalf("fresh export silently returned the old snapshot: %d %s", fresh.Code, fresh.Body.String())
	}

	stored := httptest.NewRecorder()
	server.handleStateExport(stored, httptest.NewRequest("GET", "/v1/state?lab=durable&device=as1%2FR&fresh=false", nil))
	if stored.Code != 200 {
		t.Fatalf("explicit stored export failed: %d %s", stored.Code, stored.Body.String())
	}
	var response StateExportResponse
	if err := json.NewDecoder(stored.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.FreshAt.IsZero() {
		t.Fatal("stored export claimed a fresh capture")
	}
	if len(response.Snapshots) != 1 || string(response.Snapshots[0].Content) != "old state\n" {
		t.Fatalf("stored export did not expose the known replica: %+v", response)
	}
}
