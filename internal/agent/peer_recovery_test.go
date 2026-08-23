package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/pki"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestPersistedPeerAckRequiresFreshLiveHandshake(t *testing.T) {
	top, _ := durableTopology()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ack := time.Now().Add(-time.Minute).UTC()
	if err := store.PutReplicaStatus(state.ReplicaStatus{
		Lab: top.Name,
		Acks: map[string][]state.ReplicaAck{
			"snapshot/as1/R/frr": {{Node: "n1", FailureDomain: "rack-b", Digest: "old", Acknowledged: ack}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	peerStore, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := durabilityServer(t, top, store, nil, &durablePeerFake{store: peerStore})
	server.loadPersistedPeerReplicationHealth(top)
	before := server.peerReplicationStatuses()[peerHealthKey(top.Name, "n1")]
	if before.LastSuccess != ack || before.Healthy || before.Fresh {
		t.Fatalf("persisted peer acknowledgement was not retained as stale: %+v", before)
	}
	server.transactions = map[string]applyTransaction{
		top.Name: {Generation: "failed", Phase: transactionRecovering},
	}
	server.bootstrapPeerHealth(context.Background())
	after := server.peerReplicationStatuses()[peerHealthKey(top.Name, "n1")]
	if !after.Healthy || !after.Fresh || after.LastSuccess.Before(ack) {
		t.Fatalf("live peer handshake did not refresh persisted health: %+v", after)
	}
}

func TestRecoveryFetchesOnlyManifestVerifiedReplica(t *testing.T) {
	top, device := durableTopology()
	local, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	replica, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replica.Put(state.Snapshot{
		Lab: top.Name, Device: device.ID, Kind: state.KindFRR, Content: []byte("router bgp 1\n"),
	}); err != nil {
		t.Fatal(err)
	}
	want, err := replica.Current(top.Name, device.ID, state.KindFRR)
	if err != nil {
		t.Fatal(err)
	}
	server := durabilityServer(t, top, local, nil, &durablePeerFake{store: replica})
	tx := applyTransaction{Prestate: transactionInventory{Snapshots: []transactionSnapshot{{
		Device: device.ID, Kind: string(state.KindFRR), Digest: want.Digest,
	}}}}
	if err := server.fetchRecoveryReplicas(context.Background(), top, tx); err != nil {
		t.Fatal(err)
	}
	got, err := local.Current(top.Name, device.ID, state.KindFRR)
	if err != nil || got.Digest != want.Digest {
		t.Fatalf("verified recovery replica = %+v, %v; want %s", got, err, want.Digest)
	}
}

func TestSimultaneousPendingRecoveriesBootstrapPeerQuorum(t *testing.T) {
	top, _ := durableTopology()
	top.Lab.Placement.Nodes = append(top.Lab.Placement.Nodes,
		model.NodeSpec{Name: "n2", FailureDomain: "rack-c"})
	peers := map[string]*durablePeerFake{}
	for _, node := range top.Lab.Placement.Nodes {
		store, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		peers[node.Name] = &durablePeerFake{store: store}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(top.Lab.Placement.Nodes))
	for _, node := range top.Lab.Placement.Nodes {
		node := node
		server := &Server{
			cfg: Config{Node: node.Name}, current: map[string]*model.Topology{top.Name: top},
			transactions: map[string]applyTransaction{top.Name: {Generation: "failed", Phase: transactionRecovering}},
		}
		server.peerDial = func(_ context.Context, target model.NodeSpec) (peerStateClient, error) {
			peer := peers[target.Name]
			if peer == nil {
				return nil, errors.New("missing peer")
			}
			return peer, nil
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- server.waitForRecoveryPeerQuorum(context.Background(), top)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("simultaneous recovering node did not form peer quorum: %v", err)
		}
	}
}

func TestSimultaneousPendingRecoveriesBootstrapRotatedPeerCertificates(t *testing.T) {
	dir := t.TempDir()
	bundle, err := pki.Generate(dir, map[string][]string{
		"n0": {"n0", "127.0.0.1", "localhost"},
		"n1": {"n1", "127.0.0.1", "localhost"},
		"n2": {"n2", "127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(bundle.CA.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("generated CA did not parse")
	}
	top, _ := durableTopology()
	top.Lab.Placement.Nodes = append(top.Lab.Placement.Nodes,
		model.NodeSpec{Name: "n2", FailureDomain: "rack-c"})
	servers := map[string]*httptest.Server{}
	agents := map[string]*Server{}
	for _, node := range top.Lab.Placement.Nodes {
		store, err := state.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		agent := &Server{
			cfg: Config{
				Node: node.Name, TLSCert: bundle.Nodes[node.Name].CertPath, TLSKey: bundle.Nodes[node.Name].KeyPath,
				ClientCA:    bundle.CA.CertPath,
				PeerTLSCert: bundle.Peers[node.Name].CertPath, PeerTLSKey: bundle.Peers[node.Name].KeyPath,
			},
			store: store, current: map[string]*model.Topology{top.Name: top},
			transactions: map[string]applyTransaction{top.Name: {Generation: "failed", Phase: transactionRecovering}},
			holds:        map[string]*hold{}, exempt: map[string]*exemptions{},
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/peer/state/inventory", agent.peerAuth(agent.handlePeerStateInventory))
		mux.HandleFunc("GET /v1/peer/state", agent.peerAuth(agent.handlePeerStateRead))
		mux.HandleFunc("POST /v1/peer/state", agent.peerAuth(agent.handlePeerStateImport))
		cert, err := tls.LoadX509KeyPair(bundle.Nodes[node.Name].CertPath, bundle.Nodes[node.Name].KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(mux)
		server.TLS = &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
			ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		}
		server.StartTLS()
		servers[node.Name], agents[node.Name] = server, agent
		defer server.Close()
	}
	for i := range top.Lab.Placement.Nodes {
		node := &top.Lab.Placement.Nodes[i]
		node.Addr = servers[node.Name].URL
		if _, err := pki.IssueNodePeer(dir, dir, node.Name, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(agents))
	for _, agent := range agents {
		agent := agent
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- agent.waitForRecoveryPeerQuorum(context.Background(), top)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("rotated simultaneous recovery did not form quorum: %v", err)
		}
	}
	for node, agent := range agents {
		targets, err := agent.replicaTargets(top)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range targets {
			status := agent.peerReplicationStatuses()[peerHealthKey(top.Name, target.Name)]
			if !status.Healthy || !status.Fresh {
				t.Fatalf("%s did not establish fresh rotated peer health to %s: %+v",
					node, target.Name, status)
			}
		}
	}
}

func TestRecoveredControlsMustBeRunningAndExact(t *testing.T) {
	control := rt.Spec{
		Name: "router-frr",
		Labels: map[string]string{
			deploy.LabelSpec:            "control-spec",
			deploy.LabelRuntimeContract: deploy.RuntimeSpecContractVersion,
			deploy.LabelManaged:         "true",
			deploy.LabelInternal:        "true",
			deploy.LabelFRRControl:      "true",
			deploy.LabelLab:             "lab",
		},
	}
	runtime := &controlRecoveryRuntime{containers: map[string]rt.Container{
		control.Name: {Name: control.Name, State: rt.StateRunning, Labels: control.Labels},
	}}
	server := &Server{rt: runtime}
	tx := applyTransaction{Prestate: transactionInventory{RuntimeSpecs: []transactionRuntimeSpec{{
		DeviceID: "as1/R", Control: &control,
	}}}}
	if err := server.verifyRecoveredControls(context.Background(), "lab", tx); err != nil {
		t.Fatal(err)
	}
	runtime.containers[control.Name] = rt.Container{Name: control.Name, State: rt.StateAbsent}
	if err := server.verifyRecoveredControls(context.Background(), "lab", tx); err == nil {
		t.Fatal("missing expected FRR control sidecar passed recovery verification")
	}
	runtime.containers[control.Name] = rt.Container{
		Name: control.Name, State: rt.StateRunning, Labels: control.Labels,
	}
	runtime.containers["orphan-frr"] = rt.Container{
		Name: "orphan-frr", State: rt.StateRunning,
		Labels: map[string]string{
			deploy.LabelManaged: "true", deploy.LabelInternal: "true",
			deploy.LabelFRRControl: "true", deploy.LabelLab: "lab",
		},
	}
	if err := server.verifyRecoveredControls(context.Background(), "lab", tx); err == nil {
		t.Fatal("unexpected FRR control sidecar passed recovery verification")
	}
}

type controlRecoveryRuntime struct {
	rt.Runtime
	containers map[string]rt.Container
}

func (r *controlRecoveryRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	if container, ok := r.containers[name]; ok {
		return container, nil
	}
	return rt.Container{Name: name, State: rt.StateAbsent}, nil
}

func (r *controlRecoveryRuntime) List(_ context.Context, _ rt.Filter) ([]rt.Container, error) {
	out := make([]rt.Container, 0, len(r.containers))
	for _, container := range r.containers {
		if container.State != rt.StateAbsent {
			out = append(out, container)
		}
	}
	rt.SortContainers(out)
	return out, nil
}
