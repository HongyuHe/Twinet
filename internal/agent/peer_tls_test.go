package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/pki"
)

// This is an end-to-end TLS test rather than a peerAuth unit test: the client
// loads the replication-only leaf from disk, verifies the server by its
// manifest node name, and the receiver verifies the peer role. It catches the
// rollout failure where agents accidentally presented their server leaf and
// every remote endpoint answered "bad certificate".
func TestPeerTLSMutualVerificationAndRollingLeafRotation(t *testing.T) {
	dir := t.TempDir()
	bundle, err := pki.Generate(dir, map[string][]string{
		"node-0": {"node-0", "127.0.0.1", "localhost"},
		"node-1": {"node-1", "127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}

	{
		dir := t.TempDir()
		bundle, err := pki.Generate(dir, map[string][]string{
			"node-0": {"node-0", "127.0.0.1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePeerTLSIdentity("node-0", bundle.Peers["node-0"].CertPath,
			bundle.Peers["node-0"].KeyPath, bundle.CA.CertPath); err != nil {
			t.Fatalf("generated peer credential was rejected: %v", err)
		}
		if err := validatePeerTLSIdentity("node-0", bundle.Nodes["node-0"].CertPath,
			bundle.Nodes["node-0"].KeyPath, bundle.CA.CertPath); err == nil {
			t.Fatal("listener certificate was accepted as a peer replication identity")
		}
	}
	ca, err := os.ReadFile(bundle.CA.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("cluster CA did not parse")
	}
	serverCert, err := tls.LoadX509KeyPair(bundle.Nodes["node-1"].CertPath, bundle.Nodes["node-1"].KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Server{cfg: Config{Node: "node-1"}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/peer/state/inventory", receiver.peerAuth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, PeerStateInventoryResponse{Lab: "tls-probe"})
	}))
	httpServer := httptest.NewUnstartedServer(mux)
	httpServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
	}
	httpServer.StartTLS()
	defer httpServer.Close()

	source := &Server{cfg: Config{
		Node: "node-0", TLSCert: bundle.Nodes["node-0"].CertPath, TLSKey: bundle.Nodes["node-0"].KeyPath,
		ClientCA:    bundle.CA.CertPath,
		PeerTLSCert: bundle.Peers["node-0"].CertPath, PeerTLSKey: bundle.Peers["node-0"].KeyPath,
	}}
	target := model.NodeSpec{Name: "node-1", Addr: httpServer.URL}
	probe := func() {
		peer, err := source.dialPeer(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Inventory(context.Background(), "tls-probe"); err != nil {
			t.Fatalf("mutual peer TLS inventory: %v", err)
		}
	}
	probe()
	if _, err := pki.IssueNodePeer(dir, dir, "node-0", time.Hour); err != nil {
		t.Fatal(err)
	}
	probe()
}
