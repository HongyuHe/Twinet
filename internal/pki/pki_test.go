package pki

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// The agent API creates privileged containers and rewires hosts. A shared
// bearer token over plain HTTP is replayable by anyone who sees one request,
// identical on every node so one leak compromises the cluster, and leaves the
// agent unauthenticated to the caller -- so anything that can occupy the port
// collects tokens. These tests check that the material actually enforces what
// it claims, rather than merely existing.
func TestMutualTLSRefusesAnUnknownClient(t *testing.T) {
	dir := t.TempDir()
	b, err := Generate(dir, map[string][]string{"node-0": {"127.0.0.1", "localhost"}})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cert, err := tls.LoadX509KeyPair(b.Nodes["node-0"].CertPath, b.Nodes["node-0"].KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(b.CA.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate does not parse")
	}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	// The issued client is admitted.
	clientCert, err := tls.LoadX509KeyPair(b.Client.CertPath, b.Client.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	ok := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: pool, MinVersion: tls.VersionTLS13,
	}}}
	res, err := ok.Get(srv.URL)
	if err != nil {
		t.Fatalf("the issued controller certificate was refused: %v", err)
	}
	_ = res.Body.Close()

	// A caller with no certificate is refused. This is the case a bearer token
	// cannot express: possession of a secret is not identity.
	bad := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, MinVersion: tls.VersionTLS13,
	}}}
	if resp, err := bad.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Error("a client with no certificate was admitted to a privileged API")
	}

	// A certificate from a different CA is refused, so an attacker cannot
	// simply issue themselves one.
	other := t.TempDir()
	ob, err := Generate(other, map[string][]string{"node-0": {"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	otherCert, err := tls.LoadX509KeyPair(ob.Client.CertPath, ob.Client.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	imposter := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{otherCert}, RootCAs: pool, MinVersion: tls.VersionTLS13,
	}}}
	if resp, err := imposter.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Error("a certificate from an unrelated CA was admitted")
	}
}

// Each node gets its own key. One shared server certificate would recreate the
// property that makes the bearer token unacceptable: a single compromised
// machine able to impersonate every other.
func TestEachNodeHasItsOwnKey(t *testing.T) {
	dir := t.TempDir()
	b, err := Generate(dir, map[string][]string{
		"node-0": {"10.0.1.1"}, "node-1": {"10.0.1.2"}, "node-2": {"10.0.1.3"},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for name, m := range b.Nodes {
		raw, err := os.ReadFile(m.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := seen[string(raw)]; ok {
			t.Errorf("%s and %s share a private key", name, prev)
		}
		seen[string(raw)] = name

		info, err := os.Stat(m.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s key is mode %o; a key readable by anyone on the machine is not private", name, mode)
		}
	}
}

// A server certificate must name the address it is reached at, or every client
// has to be told to skip verification and the whole exercise is theatre.
func TestServerCertificatesCarryTheirAddresses(t *testing.T) {
	dir := t.TempDir()
	b, err := Generate(dir, map[string][]string{"node-1": {"10.0.1.2", "node-1"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(b.Nodes["node-1"].CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatal("cannot parse the issued certificate")
	}
	cert, err := tls.LoadX509KeyPair(b.Nodes["node-1"].CertPath, b.Nodes["node-1"].KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("10.0.1.2"); err != nil {
		t.Errorf("the certificate does not cover the address it is served on: %v", err)
	}
	if err := leaf.VerifyHostname("node-1"); err != nil {
		t.Errorf("the certificate does not cover the node name: %v", err)
	}
	if net.ParseIP("10.0.1.2") == nil {
		t.Fatal("test address is malformed")
	}
}
