package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/authz"
	"github.com/HongyuHe/twinet/internal/pki"
)

func TestCertificateScopeCannotBeWidenedByBearerToken(t *testing.T) {
	dir := t.TempDir()
	bundle, err := pki.Generate(dir, map[string][]string{"node-0": {"127.0.0.1", "localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := pki.IssueScoped(dir, t.TempDir(), "ta-lab-a", authz.RoleOperator,
		[]string{"lab-a"}, []string{authz.ActionDeploy}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := pki.IssueDiagnostic(dir, t.TempDir(), "lab-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{cfg: Config{Node: "node-0", Token: "cluster-token"}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /deploy", server.authorize(endpointPolicy{
		Action: authz.ActionDeploy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDeploy),
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /destroy", server.authorize(endpointPolicy{
		Action: authz.ActionDestroy, Mutation: true, ResolveRequest: scopeFromJSONLab(authz.ActionDestroy),
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /observe", server.authorize(endpointPolicy{
		Action: authz.ActionObserve, ResolveRequest: scopeFromQuery(authz.ActionObserve, false),
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	serverCert, err := tls.LoadX509KeyPair(bundle.Nodes["node-0"].CertPath, bundle.Nodes["node-0"].KeyPath)
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
	httpServer := httptest.NewUnstartedServer(mux)
	httpServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	}
	httpServer.StartTLS()
	defer httpServer.Close()

	clientFor := func(cert, key string) *http.Client {
		t.Helper()
		pair, loadErr := tls.LoadX509KeyPair(cert, key)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair},
		}}}
	}
	request := func(client *http.Client, method, path, body string) int {
		t.Helper()
		req, requestErr := http.NewRequest(method, httpServer.URL+path, bytes.NewBufferString(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer cluster-token")
		req.Header.Set("Content-Type", "application/json")
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	ta := clientFor(operator.CertPath, operator.KeyPath)
	if got := request(ta, http.MethodPost, "/deploy",
		`{"lab":"lab-a","generation":"g-1","fence":{"generation":7}}`); got != http.StatusNoContent {
		t.Fatalf("scoped operator deploy in its lab = %d, want %d", got, http.StatusNoContent)
	}
	if got := request(ta, http.MethodPost, "/deploy", `{"lab":"lab-b"}`); got != http.StatusForbidden {
		t.Fatalf("operator crossed labs with shared bearer token: %d", got)
	}
	if got := request(ta, http.MethodPost, "/destroy", `{"lab":"lab-a"}`); got != http.StatusForbidden {
		t.Fatalf("operator performed an ungranted action with shared bearer token: %d", got)
	}

	diag := clientFor(diagnostic.CertPath, diagnostic.KeyPath)
	if got := request(diag, http.MethodPost, "/deploy", `{"lab":"lab-a"}`); got != http.StatusForbidden {
		t.Fatalf("diagnostic certificate used a stolen full bearer token to deploy: %d", got)
	}
	if got := request(diag, http.MethodGet, "/observe?lab=lab-a", ""); got != http.StatusNoContent {
		t.Fatalf("diagnostic certificate could not observe its own lab: %d", got)
	}

	peer := clientFor(bundle.Peers["node-0"].CertPath, bundle.Peers["node-0"].KeyPath)
	if got := request(peer, http.MethodPost, "/deploy", `{"lab":"lab-a"}`); got != http.StatusForbidden {
		t.Fatalf("peer identity impersonated a controller: %d", got)
	}

	events, _ := server.eventLog().after(0, "lab-a", 20)
	var audit Event
	for _, event := range events {
		if event.Action == authz.ActionDeploy && event.Result == "success" {
			audit = event
			break
		}
	}
	if audit.Identity != "operator:ta-lab-a" || audit.CertificateSerial == "" ||
		audit.Target != "lab-a" || audit.Lab != "lab-a" ||
		audit.Generation != "g-1" || audit.FenceGeneration != 7 {
		t.Fatalf("privileged audit event omitted certificate identity fields: %#v", audit)
	}
}

func TestAuditEventsRedactBearerAndSecrets(t *testing.T) {
	server := &Server{cfg: Config{Node: "node-0"}}
	event := server.recordEvent("lab-a", "generation", "api", "", "mutation", "error",
		"Bearer credential-value token=another-value secret=third-value")
	if event.Detail == "" || bytes.Contains([]byte(event.Detail), []byte("credential-value")) ||
		bytes.Contains([]byte(event.Detail), []byte("another-value")) ||
		bytes.Contains([]byte(event.Detail), []byte("third-value")) {
		t.Fatalf("event detail leaked credential material: %q", event.Detail)
	}
}
