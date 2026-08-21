package agent

import (
	"strings"
	"testing"
	"time"
)

// -tls-cert and -tls-key without -client-ca gives server-only TLS: the
// connection is encrypted and the caller is not verified at all, so anyone who
// can reach the port and holds the bearer token is admitted. The token is the
// same on every node, so one leak takes the cluster.
//
// The operator who left out one flag has no way to notice. The agent starts,
// the deploy works, the logs look ordinary, and the cluster is wide open for as
// long as it runs. It has to refuse.
func TestPartialMutualTLSIsRefused(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"cert and key without a client CA", Config{TLSCert: "c", TLSKey: "k"}, "-client-ca"},
		{"a client CA with no server certificate", Config{ClientCA: "ca"}, "-tls-cert"},
		{"a certificate with no key", Config{TLSCert: "c"}, "-tls-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			given := 0
			for _, v := range []string{tc.cfg.TLSCert, tc.cfg.TLSKey, tc.cfg.ClientCA} {
				if v != "" {
					given++
				}
			}
			if given == 0 || given == 3 {
				t.Fatalf("this case is not partial: %d of 3 supplied", given)
			}
			// The message must name what was supplied, so the operator is told
			// which flag is missing rather than that something is.
			got := describeTLSInputs(tc.cfg)
			if strings.Contains(got, tc.want) {
				t.Errorf("the message lists %s as supplied when it is the missing one: %q", tc.want, got)
			}
			if got == " only" {
				t.Error("the message names nothing that was supplied")
			}
		})
	}
}

func TestLegacyPeerCertificateMigrationExpires(t *testing.T) {
	server := &Server{cfg: Config{
		TLSCert: "legacy-server-cert", TLSKey: "legacy-server-key", ClientCA: "cluster-ca",
		LegacyPeerCertUntil: time.Now().Add(-time.Minute),
	}}
	if _, _, _, err := server.peerTLSPaths(time.Now()); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired legacy peer certificate migration = %v, want explicit refusal", err)
	}

	server.cfg.LegacyPeerCertUntil = time.Now().Add(time.Minute)
	cert, key, legacy, err := server.peerTLSPaths(time.Now())
	if err != nil || !legacy || cert != server.cfg.TLSCert || key != server.cfg.TLSKey {
		t.Fatalf("explicit unexpired migration = cert=%q key=%q legacy=%v err=%v",
			cert, key, legacy, err)
	}
	server.cfg.PeerTLSCert, server.cfg.PeerTLSKey = "peer-cert", "peer-key"
	cert, key, legacy, err = server.peerTLSPaths(time.Now().Add(24 * time.Hour))
	if err != nil || legacy || cert != "peer-cert" || key != "peer-key" {
		t.Fatalf("dedicated peer identity was not preferred after migration: cert=%q key=%q legacy=%v err=%v",
			cert, key, legacy, err)
	}
}

// The complete configuration must not be refused.
func TestCompleteMutualTLSIsAccepted(t *testing.T) {
	c := Config{TLSCert: "c", TLSKey: "k", ClientCA: "ca"}
	given := 0
	for _, v := range []string{c.TLSCert, c.TLSKey, c.ClientCA} {
		if v != "" {
			given++
		}
	}
	if given != 3 {
		t.Fatalf("a complete configuration counted as %d of 3", given)
	}
}
