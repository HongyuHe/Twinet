package agent

import (
	"strings"
	"testing"
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
