package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestBootstrapProducesOnlyASecureUnderlayBoundAgent(t *testing.T) {
	script := bootstrapScript(model.NodeSpec{
		Name: "node-1", Addr: "10.0.1.2:7200", UnderlayIP: "10.0.1.2",
	}, "top secret", "/tmp/pki")

	for _, want := range []string{
		"-listen 10.0.1.2:7200",
		"-tls-cert /etc/twinet/pki/server_cert.pem",
		"-tls-key /etc/twinet/pki/server_key.pem",
		"-client-ca /etc/twinet/pki/ca_cert.pem",
		"command -v docker",
		"systemctl is-active --quiet twinetd",
		"curl --fail",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap script does not contain %q", want)
		}
	}
	for _, bad := range []string{"-listen :7200", "-insecure", "top secret"} {
		if strings.Contains(script, bad) {
			t.Errorf("bootstrap script contains unsafe text %q", bad)
		}
	}
}
