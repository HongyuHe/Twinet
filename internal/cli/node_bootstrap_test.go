package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestBootstrapProducesOnlyASecureUnderlayBoundAgent(t *testing.T) {
	script := bootstrapScript(model.NodeSpec{
		Name: "node-1", Addr: "10.0.1.2:7200", UnderlayIP: "10.0.1.2",
	}, "top secret", "/project/pki")

	for _, want := range []string{
		"-listen 10.0.1.2:7200",
		"-runtime docker",
		"-runtime-socket unix:///var/run/docker.sock",
		"-tls-cert /etc/twinet/pki/server_cert.pem",
		"-tls-key /etc/twinet/pki/server_key.pem",
		"-client-ca /etc/twinet/pki/ca_cert.pem",
		"-peer-tls-cert /etc/twinet/pki/peer_cert.pem",
		"-peer-tls-key /etc/twinet/pki/peer_key.pem",
		"install_package docker docker.io",
		"TWINET_TOKEN_FILE",
		"systemctl is-active --quiet twinetd",
		"curl --fail",
		"compatibility",
		"image_cache",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap script does not contain %q", want)
		}
	}
	for _, bad := range []string{"-listen :7200", "-insecure", "top secret", "base64 -d"} {
		if strings.Contains(script, bad) {
			t.Errorf("bootstrap script contains unsafe text %q", bad)
		}
	}
}

func TestBootstrapSelectsSecurePodmanServiceAndSocket(t *testing.T) {
	script := bootstrapScriptForRuntime(model.NodeSpec{
		Name: "node-p", Addr: "10.0.1.3:7200", UnderlayIP: "10.0.1.3",
		Runtime: "podman", RuntimeSocket: "unix:///run/podman/podman.sock", UnderlayDev: "eno1",
	}, "podman", "unix:///run/podman/podman.sock", "/project/pki", "/secure/token.env",
		[]string{"10.0.1.1", "10.0.1.2"})

	for _, want := range []string{
		"-runtime podman",
		"-runtime-socket unix:///run/podman/podman.sock",
		"-underlay-dev eno1",
		"install_package podman podman",
		"podman.socket",
		"test -S \"/run/podman/podman.sock\"",
		"ping -c 1 -W 2 10.0.1.1",
		"ping -c 1 -W 2 10.0.1.2",
		"EnvironmentFile=/etc/twinet/agent.env",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("Podman bootstrap script does not contain %q", want)
		}
	}
	for _, bad := range []string{"TWINET_TOKEN=top secret", "top secret"} {
		if strings.Contains(script, bad) {
			t.Errorf("Podman bootstrap leaked secret %q", bad)
		}
	}
}
