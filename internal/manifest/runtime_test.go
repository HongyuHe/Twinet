package manifest

import (
	"strings"
	"testing"
)

func TestPlacementRuntimeDefaultsToDockerAndAcceptsPodmanOverride(t *testing.T) {
	body := minimal + `
placement:
  runtime: podman
  nodes:
    - {name: n0, runtime: docker, runtime_socket: unix:///var/run/docker.sock}
`
	loaded, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	if got := loaded.Lab.RuntimeForNode("n0"); got != "docker" {
		t.Fatalf("node runtime = %q, want docker override", got)
	}
	if got := loaded.Lab.RuntimeForNode("missing"); got != "podman" {
		t.Fatalf("lab runtime = %q, want podman default", got)
	}
}

func TestPlacementRuntimeRejectsUnavailableBackendBeforeDeployment(t *testing.T) {
	body := minimal + `
placement:
  runtime: unavailable-engine
`
	loaded, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := loaded.Validate()
	if !diagnostics.HasErrors() || !strings.Contains(diagnostics.String(), "unavailable-engine") {
		t.Fatalf("unavailable runtime diagnostics = %s", diagnostics.String())
	}
}

func TestPlacementRuntimeAcceptsContainerd(t *testing.T) {
	body := minimal + `
placement:
  runtime: containerd
  nodes:
    - {name: n0, runtime_socket: unix:///run/containerd/containerd.sock}
`
	loaded, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	if got := loaded.Lab.RuntimeForNode("n0"); got != "containerd" {
		t.Fatalf("node runtime = %q, want containerd", got)
	}
}
