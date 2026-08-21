package manifest

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"gopkg.in/yaml.v3"
)

func TestRequestValidationDistinguishesLimitFromRequest(t *testing.T) {
	limit := 1.0
	requests := &model.ResourceRequest{
		CPUs: 2, Memory: "128Mi", Pids: 32, EphemeralStorage: "64Mi",
		FileDescriptors: 128, NetDevices: 2,
	}
	var diagnostics Diagnostics
	validateDeviceResources(&diagnostics, "lab.yaml", "defaults",
		model.DeviceDefaults{CPUs: &limit, Requests: requests}, nil)
	if len(diagnostics.Items) == 0 {
		t.Fatal("request above its hard limit was accepted")
	}
	if got := diagnostics.String(); !strings.Contains(got, "request") || !strings.Contains(got, "hard container limit") {
		t.Fatalf("diagnostic confused requests and limits: %s", got)
	}
}

func TestPartialRequestInheritsKindDefaults(t *testing.T) {
	var diagnostics Diagnostics
	validateDeviceResources(&diagnostics, "lab.yaml", "kinds.router",
		model.DeviceDefaults{Requests: &model.ResourceRequest{CPUs: 0.75}}, nil)
	if diagnostics.HasErrors() {
		t.Fatalf("a partial request should inherit omitted dimensions, got %s", diagnostics.String())
	}
}

func TestHardeningRejectsHostSocketAndRouterSysAdmin(t *testing.T) {
	var diagnostics Diagnostics
	validateDeviceResources(&diagnostics, "lab.yaml", "kinds.router", model.DeviceDefaults{
		Capabilities: []string{"NET_ADMIN", "SYS_ADMIN"},
		Binds:        []string{"/var/run/docker.sock:/var/run/docker.sock"},
	}, nil)
	if !diagnostics.HasErrors() {
		t.Fatal("unsafe device hardening declaration was accepted")
	}
	message := diagnostics.String()
	for _, want := range []string{"SYS_ADMIN", "host-sensitive bind"} {
		if !strings.Contains(message, want) {
			t.Errorf("hardening diagnostics = %s, missing %q", message, want)
		}
	}
}

func TestExplicitZeroRequestIsRejectedRatherThanInherited(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("requests:\n  cpus: 0\n"), &node); err != nil {
		t.Fatal(err)
	}
	var diagnostics Diagnostics
	validateDeviceResources(&diagnostics, "lab.yaml", "defaults",
		model.DeviceDefaults{Requests: &model.ResourceRequest{}}, &node)
	if !diagnostics.HasErrors() || !strings.Contains(diagnostics.String(), "request CPUs must be positive") {
		t.Fatalf("explicit zero request was treated as inheritance: %s", diagnostics.String())
	}
}
