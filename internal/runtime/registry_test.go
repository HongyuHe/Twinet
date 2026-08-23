package runtime

import "testing"

func TestDockerRuntimeIsExplicitlyRegistered(t *testing.T) {
	runtime, err := NewRuntime("docker")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Name() != "docker" {
		t.Fatalf("runtime name = %q, want docker", runtime.Name())
	}
	if len(RuntimeNames()) == 0 {
		t.Fatal("runtime registry is empty")
	}
	capabilities, ok := CapabilitiesFor("docker")
	if !ok || !capabilities.Lifecycle || !capabilities.NetworkNamespaces || !capabilities.Events {
		t.Fatalf("docker capabilities = %#v", capabilities)
	}
}

func TestContainerdRuntimeIsExplicitlyRegistered(t *testing.T) {
	runtime, err := NewRuntime("containerd")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Name() != "containerd" {
		t.Fatalf("runtime name = %q, want containerd", runtime.Name())
	}
	capabilities, ok := CapabilitiesFor("containerd")
	if !ok || !capabilities.SupportsRoutedLab() {
		t.Fatalf("containerd capabilities = %#v", capabilities)
	}
	if err := ConfigureEndpoint(runtime, "unix:///run/containerd/containerd.sock"); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureNamespace(runtime, "twinet-node-0"); err != nil {
		t.Fatal(err)
	}
	if got := Endpoint(runtime); got != "unix:///run/containerd/containerd.sock" {
		t.Fatalf("containerd endpoint = %q", got)
	}
	if got := Namespace(runtime); got != "twinet-node-0" {
		t.Fatalf("containerd namespace = %q", got)
	}
}

func TestRoutedLabCapabilityValidationRejectsUnknownBackend(t *testing.T) {
	err := RequireRoutedLabCapabilities("not-a-runtime")
	if err == nil {
		t.Fatal("unknown runtime passed routed-lab capability validation")
	}
}

func TestEndpointConfigurationIsValidatedBeforeAnyOperation(t *testing.T) {
	runtime, err := NewRuntime("podman")
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigureEndpoint(runtime, "http://not-a-socket"); err == nil {
		t.Fatal("unsafe Podman HTTP endpoint was accepted before runtime startup")
	}
}
