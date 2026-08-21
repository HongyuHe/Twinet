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
