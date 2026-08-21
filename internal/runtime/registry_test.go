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
