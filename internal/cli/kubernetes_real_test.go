//go:build k8sbackend

package cli

import (
	"context"
	"testing"
)

// TestRealNIKAKubernetesBackendDiscovery is deliberately opt-in. A Docker
// test cannot reproduce Kubernetes faults; this gate asks the configured NIKA
// bridge to discover its real endpoint/context before any incident mutates it.
func TestRealNIKAKubernetesBackendDiscovery(t *testing.T) {
	backend := kubernetesBackendFromEnv()
	if backend == nil {
		t.Fatal("no NIKA Kubernetes endpoint/context/bridge is configured")
	}
	available, reason, err := backend.Available(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatalf("configured NIKA Kubernetes backend is unavailable: %s", reason)
	}
}
