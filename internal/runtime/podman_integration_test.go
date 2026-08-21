//go:build podman_integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPodmanIntegrationContract(t *testing.T) {
	if os.Getenv("TWINET_PODMAN_INTEGRATION") != "1" {
		t.Fatal("podman_integration requires TWINET_PODMAN_INTEGRATION=1; refusing a vacuous pass")
	}
	image := strings.TrimSpace(os.Getenv("TWINET_PODMAN_INTEGRATION_IMAGE"))
	if image == "" {
		t.Fatal("podman_integration requires TWINET_PODMAN_INTEGRATION_IMAGE with sh and sleep; refusing a vacuous pass")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	podman := NewPodman()
	defer func() {
		if err := podman.Close(); err != nil {
			t.Errorf("close Podman runtime: %v", err)
		}
	}()
	if _, err := podman.Ping(ctx); err != nil {
		t.Fatalf("ping real Podman service: %v", err)
	}
	if err := podman.PullImage(ctx, image, PullIfMissing); err != nil {
		t.Fatalf("pull integration image %q: %v", image, err)
	}

	name := fmt.Sprintf("twinet-podman-integration-%d", os.Getpid())
	labels := map[string]string{"twinet.integration": name}
	eventsCtx, cancelEvents := context.WithCancel(ctx)
	subscription := podman.Subscribe(eventsCtx, EventFilter{Labels: labels})
	defer cancelEvents()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := podman.Remove(cleanupCtx, name, true); err != nil {
			t.Errorf("remove integration container: %v", err)
		}
	}()

	if _, err := podman.Create(ctx, &Spec{
		Name:    name,
		Image:   image,
		Command: []string{"sh", "-c", "sleep 30"},
		Labels:  labels,
	}); err != nil {
		t.Fatalf("create integration container: %v", err)
	}
	if err := podman.Start(ctx, name); err != nil {
		t.Fatalf("start integration container: %v", err)
	}
	inspected, err := podman.Inspect(ctx, name)
	if err != nil {
		t.Fatalf("inspect integration container: %v", err)
	}
	if inspected.State != StateRunning {
		t.Fatalf("integration container state = %s, want running", inspected.State)
	}
	result, err := podman.Exec(ctx, name, ExecCmd{Cmd: []string{"sh", "-c", "printf podman-contract"}})
	if err != nil {
		t.Fatalf("exec integration command: %v", err)
	}
	if result.ExitCode != 0 || result.Stdout != "podman-contract" {
		t.Fatalf("integration exec result = %#v", result)
	}
	if err := podman.CopyTo(ctx, name, "/tmp/twinet-contract", 0o600, []byte("copy")); err != nil {
		t.Fatalf("copy integration file into container: %v", err)
	}
	if copied, err := podman.CopyFrom(ctx, name, "/tmp/twinet-contract"); err != nil || string(copied) != "copy" {
		t.Fatalf("copy integration file from container = (%q, %v)", copied, err)
	}

	seen := map[EventAction]bool{}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for !seen[EventCreate] || !seen[EventStart] {
		select {
		case event := <-subscription.Events:
			if event.Container == "" {
				t.Fatal("Podman event stream closed before create/start events")
			}
			seen[event.Action] = true
		case err := <-subscription.Errors:
			t.Fatalf("Podman event stream ended before create/start events: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for Podman create/start events: %#v", seen)
		}
	}
	if err := podman.Stop(ctx, name, 2*time.Second); err != nil {
		t.Fatalf("stop integration container: %v", err)
	}
}
