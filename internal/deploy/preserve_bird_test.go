package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestCaptureAndRestoreUseBIRDProviderSemantics(t *testing.T) {
	router := &model.Device{
		ID: "as1/ALL", ASN: 1, Kind: model.KindRouter, NOS: "bird", Container: "bird-as1",
	}
	captureRuntime := &readFailingRuntime{exec: func(command []string) (rt.ExecResult, error) {
		switch {
		case len(command) == 2 && command[0] == "cat" && command[1] == "/etc/bird/bird.conf":
			return rt.ExecResult{Stdout: "router id 1.151.0.1;\nprotocol device {}\n"}, nil
		default:
			// Generic tunnel/address capture is deliberately empty but
			// readable; the provider configuration is the fact under test.
			return rt.ExecResult{}, nil
		}
	}}
	snapshots, err := Capture(context.Background(), captureRuntime, router, "mixed", "topology")
	if err != nil {
		t.Fatal(err)
	}
	var bird state.Snapshot
	for _, snapshot := range snapshots {
		if snapshot.Kind == state.KindBIRD {
			bird = snapshot
		}
	}
	if !strings.Contains(string(bird.Content), "protocol device") {
		t.Fatalf("BIRD configuration was not captured: %#v", snapshots)
	}

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(bird); err != nil {
		t.Fatal(err)
	}
	restoreRuntime := &birdRestoreRuntime{}
	restored, err := Restore(context.Background(), restoreRuntime, router, "mixed", store)
	if err != nil {
		t.Fatal(err)
	}
	if !restored || restoreRuntime.path != "/etc/twinet/restore-bird.conf" {
		t.Fatalf("BIRD restore = %v, copied %q", restored, restoreRuntime.path)
	}
	if !strings.Contains(strings.Join(restoreRuntime.command, " "), "birdc") {
		t.Fatalf("BIRD restore did not reload BIRD: %v", restoreRuntime.command)
	}
}

type birdRestoreRuntime struct {
	rt.Runtime
	path    string
	command []string
}

func (r *birdRestoreRuntime) CopyTo(_ context.Context, _ string, path string, _ int64, _ []byte) error {
	r.path = path
	return nil
}

func (r *birdRestoreRuntime) Exec(_ context.Context, _ string, command rt.ExecCmd) (rt.ExecResult, error) {
	r.command = append([]string(nil), command.Cmd...)
	return rt.ExecResult{}, nil
}
