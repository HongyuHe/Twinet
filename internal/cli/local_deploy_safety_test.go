package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestLocalModeTransitionsPreserveStudentState(t *testing.T) {
	tests := []struct {
		name             string
		previousSolved   bool
		desired          render.Mode
		previous         string
		captureReference bool
		restoreStudent   bool
	}{
		{
			name: "platform to platform", desired: render.ModePlatform,
			previous: string(render.ModePlatform),
		},
		{
			name: "platform to solve", desired: render.ModeSolve,
			previous: string(render.ModePlatform), captureReference: true,
		},
		{
			name: "solve to platform", previousSolved: true, desired: render.ModePlatform,
			previous: string(render.ModeSolve), restoreStudent: true,
		},
		{
			name: "solve to solve", previousSolved: true, desired: render.ModeSolve,
			previous: string(render.ModeSolve),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := localModeTransitionPolicy(test.previousSolved, test.desired)
			if got.previousMode != test.previous ||
				got.captureBeforeReference != test.captureReference ||
				got.forceStudentReset != test.restoreStudent {
				t.Fatalf("policy = %+v, want previous=%s capture=%t restore=%t",
					got, test.previous, test.captureReference, test.restoreStudent)
			}
		})
	}
}

func TestLocalModeIsRecordedOnlyThroughAVisibleAtomicWrite(t *testing.T) {
	top := &model.Topology{Lab: &model.Lab{Dir: t.TempDir()}}
	if err := recordLabMode(top, string(render.ModeSolve)); err != nil {
		t.Fatal(err)
	}
	if !labWasSolved(top) {
		t.Fatal("a successful solve was not recorded, so destroy would capture the answer as student work")
	}
	if err := recordLabMode(top, localModeSolvePending); err != nil {
		t.Fatal(err)
	}
	if !labWasSolved(top) {
		t.Fatal("a partial solve would be captured as student work on retry or destroy")
	}
	if err := recordLabMode(top, string(render.ModePlatform)); err != nil {
		t.Fatal(err)
	}
	if labWasSolved(top) {
		t.Fatal("a successful platform restore still reads as solved, so destroy would skip student capture")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	top.Lab.Dir = blocked
	if err := recordLabMode(top, string(render.ModeSolve)); err == nil {
		t.Fatal("an unwritable mode record reported success; a later destroy would trust a mode that was never saved")
	}
}

type localPruneRuntime struct {
	rt.Runtime
	containers []rt.Container
	removed    []string
}

func (r *localPruneRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	return append([]rt.Container(nil), r.containers...), nil
}

func (r *localPruneRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.removed = append(r.removed, name)
	return nil
}

func TestLocalPruneFlagReachesTheDestructiveSafetyBoundary(t *testing.T) {
	const lab = "local-prune-command-regression"
	runtime := &localPruneRuntime{containers: []rt.Container{{
		Name: "stale-control",
		Labels: map[string]string{
			deploy.LabelLab: lab, deploy.LabelFRRControl: "true",
		},
	}}}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	top := &model.Topology{
		Name: lab, Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	desired := &deploy.Engine{Runtime: runtime, Node: "local", State: store}
	var output bytes.Buffer
	if err := pruneLocalDeployment(context.Background(), desired, top, store,
		"local", false, true, false, &output); err != nil {
		t.Fatal(err)
	}
	if len(runtime.removed) != 1 || runtime.removed[0] != "stale-control" {
		t.Fatalf("local --prune removed %v, want the stale managed object", runtime.removed)
	}
	if !bytes.Contains(output.Bytes(), []byte("pruned 1 stale container")) {
		t.Fatalf("local --prune did not report what it removed: %q", output.String())
	}
}
