package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestNoChangeBuildMarksSemanticDriftDirty(t *testing.T) {
	top := observedTopology(t, 2, nil)
	renderer := observedRenderer{revision: map[string]string{}}
	runtime := observedRuntime{files: map[string][]byte{}}
	for _, device := range top.Devices {
		renderer.revision[device.ID] = "one"
	}
	engine := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer, ObservationRoot: observeTestRoot(t),
	}
	seedObservedContainers(t, engine, top, &runtime)
	if plan, err := engine.Build(top); err != nil || plan.Len() != 0 {
		t.Fatalf("healthy baseline = %#v, %v", plan, err)
	}
	drifted := "device-000"
	engine.SemanticProbe = func(_ context.Context, device *model.Device) error {
		if device.ID == drifted {
			return errors.New("host address/default route missing")
		}
		return nil
	}
	plan, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Semantic[drifted] || !engine.LastBuildDiff().Configure[drifted] {
		t.Fatalf("semantic drift was not made dirty: %#v", engine.LastBuildDiff())
	}
	if plan.Len() == 0 {
		t.Fatal("semantic drift produced a zero-step no-change deploy")
	}
}
