package deploy

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/plan"
)

func TestModeTransitionIsDirtyDespiteMatchingRuntimeSpec(t *testing.T) {
	top := observedTopology(t, 1, nil)
	renderer := observedRenderer{revision: map[string]string{"device-000": "same"}}
	runtime := observedRuntime{files: map[string][]byte{}}
	engine := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: observeTestRoot(t), ModeKey: "platform/ungraded=0",
	}
	seedObservedContainers(t, engine, top, &runtime)
	first, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if first.Len() == 0 {
		t.Fatal("initial persisted mode was not configured")
	}
	if _, err := first.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	engine.ModeKey = "solve/ungraded=0"
	solve, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Configure["device-000"] || solve.Len() == 0 {
		t.Fatalf("platform->solve mode transition was accepted as no-change: %#v", engine.LastBuildDiff())
	}
}
