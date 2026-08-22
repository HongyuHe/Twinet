package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
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
	if _, err := solve.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}
	if clean, err := engine.Build(top); err != nil || clean.Len() != 0 {
		t.Fatalf("healthy solve no-change = %#v, %v", clean, err)
	}
}

func TestModeTransitionRewiresEveryReferenceInterfaceBeforeConfigure(t *testing.T) {
	top := observedTopology(t, 2, []*model.Link{observedLink("reference-link", nil)})
	top.Links[0].A.Link, top.Links[0].B.Link = top.Links[0], top.Links[0]
	renderer := observedRenderer{revision: map[string]string{
		"device-000": "same",
		"device-001": "same",
	}}
	runtime := observedRuntime{files: map[string][]byte{}}
	engine := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: observeTestRoot(t), ModeKey: "platform/ungraded=0",
	}
	seedObservedContainers(t, engine, top, &runtime)
	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range top.DevicesOnNode(engine.Node) {
		desired, err := engine.renderDesired(device)
		if err != nil {
			t.Fatal(err)
		}
		final, err := engine.finalRuntimeSpecs(top, device)
		if err != nil {
			t.Fatal(err)
		}
		if err := tracker.markDevice(device.ID, observedDeviceState{
			SpecHash: final.spec.Labels[LabelSpec], ConfigHash: desired.configHash,
			FileHash: desired.fileHash, CommandHash: desired.commandHash, ReadyHash: desired.readyHash,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range top.Links {
		hash, err := engine.desiredWireHash(top, link)
		if err != nil {
			t.Fatal(err)
		}
		if err := tracker.markLink(link.ID, hash); err != nil {
			t.Fatal(err)
		}
	}
	if err := tracker.markMode(); err != nil {
		t.Fatal(err)
	}

	engine.ModeKey = "solve/ungraded=0"
	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	diff := engine.LastBuildDiff()
	if !diff.Wire["reference-link"] {
		t.Fatalf("platform->solve did not dirty reference link wiring: %#v", diff)
	}
	for _, device := range top.DevicesOnNode(engine.Node) {
		if !diff.Configure[device.ID] {
			t.Fatalf("platform->solve did not configure %s: %#v", device.ID, diff)
		}
		step := findPlanStep(p, "configure:"+device.ID)
		if step == nil || !modePlanHasNeed(step.Needs, "wire:reference-link") {
			t.Fatalf("configure %s does not wait for reference wire: %#v", device.ID, step)
		}
	}
}

func TestInterruptedModeTransitionDoesNotPublishModeEarly(t *testing.T) {
	top := observedTopology(t, 2, nil)
	renderer := observedRenderer{revision: map[string]string{
		"device-000": "same",
		"device-001": "same",
	}}
	runtime := observedRuntime{files: map[string][]byte{}}
	root := observeTestRoot(t)
	platform := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: root, ModeKey: "platform/ungraded=0",
	}
	seedObservedContainers(t, platform, top, &runtime)
	initial, err := platform.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initial.Execute(context.Background(), plan.Options{Workers: 1}); err != nil {
		t.Fatal(err)
	}

	runtime.failExec = func(cmd rt.ExecCmd) bool {
		return strings.Contains(strings.Join(cmd.Cmd, " "), "daemonctl reload device-001")
	}
	solve := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: root, ModeKey: "solve/ungraded=0",
	}
	failed, err := solve.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	if report, err := failed.Execute(context.Background(), plan.Options{Workers: 1, ContinueOnError: true}); err != nil || !report.Failed() {
		t.Fatalf("forced transition failure = %#v, %v", report, err)
	}

	runtime.failExec = nil
	retry := &Engine{
		Runtime: &runtime, Node: "node-a", Renderer: renderer,
		ObservationRoot: root, ModeKey: "solve/ungraded=0",
	}
	if _, err := retry.Build(top); err != nil {
		t.Fatal(err)
	}
	for _, device := range top.DevicesOnNode("node-a") {
		if !retry.LastBuildDiff().Configure[device.ID] {
			t.Fatalf("retry skipped %s after interrupted mode transition: %#v", device.ID, retry.LastBuildDiff())
		}
	}
}

func findPlanStep(p *plan.Plan, id string) *plan.Step {
	for _, step := range p.Steps() {
		if step.ID == id {
			return step
		}
	}
	return nil
}

func modePlanHasNeed(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
