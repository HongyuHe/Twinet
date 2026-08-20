package plan

import (
	"context"
	"errors"
	"testing"
)

// A dry run must not be able to report that it built anything. The deploy
// summary took its device and link counts from the manifest, so a --dry-run
// that created nothing printed "deployed 57 devices and 74 links" and exited
// zero.
func TestDryRunCompletesNothingButPlansEverything(t *testing.T) {
	p := New()
	p.Add(&Step{ID: "create:a", Stage: StageCreate, Describe: "create a",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "create:b", Stage: StageCreate, Describe: "create b",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "wire:1", Stage: StageWire, Describe: "wire 1",
		Run: func(context.Context) error { return nil }})

	rep, err := p.Execute(context.Background(), Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Completed(StageCreate); got != 0 {
		t.Errorf("dry run reported %d devices created, want 0", got)
	}
	if got := rep.Completed(StageWire); got != 0 {
		t.Errorf("dry run reported %d links wired, want 0", got)
	}
	if got := rep.Done(); got != 0 {
		t.Errorf("dry run reported %d completed steps, want 0", got)
	}
	if got := rep.Planned(StageCreate); got != 2 {
		t.Errorf("planned devices = %d, want 2", got)
	}
	if got := rep.Planned(StageWire); got != 1 {
		t.Errorf("planned links = %d, want 1", got)
	}
}

// A deploy that falls over part way must report the part that came up, not the
// topology it set out to build.
func TestPartialDeployCountsOnlyWhatSucceeded(t *testing.T) {
	p := New()
	p.Add(&Step{ID: "create:a", Stage: StageCreate, Scope: "as1", Describe: "create a",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "create:b", Stage: StageCreate, Scope: "as2", Describe: "create b",
		Run: func(context.Context) error { return errors.New("no such image") }})
	p.Add(&Step{ID: "wire:1", Stage: StageWire, Scope: "as2", Describe: "wire 1",
		Needs: []string{"create:b"},
		Run:   func(context.Context) error { return nil }})

	rep, err := p.Execute(context.Background(), Options{ContinueOnError: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Failed() {
		t.Fatal("expected the run to be reported as failed")
	}
	if got := rep.Completed(StageCreate); got != 1 {
		t.Errorf("completed devices = %d, want 1 (b failed)", got)
	}
	// The wire step depends on the container that never came up, so it is
	// skipped; counting it would credit a link that was never made.
	if got := rep.Completed(StageWire); got != 0 {
		t.Errorf("completed links = %d, want 0 (its device failed)", got)
	}
	if got := rep.Planned(StageCreate); got != 2 {
		t.Errorf("planned devices = %d, want 2", got)
	}
}

// --only restricts the plan, and the summary has to follow it.
func TestRestrictedPlanCountsOnlyTheRestrictedScope(t *testing.T) {
	p := New()
	p.Add(&Step{ID: "create:a", Stage: StageCreate, Scope: "as1", Describe: "create a",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "create:b", Stage: StageCreate, Scope: "as2", Describe: "create b",
		Run: func(context.Context) error { return nil }})

	p = p.Restrict(func(st *Step) bool { return st.Scope == "as1" })
	rep, err := p.Execute(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Completed(StageCreate); got != 1 {
		t.Errorf("completed devices = %d, want 1; --only built one scope", got)
	}
	if got := rep.Planned(StageCreate); got != 1 {
		t.Errorf("planned devices = %d, want 1", got)
	}
}

func TestCompletedCountsASuccessfulRun(t *testing.T) {
	p := New()
	p.Add(&Step{ID: "create:a", Stage: StageCreate, Describe: "create a",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "wire:1", Stage: StageWire, Describe: "wire 1",
		Run: func(context.Context) error { return nil }})

	rep, err := p.Execute(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Completed(StageCreate); got != 1 {
		t.Errorf("completed devices = %d, want 1", got)
	}
	if got := rep.Completed(StageWire); got != 1 {
		t.Errorf("completed links = %d, want 1", got)
	}
	if got := rep.Done(); got != 2 {
		t.Errorf("done = %d, want 2", got)
	}
}
