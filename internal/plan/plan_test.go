package plan

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func step(id string, stage Stage, needs ...string) *Step {
	return &Step{ID: id, Stage: stage, Describe: id, Needs: needs, Run: func(context.Context) error { return nil }}
}

func TestValidateDanglingDependency(t *testing.T) {
	p := New()
	p.Add(step("a", StageCreate, "nope"))
	err := p.Validate()
	if err == nil {
		t.Fatal("expected a dangling dependency error")
	}
	if got := err.Error(); !contains(got, "nope") {
		t.Errorf("error should name the missing step: %s", got)
	}
}

func TestValidateCycle(t *testing.T) {
	p := New()
	p.Add(step("a", StageCreate, "c"))
	p.Add(step("b", StageCreate, "a"))
	p.Add(step("c", StageCreate, "b"))
	err := p.Validate()
	if err == nil {
		t.Fatal("expected a cycle error")
	}
	if !contains(err.Error(), "cycle") {
		t.Errorf("error should mention a cycle: %s", err)
	}
}

// A step must never depend on one in a later stage: the stage model could not
// honour it, and the plan would deadlock at run time.
func TestValidateRejectsBackwardStageDependency(t *testing.T) {
	p := New()
	p.Add(step("early", StageCreate, "late"))
	p.Add(step("late", StageReady))
	if err := p.Validate(); err == nil {
		t.Fatal("expected a stage-ordering error")
	}
}

func TestExecuteRespectsStagesAndDependencies(t *testing.T) {
	var mu sync.Mutex
	var order []string
	mk := func(id string, stage Stage, needs ...string) *Step {
		return &Step{ID: id, Stage: stage, Describe: id, Needs: needs,
			Run: func(context.Context) error {
				mu.Lock()
				order = append(order, id)
				mu.Unlock()
				return nil
			}}
	}
	p := New()
	p.Add(mk("img", StageImage))
	p.Add(mk("c1", StageCreate, "img"))
	p.Add(mk("c2", StageCreate, "img"))
	p.Add(mk("wire", StageWire, "c1", "c2"))
	p.Add(mk("ready", StageReady, "wire"))

	rep, err := p.Execute(context.Background(), Options{Workers: 4})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if rep.Failed() {
		t.Fatalf("unexpected failures: %v", rep.Err())
	}
	if len(order) != 5 {
		t.Fatalf("expected 5 steps to run, got %d: %v", len(order), order)
	}
	pos := map[string]int{}
	for i, id := range order {
		pos[id] = i
	}
	if pos["img"] != 0 {
		t.Errorf("image stage must run first, got order %v", order)
	}
	if pos["wire"] < pos["c1"] || pos["wire"] < pos["c2"] {
		t.Errorf("wire ran before its dependencies: %v", order)
	}
	if pos["ready"] != 4 {
		t.Errorf("ready stage must run last, got order %v", order)
	}
}

// Independent steps must actually run concurrently, or a class-scale deployment
// degenerates into the serial pipeline this design replaces.
func TestExecuteRunsIndependentStepsConcurrently(t *testing.T) {
	const n = 32
	var running, peak int64
	p := New()
	for i := 0; i < n; i++ {
		p.Add(&Step{
			ID: fmt.Sprintf("s%d", i), Stage: StageCreate, Describe: "s",
			Run: func(context.Context) error {
				cur := atomic.AddInt64(&running, 1)
				for {
					old := atomic.LoadInt64(&peak)
					if cur <= old || atomic.CompareAndSwapInt64(&peak, old, cur) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt64(&running, -1)
				return nil
			}})
	}
	start := time.Now()
	if _, err := p.Execute(context.Background(), Options{Workers: 16}); err != nil {
		t.Fatal(err)
	}
	if peak < 8 {
		t.Errorf("peak concurrency was %d, expected the worker pool to be used", peak)
	}
	if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
		t.Errorf("took %s; steps do not appear to be running in parallel", elapsed)
	}
}

// One broken AS must not stop a class-wide deployment. This is the single
// biggest operational difference from the legacy platform, whose only remedy
// for a partial failure was a full teardown and rebuild.
func TestFailureIsolatedToScope(t *testing.T) {
	var ran sync.Map
	mk := func(id, scope string, stage Stage, fail bool, needs ...string) *Step {
		return &Step{ID: id, Scope: scope, Stage: stage, Describe: id, Needs: needs,
			Run: func(context.Context) error {
				ran.Store(id, true)
				if fail {
					return errors.New("boom")
				}
				return nil
			}}
	}
	p := New()
	p.Add(mk("as1-create", "as1", StageCreate, true))
	p.Add(mk("as1-wire", "as1", StageWire, false, "as1-create"))
	p.Add(mk("as2-create", "as2", StageCreate, false))
	p.Add(mk("as2-wire", "as2", StageWire, false, "as2-create"))

	rep, err := p.Execute(context.Background(), Options{Workers: 4, ContinueOnError: true})
	if err != nil {
		t.Fatalf("execute returned a hard error: %v", err)
	}
	if !rep.Failed() {
		t.Fatal("expected the report to record a failure")
	}
	if got := rep.FailedScopes(); len(got) != 1 || got[0] != "as1" {
		t.Errorf("failed scopes = %v, want [as1]", got)
	}
	if _, ok := ran.Load("as1-wire"); ok {
		t.Error("as1-wire should have been skipped after its scope failed")
	}
	if _, ok := ran.Load("as2-wire"); !ok {
		t.Error("as2 should have completed despite as1 failing")
	}
}

func TestExecuteStopsOnErrorWhenAsked(t *testing.T) {
	p := New()
	p.Add(&Step{ID: "boom", Stage: StageCreate, Describe: "boom",
		Run: func(context.Context) error { return errors.New("nope") }})
	if _, err := p.Execute(context.Background(), Options{ContinueOnError: false}); err == nil {
		t.Fatal("expected execute to fail")
	}
}

func TestDryRunRunsNothing(t *testing.T) {
	var called bool
	p := New()
	p.Add(&Step{ID: "a", Stage: StageCreate, Describe: "a",
		Run: func(context.Context) error { called = true; return nil }})
	if _, err := p.Execute(context.Background(), Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("dry run executed a step")
	}
}

func TestWaitSucceedsAfterStabilising(t *testing.T) {
	n := 0
	err := Wait(context.Background(), Waiter{
		Describe:  "a counter to reach 3",
		Interval:  time.Millisecond,
		Timeout:   2 * time.Second,
		StableFor: 2,
		Check: func(context.Context) (bool, error) {
			n++
			return n >= 3, nil
		},
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if n < 4 {
		t.Errorf("StableFor=2 should require two consecutive successes, checked %d times", n)
	}
}

// A predicate that flaps must not be mistaken for a converged one. This is what
// makes convergence detection trustworthy enough to replace fixed sleeps.
func TestWaitRejectsFlapping(t *testing.T) {
	n := 0
	err := Wait(context.Background(), Waiter{
		Describe:  "a flapping condition",
		Interval:  time.Millisecond,
		Timeout:   150 * time.Millisecond,
		StableFor: 3,
		Check: func(context.Context) (bool, error) {
			n++
			return n%2 == 0, nil // alternates, never three in a row
		},
	})
	if err == nil {
		t.Fatal("expected a timeout, since the condition never held three times running")
	}
}

func TestWaitReportsLastError(t *testing.T) {
	err := Wait(context.Background(), Waiter{
		Describe: "BGP sessions to establish",
		Interval: time.Millisecond,
		Timeout:  30 * time.Millisecond,
		Check: func(context.Context) (bool, error) {
			return false, errors.New("2 of 7 sessions are Idle")
		},
	})
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if !contains(err.Error(), "2 of 7 sessions are Idle") {
		t.Errorf("timeout should quote the last check result, got: %v", err)
	}
	if !contains(err.Error(), "BGP sessions to establish") {
		t.Errorf("timeout should say what it waited for, got: %v", err)
	}
}

func TestWaitHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Wait(ctx, Waiter{
		Describe: "anything",
		Interval: time.Millisecond,
		Timeout:  5 * time.Second,
		Check:    func(context.Context) (bool, error) { return false, nil },
	})
	if err == nil {
		t.Fatal("expected cancellation to abort the wait")
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// A step whose prerequisite failed must not run, even when the prerequisite
// belongs to a different scope.
//
// Inter-AS wiring is scoped to "peering" while the routers that depend on it
// are scoped to their AS, so scope isolation alone would configure and start a
// router whose links were never created. That is precisely the half-wired state
// the design claims to prevent.
func TestFailedPrerequisiteBlocksDependentInAnotherScope(t *testing.T) {
	var ran sync.Map
	mk := func(id, scope string, stage Stage, fail bool, needs ...string) *Step {
		return &Step{ID: id, Scope: scope, Stage: stage, Describe: id, Needs: needs,
			Run: func(context.Context) error {
				ran.Store(id, true)
				if fail {
					return errors.New("boom")
				}
				return nil
			}}
	}
	p := New()
	p.Add(mk("as1-create", "as1", StageCreate, false))
	p.Add(mk("wire-peering", "peering", StageWire, true, "as1-create"))
	p.Add(mk("as1-configure", "as1", StageConfigure, false, "as1-create", "wire-peering"))
	p.Add(mk("as1-ready", "as1", StageReady, false, "as1-configure"))

	rep, err := p.Execute(context.Background(), Options{Workers: 4, ContinueOnError: true})
	if err != nil {
		t.Fatalf("execute returned a hard error: %v", err)
	}
	if !rep.Failed() {
		t.Fatal("expected the peering failure to be recorded")
	}
	if _, ok := ran.Load("as1-configure"); ok {
		t.Error("as1-configure ran despite its wire prerequisite failing: this is the half-wired state the design forbids")
	}
	if _, ok := ran.Load("as1-ready"); ok {
		t.Error("as1-ready ran despite an upstream failure")
	}
}

// A failure in one scope must not skip an unrelated scope that merely shares an
// earlier step, or one broken image pull would stop a whole class.
func TestUnrelatedScopesStillRunAfterAFailure(t *testing.T) {
	var ran sync.Map
	mk := func(id, scope string, stage Stage, fail bool, needs ...string) *Step {
		return &Step{ID: id, Scope: scope, Stage: stage, Describe: id, Needs: needs,
			Run: func(context.Context) error {
				ran.Store(id, true)
				if fail {
					return errors.New("boom")
				}
				return nil
			}}
	}
	p := New()
	p.Add(mk("image", "", StageImage, false))
	p.Add(mk("as1-create", "as1", StageCreate, true, "image"))
	p.Add(mk("as2-create", "as2", StageCreate, false, "image"))
	p.Add(mk("as2-configure", "as2", StageConfigure, false, "as2-create"))

	rep, _ := p.Execute(context.Background(), Options{Workers: 4, ContinueOnError: true})
	if !rep.Failed() {
		t.Fatal("expected as1 to be recorded as failed")
	}
	if _, ok := ran.Load("as2-configure"); !ok {
		t.Error("as2 should have completed despite as1 failing")
	}
}

// Stages are progress labels, not global barriers. A slow unrelated create
// must not hold back a link and configuration whose own dependencies are done.
func TestExecutePipelinesAcrossStages(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	wireStarted := make(chan struct{})
	configured := make(chan struct{})

	p := New()
	p.Add(&Step{ID: "create:slow", Stage: StageCreate, Describe: "slow create",
		Run: func(context.Context) error {
			close(slowStarted)
			<-releaseSlow
			return nil
		}})
	p.Add(&Step{ID: "create:fast", Stage: StageCreate, Describe: "fast create",
		Run: func(context.Context) error { return nil }})
	p.Add(&Step{ID: "wire:fast", Stage: StageWire, Describe: "fast wire",
		Needs: []string{"create:fast"},
		Run: func(context.Context) error {
			close(wireStarted)
			return nil
		}})
	p.Add(&Step{ID: "configure:fast", Stage: StageConfigure, Describe: "fast configure",
		Needs: []string{"wire:fast"},
		Run: func(context.Context) error {
			close(configured)
			return nil
		}})

	done := make(chan error, 1)
	go func() {
		_, err := p.Execute(context.Background(), Options{Workers: 2})
		done <- err
	}()
	<-slowStarted
	select {
	case <-wireStarted:
	case <-time.After(time.Second):
		t.Fatal("wire waited for an unrelated create stage to finish")
	}
	select {
	case <-configured:
	case <-time.After(time.Second):
		t.Fatal("configure waited for an unrelated wire or create stage to finish")
	}
	close(releaseSlow)
	if err := <-done; err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestExecuteNeverExceedsWorkerBound(t *testing.T) {
	const workers = 3
	release := make(chan struct{})
	var running, peak int64
	p := New()
	for i := 0; i < 12; i++ {
		p.Add(&Step{ID: fmt.Sprintf("s%d", i), Stage: StageCreate, Describe: "bounded",
			Run: func(context.Context) error {
				n := atomic.AddInt64(&running, 1)
				for {
					old := atomic.LoadInt64(&peak)
					if n <= old || atomic.CompareAndSwapInt64(&peak, old, n) {
						break
					}
				}
				<-release
				atomic.AddInt64(&running, -1)
				return nil
			}})
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.Execute(context.Background(), Options{Workers: workers})
		done <- err
	}()
	deadline := time.After(time.Second)
	for atomic.LoadInt64(&peak) < workers {
		select {
		case <-deadline:
			t.Fatalf("only %d workers started, want %d", peak, workers)
		case <-time.After(time.Millisecond):
		}
	}
	if got := atomic.LoadInt64(&peak); got != workers {
		t.Fatalf("peak workers = %d, want exactly %d", got, workers)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestExecuteCancellationDoesNotStartQueuedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var queued atomic.Bool
	p := New()
	p.Add(&Step{ID: "running", Stage: StageCreate, Describe: "running",
		Run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}})
	p.Add(&Step{ID: "queued", Stage: StageCreate, Describe: "queued",
		Run: func(context.Context) error {
			queued.Store(true)
			return nil
		}})

	done := make(chan error, 1)
	go func() {
		_, err := p.Execute(ctx, Options{Workers: 1})
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("execute error = %v, want context cancellation", err)
	}
	if queued.Load() {
		t.Fatal("a queued step ran after cancellation")
	}
}

func TestExecuteReportsResultsInPlanOrder(t *testing.T) {
	release := make(chan struct{})
	firstStarted := make(chan struct{})
	secondDone := make(chan struct{})
	p := New()
	p.Add(&Step{ID: "first", Stage: StageCreate, Describe: "first",
		Run: func(context.Context) error {
			close(firstStarted)
			<-release
			return nil
		}})
	p.Add(&Step{ID: "second", Stage: StageCreate, Describe: "second",
		Run: func(context.Context) error {
			close(secondDone)
			return nil
		}})

	type outcome struct {
		rep *Report
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		rep, err := p.Execute(context.Background(), Options{Workers: 2})
		done <- outcome{rep: rep, err: err}
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first step did not start")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second step did not complete while first was blocked")
	}
	close(release)
	out := <-done
	if out.err != nil {
		t.Fatalf("execute: %v", out.err)
	}
	rep := out.rep
	if len(rep.Results) != 2 || rep.Results[0].Step.ID != "first" || rep.Results[1].Step.ID != "second" {
		t.Fatalf("results are not insertion ordered: %#v", rep.Results)
	}
}
