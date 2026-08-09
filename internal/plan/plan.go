// Package plan builds and executes the deployment plan.
//
// The legacy platform's startup.sh ran twenty scripts in a fixed sequence with
// two hardcoded `sleep 60`s, and a failure anywhere left an unrecoverable
// half-built network whose documented remedy was a full teardown. Twinet
// instead builds a dependency graph of small, idempotent steps, runs
// independent steps concurrently, and waits on readiness predicates rather than
// the clock.
package plan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Stage names the phase a step belongs to. Steps in a later stage never start
// before every step they depend on has finished.
type Stage string

const (
	StageImage     Stage = "image"     // pull images
	StageCreate    Stage = "create"    // create and start containers
	StageWire      Stage = "wire"      // attach interfaces, apply shaping
	StageConfigure Stage = "configure" // push configuration, start daemons
	StageReady     Stage = "ready"     // wait for readiness predicates
)

// StageOrder is the canonical progression.
var StageOrder = []Stage{StageImage, StageCreate, StageWire, StageConfigure, StageReady}

// Step is one unit of work.
type Step struct {
	// ID is unique within the plan.
	ID string
	// Stage groups the step.
	Stage Stage
	// Scope names the AS or service the step belongs to, so a failure can be
	// attributed and isolated instead of aborting the whole run.
	Scope string
	// Describe is a short human-readable label.
	Describe string
	// Needs lists step IDs that must complete first.
	Needs []string
	// Run performs the work. It must be idempotent.
	Run func(context.Context) error
	// Optional marks a step whose failure degrades but does not fail the scope.
	Optional bool
}

// Plan is a directed acyclic graph of steps.
type Plan struct {
	steps map[string]*Step
	order []string
}

// New creates an empty plan.
func New() *Plan { return &Plan{steps: map[string]*Step{}} }

// Add registers a step. Adding the same ID twice is a programming error and
// panics, because a duplicate would silently drop work.
func (p *Plan) Add(s *Step) {
	if s.ID == "" {
		panic("plan: step with empty ID")
	}
	if _, dup := p.steps[s.ID]; dup {
		panic("plan: duplicate step ID " + s.ID)
	}
	p.steps[s.ID] = s
	p.order = append(p.order, s.ID)
}

// Len returns the number of steps.
func (p *Plan) Len() int { return len(p.steps) }

// Steps returns the steps in insertion order.
func (p *Plan) Steps() []*Step {
	out := make([]*Step, 0, len(p.order))
	for _, id := range p.order {
		out = append(out, p.steps[id])
	}
	return out
}

// Validate checks that every dependency exists and the graph is acyclic.
// Running an invalid plan would deadlock, so this is checked before execution.
func (p *Plan) Validate() error {
	var missing []string
	for _, id := range p.order {
		for _, need := range p.steps[id].Needs {
			if _, ok := p.steps[need]; !ok {
				missing = append(missing, fmt.Sprintf("%s needs %s, which does not exist", id, need))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("plan has dangling dependencies:\n  %s", strings.Join(missing, "\n  "))
	}
	if cycle := p.findCycle(); cycle != nil {
		return fmt.Errorf("plan has a dependency cycle: %s", strings.Join(cycle, " -> "))
	}
	// Stage ordering must not be violated by an explicit dependency, or the
	// graph would express something the stage model cannot honour.
	rank := map[Stage]int{}
	for i, s := range StageOrder {
		rank[s] = i
	}
	for _, id := range p.order {
		s := p.steps[id]
		for _, need := range s.Needs {
			n := p.steps[need]
			if rank[n.Stage] > rank[s.Stage] {
				return fmt.Errorf("step %s (%s) depends on %s in the later stage %s",
					id, s.Stage, need, n.Stage)
			}
		}
	}
	return nil
}

func (p *Plan) findCycle() []string {
	const (
		white = 0
		grey  = 1
		black = 2
	)
	colour := map[string]int{}
	var path []string
	var walk func(string) []string
	walk = func(id string) []string {
		colour[id] = grey
		path = append(path, id)
		for _, need := range p.steps[id].Needs {
			switch colour[need] {
			case grey:
				return append(append([]string{}, path...), need)
			case white:
				if c := walk(need); c != nil {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		colour[id] = black
		return nil
	}
	ids := append([]string{}, p.order...)
	sort.Strings(ids)
	for _, id := range ids {
		if colour[id] == white {
			if c := walk(id); c != nil {
				return c
			}
		}
	}
	return nil
}

// Result records the outcome of one step.
type Result struct {
	Step     *Step
	Err      error
	Skipped  bool
	Duration time.Duration
}

// Report summarises an execution.
type Report struct {
	Results []Result
	// ScopeErrors maps a scope (an AS or service) to its failures, so the
	// caller can report "AS 12 is degraded" without failing the whole class.
	ScopeErrors map[string][]error
	Duration    time.Duration
}

// Failed reports whether any required step failed.
func (r *Report) Failed() bool { return len(r.ScopeErrors) > 0 }

// FailedScopes returns the affected scopes in sorted order.
func (r *Report) FailedScopes() []string {
	out := make([]string, 0, len(r.ScopeErrors))
	for s := range r.ScopeErrors {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Err summarises the failures.
func (r *Report) Err() error {
	if !r.Failed() {
		return nil
	}
	var b strings.Builder
	scopes := r.FailedScopes()
	fmt.Fprintf(&b, "%d scope(s) failed:\n", len(scopes))
	for _, s := range scopes {
		for _, e := range r.ScopeErrors[s] {
			fmt.Fprintf(&b, "  %s: %v\n", s, e)
		}
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}

// Observer receives progress events. The CLI renders them; the web UI and the
// grader consume the same stream, so progress reporting never leaks into the
// planning logic itself.
type Observer interface {
	StepStarted(s *Step)
	StepFinished(r Result)
}

// nopObserver ignores everything.
type nopObserver struct{}

func (nopObserver) StepStarted(*Step)   {}
func (nopObserver) StepFinished(Result) {}

// Options control execution.
type Options struct {
	// Workers bounds concurrency. Zero means one per CPU, which is the right
	// default for a fan-out of container and netlink operations.
	Workers int
	// Observer receives progress events.
	Observer Observer
	// ContinueOnError keeps going when a scope fails, marking it degraded.
	// This is on by default: one broken student AS must not stop a class-wide
	// deployment, which is exactly what the legacy platform did.
	ContinueOnError bool
	// DryRun reports what would run without running it.
	DryRun bool
}

// Execute runs the plan, honouring dependencies and stage ordering.
func (p *Plan) Execute(ctx context.Context, opts Options) (*Report, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	obs := opts.Observer
	if obs == nil {
		obs = nopObserver{}
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = defaultWorkers()
	}

	start := time.Now()
	rep := &Report{ScopeErrors: map[string][]error{}}

	// Dependency bookkeeping.
	remaining := map[string]int{}
	dependents := map[string][]string{}
	for _, id := range p.order {
		remaining[id] = len(p.steps[id].Needs)
		for _, need := range p.steps[id].Needs {
			dependents[need] = append(dependents[need], id)
		}
	}

	// A scope that has failed causes its not-yet-started steps to be skipped,
	// so one broken AS does not spew a cascade of derived errors.
	failedScopes := map[string]bool{}

	var (
		mu      sync.Mutex
		results []Result
	)

	// Ready queues, one per stage, so a step never starts before every step of
	// every earlier stage has settled.
	for _, stage := range StageOrder {
		var batch []*Step
		for _, id := range p.order {
			if p.steps[id].Stage == stage {
				batch = append(batch, p.steps[id])
			}
		}
		if len(batch) == 0 {
			continue
		}

		if err := runStage(ctx, batch, remaining, dependents, workers, opts, obs,
			&mu, &results, rep, failedScopes, p); err != nil {
			rep.Results = results
			rep.Duration = time.Since(start)
			return rep, err
		}
	}

	mu.Lock()
	rep.Results = results
	mu.Unlock()
	rep.Duration = time.Since(start)
	return rep, nil
}

// runStage executes every step of one stage, respecting intra-stage
// dependencies, with a bounded worker pool.
func runStage(
	ctx context.Context,
	batch []*Step,
	remaining map[string]int,
	dependents map[string][]string,
	workers int,
	opts Options,
	obs Observer,
	mu *sync.Mutex,
	results *[]Result,
	rep *Report,
	failedScopes map[string]bool,
	p *Plan,
) error {
	inStage := map[string]bool{}
	for _, s := range batch {
		inStage[s.ID] = true
	}

	ready := make([]*Step, 0, len(batch))
	pending := map[string]*Step{}
	for _, s := range batch {
		if remaining[s.ID] == 0 {
			ready = append(ready, s)
		} else {
			pending[s.ID] = s
		}
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	done := make(chan Result, len(batch))
	launched := 0

	launch := func(s *Step) {
		launched++
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			mu.Lock()
			skip := s.Scope != "" && failedScopes[s.Scope]
			mu.Unlock()
			if skip {
				done <- Result{Step: s, Skipped: true}
				return
			}
			if opts.DryRun {
				done <- Result{Step: s, Skipped: true}
				return
			}

			obs.StepStarted(s)
			t0 := time.Now()
			var err error
			if s.Run != nil {
				err = s.Run(ctx)
			}
			r := Result{Step: s, Err: err, Duration: time.Since(t0)}
			obs.StepFinished(r)
			done <- r
		}()
	}

	for _, s := range ready {
		launch(s)
	}

	settled := 0
	total := len(batch)
	for settled < total {
		if launched == settled && len(pending) > 0 {
			// Nothing running and nothing runnable: an intra-stage cycle that
			// Validate should have caught. Fail loudly rather than hang.
			ids := make([]string, 0, len(pending))
			for id := range pending {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			return fmt.Errorf("plan deadlocked in stage %s; unrunnable steps: %s",
				batch[0].Stage, strings.Join(ids, ", "))
		}

		var r Result
		select {
		case r = <-done:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		settled++

		mu.Lock()
		*results = append(*results, r)
		if r.Err != nil && !r.Step.Optional {
			scope := r.Step.Scope
			if scope == "" {
				scope = "lab"
			}
			rep.ScopeErrors[scope] = append(rep.ScopeErrors[scope],
				fmt.Errorf("%s: %w", r.Step.Describe, r.Err))
			failedScopes[scope] = true
		}
		mu.Unlock()

		if r.Err != nil && !r.Step.Optional && !opts.ContinueOnError {
			wg.Wait()
			return fmt.Errorf("%s: %w", r.Step.Describe, r.Err)
		}

		// Release anything that was waiting on this step.
		for _, dep := range dependents[r.Step.ID] {
			remaining[dep]--
			if remaining[dep] == 0 && inStage[dep] {
				s := pending[dep]
				delete(pending, dep)
				launch(s)
			}
		}
	}

	wg.Wait()
	return nil
}

func defaultWorkers() int {
	n := numCPU()
	// Container creation and netlink calls are latency-bound rather than
	// CPU-bound, so oversubscribe: at class scale this is the difference
	// between a two-minute and a ten-minute deployment.
	w := n * 4
	if w < 8 {
		w = 8
	}
	if w > 256 {
		w = 256
	}
	return w
}
