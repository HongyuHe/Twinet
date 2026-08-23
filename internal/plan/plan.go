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

// Stage names the phase a step belongs to. Stages describe progress for people
// and reports; dependencies, rather than stage-wide barriers, control when
// work starts.
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

// Completed counts the steps in a stage that actually ran and succeeded.
//
// The count a deployment reports has to come from here rather than from the
// topology it set out to build. The plan is what was intended: it is the same
// number whether the run was a dry run, was restricted to one AS with --only,
// or fell over half way. Summarising a deploy with the manifest's own device
// count is how "deployed 57 devices and 74 links" came to be printed by a
// --dry-run that created nothing.
func (r *Report) Completed(stage Stage) int {
	n := 0
	for _, res := range r.Results {
		if res.Step != nil && res.Step.Stage == stage && !res.Skipped && res.Err == nil {
			n++
		}
	}
	return n
}

// Planned counts the steps in a stage that the plan contained, run or not.
func (r *Report) Planned(stage Stage) int {
	n := 0
	for _, res := range r.Results {
		if res.Step != nil && res.Step.Stage == stage {
			n++
		}
	}
	return n
}

// Done counts every step that ran and succeeded, across all stages.
func (r *Report) Done() int {
	n := 0
	for _, res := range r.Results {
		if !res.Skipped && res.Err == nil {
			n++
		}
	}
	return n
}

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

// Restrict returns a copy of the plan containing only the steps that match,
// together with every step they transitively depend on.
//
// This is how a scoped repair is expressed. The alternative -- deleting devices
// from the topology -- leaves every cross-reference dangling, so an AS whose
// routers were removed still claims to own them and expansion-time invariants
// no longer hold. Narrowing the *work* rather than the *world* keeps the model
// whole.
func (p *Plan) Restrict(match func(*Step) bool) *Plan {
	keep := map[string]bool{}
	var need func(id string)
	need = func(id string) {
		if keep[id] {
			return
		}
		keep[id] = true
		for _, dep := range p.steps[id].Needs {
			if _, ok := p.steps[dep]; ok {
				need(dep)
			}
		}
	}
	for _, id := range p.order {
		if match(p.steps[id]) {
			need(id)
		}
	}

	out := New()
	for _, id := range p.order {
		if !keep[id] {
			continue
		}
		s := *p.steps[id]
		var needs []string
		for _, dep := range s.Needs {
			if keep[dep] {
				needs = append(needs, dep)
			}
		}
		s.Needs = needs
		out.Add(&s)
	}
	return out
}

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

// Execute runs the plan with a bounded dependency scheduler.
//
// A stage is not a barrier: a wire can start as soon as its endpoints exist,
// and a device can configure as soon as its own links are ready. This lets a
// large deployment pipeline independent ASes instead of waiting for every
// create or wire operation in the class to settle first.
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
	// A step whose own prerequisite failed or was skipped because its scope
	// failed must also be skipped, even when the prerequisite belongs to a
	// different scope. An inter-AS wire step is scoped to "peering" while the
	// router that depends on it is scoped to its AS, so scope isolation alone
	// would happily configure and start a router whose links were never made.
	failedSteps := map[string]bool{}

	results := make(map[string]Result, p.Len())
	order := make(map[string]int, p.Len())
	for i, id := range p.order {
		order[id] = i
	}
	ready := make([]*Step, 0, p.Len())
	for _, id := range p.order {
		if remaining[id] == 0 {
			ready = append(ready, p.steps[id])
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	work := make(chan *Step)
	done := make(chan Result, workers)
	var wg sync.WaitGroup
	if !opts.DryRun {
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range work {
					// Dispatch and cancellation can race as a worker becomes
					// free. A queued step must not begin mutating after its
					// execution context has been cancelled.
					if err := runCtx.Err(); err != nil {
						done <- Result{Step: s, Skipped: true, Err: err}
						continue
					}
					obs.StepStarted(s)
					t0 := time.Now()
					var err error
					if s.Run != nil {
						err = s.Run(runCtx)
					}
					r := Result{Step: s, Err: err, Duration: time.Since(t0)}
					obs.StepFinished(r)
					done <- r
				}
			}()
		}
	}
	closeWorkers := func() {
		if opts.DryRun {
			return
		}
		close(work)
		wg.Wait()
	}

	// Settle releases dependent work. It is deliberately owned by the
	// scheduler goroutine: result order and failure aggregation therefore do
	// not depend on which worker happened to finish first.
	settle := func(r Result, skippedByFailure bool) {
		results[r.Step.ID] = r
		if skippedByFailure || (r.Err != nil && !r.Skipped && !r.Step.Optional) {
			failedSteps[r.Step.ID] = true
		}
		if r.Err != nil && !r.Skipped && !r.Step.Optional {
			scope := r.Step.Scope
			if scope == "" {
				scope = "lab"
			}
			failedScopes[scope] = true
		}
		for _, dep := range dependents[r.Step.ID] {
			remaining[dep]--
			if remaining[dep] == 0 {
				ready = append(ready, p.steps[dep])
			}
		}
		sort.SliceStable(ready, func(i, j int) bool {
			return order[ready[i].ID] < order[ready[j].ID]
		})
	}

	skip := func(s *Step) (Result, bool) {
		if opts.DryRun {
			return Result{Step: s, Skipped: true}, false
		}
		if s.Scope != "" && failedScopes[s.Scope] {
			return Result{Step: s, Skipped: true}, true
		}
		for _, need := range s.Needs {
			if failedSteps[need] {
				return Result{
					Step:    s,
					Skipped: true,
					Err:     fmt.Errorf("skipped: its prerequisite %q failed", need),
				}, true
			}
		}
		return Result{}, false
	}

	running := 0
	stopScheduling := false
	var stopErr error
	for len(results) < p.Len() && !stopScheduling {
		if err := ctx.Err(); err != nil {
			stopErr = err
			cancel()
			break
		}

		// Resolve all skips before consuming a worker. A scope failure can
		// release a long downstream chain, and none of it should occupy the
		// bounded pool merely to report that it cannot run.
		progressed := false
		for len(ready) > 0 {
			s := ready[0]
			r, blocked := skip(s)
			if r.Step == nil {
				break
			}
			ready = ready[1:]
			settle(r, blocked)
			progressed = true
		}
		if progressed {
			continue
		}

		if len(ready) > 0 && running < workers {
			s := ready[0]
			select {
			case work <- s:
				ready = ready[1:]
				running++
				continue
			case <-ctx.Done():
				stopScheduling = true
				stopErr = ctx.Err()
				cancel()
				break
			}
		}
		if stopScheduling {
			break
		}
		if running == 0 {
			// Validate rules out cycles, so getting here would be an internal
			// scheduler bug. Naming the unresolved IDs is much more useful
			// than blocking forever in a deployment.
			var pending []string
			for _, id := range p.order {
				if _, ok := results[id]; !ok {
					pending = append(pending, id)
				}
			}
			stopErr = fmt.Errorf("plan deadlocked; unrunnable steps: %s", strings.Join(pending, ", "))
			cancel()
			break
		}

		select {
		case r := <-done:
			running--
			settle(r, false)
			if r.Err != nil && !r.Step.Optional && !opts.ContinueOnError {
				stopScheduling = true
				stopErr = fmt.Errorf("%s: %w", r.Step.Describe, r.Err)
				cancel()
			}
		case <-ctx.Done():
			stopScheduling = true
			stopErr = ctx.Err()
			cancel()
		}
	}

	// A stopped scheduler must still collect each in-flight worker result
	// before closing the pool. They are deliberately not added to the report:
	// they began before cancellation and may only be reporting the executor's
	// cancellation, not an independently settled plan outcome. The buffered
	// channel is sized to the worker count, so no worker can be stranded.
	for running > 0 {
		<-done
		running--
	}
	closeWorkers()

	rep := reportFromResults(p, results, start)
	if stopErr != nil {
		return rep, stopErr
	}
	return rep, nil
}

// reportFromResults rebuilds reports in plan insertion order rather than
// worker completion order. Concurrent execution must not make user-facing
// errors or summaries flap from one invocation to the next.
func reportFromResults(p *Plan, results map[string]Result, start time.Time) *Report {
	rep := &Report{ScopeErrors: map[string][]error{}, Duration: time.Since(start)}
	for _, id := range p.order {
		r, ok := results[id]
		if !ok {
			continue
		}
		rep.Results = append(rep.Results, r)
		if r.Err == nil || r.Skipped || r.Step.Optional {
			continue
		}
		scope := r.Step.Scope
		if scope == "" {
			scope = "lab"
		}
		rep.ScopeErrors[scope] = append(rep.ScopeErrors[scope],
			fmt.Errorf("%s: %w", r.Step.Describe, r.Err))
	}
	return rep
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
