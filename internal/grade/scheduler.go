package grade

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProbeResourceKind names a fact whose attribution is invalid when two active
// checks touch it at the same time.
type ProbeResourceKind string

const (
	ProbeSource      ProbeResourceKind = "source"
	ProbeDestination ProbeResourceKind = "destination"
	ProbeInterface   ProbeResourceKind = "interface"
	ProbeCounter     ProbeResourceKind = "counter"
	ProbeCapture     ProbeResourceKind = "capture"
	ProbePort        ProbeResourceKind = "port"
)

// ProbeResource is an exclusive active-probe resource. IDs are topology
// identities (device IDs, interface IDs, or flow tags), never human names, so
// two similar student routers cannot accidentally share a lock.
type ProbeResource struct {
	Kind ProbeResourceKind
	ID   string
}

func (r ProbeResource) key() string {
	return string(r.Kind) + "\x00" + r.ID
}

// ProbeResourceResolver turns a rubric's concrete arguments into the active
// resources a check will use. It must be pure: scheduler decisions are made
// before a check runs and must not observe or mutate student state.
type ProbeResourceResolver func(env *Env, args map[string]any) []ProbeResource

type scheduledCheck struct {
	order int
	check *Check
	spec  CheckSpec
	env   *Env
}

type scheduledCheckResult struct {
	order  int
	result Result
}

// scheduleChecks executes a fixed check set at a bounded width. It always
// considers jobs in rubric order, starts every non-conflicting job it can, and
// writes results back in that same order. Completion timing can therefore
// never change report ordering or which evidence is attached to a check.
func scheduleChecks(ctx context.Context, jobs []scheduledCheck, opts RunOptions) []Result {
	results := make([]Result, len(jobs))
	if len(jobs) == 0 {
		return results
	}
	if opts.Parallel <= 0 {
		opts.Parallel = 4
	}
	if opts.CheckTimeout <= 0 {
		opts.CheckTimeout = 120 * time.Second
	}

	pending := append([]scheduledCheck(nil), jobs...)
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].order < pending[j].order })
	running := map[int][]ProbeResource{}
	done := make(chan scheduledCheckResult, len(pending))
	finished := 0

	start := func(job scheduledCheck, resources []ProbeResource) {
		running[job.order] = resources
		go func() {
			done <- scheduledCheckResult{
				order:  job.order,
				result: executeScheduledCheck(ctx, job, opts),
			}
		}()
	}

	for finished < len(jobs) {
		for len(running) < opts.Parallel {
			index := firstRunnable(pending, running)
			if index < 0 {
				break
			}
			job := pending[index]
			resources := resourcesFor(job)
			pending = append(pending[:index], pending[index+1:]...)
			start(job, resources)
		}
		if len(running) == 0 {
			// Resources are normalized before scheduling, so this can only
			// happen if a malformed job escaped normalization. Turn it into
			// a grader error rather than spin forever.
			for _, job := range pending {
				name := job.spec.Check
				if job.check != nil {
					name = job.check.Name
				}
				results[job.order] = Errored(name,
					fmt.Errorf("check scheduler could not admit its probe resources"))
			}
			break
		}
		select {
		case completed := <-done:
			results[completed.order] = completed.result
			delete(running, completed.order)
			finished++
		case <-ctx.Done():
			for _, job := range pending {
				results[job.order] = Errored(job.check.Name, ctxErr(ctx))
			}
			for order := range running {
				if results[order].Check == "" {
					name := jobs[order].spec.Check
					if jobs[order].check != nil {
						name = jobs[order].check.Name
					}
					results[order] = Errored(name, ctxErr(ctx))
				}
			}
			return results
		}
	}
	return results
}

func firstRunnable(pending []scheduledCheck, running map[int][]ProbeResource) int {
	for i, job := range pending {
		resources := resourcesFor(job)
		if !conflicts(resources, running) {
			return i
		}
	}
	return -1
}

func conflicts(want []ProbeResource, running map[int][]ProbeResource) bool {
	if len(want) == 0 {
		return false
	}
	held := map[string]bool{}
	for _, resources := range running {
		for _, resource := range resources {
			held[resource.key()] = true
		}
	}
	for _, resource := range want {
		if held[resource.key()] {
			return true
		}
	}
	return false
}

func resourcesFor(job scheduledCheck) []ProbeResource {
	var resources []ProbeResource
	if job.check != nil && job.check.Resources != nil {
		resources = job.check.Resources(job.env, job.spec.Args)
	} else if job.check != nil {
		resources = inferredProbeResources(job.check.Name, job.env)
	}
	seen := map[string]bool{}
	out := make([]ProbeResource, 0, len(resources))
	for _, resource := range resources {
		if resource.Kind == "" || strings.TrimSpace(resource.ID) == "" {
			continue
		}
		key := resource.key()
		if !seen[key] {
			seen[key] = true
			out = append(out, resource)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// inferredProbeResources protects shipped active checks while keeping
// control-plane reads fully concurrent. They share target hosts and their
// destination counters/captures, so concurrent attribution would be invalid;
// independent AS grades have different device IDs and do not serialize.
func inferredProbeResources(name string, env *Env) []ProbeResource {
	switch name {
	case "dataplane.internal_reachability", "l2.vlan_isolation", "ospf.ecmp_paths",
		"tunnel.sixin4", "policy.traffic_engineering", "vpn.site_reachability",
		"vpn.label_switched", "vpn.isolation", "multicast.delivery", "multicast.no_flooding":
		return targetProbeResources(env)
	default:
		return nil
	}
}

func targetProbeResources(env *Env) []ProbeResource {
	if env == nil || env.Topology == nil {
		return nil
	}
	seen := map[string]bool{}
	add := func(device string) {
		if device != "" {
			seen[device] = true
		}
	}
	for _, device := range targetDevices(env) {
		add(device.ID)
		for _, iface := range device.Ifaces {
			if iface != nil && iface.Peer != nil && iface.Peer.Device != nil {
				add(iface.Peer.Device.ID)
			}
		}
	}
	var out []ProbeResource
	for device := range seen {
		out = append(out,
			ProbeResource{Kind: ProbeCounter, ID: device},
			ProbeResource{Kind: ProbeCapture, ID: device},
		)
	}
	return out
}

func executeScheduledCheck(ctx context.Context, job scheduledCheck, opts RunOptions) Result {
	if job.check == nil {
		return Errored(job.spec.Check, fmt.Errorf("no such check"))
	}
	cctx, cancel := context.WithTimeout(ctx, opts.CheckTimeout)
	defer cancel()

	// Each check owns mutable arguments and its infrastructure tracker, while
	// the snapshot and peer cache remain shared by pointer.
	env := *job.env
	if env.peers == nil {
		env.peers = &peerCache{addr: map[string]string{}}
	}
	env.Args = job.spec.Args
	env.infraSeen = &infraTracker{}
	env.liveState = job.check.LiveObservations
	res := runCheck(cctx, job.check, &env)

	if fail := env.infraSeen.failure(); fail != nil && res.Status != StatusError {
		res = Errored(job.spec.Check, fail)
	}
	if cctx.Err() != nil && res.Status != StatusError {
		res = Errored(job.spec.Check, fmt.Errorf(
			"this check ran out of time after %s, so what it found is what it had managed "+
				"to look at rather than a judgement about the submission: %w",
			opts.CheckTimeout, cctx.Err()))
	}
	return res
}

// runChecks remains the package-local convenience used by focused tests and
// callers that grade one question. Run uses the same scheduler across every
// currently independent question, so active resources are also protected
// across question boundaries.
func runChecks(ctx context.Context, q QuestionSpec, env *Env, opts RunOptions) []Result {
	jobs := make([]scheduledCheck, 0, len(q.Checks))
	for i, spec := range q.Checks {
		check, ok := Lookup(spec.Check)
		if !ok {
			jobs = append(jobs, scheduledCheck{order: i, spec: spec})
			continue
		}
		jobs = append(jobs, scheduledCheck{order: i, check: check, spec: spec, env: env})
	}
	return scheduleChecks(ctx, jobs, opts)
}

// runChecksAcrossQuestions schedules a dependency-ready question wave as one
// job list. Results are split back into question order after all active probe
// conflicts have been resolved.
func runChecksAcrossQuestions(ctx context.Context, questions []QuestionSpec, indices []int,
	env *Env, opts RunOptions,
) map[int][]Result {
	type location struct {
		question int
		check    int
	}
	var (
		jobs      []scheduledCheck
		locations []location
	)
	for _, questionIndex := range indices {
		q := questions[questionIndex]
		for checkIndex, spec := range q.Checks {
			check, _ := Lookup(spec.Check)
			jobs = append(jobs, scheduledCheck{
				order: len(jobs), check: check, spec: spec, env: env,
			})
			locations = append(locations, location{question: questionIndex, check: checkIndex})
		}
	}
	flat := scheduleChecks(ctx, jobs, opts)
	out := map[int][]Result{}
	for _, questionIndex := range indices {
		out[questionIndex] = make([]Result, len(questions[questionIndex].Checks))
	}
	for index, result := range flat {
		where := locations[index]
		out[where.question][where.check] = result
	}
	return out
}

// waitSnapshotConvergence runs each declared convergence scope once before a
// grade's immutable observation boundary. An empty scope means both control
// planes and subsumes the narrower OSPF/BGP waits.
func waitSnapshotConvergence(ctx context.Context, questions []QuestionSpec,
	env *Env, timeout time.Duration,
) map[string]string {
	scopes := map[string]bool{}
	for _, question := range questions {
		if question.Converge {
			scopes[question.ConvergeScope] = true
		}
	}
	if scopes[""] {
		scopes = map[string]bool{"": true}
	}
	ordered := make([]string, 0, len(scopes))
	for scope := range scopes {
		ordered = append(ordered, scope)
	}
	sort.Strings(ordered)
	notes := map[string]string{}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, scope := range ordered {
		scope := scope
		wg.Add(1)
		go func() {
			defer wg.Done()
			live := *env
			live.liveState = true
			if err := waitForScope(ctx, &live, scope, timeout); err != nil {
				mu.Lock()
				notes[scope] = err.Error()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return notes
}

func convergenceNote(question QuestionSpec, notes map[string]string) string {
	if !question.Converge {
		return ""
	}
	if note := notes[question.ConvergeScope]; note != "" {
		return note
	}
	return notes[""]
}
