package grade

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type checkTraceContextKey struct{}

// ObservationStats is the cache and execution accounting for one grade or
// check. A cache miss is a new observation; coalesced is a concurrent caller
// joining that in-flight read rather than issuing another exec.
type ObservationStats struct {
	Hits      int `json:"hits"`
	Misses    int `json:"misses"`
	Coalesced int `json:"coalesced"`
	ExecCalls int `json:"exec_calls"`
}

type checkTrace struct {
	mu    sync.Mutex
	stats ObservationStats
}

func withCheckTrace(ctx context.Context, trace *checkTrace) context.Context {
	if trace == nil {
		return ctx
	}
	return context.WithValue(ctx, checkTraceContextKey{}, trace)
}

func traceFromContext(ctx context.Context) *checkTrace {
	trace, _ := ctx.Value(checkTraceContextKey{}).(*checkTrace)
	return trace
}

func (t *checkTrace) cache(hit, coalesced bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if hit {
		t.stats.Hits++
	} else {
		t.stats.Misses++
	}
	if coalesced {
		t.stats.Coalesced++
	}
}

func (t *checkTrace) exec() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.stats.ExecCalls++
	t.mu.Unlock()
}

func (t *checkTrace) snapshot() ObservationStats {
	if t == nil {
		return ObservationStats{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stats
}

type execTracker struct {
	mu    sync.Mutex
	total int
}

func (t *execTracker) wrap(raw rtExecFunc) rtExecFunc {
	return func(ctx context.Context, device string, command []string) (rt.ExecResult, error) {
		t.mu.Lock()
		t.total++
		t.mu.Unlock()
		if trace := traceFromContext(ctx); trace != nil {
			trace.exec()
		}
		return raw(ctx, device, command)
	}
}

func (t *execTracker) wrapBatch(raw func(context.Context, []BatchExecRequest) ([]BatchExecResult, error)) func(context.Context, []BatchExecRequest) ([]BatchExecResult, error) {
	return func(ctx context.Context, requests []BatchExecRequest) ([]BatchExecResult, error) {
		results, err := raw(ctx, requests)
		t.mu.Lock()
		for _, result := range results {
			if result.Err == nil {
				t.total++
			}
		}
		t.mu.Unlock()
		return results, err
	}
}

func (t *execTracker) count() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

type schedulerEvent struct {
	key        string
	check      string
	queuedAt   time.Time
	startedAt  time.Time
	finishedAt time.Time
	resources  []string
	waitReason string
	blockedBy  []string
	stats      ObservationStats
}

type schedulerTrace struct {
	mu     sync.Mutex
	events map[string]schedulerEvent
}

func newSchedulerTrace() *schedulerTrace {
	return &schedulerTrace{events: map[string]schedulerEvent{}}
}

func (t *schedulerTrace) record(event schedulerEvent) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.events[event.key] = event
	t.mu.Unlock()
}

// SchedulerCriticalPath reports the observed wall-clock dependency chain.
// It names resource/parallel predecessors rather than pretending every check
// that happened to overlap is causally on the path.
type SchedulerCriticalPath struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   string    `json:"duration"`
	Checks     []string  `json:"checks,omitempty"`
}

func (t *schedulerTrace) criticalPath() SchedulerCriticalPath {
	if t == nil {
		return SchedulerCriticalPath{}
	}
	t.mu.Lock()
	events := make(map[string]schedulerEvent, len(t.events))
	for key, event := range t.events {
		events[key] = event
	}
	t.mu.Unlock()
	if len(events) == 0 {
		return SchedulerCriticalPath{}
	}
	var (
		first time.Time
		last  schedulerEvent
	)
	for _, event := range events {
		if first.IsZero() || event.queuedAt.Before(first) {
			first = event.queuedAt
		}
		if last.finishedAt.IsZero() || event.finishedAt.After(last.finishedAt) {
			last = event
		}
	}
	chain := []string{}
	seen := map[string]bool{}
	for current := last; current.key != "" && !seen[current.key]; {
		seen[current.key] = true
		chain = append(chain, current.check)
		var parent schedulerEvent
		for _, key := range current.blockedBy {
			candidate, ok := events[key]
			if !ok {
				continue
			}
			if parent.key == "" || candidate.finishedAt.After(parent.finishedAt) {
				parent = candidate
			}
		}
		current = parent
	}
	for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
		chain[left], chain[right] = chain[right], chain[left]
	}
	return SchedulerCriticalPath{
		StartedAt: first, FinishedAt: last.finishedAt,
		Duration: last.finishedAt.Sub(first).Round(time.Millisecond).String(),
		Checks:   chain,
	}
}

func resourceKeys(resources []ProbeResource) []string {
	out := make([]string, 0, len(resources))
	for _, resource := range resources {
		out = append(out, strings.ReplaceAll(resource.key(), "\x00", "/"))
	}
	sort.Strings(out)
	return out
}
