// Package limiter provides node-wide, observable backpressure for operations
// that contend on the container runtime, netlink, and host kernel.
package limiter

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Kind identifies a shared operation budget.
type Kind string

const (
	Apply     Kind = "apply"
	Lifecycle Kind = "lifecycle"
	ExecProbe Kind = "exec_probe"
	Netlink   Kind = "netlink"
	ImagePull Kind = "image_pull"
	Capture   Kind = "capture"
)

var allKinds = []Kind{Apply, Lifecycle, ExecProbe, Netlink, ImagePull, Capture}

// Config configures one node-wide budget per operation class.
type Config struct {
	Apply     int
	Lifecycle int
	ExecProbe int
	Netlink   int
	ImagePull int
	Capture   int
}

// DefaultConfig is conservative enough for a node that hosts multiple labs,
// rather than assuming one controller owns every worker on the machine.
func DefaultConfig() Config {
	n := runtime.NumCPU()
	return Config{
		Apply:     bounded(n*2, 4, 32),
		Lifecycle: bounded(n*2, 4, 16),
		ExecProbe: bounded(n*4, 8, 48),
		Netlink:   bounded(n, 2, 12),
		ImagePull: 2,
		Capture:   bounded(n, 2, 8),
	}
}

func bounded(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

// Stats is a snapshot suitable for status APIs and later metrics export.
type Stats struct {
	Limit        int           `json:"limit"`
	InFlight     int           `json:"in_flight"`
	QueueDepth   int           `json:"queue_depth"`
	Acquisitions uint64        `json:"acquisitions"`
	TotalWait    time.Duration `json:"total_wait"`
	MaxWait      time.Duration `json:"max_wait"`
	LastWait     time.Duration `json:"last_wait"`
}

type bucket struct {
	slots chan struct{}
	stats Stats
}

// Limiter is shared by every lab handled by one agent process.
type Limiter struct {
	mu      sync.Mutex
	buckets map[Kind]*bucket
}

// New constructs a limiter. A non-positive configured budget is normalised to
// one, because an accidental zero must not turn every operation into a queue
// that can never advance.
func New(cfg Config) *Limiter {
	limits := map[Kind]int{
		Apply: cfg.Apply, Lifecycle: cfg.Lifecycle, ExecProbe: cfg.ExecProbe,
		Netlink: cfg.Netlink, ImagePull: cfg.ImagePull, Capture: cfg.Capture,
	}
	out := &Limiter{buckets: map[Kind]*bucket{}}
	for _, kind := range allKinds {
		limit := limits[kind]
		if limit <= 0 {
			limit = 1
		}
		out.buckets[kind] = &bucket{
			slots: make(chan struct{}, limit),
			stats: Stats{Limit: limit},
		}
	}
	return out
}

// Acquire waits for every named budget in stable order. The release function
// is idempotent and must be called as soon as the protected operation returns.
func (l *Limiter) Acquire(ctx context.Context, kinds ...Kind) (func(), error) {
	if l == nil || len(kinds) == 0 {
		return func() {}, nil
	}
	want := normaliseKinds(kinds)
	acquired := make([]Kind, 0, len(want))
	for _, kind := range want {
		l.mu.Lock()
		bucket := l.buckets[kind]
		if bucket == nil {
			l.mu.Unlock()
			releaseKinds(l, acquired)
			return nil, context.Canceled
		}
		bucket.stats.QueueDepth++
		l.mu.Unlock()

		start := time.Now()
		select {
		case bucket.slots <- struct{}{}:
			wait := time.Since(start)
			l.mu.Lock()
			bucket.stats.QueueDepth--
			bucket.stats.InFlight++
			bucket.stats.Acquisitions++
			bucket.stats.TotalWait += wait
			bucket.stats.LastWait = wait
			if wait > bucket.stats.MaxWait {
				bucket.stats.MaxWait = wait
			}
			l.mu.Unlock()
			acquired = append(acquired, kind)
		case <-ctx.Done():
			l.mu.Lock()
			bucket.stats.QueueDepth--
			l.mu.Unlock()
			releaseKinds(l, acquired)
			return nil, ctx.Err()
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() { releaseKinds(l, acquired) })
	}, nil
}

// Run acquires the requested shared budgets around fn.
func (l *Limiter) Run(ctx context.Context, kinds []Kind, fn func() error) error {
	release, err := l.Acquire(ctx, kinds...)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

func releaseKinds(l *Limiter, kinds []Kind) {
	for i := len(kinds) - 1; i >= 0; i-- {
		kind := kinds[i]
		l.mu.Lock()
		bucket := l.buckets[kind]
		l.mu.Unlock()
		if bucket == nil {
			continue
		}
		<-bucket.slots
		l.mu.Lock()
		bucket.stats.InFlight--
		l.mu.Unlock()
	}
}

func normaliseKinds(kinds []Kind) []Kind {
	seen := map[Kind]bool{}
	out := make([]Kind, 0, len(kinds))
	for _, kind := range kinds {
		if !seen[kind] {
			seen[kind] = true
			out = append(out, kind)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Snapshot returns independent per-kind queue and wait statistics.
func (l *Limiter) Snapshot() map[string]Stats {
	out := map[string]Stats{}
	if l == nil {
		return out
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for kind, bucket := range l.buckets {
		out[string(kind)] = bucket.stats
	}
	return out
}

// Limit returns the configured concurrency for one kind. It is used to cap a
// per-request plan worker count before it can create a large blocked pool that
// merely waits behind the shared node budget.
func (l *Limiter) Limit(kind Kind) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if bucket := l.buckets[kind]; bucket != nil {
		return bucket.stats.Limit
	}
	return 0
}

// ClampWorkers applies a shared budget to an optional requested worker count.
// Zero adopts the budget rather than a plan-local CPU-derived default.
func (l *Limiter) ClampWorkers(kind Kind, requested int) int {
	limit := l.Limit(kind)
	if limit <= 0 {
		return requested
	}
	if requested <= 0 || requested > limit {
		return limit
	}
	return requested
}
