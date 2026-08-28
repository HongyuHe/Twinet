package harness

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const warmPoolInitCleanupTimeout = 10 * time.Minute

// WarmIdentity binds a reusable harness to the same safety boundaries as an
// ordinary isolated deployment. Namespace must be unique per worker; Fence and
// ImageLock make a pool adapter prove it did not bypass fenced deployment or
// immutable-image admission while trying to save startup time.
type WarmIdentity struct {
	Namespace string
	Fence     string
	ImageLock string
}

// WarmHarness is a deployed reference/synthetic substrate. Reset must restore
// the exact clean student baseline, including submitted scripts, dynamic
// kernel/OVS state, ROAs, and reference peer adaptations; it is called before
// and after each lease.
type WarmHarness interface {
	WarmIdentity() WarmIdentity
	Reset(context.Context) error
	Destroy(context.Context) error
}

// TaintedWarmHarness reports state outside the target reset boundary that
// could not be restored. A pool must destroy rather than recycle it: resetting
// only the submission AS cannot erase a peer adaptation left on a reference
// neighbour.
type TaintedWarmHarness interface {
	WarmTaint() error
}

// WarmFactory deploys one substrate exactly once for a worker. The factory is
// where a cluster adapter acquires the fenced hold and image lock.
type WarmFactory func(context.Context, int) (WarmHarness, error)

// WarmPool owns a bounded set of clean, reusable private harnesses. It is
// deliberately a pool of whole namespaces rather than mutable target AS
// objects: nothing from one submission can be visible in another pool slot.
type WarmPool struct {
	slots chan WarmHarness

	mu       sync.Mutex
	all      map[string]WarmHarness
	closed   bool
	closeErr error
	active   sync.WaitGroup
	failure  error

	unavailable     chan struct{}
	unavailableOnce sync.Once
	closeOnce       sync.Once
	closeDone       chan struct{}
}

// NewWarmPool deploys and validates every worker substrate before admitting a
// submission. If any deployment/reset fails, all already-created slots are
// destroyed; a partially initialized pool is never used.
func NewWarmPool(ctx context.Context, workers int, factory WarmFactory) (*WarmPool, error) {
	if workers < 1 {
		return nil, fmt.Errorf("warm pool needs at least one worker")
	}
	if factory == nil {
		return nil, fmt.Errorf("warm pool needs a factory")
	}
	pool := &WarmPool{
		slots: make(chan WarmHarness, workers), all: map[string]WarmHarness{},
		unavailable: make(chan struct{}), closeDone: make(chan struct{}),
	}
	created := make([]WarmHarness, workers)
	initErrs := make([]error, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			harness, err := factory(ctx, worker)
			if harness != nil {
				created[worker] = harness
			}
			if err == nil && harness == nil {
				err = fmt.Errorf("warm factory returned nil harness")
			}
			if err == nil {
				err = harness.Reset(ctx)
			}
			if err != nil {
				initErrs[worker] = fmt.Errorf("initializing warm worker %d: %w", worker, err)
			}
		}(worker)
	}
	wg.Wait()
	var initErr error
	for _, err := range initErrs {
		initErr = errors.Join(initErr, err)
	}
	if initErr == nil {
		for _, harness := range created {
			if err := pool.add(harness); err != nil {
				initErr = errors.Join(initErr, err)
			}
		}
	}
	if initErr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), warmPoolInitCleanupTimeout)
		defer cancel()
		for _, harness := range created {
			if harness == nil {
				continue
			}
			if err := harness.Destroy(cleanupCtx); err != nil {
				initErr = errors.Join(initErr,
					fmt.Errorf("destroying failed warm worker %s: %w",
						harness.WarmIdentity().Namespace, err))
			}
		}
		return nil, initErr
	}
	for _, harness := range created {
		pool.slots <- harness
	}
	return pool, nil
}

func (p *WarmPool) add(harness WarmHarness) error {
	if harness == nil {
		return fmt.Errorf("warm factory returned nil harness")
	}
	identity := harness.WarmIdentity()
	if identity.Namespace == "" {
		return fmt.Errorf("warm harness has no unique namespace")
	}
	if identity.Fence == "" {
		return fmt.Errorf("warm harness %s has no fenced deployment identity", identity.Namespace)
	}
	if identity.ImageLock == "" {
		return fmt.Errorf("warm harness %s has no image lock identity", identity.Namespace)
	}
	if _, exists := p.all[identity.Namespace]; exists {
		return fmt.Errorf("warm harness namespace %q is not unique", identity.Namespace)
	}
	p.all[identity.Namespace] = harness
	return nil
}

// With leases one clean harness. A reset failure destroys that slot and returns
// an infrastructure error; it never hands the potentially contaminated
// namespace to a later submission.
func (p *WarmPool) With(ctx context.Context, grade func(context.Context, WarmHarness) error) error {
	if p == nil || grade == nil {
		return fmt.Errorf("warm pool and grade function are required")
	}
	p.mu.Lock()
	if p.closed {
		err := p.unavailableErrorLocked()
		p.mu.Unlock()
		return err
	}
	p.mu.Unlock()
	select {
	case harness, ok := <-p.slots:
		if !ok {
			return fmt.Errorf("warm pool is closed")
		}
		p.mu.Lock()
		if p.closed {
			err := p.unavailableErrorLocked()
			p.mu.Unlock()
			p.discard(context.WithoutCancel(ctx), harness)
			return err
		}
		p.active.Add(1)
		p.mu.Unlock()
		defer p.active.Done()
		return p.use(ctx, harness, grade)
	case <-p.unavailable:
		p.mu.Lock()
		err := p.unavailableErrorLocked()
		p.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *WarmPool) use(ctx context.Context, harness WarmHarness,
	grade func(context.Context, WarmHarness) error,
) error {
	if err := harness.Reset(ctx); err != nil {
		p.discard(context.WithoutCancel(ctx), harness)
		return fmt.Errorf("resetting warm harness %s before submission: %w",
			harness.WarmIdentity().Namespace, err)
	}
	gradeErr := grade(ctx, harness)
	if tainted, ok := harness.(TaintedWarmHarness); ok {
		if taint := tainted.WarmTaint(); taint != nil {
			p.discard(context.WithoutCancel(ctx), harness)
			if gradeErr != nil {
				return fmt.Errorf("%v; warm harness %s is tainted: %w",
					gradeErr, harness.WarmIdentity().Namespace, taint)
			}
			return fmt.Errorf("warm harness %s is tainted: %w",
				harness.WarmIdentity().Namespace, taint)
		}
	}
	if err := harness.Reset(context.WithoutCancel(ctx)); err != nil {
		p.discard(context.WithoutCancel(ctx), harness)
		if gradeErr != nil {
			return fmt.Errorf("%v; resetting warm harness %s afterwards: %w",
				gradeErr, harness.WarmIdentity().Namespace, err)
		}
		return fmt.Errorf("resetting warm harness %s after submission: %w",
			harness.WarmIdentity().Namespace, err)
	}
	p.mu.Lock()
	closed := p.closed
	closedErr := p.unavailableErrorLocked()
	p.mu.Unlock()
	if closed {
		p.discard(context.WithoutCancel(ctx), harness)
		return fmt.Errorf("%w while grading %s", closedErr, harness.WarmIdentity().Namespace)
	}
	p.slots <- harness
	return gradeErr
}

func (p *WarmPool) discard(ctx context.Context, harness WarmHarness) {
	if harness == nil {
		return
	}
	p.markUnavailable(fmt.Errorf("warm slot %s was discarded", harness.WarmIdentity().Namespace))
	_ = harness.Destroy(ctx)
	p.mu.Lock()
	delete(p.all, harness.WarmIdentity().Namespace)
	p.mu.Unlock()
}

func (p *WarmPool) markUnavailable(reason error) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.failure = reason
		p.unavailableOnce.Do(func() { close(p.unavailable) })
	}
	p.mu.Unlock()
}

func (p *WarmPool) unavailableErrorLocked() error {
	if p.failure != nil {
		return p.failure
	}
	return fmt.Errorf("warm pool is closed")
}

// Close destroys every substrate, including currently idle slots. Callers
// should cancel/drain their workers before Close so no live harness is omitted.
func (p *WarmPool) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() { go p.finishClose(ctx) })
	select {
	case <-p.closeDone:
		p.mu.Lock()
		err := p.closeErr
		p.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *WarmPool) finishClose(ctx context.Context) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.unavailableOnce.Do(func() { close(p.unavailable) })
	}
	p.mu.Unlock()
	p.active.Wait()
	p.mu.Lock()
	all := make([]WarmHarness, 0, len(p.all))
	for _, harness := range p.all {
		all = append(all, harness)
	}
	p.mu.Unlock()
	close(p.slots)
	sort.Slice(all, func(i, j int) bool {
		return all[i].WarmIdentity().Namespace < all[j].WarmIdentity().Namespace
	})
	var first error
	for _, harness := range all {
		if err := harness.Destroy(ctx); err != nil && first == nil {
			first = fmt.Errorf("destroying warm harness %s: %w", harness.WarmIdentity().Namespace, err)
		}
	}
	p.mu.Lock()
	p.closeErr = first
	p.mu.Unlock()
	close(p.closeDone)
}
