package harness

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeWarmHarness struct {
	identity WarmIdentity

	mu        sync.Mutex
	state     string
	resets    int
	destroyed int
	resetErr  error
	taintErr  error
}

func (h *fakeWarmHarness) WarmIdentity() WarmIdentity { return h.identity }
func (h *fakeWarmHarness) WarmTaint() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.taintErr
}

func (h *fakeWarmHarness) Reset(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.resets++
	if h.resetErr != nil {
		return h.resetErr
	}
	h.state = "baseline"
	return nil
}

func (h *fakeWarmHarness) Destroy(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.destroyed++
	return nil
}

func (h *fakeWarmHarness) set(value string) {
	h.mu.Lock()
	h.state = value
	h.mu.Unlock()
}

func (h *fakeWarmHarness) get() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

func TestWarmPoolResetsEverySubmissionAndDestroysAtEnd(t *testing.T) {
	created := make([]*fakeWarmHarness, 2)
	pool, err := NewWarmPool(context.Background(), 2, func(_ context.Context, worker int) (WarmHarness, error) {
		harness := &fakeWarmHarness{identity: WarmIdentity{
			Namespace: fmt.Sprintf("grade-worker-%d", worker),
			Fence:     fmt.Sprintf("fence-%d", worker),
			ImageLock: "sha256:locked",
		}}
		created[worker] = harness
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for submission := 0; submission < 4; submission++ {
		submission := submission
		if err := pool.With(context.Background(), func(_ context.Context, warm WarmHarness) error {
			harness := warm.(*fakeWarmHarness)
			if got := harness.get(); got != "baseline" {
				t.Fatalf("submission %d inherited %q instead of a baseline", submission, got)
			}
			harness.set(fmt.Sprintf("submission-%d", submission))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, harness := range created {
		if seen[harness.identity.Namespace] {
			t.Fatalf("workers shared namespace %q", harness.identity.Namespace)
		}
		seen[harness.identity.Namespace] = true
		if got := harness.get(); got != "baseline" {
			t.Errorf("%s leaked %q after its final submission", harness.identity.Namespace, got)
		}
		if harness.destroyed != 1 {
			t.Errorf("%s destroy count = %d, want 1", harness.identity.Namespace, harness.destroyed)
		}
		// One baseline capture/reset at construction, then a reset before and
		// after every use it happened to serve.
		if harness.resets < 1 {
			t.Errorf("%s was never reset", harness.identity.Namespace)
		}
	}
}

func TestWarmPoolInitializesWorkersConcurrently(t *testing.T) {
	const workers = 4
	started := make(chan int, workers)
	release := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		pool, err := NewWarmPool(context.Background(), workers,
			func(_ context.Context, worker int) (WarmHarness, error) {
				started <- worker
				<-release
				return &fakeWarmHarness{identity: WarmIdentity{
					Namespace: fmt.Sprintf("grade-worker-%d", worker),
					Fence:     fmt.Sprintf("fence-%d", worker),
					ImageLock: "sha256:locked",
				}}, nil
			})
		if pool != nil {
			err = errors.Join(err, pool.Close(context.Background()))
		}
		result <- err
	}()
	for worker := 0; worker < workers; worker++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d warm factories started before release", worker, workers)
		}
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestWarmPoolDestroysEveryCreatedWorkerWhenInitializationFails(t *testing.T) {
	created := make([]*fakeWarmHarness, 3)
	_, err := NewWarmPool(context.Background(), len(created),
		func(_ context.Context, worker int) (WarmHarness, error) {
			harness := &fakeWarmHarness{identity: WarmIdentity{
				Namespace: fmt.Sprintf("grade-worker-%d", worker),
				Fence:     fmt.Sprintf("fence-%d", worker),
				ImageLock: "sha256:locked",
			}}
			created[worker] = harness
			if worker == 1 {
				return harness, fmt.Errorf("deployment failed")
			}
			return harness, nil
		})
	if err == nil {
		t.Fatal("partial warm pool initialization succeeded")
	}
	for worker, harness := range created {
		if harness == nil || harness.destroyed != 1 {
			t.Errorf("worker %d cleanup = %#v, want one destroy", worker, harness)
		}
	}
}

func TestWarmPoolDiscardsFailedResetRatherThanReusingState(t *testing.T) {
	harness := &fakeWarmHarness{identity: WarmIdentity{
		Namespace: "grade-worker", Fence: "fence", ImageLock: "sha256:locked",
	}}
	pool, err := NewWarmPool(context.Background(), 1, func(context.Context, int) (WarmHarness, error) {
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.mu.Lock()
	harness.resetErr = fmt.Errorf("cannot clear ROAs")
	harness.mu.Unlock()
	if err := pool.With(context.Background(), func(context.Context, WarmHarness) error { return nil }); err == nil {
		t.Fatal("reset failure reused an unclean warm harness")
	}
	if harness.destroyed != 1 {
		t.Fatalf("failed worker was not destroyed: %#v", harness)
	}
	_ = pool.Close(context.Background())
}

func TestWarmPoolDiscardsTaintedPeerStateAfterGrade(t *testing.T) {
	harness := &fakeWarmHarness{identity: WarmIdentity{
		Namespace: "grade-worker", Fence: "fence", ImageLock: "sha256:locked",
	}}
	pool, err := NewWarmPool(context.Background(), 1, func(context.Context, int) (WarmHarness, error) {
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = pool.With(context.Background(), func(context.Context, WarmHarness) error {
		harness.mu.Lock()
		harness.taintErr = fmt.Errorf("reference peer adaptation could not be undone")
		harness.mu.Unlock()
		return nil
	})
	if err == nil {
		t.Fatal("tainted reference peer state was returned to the warm pool")
	}
	if harness.destroyed != 1 {
		t.Fatalf("tainted worker destroy count=%d, want 1", harness.destroyed)
	}
	_ = pool.Close(context.Background())
}

func TestWarmPoolFailsSecondLeaseImmediatelyAfterDiscard(t *testing.T) {
	harness := &fakeWarmHarness{identity: WarmIdentity{
		Namespace: "grade-worker", Fence: "fence", ImageLock: "sha256:locked",
	}}
	pool, err := NewWarmPool(context.Background(), 1, func(context.Context, int) (WarmHarness, error) {
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.mu.Lock()
	harness.resetErr = fmt.Errorf("cannot restore baseline")
	harness.mu.Unlock()
	if err := pool.With(context.Background(), func(context.Context, WarmHarness) error { return nil }); err == nil {
		t.Fatal("first failed reset did not discard the only slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = pool.With(ctx, func(context.Context, WarmHarness) error { return nil })
	if err == nil || time.Since(start) >= 25*time.Millisecond {
		t.Fatalf("second lease blocked after slot loss: err=%v elapsed=%s", err, time.Since(start))
	}
	_ = pool.Close(context.Background())
}

func TestWarmPoolCloseAndWithDoNotDeadlockAfterSlotLoss(t *testing.T) {
	harness := &fakeWarmHarness{identity: WarmIdentity{
		Namespace: "grade-worker", Fence: "fence", ImageLock: "sha256:locked",
	}}
	pool, err := NewWarmPool(context.Background(), 1, func(context.Context, int) (WarmHarness, error) {
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.mu.Lock()
	harness.taintErr = fmt.Errorf("peer reset failed")
	harness.mu.Unlock()
	if err := pool.With(context.Background(), func(context.Context, WarmHarness) error { return nil }); err == nil {
		t.Fatal("tainted slot was not discarded")
	}
	done := make(chan error, 1)
	go func() { done <- pool.Close(context.Background()) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked after discarded slot")
	}
	if err := pool.With(context.Background(), func(context.Context, WarmHarness) error { return nil }); err == nil {
		t.Fatal("With succeeded after Close")
	}
}

func TestWarmPoolCloseHonorsContextWhileLeaseIsActive(t *testing.T) {
	harness := &fakeWarmHarness{identity: WarmIdentity{
		Namespace: "grade-worker", Fence: "fence", ImageLock: "sha256:locked",
	}}
	pool, err := NewWarmPool(context.Background(), 1, func(context.Context, int) (WarmHarness, error) {
		return harness, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	used := make(chan error, 1)
	go func() {
		used <- pool.With(context.Background(), func(context.Context, WarmHarness) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pool.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close with active lease error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-used; err == nil {
		t.Fatal("active lease returned to a pool that was closing")
	}
	if err := pool.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
