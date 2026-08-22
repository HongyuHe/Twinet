package harness

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type fakeWarmHarness struct {
	identity WarmIdentity

	mu        sync.Mutex
	state     string
	resets    int
	destroyed int
	resetErr  error
}

func (h *fakeWarmHarness) WarmIdentity() WarmIdentity { return h.identity }

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
	var created []*fakeWarmHarness
	pool, err := NewWarmPool(context.Background(), 2, func(_ context.Context, worker int) (WarmHarness, error) {
		harness := &fakeWarmHarness{identity: WarmIdentity{
			Namespace: fmt.Sprintf("grade-worker-%d", worker),
			Fence:     fmt.Sprintf("fence-%d", worker),
			ImageLock: "sha256:locked",
		}}
		created = append(created, harness)
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
