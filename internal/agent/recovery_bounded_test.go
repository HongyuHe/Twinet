package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type bulkRecoveryRuntime struct {
	rt.Runtime
	mu        sync.Mutex
	remaining map[string]bool
	budget    int
}

func newBulkRecoveryRuntime(items int) *bulkRecoveryRuntime {
	runtime := &bulkRecoveryRuntime{remaining: map[string]bool{}, budget: -1}
	runtime.create(items)
	return runtime
}

func (r *bulkRecoveryRuntime) create(items int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start := len(r.remaining)
	for i := 0; i < items; i++ {
		r.remaining[fmt.Sprintf("container-%03d", start+i)] = true
	}
}

func (r *bulkRecoveryRuntime) setBudget(items int) {
	r.mu.Lock()
	r.budget = items
	r.mu.Unlock()
}

func (r *bulkRecoveryRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]rt.Container, 0, len(r.remaining))
	for name := range r.remaining {
		out = append(out, rt.Container{Name: name, State: rt.StateRunning})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *bulkRecoveryRuntime) Remove(ctx context.Context, name string, _ bool) error {
	return r.remove(ctx, name)
}

func (r *bulkRecoveryRuntime) remove(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.remaining[name] {
		return nil
	}
	if r.budget == 0 {
		return context.DeadlineExceeded
	}
	if r.budget > 0 {
		r.budget--
	}
	delete(r.remaining, name)
	return nil
}

func (r *bulkRecoveryRuntime) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.remaining)
}

func TestRunBoundedDeviceChecksCancelsAfterFirstSystemicFailure(t *testing.T) {
	items := make([]int, 64)
	for i := range items {
		items[i] = i
	}
	var started atomic.Int32
	start := time.Now()
	err := runBoundedDeviceChecks(context.Background(), 4, items, time.Second,
		func(int) string { return "device" },
		func(ctx context.Context, item int) error {
			started.Add(1)
			if item == 0 {
				return errors.New("dynamic state mismatch")
			}
			<-ctx.Done()
			return ctx.Err()
		})
	if err == nil || !strings.Contains(err.Error(), "dynamic state mismatch") {
		t.Fatalf("first recovery failure was not returned: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded recovery waited after systemic failure: %s", elapsed)
	}
	if got := started.Load(); got > 4 {
		t.Fatalf("recovery kept scheduling after the first failure: started %d devices", got)
	}
}

func TestRunBoundedDeviceChecksEnforcesPerDeviceDeadline(t *testing.T) {
	err := runBoundedDeviceChecks(context.Background(), 1, []int{1}, 10*time.Millisecond,
		func(int) string { return "slow-device" },
		func(ctx context.Context, _ int) error {
			<-ctx.Done()
			return ctx.Err()
		})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("per-device deadline was not returned: %v", err)
	}
}

func TestRunBoundedRecoveryItemsMakesMonotonicProgress(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	remaining := map[string]bool{}
	for _, item := range items {
		remaining[item] = true
	}
	var mu sync.Mutex
	failOnce := true
	run := func() error {
		return runBoundedRecoveryItems(context.Background(), 3, items, time.Second,
			func(item string) string { return item },
			func(_ context.Context, item string) error {
				mu.Lock()
				defer mu.Unlock()
				if !remaining[item] {
					return nil
				}
				if item == "c" && failOnce {
					failOnce = false
					return errors.New("transient remove")
				}
				delete(remaining, item)
				return nil
			})
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "c: transient remove") {
		t.Fatalf("first cleanup error = %v", err)
	}
	mu.Lock()
	firstRemaining := len(remaining)
	mu.Unlock()
	if firstRemaining != 1 {
		t.Fatalf("first cleanup left %d items, want only the transient failure", firstRemaining)
	}
	if err := run(); err != nil {
		t.Fatalf("resumed cleanup: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(remaining) != 0 {
		t.Fatalf("resumed cleanup did not monotonically reach zero: %v", remaining)
	}
}

func TestRepeatedBulkRecoveryMatchesLiveMonotonicCounts(t *testing.T) {
	// Mirrors the node-0 takeover observations from the 84-AS incident after
	// the stale apply had recreated 626 containers.
	runtime := newBulkRecoveryRuntime(626)
	want := []int{461, 3, 0}
	for attempt, remove := range []int{165, 458, 3} {
		runtime.setBudget(remove)
		containers, err := runtime.List(context.Background(), rt.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		err = runBoundedRecoveryItems(context.Background(), 8, containers, time.Second,
			func(container rt.Container) string { return container.Name },
			func(ctx context.Context, container rt.Container) error {
				return runtime.Remove(ctx, container.Name, true)
			})
		if attempt < 2 && err == nil {
			t.Fatalf("attempt %d unexpectedly completed", attempt+1)
		}
		if got := runtime.count(); got != want[attempt] {
			t.Fatalf("attempt %d remaining=%d, want live-regression count %d",
				attempt+1, got, want[attempt])
		}
	}
}

func TestRecoveryRollbackBudgetScalesPastNinetySeconds(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	fakeNow := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return fakeNow }
	tx := s.transactions["cos461"]
	tx.Previous = nil
	tx.Prestate.Containers = nil
	tx.Prestate.RuntimeSpecs = make([]transactionRuntimeSpec, 600)
	for i := range tx.Prestate.RuntimeSpecs {
		tx.Prestate.RuntimeSpecs[i].Spec = rt.Spec{Name: fmt.Sprintf("container-%03d", i)}
	}
	s.transactions["cos461"] = tx

	limit := s.recoveryRollbackLimit(tx)
	if limit <= defaultRecoveryPhaseTimeout {
		t.Fatalf("600-item rollback budget = %s, want greater than legacy %s",
			limit, defaultRecoveryPhaseTimeout)
	}
	if limit > s.recoveryTotalLimit() {
		t.Fatalf("rollback budget %s exceeds total recovery deadline %s",
			limit, s.recoveryTotalLimit())
	}
}

func TestDestroyRecoveryBudgetIncludesLiveDockerContentionMargin(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	tx := s.transactions["cos461"]
	tx.Previous = nil
	tx.Prestate.Containers = make([]transactionContainer, 880)

	const minimumMeasuredMargin = 8 * time.Second
	if recoveryDestroyItemBudget < minimumMeasuredMargin {
		t.Fatalf("destroy per-item budget = %s, want at least %s",
			recoveryDestroyItemBudget, minimumMeasuredMargin)
	}
	limit := s.recoveryRollbackBudget(tx)
	minimum := recoveryPhaseBaseBudget +
		time.Duration((len(tx.Prestate.Containers)+s.recoveryWorkerCount()-1)/
			s.recoveryWorkerCount())*minimumMeasuredMargin
	if limit < minimum {
		t.Fatalf("880-item destroy budget = %s, want at least measured-margin budget %s",
			limit, minimum)
	}
	if limit <= 6*time.Minute+15*time.Second {
		t.Fatalf("880-item destroy budget = %s, still permits the observed 6m15s cutoff", limit)
	}
}

func TestLargeRecoveryTotalCoversRequiredPhaseBudgets(t *testing.T) {
	s, _ := recoveryServer(t, nil)
	tx := s.transactions["cos461"]
	tx.Previous = []byte(`{"lab":"cos461","mode":"platform"}`)
	tx.Prestate.RuntimeSpecs = make([]transactionRuntimeSpec, 1000)

	phaseSum := s.recoveryRollbackBudget(tx) +
		2*s.recoveryArtifactLimit() +
		4*s.recoveryVerifyBudget(tx) +
		2*s.recoveryPhaseLimit()
	total := s.recoveryTotalLimit(tx)
	if total <= minimumRecoveryTotalTimeout {
		t.Fatalf("1000-object recovery total = %s, want more than fixed 30m", total)
	}
	if total <= phaseSum {
		t.Fatalf("recovery total %s does not cover required phase sum %s plus slack",
			total, phaseSum)
	}
	if total > MaximumRecoveryTotalTimeout {
		t.Fatalf("recovery total %s exceeds cap %s", total, MaximumRecoveryTotalTimeout)
	}
	if clientDeadline := MaximumRecoveryTotalTimeout; clientDeadline < total {
		t.Fatalf("client recovery deadline %s undercuts server budget %s", clientDeadline, total)
	}
}
