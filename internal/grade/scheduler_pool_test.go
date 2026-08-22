package grade

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestActivePoolBoundsConcurrencyAndStartsTimeoutAfterQueue(t *testing.T) {
	var active, maxActive atomic.Int64
	check := &Check{
		Name:  "test.active_pool",
		Class: CheckActive,
		Run: func(context.Context, *Env) Result {
			now := active.Add(1)
			for {
				old := maxActive.Load()
				if now <= old || maxActive.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			active.Add(-1)
			return Pass("test.active_pool", Evidence{})
		},
	}
	jobs := []scheduledCheck{
		{order: 0, check: check, env: &Env{}},
		{order: 1, check: check, env: &Env{}},
		{order: 2, check: check, env: &Env{}},
		{order: 3, check: check, env: &Env{}},
	}
	results := scheduleChecks(context.Background(), jobs, RunOptions{
		Parallel: 8, ReadParallel: 8, ActiveParallel: 2, CheckTimeout: 45 * time.Millisecond,
	})
	if got := maxActive.Load(); got != 2 {
		t.Fatalf("active pool max = %d, want 2", got)
	}
	for index, result := range results {
		if result.Status != StatusPass {
			t.Fatalf("queued active check %d lost its post-acquisition timeout: %#v", index, result)
		}
	}
}
