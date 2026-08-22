package agent

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
