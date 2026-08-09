package plan

import (
	"context"
	"fmt"
	"time"
)

func numCPU() int { return runtimeNumCPU() }

// Wait polls a readiness predicate until it holds, the deadline expires, or the
// context is cancelled.
//
// Every place the legacy platform wrote `sleep 60` becomes a call to this. That
// is not only faster: a sleep is either too short (and the next step fails
// mysteriously) or too long (and everyone waits). A predicate is exactly right,
// and it reports what it was waiting for when it gives up.
func Wait(ctx context.Context, w Waiter) error {
	interval := w.Interval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Consecutive successes required, so a predicate that flaps (a BGP RIB
	// mid-convergence, say) is not mistaken for a stable one.
	need := w.StableFor
	if need <= 0 {
		need = 1
	}
	streak := 0
	var lastErr error
	deadline := time.Now().Add(timeout)

	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("timed out after %s waiting for %s: last check said: %w",
					timeout, w.Describe, lastErr)
			}
			return fmt.Errorf("timed out after %s waiting for %s", timeout, w.Describe)
		case <-t.C:
		}

		ok, err := w.Check(ctx)
		switch {
		case err != nil:
			lastErr = err
			streak = 0
		case ok:
			streak++
			if streak >= need {
				return nil
			}
		default:
			streak = 0
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			continue // let the ctx.Done branch produce the message
		}
		next := interval
		if next > remaining {
			next = remaining
		}
		t.Reset(next)
	}
}

// Waiter is a readiness predicate with its metadata.
type Waiter struct {
	// Describe says what is being waited for, and appears in timeout errors.
	Describe string
	// Check reports whether the condition holds. An error means "not yet, and
	// here is why", and is surfaced if the wait times out.
	Check func(context.Context) (bool, error)
	// Interval between polls.
	Interval time.Duration
	// Timeout bounds the wait.
	Timeout time.Duration
	// StableFor requires this many consecutive successes, which is how
	// convergence (as opposed to a momentary state) is detected.
	StableFor int
}
