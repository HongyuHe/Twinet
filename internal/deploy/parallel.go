package deploy

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

const defaultAuxiliaryWorkers = 8

func (e *Engine) auxiliaryWorkers(items int) int {
	if items <= 0 {
		return 0
	}
	workers := e.Workers
	if workers <= 0 {
		workers = defaultAuxiliaryWorkers
	}
	if workers > items {
		return items
	}
	return workers
}

// runBounded runs indexed work with a fixed-size worker pool. Callers keep
// their input sorted and aggregate errs by index, which gives concurrent work
// deterministic results and error messages.
func (e *Engine) runBounded(ctx context.Context, items int, fn func(int) error) (
	started []bool, errs []error, ctxErr error,
) {
	started = make([]bool, items)
	errs = make([]error, items)
	if items == 0 {
		return started, errs, ctx.Err()
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for range e.auxiliaryWorkers(items) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				// A sender can race a cancellation exactly as a worker becomes
				// available. Never let that queued item invoke a destructive
				// operation after the request was cancelled.
				if ctx.Err() != nil {
					continue
				}
				started[i] = true
				errs[i] = fn(i)
			}
		}()
	}

	for i := range items {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return started, errs, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return started, errs, ctx.Err()
}

func deterministicError(ctxErr error, problems []string) error {
	if len(problems) == 0 {
		return ctxErr
	}
	body := strings.Join(problems, "; ")
	if ctxErr != nil {
		return fmt.Errorf("%w: %s", ctxErr, body)
	}
	return fmt.Errorf("%s", body)
}
