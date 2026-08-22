package grade

import (
	"context"
	"strings"
	"sync"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestObservationBatcherCoalescesDevicesIntoOneNodeRequest(t *testing.T) {
	snapshot := newObservationSnapshot(func(context.Context, string, []string) (rt.ExecResult, error) {
		t.Fatal("batcher should use BatchExec instead of single exec")
		return rt.ExecResult{}, nil
	})
	var (
		mu        sync.Mutex
		callCount int
		batchSize int
	)
	batcher := newObservationBatcher(context.Background(), snapshot,
		func(_ context.Context, requests []BatchExecRequest) ([]BatchExecResult, error) {
			mu.Lock()
			callCount++
			batchSize = len(requests)
			mu.Unlock()
			results := make([]BatchExecResult, len(requests))
			for index, request := range requests {
				marker := batchMarker(t, request.Command[2])
				results[index].Result = rt.ExecResult{Stdout: strings.Join([]string{
					marker + "_0_RC=0", "{}", marker + "_0_END",
				}, "\n") + "\n"}
			}
			return results, nil
		})
	defer batcher.close()

	commands := [][]string{{"ip", "-j", "address", "show"}}
	var wg sync.WaitGroup
	for _, device := range []string{"as3/A", "as3/B"} {
		device := device
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := batcher.run(context.Background(), "test", device, commands); err != nil {
				t.Errorf("batch %s: %v", device, err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 || batchSize != 2 {
		t.Fatalf("node batch calls=%d size=%d, want one request for two devices", callCount, batchSize)
	}
}
