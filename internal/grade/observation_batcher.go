package grade

import (
	"context"
	"fmt"
	"sync"
	"time"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// observationBatcher collects the simultaneous per-device surveys created by
// snapshot construction and sends them through one node-aware BatchExec call.
// A short collection window is enough because the plan launches all state
// tasks together; it avoids delaying an isolated library read.
type observationBatcher struct {
	snapshot *ObservationSnapshot
	exec     func(context.Context, []BatchExecRequest) ([]BatchExecResult, error)
	ctx      context.Context

	requests chan observationBatchRequest
	done     chan struct{}
	once     sync.Once
}

type observationBatchRequest struct {
	ctx      context.Context
	source   string
	device   string
	commands [][]string
	marker   string
	script   string
	reply    chan observationBatchReply
}

type observationBatchReply struct {
	results []rt.ExecResult
	err     error
}

func newObservationBatcher(ctx context.Context, snapshot *ObservationSnapshot,
	exec func(context.Context, []BatchExecRequest) ([]BatchExecResult, error),
) *observationBatcher {
	if snapshot == nil || exec == nil {
		return nil
	}
	batcher := &observationBatcher{
		snapshot: snapshot, exec: exec, ctx: ctx,
		requests: make(chan observationBatchRequest), done: make(chan struct{}),
	}
	go batcher.loop()
	return batcher
}

func (b *observationBatcher) run(ctx context.Context, source, device string,
	commands [][]string,
) ([]rt.ExecResult, error) {
	if b == nil {
		return nil, fmt.Errorf("nil observation batcher")
	}
	reply := make(chan observationBatchReply, 1)
	script, marker, err := observationBatchScript(commands)
	if err != nil {
		return nil, err
	}
	request := observationBatchRequest{
		ctx: ctx, source: source, device: device, commands: commands, script: script, marker: marker, reply: reply,
	}
	select {
	case b.requests <- request:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.done:
		return nil, fmt.Errorf("observation batcher is closed")
	}
	select {
	case result := <-reply:
		return result.results, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *observationBatcher) close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		close(b.done)
	})
}

func (b *observationBatcher) loop() {
	defer func() {
		// Callers are only present while collectObservationSnapshot waits for
		// its tasks. Once closed, any late caller observes b.done above.
	}()
	for {
		select {
		case <-b.done:
			return
		case first := <-b.requests:
			batch := []observationBatchRequest{first}
			timer := time.NewTimer(2 * time.Millisecond)
		collect:
			for len(batch) < 32 {
				select {
				case <-b.done:
					if !timer.Stop() {
						<-timer.C
					}
					b.replyCancelled(batch)
					return
				case request := <-b.requests:
					batch = append(batch, request)
				case <-timer.C:
					break collect
				}
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			b.execute(batch)
		}
	}
}

func (b *observationBatcher) execute(batch []observationBatchRequest) {
	requests := make([]BatchExecRequest, len(batch))
	for index, request := range batch {
		requests[index] = BatchExecRequest{
			DeviceID: request.device,
			Command:  []string{"sh", "-c", request.script},
		}
	}
	results, err := b.exec(b.ctx, requests)
	if err != nil {
		for _, request := range batch {
			request.reply <- observationBatchReply{err: err}
		}
		return
	}
	if len(results) != len(batch) {
		err := fmt.Errorf("batch executor returned %d results for %d observations", len(results), len(batch))
		for _, request := range batch {
			request.reply <- observationBatchReply{err: err}
		}
		return
	}
	for index, request := range batch {
		result := results[index]
		if result.Err != nil {
			request.reply <- observationBatchReply{err: result.Err}
			continue
		}
		b.snapshot.recordExternalBatchExec()
		parsed, err := b.snapshot.finishObservationBatch(request.device, request.source,
			request.commands, request.marker, result.Result)
		request.reply <- observationBatchReply{results: parsed, err: err}
	}
}

func (b *observationBatcher) replyCancelled(batch []observationBatchRequest) {
	for _, request := range batch {
		request.reply <- observationBatchReply{err: context.Canceled}
	}
}
