package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/limiter"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type gatedLifecycleRuntime struct {
	rt.Runtime
	createRelease chan struct{}
	startRelease  chan struct{}
	createStarted chan struct{}
	startStarted  chan struct{}
	createRunning atomic.Int32
	startRunning  atomic.Int32
	createPeak    atomic.Int32
	startPeak     atomic.Int32
}

func recordPeak(current *atomic.Int32, peak *atomic.Int32) {
	n := current.Add(1)
	for {
		old := peak.Load()
		if n <= old || peak.CompareAndSwap(old, n) {
			return
		}
	}
}

func (r *gatedLifecycleRuntime) Create(context.Context, *rt.Spec) (string, error) {
	recordPeak(&r.createRunning, &r.createPeak)
	r.createStarted <- struct{}{}
	<-r.createRelease
	r.createRunning.Add(-1)
	return "created", nil
}

func (r *gatedLifecycleRuntime) Start(context.Context, string) error {
	recordPeak(&r.startRunning, &r.startPeak)
	r.startStarted <- struct{}{}
	<-r.startRelease
	r.startRunning.Add(-1)
	return nil
}

func TestObservedRuntimePipelinesBoundedCreateAndStart(t *testing.T) {
	fake := &gatedLifecycleRuntime{
		createRelease: make(chan struct{}),
		startRelease:  make(chan struct{}),
		createStarted: make(chan struct{}, 12),
		startStarted:  make(chan struct{}, 12),
	}
	limits := limiter.WithDefaults(limiter.Config{ContainerCreate: 4, ContainerStart: 4})
	observed := &observedRuntime{
		runtime: fake, metrics: newAgentMetrics(), limiter: limiter.New(limits),
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = observed.Create(context.Background(), &rt.Spec{Name: "scratch"})
		}()
		go func() {
			defer wg.Done()
			_ = observed.Start(context.Background(), "scratch")
		}()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-fake.createStarted:
		case <-time.After(time.Second):
			t.Fatal("create gate did not admit four workers")
		}
		select {
		case <-fake.startStarted:
		case <-time.After(time.Second):
			t.Fatal("start gate did not admit four workers independently")
		}
	}
	if got := fake.createPeak.Load(); got != 4 {
		t.Fatalf("create peak = %d, want 4", got)
	}
	if got := fake.startPeak.Load(); got != 4 {
		t.Fatalf("start peak = %d, want 4", got)
	}
	close(fake.createRelease)
	close(fake.startRelease)
	wg.Wait()
}
