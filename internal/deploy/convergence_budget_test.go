package deploy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/limiter"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestConvergenceBudgetQueuesRouterStartsWithoutChangingRequests(t *testing.T) {
	engine := &Engine{
		Limiter:          limiter.New(limiter.Config{Apply: 2, ExecProbe: 2, Convergence: 8}),
		ConvergenceLimit: 1,
	}
	top := &model.Topology{Lab: &model.Lab{}}
	router := &model.Device{Kind: model.KindRouter}
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := engine.converging(context.Background(), top, router, func() error {
				started <- struct{}{}
				<-release
				return nil
			}); err != nil {
				t.Errorf("converging: %v", err)
			}
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first router did not enter convergence queue")
	}
	select {
	case <-started:
		t.Fatal("two routers entered a max_concurrent=1 convergence burst")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	wg.Wait()
}
