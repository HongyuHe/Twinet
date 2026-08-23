package limiter

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedLimiterBoundsConcurrentLabsAndReportsQueueing(t *testing.T) {
	l := New(Config{Apply: 1, Netlink: 1, Lifecycle: 1, ExecProbe: 1, ImagePull: 1, Capture: 1})
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var running atomic.Int64
	var peak atomic.Int64
	var wg sync.WaitGroup

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.Run(context.Background(), []Kind{Apply, Netlink}, func() error {
				n := running.Add(1)
				for {
					old := peak.Load()
					if n <= old || peak.CompareAndSwap(old, n) {
						break
					}
				}
				started <- struct{}{}
				<-release
				running.Add(-1)
				return nil
			})
			if err != nil {
				t.Errorf("limited operation: %v", err)
			}
		}()
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first lab never acquired the shared limiter")
	}
	deadline := time.Now().Add(time.Second)
	for l.Snapshot()[string(Apply)].QueueDepth == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := l.Snapshot()[string(Apply)]; stats.QueueDepth == 0 {
		t.Fatal("second lab was not visible in the shared apply queue")
	}
	if got := peak.Load(); got != 1 {
		t.Fatalf("global peak = %d, want 1", got)
	}
	close(release)
	wg.Wait()
	stats := l.Snapshot()[string(Apply)]
	if stats.Acquisitions != 2 || stats.TotalWait <= 0 {
		t.Fatalf("queue metrics lost contention: %+v", stats)
	}
}

func TestScaleDefaultsAndPartialOverrides(t *testing.T) {
	cfg := defaultConfig(56)
	if cfg.Apply != 48 || cfg.Lifecycle != 48 {
		t.Fatalf("56-core defaults = apply %d lifecycle %d, want 48/48",
			cfg.Apply, cfg.Lifecycle)
	}
	if cfg.ContainerCreate != 4 || cfg.ContainerStart != 4 {
		t.Fatalf("Docker lifecycle split defaults = create %d start %d, want 4/4",
			cfg.ContainerCreate, cfg.ContainerStart)
	}
	podman := defaultConfigForRuntime(56, "podman")
	if podman.ContainerCreate != 8 || podman.ContainerStart != 8 {
		t.Fatalf("Podman lifecycle split defaults = create %d start %d, want 8/8",
			podman.ContainerCreate, podman.ContainerStart)
	}
	overridden := WithDefaults(Config{Lifecycle: 24})
	defaults := DefaultConfig()
	if overridden.Lifecycle != 24 || overridden.Apply != defaults.Apply ||
		overridden.Netlink != defaults.Netlink {
		t.Fatalf("partial limiter override lost defaults: %+v", overridden)
	}
}
