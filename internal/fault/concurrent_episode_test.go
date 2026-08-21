package fault

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// TestConcurrentEpisodeIsolation is deliberately a short in-process gate by
// default. The release target sets TWINET_FAULT_STRESS_EPISODES=100, exercising
// one hundred simultaneous inject/verify/resolve/reset lifecycles without a
// shared fake baseline or a skipped registered native fault.
func TestConcurrentEpisodeIsolation(t *testing.T) {
	episodes := 16
	if raw := os.Getenv("TWINET_FAULT_STRESS_EPISODES"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			t.Fatalf("invalid TWINET_FAULT_STRESS_EPISODES=%q", raw)
		}
		episodes = value
	}
	const name = "test.concurrent_episode_isolation"
	Register(&Fault{
		Name: name, Category: CatContention, Needs: []Capability{CapExec},
		Symptom: "a bounded test workload is active", Describe: "an isolated test workload",
		Inject: func(_ context.Context, e *Env, _ Target) (State, error) {
			e.Seed++
			return State{"seed": strconv.FormatInt(e.Seed, 10)}, nil
		},
		Verify: func(_ context.Context, e *Env, _ Target, s State) (Evidence, error) {
			active := e.Seed > 0
			if !e.wantSymptom {
				active = false
			}
			return Evidence{Verified: active, Observed: s["seed"]}, nil
		},
		Resolve: func(_ context.Context, e *Env, _ Target, _ State) error {
			e.Seed = 0
			return nil
		},
	})
	defer delete(registry, name)

	var wg sync.WaitGroup
	errs := make(chan error, episodes)
	for i := 0; i < episodes; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			var calls atomic.Int64
			env := &Env{Seed: seed, Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
				calls.Add(1)
				return rt.ExecResult{}, nil
			}}
			inj, err := Inject(context.Background(), env, name, Target{})
			if err == nil {
				err = Resolve(context.Background(), env, inj)
			}
			if err == nil && env.Seed != 0 {
				err = &episodeIsolationError{seed: seed}
			}
			if calls.Load() == 0 {
				err = &episodeIsolationError{seed: seed}
			}
			if err != nil {
				errs <- err
			}
		}(int64(i + 1))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

type episodeIsolationError struct{ seed int64 }

func (e *episodeIsolationError) Error() string {
	return "episode did not reset independently (seed " + strconv.FormatInt(e.seed, 10) + ")"
}
