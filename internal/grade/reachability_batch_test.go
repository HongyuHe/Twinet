package grade

import (
	"context"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestBatchedPingFailuresUsesOneExecPerSource(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	calls := map[string]int{}
	var mu sync.Mutex
	env := &Env{Exec: func(_ context.Context, device string, command []string) (rt.ExecResult, error) {
		mu.Lock()
		calls[device]++
		mu.Unlock()
		if len(command) != 3 || command[0] != "sh" || command[1] != "-c" {
			t.Fatalf("want agent-side shell batch, got %v", command)
		}
		if device == a.ID {
			return rt.ExecResult{Stdout: "@ 0 0\n"}, nil
		}
		return rt.ExecResult{Stdout: "@ 1 0\n"}, nil
	}}
	probes := []reachabilityProbe{{from: a, to: b}, {from: b, to: a}}
	failed, complete := batchedPingFailures(context.Background(), env, probes,
		map[string]string{a.ID: "192.0.2.1", b.ID: "192.0.2.2"})
	if !complete || len(failed) != 0 {
		t.Fatalf("complete=%v failed=%v", complete, failed)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls[a.ID] != 1 || calls[b.ID] != 1 {
		t.Fatalf("calls=%v, want one exec per source", calls)
	}
}

func TestTransportBatchRequiresExactPortsAndCounters(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	attempts := []transportAttempt{{
		index: 0, from: a, to: b, sourcePort: "31001", destPort: "32001",
	}}
	ok := transportBatchVerified(attempts, map[int]bool{0: true}, true,
		map[string]counterWitness{b.ID: {global: 10}},
		map[string]counterWitness{b.ID: {global: 11}},
		map[string]transportTapReading{b.ID: {live: true, ports: map[string]int{"31001": 1}}},
		1)
	if !ok {
		t.Fatal("a fully witnessed batch was rejected")
	}
	if transportBatchVerified(attempts, map[int]bool{0: true}, true,
		map[string]counterWitness{b.ID: {global: 10}},
		map[string]counterWitness{b.ID: {global: 11}},
		map[string]transportTapReading{b.ID: {live: true, ports: map[string]int{}}},
		1) {
		t.Fatal("a batch without the exact source-port witness passed")
	}
}
