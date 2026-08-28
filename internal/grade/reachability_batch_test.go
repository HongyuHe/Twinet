package grade

import (
	"context"
	"fmt"
	"strings"
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

func TestBatchedPingObservationsIdentifyTheFailedPair(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	env := &Env{Exec: func(_ context.Context, device string, _ []string) (rt.ExecResult, error) {
		if device == a.ID {
			return rt.ExecResult{Stdout: "@ 0 1\n"}, nil
		}
		return rt.ExecResult{Stdout: "@ 1 0\n"}, nil
	}}
	probes := []reachabilityProbe{{from: a, to: b}, {from: b, to: a}}
	observed := batchedPingObservations(context.Background(), env, probes,
		map[string]string{a.ID: "192.0.2.1", b.ID: "192.0.2.2"})
	if !observed.complete || len(observed.failures) != 1 {
		t.Fatalf("observation = %#v", observed)
	}
	if !observed.failedPairs[hostPairKey(a, b)] || observed.failedPairs[hostPairKey(b, a)] {
		t.Fatalf("failed pairs = %v, want only A to B", observed.failedPairs)
	}
}

func TestBatchedPingFailuresBoundsSourceSidePressure(t *testing.T) {
	source := &model.Device{ID: "as3/A", Name: "A"}
	probes := make([]reachabilityProbe, 0, sourceBatchWidth+1)
	addresses := map[string]string{}
	for i := 0; i < sourceBatchWidth+1; i++ {
		target := &model.Device{ID: "as3/T" + string(rune('A'+i)), Name: "T"}
		probes = append(probes, reachabilityProbe{from: source, to: target})
		addresses[target.ID] = "192.0.2." + string(rune('1'+i))
	}
	var script string
	env := &Env{Exec: func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
		script = command[2]
		var out strings.Builder
		for i := range probes {
			fmt.Fprintf(&out, "@ %d 0\n", i)
		}
		return rt.ExecResult{Stdout: out.String()}, nil
	}}
	if _, complete := batchedPingFailures(context.Background(), env, probes, addresses); !complete {
		t.Fatal("bounded batch was incomplete")
	}
	if got := strings.Count(script, "wait\n"); got < 2 {
		t.Fatalf("source batch did not drain bounded child groups: script=%q", script)
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

func TestTransportBatchRetriesOnlyTheUnprovenFlow(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	dst := &model.Device{ID: "as3/D", Name: "D"}
	attempts := []transportAttempt{
		{index: 0, from: a, to: dst, sourcePort: "31001", destPort: "32001"},
		{index: 1, from: b, to: dst, sourcePort: "31002", destPort: "32001"},
	}
	retry := transportBatchRetries(attempts, map[int]bool{0: true, 1: true}, true,
		map[string]counterWitness{dst.ID: {global: 10}},
		map[string]counterWitness{dst.ID: {global: 11}},
		map[string]transportTapReading{
			dst.ID: {live: true, ports: map[string]int{"31001": 1}},
		},
		1)
	if retry[0] || !retry[1] || len(retry) != 1 {
		t.Fatalf("retry = %v, want only the flow without an exact capture", retry)
	}
}

func TestTransportBatchRetriesDestinationWhenCountersCannotProveDelivery(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	dst := &model.Device{ID: "as3/D", Name: "D"}
	attempts := []transportAttempt{
		{index: 0, from: a, to: dst, sourcePort: "31001", destPort: "32001"},
		{index: 1, from: b, to: dst, sourcePort: "31002", destPort: "32001"},
	}
	retry := transportBatchRetries(attempts, map[int]bool{0: true, 1: true}, true,
		map[string]counterWitness{dst.ID: {global: 10}},
		map[string]counterWitness{dst.ID: {global: 11}},
		map[string]transportTapReading{
			dst.ID: {live: true, ports: map[string]int{"31001": 1, "31002": 1}},
		},
		1)
	if !retry[0] || !retry[1] || len(retry) != 2 {
		t.Fatalf("retry = %v, want every flow to the under-counted destination", retry)
	}
}

func TestTransportAttemptsSkipPairsAlreadyProvedUnreachable(t *testing.T) {
	a := &model.Device{ID: "as3/A", Name: "A"}
	b := &model.Device{ID: "as3/B", Name: "B"}
	attempts, ok := makeTransportAttempts(
		[]*model.Device{a, b},
		map[string]string{a.ID: "192.0.2.1", b.ID: "192.0.2.2"},
		map[string]bool{hostPairKey(a, b): true},
	)
	if !ok || len(attempts) != 1 {
		t.Fatalf("attempts = %#v, ok=%v", attempts, ok)
	}
	if attempts[0].from != b || attempts[0].to != a {
		t.Fatalf("retained attempt = %#v, want B to A", attempts[0])
	}
}
