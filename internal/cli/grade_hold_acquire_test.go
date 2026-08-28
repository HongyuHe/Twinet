package cli

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestInitialHoldAcquiresInCanonicalOrder(t *testing.T) {
	var calls []string
	target := func(name string) initialHoldTarget {
		return initialHoldTarget{name: name, set: func(_ context.Context, seconds int) error {
			calls = append(calls, name+":"+strconv.Itoa(seconds))
			return nil
		}}
	}
	err := acquireInitialHold(t.Context(), []initialHoldTarget{
		target("node-2"), target("node-0"), target("node-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"node-0:180", "node-1:180", "node-2:180"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("hold calls = %v, want %v", calls, want)
	}
}

func TestInitialHoldRollsBackAcquiredPrefix(t *testing.T) {
	var calls []string
	target := func(name string, fail bool) initialHoldTarget {
		return initialHoldTarget{name: name, set: func(_ context.Context, seconds int) error {
			calls = append(calls, name+":"+strconv.Itoa(seconds))
			if fail && seconds > 0 {
				return errors.New("already held")
			}
			return nil
		}}
	}
	err := acquireInitialHold(t.Context(), []initialHoldTarget{
		target("node-2", false), target("node-1", true), target("node-0", false),
	})
	if err == nil || !strings.Contains(err.Error(), "node-1") {
		t.Fatalf("acquisition error = %v", err)
	}
	want := []string{"node-0:180", "node-1:180", "node-1:0", "node-0:0"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("hold calls = %v, want %v", calls, want)
	}
}

func TestInitialHoldReportsFailedTargetRollbackFailure(t *testing.T) {
	var calls []string
	err := acquireInitialHold(t.Context(), []initialHoldTarget{{
		name: "node-0",
		set: func(_ context.Context, seconds int) error {
			calls = append(calls, "node-0:"+strconv.Itoa(seconds))
			if seconds > 0 {
				return errors.New("durability uncertain")
			}
			return errors.New("release unavailable")
		},
	}})
	if err == nil ||
		!strings.Contains(err.Error(), "node-0 (release unavailable)") ||
		!strings.Contains(err.Error(), "bounded by their lease") {
		t.Fatalf("acquisition error = %v", err)
	}
	want := []string{"node-0:180", "node-0:0"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("hold calls = %v, want %v", calls, want)
	}
}
