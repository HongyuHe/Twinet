package netx

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink/nl"
)

func TestRetryNetlinkDumpRetriesInterruptedResult(t *testing.T) {
	attempts := 0
	got, err := retryNetlinkDump(func() ([]int, error) {
		attempts++
		if attempts < 3 {
			return []int{attempts}, nl.ErrDumpInterrupted
		}
		return []int{1, 2, 3}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || len(got) != 3 {
		t.Fatalf("dump attempts=%d result=%v, want 3 complete items after 3 attempts", attempts, got)
	}
}

func TestRetryNetlinkDumpPreservesPersistentErrors(t *testing.T) {
	persistent := errors.New("permission denied")
	attempts := 0
	if _, err := retryNetlinkDump(func() ([]int, error) {
		attempts++
		return nil, persistent
	}); !errors.Is(err, persistent) {
		t.Fatalf("persistent error = %v, want %v", err, persistent)
	}
	if attempts != 1 {
		t.Fatalf("persistent error retried %d times, want once", attempts)
	}
}

func TestRetryNetlinkDumpReturnsPersistentInterruption(t *testing.T) {
	attempts := 0
	if _, err := retryNetlinkDump(func() ([]int, error) {
		attempts++
		return nil, nl.ErrDumpInterrupted
	}); !errors.Is(err, nl.ErrDumpInterrupted) {
		t.Fatalf("persistent dump interruption = %v", err)
	}
	if attempts != netlinkDumpAttempts {
		t.Fatalf("dump attempts=%d, want %d", attempts, netlinkDumpAttempts)
	}
}
