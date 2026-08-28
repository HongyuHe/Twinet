package netx

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
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

func TestHostLinkPresenceFallsBackToTargetedLookupsAfterInterruptedDump(t *testing.T) {
	want := map[string]struct{}{"present": {}, "absent": {}}
	out := map[string]bool{"present": false, "absent": false}
	lookups := 0
	got, err := hostLinksPresentFrom(want, out,
		func(name string) (netlink.Link, error) {
			lookups++
			if name == "present" {
				return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
			}
			return nil, netlink.LinkNotFoundError{}
		},
		func() ([]netlink.Link, error) {
			return nil, nl.ErrDumpInterrupted
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !got["present"] || got["absent"] || lookups != len(want) {
		t.Fatalf("targeted fallback = %#v with %d lookups", got, lookups)
	}

	lookupErr := errors.New("socket failed")
	_, err = hostLinksPresentFrom(want, out,
		func(string) (netlink.Link, error) {
			return nil, lookupErr
		},
		func() ([]netlink.Link, error) {
			return nil, nl.ErrDumpInterrupted
		},
	)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("unexpected targeted lookup error: %v", err)
	}
}
