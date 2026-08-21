package netx

import (
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

func TestNSDoDoesNotSerializeIndependentCalls(t *testing.T) {
	withNamespaceHooks(t, func() (netns.NsHandle, error) {
		return netns.None(), nil
	}, func(netns.NsHandle) error {
		return nil
	})

	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	startedA := make(chan struct{})
	startedB := make(chan struct{})
	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() {
		doneA <- (&NS{handle: 1, path: "a"}).Do(func() error {
			close(startedA)
			<-release
			return nil
		})
	}()
	select {
	case <-startedA:
	case err := <-doneA:
		t.Fatalf("first namespace call failed before starting: %v", err)
	case <-time.After(time.Second):
		t.Fatal("first namespace call did not start")
	}

	go func() {
		doneB <- (&NS{handle: 2, path: "b"}).Do(func() error {
			close(startedB)
			<-release
			return nil
		})
	}()
	select {
	case <-startedB:
		// The old process-wide namespace mutex cannot reach here until A is
		// released, so this is a direct regression test for global
		// serialisation.
	case err := <-doneB:
		t.Fatalf("second namespace call failed before starting: %v", err)
	case <-time.After(time.Second):
		t.Fatal("independent namespace calls were serialized")
	}
	close(release)
	released = true
	if err := <-doneA; err != nil {
		t.Fatalf("first namespace call: %v", err)
	}
	if err := <-doneB; err != nil {
		t.Fatalf("second namespace call: %v", err)
	}
}

func TestNSDoTargetsAndRestoresNamespace(t *testing.T) {
	var mu sync.Mutex
	current := netns.None()
	target := netns.NsHandle(42)
	withNamespaceHooks(t, func() (netns.NsHandle, error) {
		mu.Lock()
		defer mu.Unlock()
		return current, nil
	}, func(next netns.NsHandle) error {
		mu.Lock()
		defer mu.Unlock()
		current = next
		return nil
	})
	ns := &NS{handle: target, path: "test-target"}
	var inside netns.NsHandle
	if err := ns.Do(func() error {
		var err error
		inside, err = getNetNS()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !inside.Equal(target) {
		t.Fatalf("callback ran in namespace %s, want target %s", inside, target)
	}
	mu.Lock()
	defer mu.Unlock()
	if !current.Equal(netns.None()) {
		t.Fatalf("caller remained in namespace %s after Do, want original namespace", current)
	}
}

func withNamespaceHooks(t *testing.T, get func() (netns.NsHandle, error),
	set func(netns.NsHandle) error) {
	t.Helper()
	previousGet, previousSet := getNetNS, setNetNS
	getNetNS, setNetNS = get, set
	t.Cleanup(func() {
		getNetNS, setNetNS = previousGet, previousSet
	})
}
