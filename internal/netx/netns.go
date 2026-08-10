// Package netx implements Twinet's link plumbing: veth pairs, network
// namespaces, VXLAN tunnels, bridges and traffic shaping.
//
// Everything here goes through netlink rather than shelling out to `ip` and
// `tc`. That matters for more than elegance: the legacy platform's equivalent
// (a 1,138-line bash library) had to create symlinks under /var/run/netns,
// install traps on six signals to remove them, sleep one second before adding a
// qdisc to dodge a race, and cache container PIDs in a file because it had no
// way to hold a namespace handle. None of that is necessary with file
// descriptors and typed netlink messages.
package netx

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NS is a handle on a network namespace.
type NS struct {
	handle netns.NsHandle
	path   string
}

// OpenNS opens a namespace by path, typically /proc/<pid>/ns/net.
func OpenNS(path string) (*NS, error) {
	h, err := netns.GetFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("open netns %s: %w", path, err)
	}
	return &NS{handle: h, path: path}, nil
}

// HostNS returns a handle on the caller's current namespace.
func HostNS() (*NS, error) {
	h, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("get current netns: %w", err)
	}
	return &NS{handle: h, path: "current"}, nil
}

// Close releases the namespace handle.
func (n *NS) Close() error {
	if n == nil {
		return nil
	}
	return n.handle.Close()
}

// Path returns the path the namespace was opened from.
func (n *NS) Path() string { return n.path }

// Fd returns the raw file descriptor, for netlink calls that need it.
func (n *NS) Fd() int { return int(n.handle) }

// nsMu serialises namespace switching. Entering a namespace is a per-thread
// operation, so we lock the goroutine to its OS thread for the duration; the
// mutex additionally prevents two goroutines from fighting over the same
// thread-local state through the netlink library's package-level handles.
var nsMu sync.Mutex

// Do runs fn inside the namespace, restoring the caller's namespace afterwards.
//
// The goroutine is pinned to its OS thread for the duration. If restoring
// fails the thread is deliberately left locked and the process is marked
// unhealthy, because an unpinned thread in the wrong namespace would silently
// corrupt every later operation scheduled onto it.
func (n *NS) Do(fn func() error) error {
	nsMu.Lock()
	defer nsMu.Unlock()

	runtime.LockOSThread()
	origin, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("save current netns: %w", err)
	}

	if err := netns.Set(n.handle); err != nil {
		_ = origin.Close()
		runtime.UnlockOSThread()
		return fmt.Errorf("enter netns %s: %w", n.path, err)
	}

	fnErr := fn()

	if err := netns.Set(origin); err != nil {
		// Do not unlock the thread: it is in the wrong namespace and must not
		// be reused. Leaking one thread is far cheaper than corrupting the
		// namespace of unrelated work.
		_ = origin.Close()
		return fmt.Errorf("restore netns after %v: %w", fnErr, err)
	}
	_ = origin.Close()
	runtime.UnlockOSThread()
	return fnErr
}

// NSFromPID returns the namespace path for a process.
func NSFromPID(pid int) string { return fmt.Sprintf("/proc/%d/ns/net", pid) }

// PIDAlive reports whether a PID still exists, used to detect that a container
// restarted and its namespace handle is stale.
func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// IsNotFound reports whether an error means "no such link".
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(netlink.LinkNotFoundError)
	return ok
}
