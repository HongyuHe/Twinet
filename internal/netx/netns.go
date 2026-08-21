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

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NS is a handle on a network namespace.
type NS struct {
	handle netns.NsHandle
	path   string
}

// These indirections keep namespace switching testable without requiring
// CAP_SYS_ADMIN. Production always uses the netns package functions.
var (
	getNetNS = netns.Get
	setNetNS = netns.Set
)

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

// Do runs fn inside the namespace, restoring the caller's namespace afterwards.
//
// Namespace membership is per OS thread. Each call therefore uses a short
// lived pinned worker instead of serialising all callers behind a process-wide
// mutex. On a restore failure the worker exits while still pinned; Go then
// terminates that OS thread rather than returning a thread in the wrong
// namespace to the scheduler.
func (n *NS) Do(fn func() error) error {
	if n == nil {
		return fmt.Errorf("enter nil netns")
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		origin, err := getNetNS()
		if err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("save current netns: %w", err)
			return
		}
		if err := setNetNS(n.handle); err != nil {
			_ = origin.Close()
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enter netns %s: %w", n.path, err)
			return
		}

		fnErr := fn()
		if err := setNetNS(origin); err != nil {
			_ = origin.Close()
			result <- fmt.Errorf("restore netns after %v: %w", fnErr, err)
			// Per runtime.LockOSThread's contract, exiting without unlocking
			// terminates this thread. Never let it re-enter Go's thread pool
			// while it is still in the target namespace.
			runtime.Goexit()
		}
		_ = origin.Close()
		runtime.UnlockOSThread()
		result <- fnErr
	}()
	return <-result
}

// Handle returns a netlink handle whose sockets are bound to this namespace.
//
// Operations through the returned handle do not switch the calling thread.
// This is the normal path for concurrent endpoint operations; Do is needed
// only while creating the sockets (and for the few /proc operations that are
// inherently namespace-relative).
func (n *NS) Handle() (*netlink.Handle, error) {
	var h *netlink.Handle
	err := n.Do(func() error {
		var err error
		h, err = netlink.NewHandle()
		return err
	})
	if err != nil {
		if h != nil {
			h.Close()
		}
		return nil, fmt.Errorf("open netlink handle for %s: %w", n.path, err)
	}
	return h, nil
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
