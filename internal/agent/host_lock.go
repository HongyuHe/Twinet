package agent

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// defaultHostLockDir holds one lock file per network namespace an agent owns.
const defaultHostLockDir = "/run/twinet"

// legacyHostLockName is the fixed path every build before the namespace-derived
// lock used. An agent in the host's root network namespace still takes it, so a
// stale older agent -- the kind that once deleted this cluster's live veths
// from a second containerd metadata namespace -- is still refused.
const legacyHostLockName = "agent.lock"

var (
	// hostNetnsPath and initNetnsPath are the kernel's handles to this
	// process's and PID 1's network namespaces. They are variables only so a
	// test can point the derivation at other handles without entering a
	// namespace it may not be allowed to create.
	hostNetnsPath = "/proc/self/ns/net"
	initNetnsPath = "/proc/1/ns/net"
)

// hostNetnsIdentity is the kernel's identity for a network namespace: the nsfs
// device and inode behind /proc/<pid>/ns/net.
//
// This is the only thing that may decide which agents contend for a host. A
// lock at an operator-chosen path decided nothing: two agents told to use
// different files shared one root namespace and both created, rewired and
// deleted the same veths, bridges and VXLANs, which is the failure the lock
// exists to prevent. Two processes in one namespace observe the same inode
// however their filesystems are arranged, and two processes in genuinely
// separate namespaces never do.
func hostNetnsIdentity(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", fmt.Errorf("identify this host network namespace through %s: %w; "+
			"the agent rewires the root namespace and will not start without knowing "+
			"which one it is in", path, err)
	}
	return fmt.Sprintf("%d-%d", st.Dev, st.Ino), nil
}

// hostLease is one agent's exclusive ownership of a host network namespace.
type hostLease struct {
	namespace string
	// claim is an abstract UNIX socket. The abstract socket namespace is
	// scoped by the kernel to the network namespace, which makes it the one
	// primitive whose exclusion means exactly what this lock is trying to
	// say: no lock directory, mount namespace, or bind mount can put two
	// agents of one network namespace onto two different objects, and none
	// can put two agents of separate namespaces onto the same one. The flocks
	// below are the durable, inspectable record and the guard against builds
	// that predate this; the socket is the decision.
	claim  net.Listener
	files  []*os.File
	closed sync.Once
}

func (l *hostLease) Close() error {
	if l == nil {
		return nil
	}
	var err error
	l.closed.Do(func() {
		if l.claim != nil {
			err = l.claim.Close()
		}
		for _, file := range l.files {
			if fileErr := file.Close(); err == nil {
				err = fileErr
			}
		}
	})
	return err
}

// hostClaimAddress is the abstract socket that represents ownership of one
// network namespace. The leading @ makes it abstract: it lives in the kernel
// rather than in any filesystem, and it disappears with the process that bound
// it, so a killed agent never leaves a claim behind.
func hostClaimAddress(identity string) string {
	return "@twinet-agent-netns-" + identity
}

func hostLockDir(dir string) string {
	if dir = strings.TrimSpace(dir); dir == "" {
		return defaultHostLockDir
	}
	return dir
}

// hostAgentLockPath names the durable record for the namespace this process is
// in. The directory is configurable for hosts whose /run is unusual; the file
// name is not, because the file name is the identity.
func namespaceLockPath(dir, identity string) string {
	return filepath.Join(hostLockDir(dir), "agent-netns-"+identity+".lock")
}

func acquireHostAgentLock(dir, node, listen, runtimeNamespace string) (*hostLease, error) {
	return acquireHostAgentLockIn(dir, hostNetnsPath, initNetnsPath, node, listen, runtimeNamespace)
}

func acquireHostAgentLockIn(dir, nsPath, initPath, node, listen, runtimeNamespace string,
) (*hostLease, error) {
	identity, err := hostNetnsIdentity(nsPath)
	if err != nil {
		return nil, err
	}
	owner := fmt.Sprintf("pid=%d node=%s listen=%s runtime_namespace=%s netns=%s",
		os.Getpid(), node, listen, runtimeNamespace, identity)

	address := hostClaimAddress(identity)
	claim, err := net.Listen("unix", address)
	if err != nil {
		return nil, hostClaimConflict(identity, address, dir, err)
	}
	lease := &hostLease{namespace: identity, claim: claim}
	go serveHostLeaseOwner(claim, owner)

	// The record, and the compatibility guard against a build that only ever
	// knew the fixed path. Only an agent in the host's root namespace takes
	// the legacy name: an isolated one has only its own links to protect, and
	// refusing it merely because it shares a /run would defeat the isolation
	// its namespace already provides.
	paths := []string{namespaceLockPath(dir, identity)}
	if rootNamespace(nsPath, initPath) {
		paths = append(paths, filepath.Join(hostLockDir(dir), legacyHostLockName))
	}
	for _, path := range paths {
		file, err := lockHostFile(path, owner)
		if err != nil {
			_ = lease.Close()
			return nil, err
		}
		lease.files = append(lease.files, file)
	}
	return lease, nil
}

// rootNamespace reports whether this process shares PID 1's network namespace.
// An unreadable PID 1 handle is treated as the root namespace: over-refusing a
// second agent is recoverable, and admitting two into one namespace is the
// thing this lock exists to prevent.
func rootNamespace(nsPath, initPath string) bool {
	mine, err := hostNetnsIdentity(nsPath)
	if err != nil {
		return true
	}
	init, err := hostNetnsIdentity(initPath)
	if err != nil {
		return true
	}
	return mine == init
}

func lockHostFile(path, owner string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create host agent lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open host agent lock %s: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		detail, _ := os.ReadFile(path)
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("another Twinet agent already holds %s (%s); stop it before "+
				"starting this one. A separate runtime namespace or API port does not isolate "+
				"root-namespace veths, bridges, or VXLANs",
				path, describeLockOwner(strings.TrimSpace(string(detail))))
		}
		return nil, fmt.Errorf("lock host network namespace with %s: %w", path, err)
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("truncate host agent lock: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("seek host agent lock: %w", err)
	}
	if _, err := file.WriteString(owner + "\n"); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("record host agent lock owner: %w", err)
	}
	return file, nil
}

func hostClaimConflict(identity, address, dir string, cause error) error {
	if !errors.Is(cause, unix.EADDRINUSE) {
		return fmt.Errorf("claim network namespace %s through %s: %w", identity, address, cause)
	}
	owner := hostLeaseOwner(address)
	if owner == "" {
		owner = recordedHostLockOwner(namespaceLockPath(dir, identity))
	}
	return fmt.Errorf("another Twinet agent already owns network namespace %s (%s); stop the "+
		"other agent before starting this one. The claim is scoped by the kernel to the network "+
		"namespace, so this is the same namespace and not merely the same file: a separate lock "+
		"directory, runtime namespace, or API port does not isolate root-namespace veths, "+
		"bridges, or VXLANs", identity, describeLockOwner(owner))
}

func describeLockOwner(owner string) string {
	if owner == "" {
		return "another running process"
	}
	return owner
}

func recordedHostLockOwner(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// serveHostLeaseOwner answers "who has it?" for whoever is refused. Without it
// the refusal could only name a file, which is exactly what made the old
// message unactionable when the other agent was not using that file at all.
func serveHostLeaseOwner(listener net.Listener, owner string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.WriteString(conn, owner+"\n"); err != nil {
			slog.Debug("report host agent lock owner", "err", err)
		}
		_ = conn.Close()
	}
}

func hostLeaseOwner(address string) string {
	conn, err := net.DialTimeout("unix", address, time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := io.ReadAll(io.LimitReader(conn, 1024))
	if err != nil && len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
