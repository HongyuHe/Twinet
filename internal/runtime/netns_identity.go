package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// NetnsIdentity is the kernel identity of one network namespace.
//
// A namespace is identified by the device and inode of its nsfs entry, which
// is what `readlink /proc/<pid>/ns/net` prints as net:[4026552127]. The number
// is stable for the life of the namespace and unique while it exists, so two
// containers are in the same namespace if and only if their identities are
// equal. A path is not an identity: /proc/<pid>/ns/net names a different
// namespace the moment the container behind that PID is restarted.
type NetnsIdentity struct {
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
}

// Known reports whether the identity was actually established. The zero value
// means "not proven" and must never be compared for equality with another
// identity, because two unknowns are not the same namespace.
func (n NetnsIdentity) Known() bool { return n.Inode != 0 }

// SameAs reports whether both identities are known and name one namespace.
func (n NetnsIdentity) SameAs(other NetnsIdentity) bool {
	return n.Known() && other.Known() && n.Dev == other.Dev && n.Inode == other.Inode
}

// String renders the identity the way the kernel does.
func (n NetnsIdentity) String() string {
	if !n.Known() {
		return "unknown"
	}
	return fmt.Sprintf("net:[%d]", n.Inode)
}

var (
	// ErrNamespaceIdentityUnsupported means the backend cannot prove which
	// network namespace a container is attached to. Callers must treat it as
	// a missing capability, not as a fault: it is the gate that keeps unit
	// runtimes and future backends out of a host-specific proof.
	ErrNamespaceIdentityUnsupported = errors.New("runtime backend cannot prove network namespace identity")
	// ErrNamespaceIdentityUnknown means the proof was attempted and did not
	// succeed. Every caller must fail closed on it: an unreadable namespace
	// is never evidence that two containers share one.
	ErrNamespaceIdentityUnknown = errors.New("network namespace identity could not be established")
)

// NetnsIdentityRuntime is implemented by backends that can prove which network
// namespace a container is attached to.
//
// It is deliberately a capability rather than part of Runtime. Proving
// namespace identity needs host visibility of the engine's processes, which a
// remote or in-memory backend does not have; those must be told apart from a
// backend that answers wrongly.
type NetnsIdentityRuntime interface {
	Runtime
	// NetnsIdentity proves the network namespace a running container is
	// attached to right now.
	NetnsIdentity(ctx context.Context, nameOrID string) (NetnsIdentity, error)
	// ObservedNetnsIdentity resolves the namespace identity implied by an
	// observation the caller already holds, without a further engine round
	// trip. It is the cheap form used to screen a whole node; anything acting
	// on the answer must confirm it with NetnsIdentity.
	ObservedNetnsIdentity(ctx context.Context, container Container) (NetnsIdentity, error)
}

// SupportsNetnsIdentity reports whether a backend can prove namespace identity.
func SupportsNetnsIdentity(r Runtime) bool {
	_, ok := r.(NetnsIdentityRuntime)
	return ok
}

// NetnsIdentityOf proves one container's network namespace identity through
// whichever backend is in use, or reports the missing capability.
func NetnsIdentityOf(ctx context.Context, r Runtime, nameOrID string) (NetnsIdentity, error) {
	prover, ok := r.(NetnsIdentityRuntime)
	if !ok {
		return NetnsIdentity{}, fmt.Errorf("%w: %s", ErrNamespaceIdentityUnsupported, runtimeBackendName(r))
	}
	return prover.NetnsIdentity(ctx, nameOrID)
}

// ObservedNetnsIdentityOf resolves the namespace identity of an observation the
// caller already holds.
func ObservedNetnsIdentityOf(ctx context.Context, r Runtime, container Container) (NetnsIdentity, error) {
	prover, ok := r.(NetnsIdentityRuntime)
	if !ok {
		return NetnsIdentity{}, fmt.Errorf("%w: %s", ErrNamespaceIdentityUnsupported, runtimeBackendName(r))
	}
	return prover.ObservedNetnsIdentity(ctx, container)
}

// SelfNetnsIdentity returns the identity of the calling process's own network
// namespace. Callers use it as a sanity check: a Twinet device never shares the
// namespace its agent runs in, so an answer equal to this one is proof that a
// namespace path resolved to something other than the container's task.
func SelfNetnsIdentity() (NetnsIdentity, error) {
	return NetnsIdentityOfPath("/proc/self/ns/net")
}

// NetnsIdentityOfPath reads the identity a namespace path resolves to.
func NetnsIdentityOfPath(path string) (NetnsIdentity, error) {
	if path == "" {
		return NetnsIdentity{}, fmt.Errorf("%w: empty namespace path", ErrNamespaceIdentityUnknown)
	}
	info, err := os.Stat(path)
	if err != nil {
		return NetnsIdentity{}, fmt.Errorf("%w: stat %s: %w", ErrNamespaceIdentityUnknown, path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return NetnsIdentity{}, fmt.Errorf("%w: %s carries no inode identity",
			ErrNamespaceIdentityUnknown, path)
	}
	identity := NetnsIdentity{Dev: uint64(stat.Dev), Inode: uint64(stat.Ino)} //nolint:unconvert // Dev is not uint64 everywhere
	if !identity.Known() {
		return NetnsIdentity{}, fmt.Errorf("%w: %s reported inode 0", ErrNamespaceIdentityUnknown, path)
	}
	return identity, nil
}

// netnsIdentityViaTask proves a container's namespace identity from the
// namespace path its own backend reports.
//
// The container is inspected either side of the read. A PID that changed, or a
// container that stopped being joinable, means the task was replaced while the
// namespace was being read: the identity just obtained belongs to whichever
// process now owns that PID, which after a restart is a different namespace and
// after PID reuse may be an unrelated process entirely. Both cases return
// ErrNamespaceIdentityUnknown rather than a plausible-looking number.
func netnsIdentityViaTask(ctx context.Context, r Runtime, nameOrID string) (NetnsIdentity, error) {
	before, err := r.Inspect(ctx, nameOrID)
	if err != nil {
		return NetnsIdentity{}, fmt.Errorf("%w: inspect %s: %w", ErrNamespaceIdentityUnknown, nameOrID, err)
	}
	if err := joinableForIdentity(nameOrID, before); err != nil {
		return NetnsIdentity{}, err
	}
	path, err := r.NSPath(ctx, nameOrID)
	if err != nil {
		return NetnsIdentity{}, fmt.Errorf("%w: namespace path for %s: %w",
			ErrNamespaceIdentityUnknown, nameOrID, err)
	}
	identity, err := NetnsIdentityOfPath(path)
	if err != nil {
		return NetnsIdentity{}, err
	}
	after, err := r.Inspect(ctx, nameOrID)
	if err != nil {
		return NetnsIdentity{}, fmt.Errorf("%w: re-inspect %s: %w", ErrNamespaceIdentityUnknown, nameOrID, err)
	}
	if err := joinableForIdentity(nameOrID, after); err != nil {
		return NetnsIdentity{}, err
	}
	if after.PID != before.PID {
		return NetnsIdentity{}, fmt.Errorf(
			"%w: %s changed from pid %d to pid %d while its namespace was read",
			ErrNamespaceIdentityUnknown, nameOrID, before.PID, after.PID)
	}
	return identity, nil
}

// observedNetnsIdentityViaTask resolves the namespace identity implied by an
// observation. It performs no engine call, so it is safe to run across every
// container on a node; it is screening, not proof.
func observedNetnsIdentityViaTask(container Container) (NetnsIdentity, error) {
	name := container.Name
	if name == "" {
		name = container.ID
	}
	if err := joinableForIdentity(name, container); err != nil {
		return NetnsIdentity{}, err
	}
	return NetnsIdentityOfPath(fmt.Sprintf("/proc/%d/ns/net", container.PID))
}

func joinableForIdentity(name string, container Container) error {
	if !container.State.Joinable() {
		return fmt.Errorf("%w: %s is %s, so it has no network namespace to prove",
			ErrNamespaceIdentityUnknown, name, container.State)
	}
	if container.PID <= 0 {
		return fmt.Errorf("%w: %s reports pid %d", ErrNamespaceIdentityUnknown, name, container.PID)
	}
	return nil
}

func runtimeBackendName(r Runtime) (name string) {
	defer func() {
		if recover() != nil {
			name = "unknown backend"
		}
	}()
	if r == nil {
		return "unknown backend"
	}
	if name = r.Name(); name == "" {
		return "unknown backend"
	}
	return name
}
