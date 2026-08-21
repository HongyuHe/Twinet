// Package runtime abstracts the container engine.
//
// The interface is deliberately narrow: create, start, stop, remove, list,
// exec, copy, and "give me the network namespace path". Wiring is not a runtime
// concern — that belongs to internal/netx — so a second backend is a few
// hundred lines rather than a parallel implementation of the whole system.
package runtime

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"
)

// PullPolicy controls when images are fetched.
type PullPolicy string

const (
	PullIfMissing PullPolicy = "if-missing"
	PullAlways    PullPolicy = "always"
	PullNever     PullPolicy = "never"
)

// State is the normalised lifecycle state of a container.
type State string

const (
	StateAbsent     State = "absent"
	StateCreated    State = "created"
	StateRunning    State = "running"
	StatePaused     State = "paused"
	StateRestarting State = "restarting"
	StateExited     State = "exited"
	StateDead       State = "dead"
)

// Joinable reports whether the container has a network namespace that can be
// entered. Wiring a container in any other state silently does nothing, which
// is a failure mode worth making explicit.
func (s State) Joinable() bool { return s == StateRunning || s == StatePaused }

// Spec is everything needed to create a container.
type Spec struct {
	Name         string
	Image        string
	Hostname     string
	Command      []string
	Entrypoint   []string
	Env          map[string]string
	Labels       map[string]string
	Binds        []Bind
	Sysctls      map[string]string
	Capabilities []string
	CapDrop      []string
	// SecurityOpt contains Docker security options such as
	// no-new-privileges, seccomp=..., and apparmor=....
	SecurityOpt []string
	// ReadOnlyRootfs mounts the container root filesystem read-only.
	ReadOnlyRootfs bool
	// RuntimeClass is the Docker runtime name supplied to --runtime.
	RuntimeClass string
	// UsernsMode is the Docker user namespace mode, for example "host".
	UsernsMode string
	// PidMode controls the process namespace. Empty and "private" both map to
	// Docker's default private namespace; host and container:<name> are
	// explicit sharing modes.
	PidMode string
	// MaskedPaths and ReadonlyPaths customize the Engine API's OCI system
	// path restrictions. The CLI fallback can only represent the paired empty
	// lists through security-opt=systempaths=unconfined.
	MaskedPaths   []string
	ReadonlyPaths []string
	Privileged    bool
	CPUs          float64
	Memory        string
	PidsLimit     int64
	Restart       string
	DNS           []string
	DNSSearch     []string
	ExtraHosts    []string
	Ports         []PortMap
	Tmpfs         map[string]string
	// NetworkMode is "none" for every Twinet device: interfaces are attached
	// explicitly by netx, never by the container engine's own IPAM. This is
	// what keeps addressing entirely inside the model.
	NetworkMode string
	StopSignal  string
	StopTimeout *int
	Init        bool
	Health      *Health
}

// Bind is a host path mounted into the container.
type Bind struct {
	Source   string
	Target   string
	ReadOnly bool
}

func (b Bind) String() string {
	s := b.Source + ":" + b.Target
	if b.ReadOnly {
		s += ":ro"
	}
	return s
}

// PortMap publishes a container port on the host.
type PortMap struct {
	HostIP    string
	HostPort  int
	Container int
	Protocol  string
}

// Health is a container healthcheck.
type Health struct {
	Test        []string
	Interval    time.Duration
	Timeout     time.Duration
	Retries     int
	StartPeriod time.Duration
}

// Container is an observed container.
type Container struct {
	ID    string
	Name  string
	Image string
	// ImageID identifies the image the container is actually running. The
	// reference above is a tag, and a tag moves; anything that must compare a
	// container against the software it was built from has to use this.
	ImageID string
	State   State
	Status  string
	PID     int
	Labels  map[string]string
	Health  string
}

// Label returns a label value.
func (c Container) Label(k string) string { return c.Labels[k] }

// ExecCmd is a command to run inside a container.
type ExecCmd struct {
	Cmd    []string
	Env    map[string]string
	User   string
	Stdin  io.Reader
	TTY    bool
	Detach bool
	// WorkDir is the working directory inside the container.
	WorkDir string
}

// ExecResult is the outcome of an exec.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// Err returns a descriptive error when the command failed.
func (r ExecResult) Err() error {
	if r.ExitCode == 0 {
		return nil
	}
	msg := r.Stderr
	if msg == "" {
		msg = r.Stdout
	}
	return fmt.Errorf("exit status %d: %s", r.ExitCode, trim(msg))
}

func trim(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "... (truncated)"
	}
	return s
}

// Filter selects containers by label.
type Filter struct {
	Labels map[string]string
	// All includes stopped containers.
	All bool
}

// EventAction is the normalised action of a container lifecycle event.
type EventAction string

const (
	EventCreate  EventAction = "create"
	EventStart   EventAction = "start"
	EventDie     EventAction = "die"
	EventStop    EventAction = "stop"
	EventDestroy EventAction = "destroy"
	EventRestart EventAction = "restart"
	EventOOM     EventAction = "oom"
	EventHealth  EventAction = "health"
)

// EventFilter selects container events by label.
type EventFilter struct {
	Labels map[string]string
}

// EventSubscription is an asynchronous container event stream.
//
// Errors receives exactly one non-nil terminal error, including io.EOF when an
// engine stream ends and a context error when its context is cancelled. It
// then closes, so a caller can distinguish a reconnectable stream end from a
// silently closed channel.
type EventSubscription struct {
	Events <-chan Event
	Errors <-chan error
}

// EventSource subscribes to container lifecycle events.
type EventSource interface {
	Subscribe(ctx context.Context, filter EventFilter) EventSubscription
}

// Event is a normalised container lifecycle event.
type Event struct {
	// Container is the Engine container ID.
	Container string
	// Name is the Engine container name when the backend provides one.
	Name   string
	Action EventAction
	Labels map[string]string
	At     time.Time
}

// Runtime is the container engine abstraction.
type Runtime interface {
	// Name identifies the backend, for diagnostics.
	Name() string
	// Ping verifies the engine is reachable and returns its version.
	Ping(ctx context.Context) (string, error)
	// PullImage fetches an image according to the policy.
	PullImage(ctx context.Context, ref string, policy PullPolicy) error
	// ImageExists reports whether an image is present locally.
	ImageExists(ctx context.Context, ref string) (bool, error)
	// Create makes a container without starting it.
	Create(ctx context.Context, spec *Spec) (string, error)
	// Start starts a created container.
	Start(ctx context.Context, nameOrID string) error
	// Stop stops a running container.
	Stop(ctx context.Context, nameOrID string, timeout time.Duration) error
	// Pause freezes every process in a container without stopping it, which is
	// what a crashed machine looks like from the network: addresses still
	// assigned, nothing answering, not even ARP.
	Pause(ctx context.Context, nameOrID string) error
	// Unpause resumes a paused container.
	Unpause(ctx context.Context, nameOrID string) error
	// ImageDigest resolves an image reference to the digest actually in use,
	// so a grade can be traced to exact software rather than to a mutable tag.
	ImageDigest(ctx context.Context, ref string) (string, error)
	// Remove deletes a container, stopping it first if necessary.
	Remove(ctx context.Context, nameOrID string, force bool) error
	// Inspect returns one container, or StateAbsent if it does not exist.
	Inspect(ctx context.Context, nameOrID string) (Container, error)
	// List returns containers matching the filter.
	List(ctx context.Context, f Filter) ([]Container, error)
	// NSPath returns the network namespace path of a running container.
	NSPath(ctx context.Context, nameOrID string) (string, error)
	// Exec runs a command inside a container.
	Exec(ctx context.Context, nameOrID string, cmd ExecCmd) (ExecResult, error)
	// CopyTo writes a file into a container.
	CopyTo(ctx context.Context, nameOrID, dstPath string, mode int64, content []byte) error
	// CopyFrom reads a file out of a container.
	CopyFrom(ctx context.Context, nameOrID, srcPath string) ([]byte, error)
	// Close releases any resources held by the client.
	Close() error
}

// EventRuntime is a Runtime that can subscribe to container lifecycle events.
type EventRuntime interface {
	Runtime
	EventSource
}

// SortContainers orders containers by name for deterministic output.
func SortContainers(cs []Container) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
}
