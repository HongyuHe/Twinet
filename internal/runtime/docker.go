package runtime

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const dockerBackendEnv = "TWINET_DOCKER_BACKEND"

type engineBackend interface {
	Close() error
	Ping(context.Context) (string, error)
	ImageExists(context.Context, string) (bool, error)
	PullImage(context.Context, string, PullPolicy) error
	Create(context.Context, *Spec) (string, error)
	Start(context.Context, string) error
	ImageDigest(context.Context, string) (string, error)
	Pause(context.Context, string) error
	Unpause(context.Context, string) error
	Stop(context.Context, string, time.Duration) error
	Remove(context.Context, string, bool) error
	Inspect(context.Context, string) (Container, error)
	List(context.Context, Filter) ([]Container, error)
	NSPath(context.Context, string) (string, error)
	Exec(context.Context, string, ExecCmd) (ExecResult, error)
	CopyTo(context.Context, string, string, int64, []byte) error
	CopyFrom(context.Context, string, string) ([]byte, error)
	CopyFromFollow(context.Context, string, string) ([]byte, error)
	Subscribe(context.Context, EventFilter) EventSubscription
}

// Docker drives the Docker Engine API. Set TWINET_DOCKER_BACKEND=cli only to
// select the compatibility CLI backend explicitly.
type Docker struct {
	mode     string
	endpoint string

	once    sync.Once
	backend engineBackend
	err     error
}

var _ EventRuntime = (*Docker)(nil)

// NewDocker constructs a Docker runtime. The Engine API client is initialized
// on the first operation so construction remains compatible with all callers.
func NewDocker() *Docker {
	return &Docker{
		mode:     strings.ToLower(strings.TrimSpace(os.Getenv(dockerBackendEnv))),
		endpoint: strings.TrimSpace(os.Getenv("DOCKER_HOST")),
	}
}

// Name identifies the backend.
func (d *Docker) Name() string { return "docker" }

// SetRuntimeEndpoint selects the Engine API endpoint before the first runtime
// operation. It is intentionally a backend method rather than a process
// environment mutation: one in-process test agent must not redirect another.
func (d *Docker) SetRuntimeEndpoint(endpoint string) error {
	normalized, err := normalizeDockerHost(endpoint)
	if err != nil {
		return err
	}
	d.endpoint = normalized
	return nil
}

// RuntimeEndpoint reports the Engine API endpoint selected for this runtime.
func (d *Docker) RuntimeEndpoint() string {
	if d.endpoint != "" {
		return d.endpoint
	}
	return "unix:///var/run/docker.sock"
}

func (d *Docker) initialize() {
	switch d.mode {
	case "", "api", "engine":
		backend, err := newDockerAPI(d.endpoint)
		if err != nil {
			d.err = fmt.Errorf("initialize Docker Engine API client: %w", err)
			return
		}
		d.backend = backend
	case "cli":
		d.backend = &dockerCLI{bin: "docker"}
	default:
		d.err = fmt.Errorf("invalid %s=%q; use %q (the default) or %q",
			dockerBackendEnv, d.mode, "api", "cli")
	}
}

func normalizeDockerHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("Docker runtime socket is empty")
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return "", fmt.Errorf("Docker runtime socket %q contains whitespace", host)
	}
	if strings.HasPrefix(host, "/") {
		return "unix://" + host, nil
	}
	switch {
	case strings.HasPrefix(host, "unix://"), strings.HasPrefix(host, "tcp://"):
		return host, nil
	default:
		return "", fmt.Errorf("Docker runtime socket %q must be an absolute Unix socket path, unix:// URI, or tcp:// URI", host)
	}
}

func (d *Docker) backendFor() (engineBackend, error) {
	d.once.Do(d.initialize)
	if d.err != nil {
		return nil, d.err
	}
	if d.backend == nil {
		return nil, fmt.Errorf("Docker backend was not initialized")
	}
	return d.backend, nil
}

// Close releases resources held by the selected backend.
func (d *Docker) Close() error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Close()
}

// Ping verifies the daemon is reachable.
func (d *Docker) Ping(ctx context.Context) (string, error) {
	backend, err := d.backendFor()
	if err != nil {
		return "", err
	}
	return backend.Ping(ctx)
}

// ImageExists reports whether an image is present locally.
func (d *Docker) ImageExists(ctx context.Context, ref string) (bool, error) {
	backend, err := d.backendFor()
	if err != nil {
		return false, err
	}
	return backend.ImageExists(ctx, ref)
}

// PullImage fetches an image according to the policy.
func (d *Docker) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.PullImage(ctx, ref, policy)
}

// Create makes a container without starting it.
func (d *Docker) Create(ctx context.Context, spec *Spec) (string, error) {
	backend, err := d.backendFor()
	if err != nil {
		return "", err
	}
	return backend.Create(ctx, spec)
}

// Start starts a created container.
func (d *Docker) Start(ctx context.Context, nameOrID string) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Start(ctx, nameOrID)
}

// ImageDigest resolves an image reference to the digest actually in use.
func (d *Docker) ImageDigest(ctx context.Context, ref string) (string, error) {
	backend, err := d.backendFor()
	if err != nil {
		return "", err
	}
	return backend.ImageDigest(ctx, ref)
}

// Pause freezes every process in a container without stopping it.
func (d *Docker) Pause(ctx context.Context, nameOrID string) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Pause(ctx, nameOrID)
}

// Unpause resumes a paused container.
func (d *Docker) Unpause(ctx context.Context, nameOrID string) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Unpause(ctx, nameOrID)
}

// Stop stops a running container.
func (d *Docker) Stop(ctx context.Context, nameOrID string, timeout time.Duration) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Stop(ctx, nameOrID, timeout)
}

// Remove deletes a container.
func (d *Docker) Remove(ctx context.Context, nameOrID string, force bool) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.Remove(ctx, nameOrID, force)
}

// Inspect returns one container, or StateAbsent when it does not exist.
func (d *Docker) Inspect(ctx context.Context, nameOrID string) (Container, error) {
	backend, err := d.backendFor()
	if err != nil {
		return Container{}, err
	}
	return backend.Inspect(ctx, nameOrID)
}

// List returns containers matching the filter.
func (d *Docker) List(ctx context.Context, filter Filter) ([]Container, error) {
	backend, err := d.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.List(ctx, filter)
}

// NSPath returns the network namespace path of a running container.
func (d *Docker) NSPath(ctx context.Context, nameOrID string) (string, error) {
	backend, err := d.backendFor()
	if err != nil {
		return "", err
	}
	return backend.NSPath(ctx, nameOrID)
}

// Exec runs a command inside a container.
func (d *Docker) Exec(ctx context.Context, nameOrID string, cmd ExecCmd) (ExecResult, error) {
	backend, err := d.backendFor()
	if err != nil {
		return ExecResult{}, err
	}
	return backend.Exec(ctx, nameOrID, cmd)
}

// CopyTo writes a file into a container.
func (d *Docker) CopyTo(ctx context.Context, nameOrID, dstPath string, mode int64, content []byte) error {
	backend, err := d.backendFor()
	if err != nil {
		return err
	}
	return backend.CopyTo(ctx, nameOrID, dstPath, mode, content)
}

// CopyFrom reads a file out of a container.
func (d *Docker) CopyFrom(ctx context.Context, nameOrID, srcPath string) ([]byte, error) {
	backend, err := d.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.CopyFrom(ctx, nameOrID, srcPath)
}

// CopyFromFollow reads a file out of a container, following the final symlink.
func (d *Docker) CopyFromFollow(ctx context.Context, nameOrID, srcPath string) ([]byte, error) {
	backend, err := d.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.CopyFromFollow(ctx, nameOrID, srcPath)
}

// Subscribe receives container lifecycle events until ctx is cancelled or the
// backend reports a terminal stream error.
func (d *Docker) Subscribe(ctx context.Context, filter EventFilter) EventSubscription {
	backend, err := d.backendFor()
	if err != nil {
		return failedEventSubscription(err)
	}
	return backend.Subscribe(ctx, filter)
}
