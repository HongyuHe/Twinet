package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const podmanBackendEnv = "TWINET_PODMAN_HOST"

// ErrUnsupported identifies a runtime operation that the selected backend
// cannot faithfully implement.
var ErrUnsupported = errors.New("runtime operation unsupported")

// Podman drives Podman's Docker-compatible API.
type Podman struct {
	host string

	once    sync.Once
	backend engineBackend
	err     error
}

var _ EventRuntime = (*Podman)(nil)

// NewPodman constructs a Podman runtime. Its API client is initialized on the
// first operation so callers get a clear configuration error from that call.
func NewPodman() *Podman { return &Podman{} }

// Name identifies the backend.
func (p *Podman) Name() string { return "podman" }

// SetRuntimeEndpoint selects Podman's Docker-compatible API endpoint before
// the first operation.
func (p *Podman) SetRuntimeEndpoint(endpoint string) error {
	normalized, err := normalizePodmanHost(endpoint)
	if err != nil {
		return err
	}
	p.host = normalized
	return nil
}

// RuntimeEndpoint reports the selected API socket. Resolving the default here
// keeps status useful before the first operation has initialized the client.
func (p *Podman) RuntimeEndpoint() string {
	if p.host != "" {
		return p.host
	}
	host, err := podmanHost()
	if err != nil {
		return ""
	}
	return host
}

func (p *Podman) initialize() {
	host := p.host
	if host == "" {
		var err error
		host, err = podmanHost()
		if err != nil {
			p.err = fmt.Errorf("resolve Podman API host: %w", err)
			return
		}
	}
	backend, err := newPodmanAPI(host)
	if err != nil {
		p.err = fmt.Errorf("initialize Podman Docker-compatible API client: %w", err)
		return
	}
	p.backend = backend
}

func (p *Podman) backendFor() (engineBackend, error) {
	p.once.Do(p.initialize)
	if p.err != nil {
		return nil, p.err
	}
	if p.backend == nil {
		return nil, fmt.Errorf("Podman backend was not initialized")
	}
	return p.backend, nil
}

// Close releases resources held by the Podman API client.
func (p *Podman) Close() error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Close()
}

// Ping verifies the Podman service is reachable.
func (p *Podman) Ping(ctx context.Context) (string, error) {
	backend, err := p.backendFor()
	if err != nil {
		return "", err
	}
	return backend.Ping(ctx)
}

// ImageExists reports whether an image is present locally.
func (p *Podman) ImageExists(ctx context.Context, ref string) (bool, error) {
	backend, err := p.backendFor()
	if err != nil {
		return false, err
	}
	return backend.ImageExists(ctx, ref)
}

// PullImage fetches an image according to the policy.
func (p *Podman) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.PullImage(ctx, ref, policy)
}

// Create makes a container without starting it.
func (p *Podman) Create(ctx context.Context, spec *Spec) (string, error) {
	backend, err := p.backendFor()
	if err != nil {
		return "", err
	}
	return backend.Create(ctx, spec)
}

// Start starts a created container.
func (p *Podman) Start(ctx context.Context, nameOrID string) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Start(ctx, nameOrID)
}

// Stop stops a running container.
func (p *Podman) Stop(ctx context.Context, nameOrID string, timeout time.Duration) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Stop(ctx, nameOrID, timeout)
}

// Pause freezes every process in a container without stopping it.
func (p *Podman) Pause(ctx context.Context, nameOrID string) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Pause(ctx, nameOrID)
}

// Unpause resumes a paused container.
func (p *Podman) Unpause(ctx context.Context, nameOrID string) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Unpause(ctx, nameOrID)
}

// ImageDigest resolves an image reference to the digest actually in use.
func (p *Podman) ImageDigest(ctx context.Context, ref string) (string, error) {
	backend, err := p.backendFor()
	if err != nil {
		return "", err
	}
	return backend.ImageDigest(ctx, ref)
}

// Remove deletes a container.
func (p *Podman) Remove(ctx context.Context, nameOrID string, force bool) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.Remove(ctx, nameOrID, force)
}

// Inspect returns one container, or StateAbsent when it does not exist.
func (p *Podman) Inspect(ctx context.Context, nameOrID string) (Container, error) {
	backend, err := p.backendFor()
	if err != nil {
		return Container{}, err
	}
	return backend.Inspect(ctx, nameOrID)
}

// List returns containers matching the filter.
func (p *Podman) List(ctx context.Context, filter Filter) ([]Container, error) {
	backend, err := p.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.List(ctx, filter)
}

// NSPath returns the network namespace path of a running container.
func (p *Podman) NSPath(ctx context.Context, nameOrID string) (string, error) {
	backend, err := p.backendFor()
	if err != nil {
		return "", err
	}
	return backend.NSPath(ctx, nameOrID)
}

// Exec runs a command inside a container.
func (p *Podman) Exec(ctx context.Context, nameOrID string, cmd ExecCmd) (ExecResult, error) {
	backend, err := p.backendFor()
	if err != nil {
		return ExecResult{}, err
	}
	return backend.Exec(ctx, nameOrID, cmd)
}

// CopyTo writes a file into a container.
func (p *Podman) CopyTo(ctx context.Context, nameOrID, dstPath string, mode int64, content []byte) error {
	backend, err := p.backendFor()
	if err != nil {
		return err
	}
	return backend.CopyTo(ctx, nameOrID, dstPath, mode, content)
}

// CopyFrom reads a file out of a container.
func (p *Podman) CopyFrom(ctx context.Context, nameOrID, srcPath string) ([]byte, error) {
	backend, err := p.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.CopyFrom(ctx, nameOrID, srcPath)
}

// CopyFromFollow reads a file out of a container, following the final symlink.
func (p *Podman) CopyFromFollow(ctx context.Context, nameOrID, srcPath string) ([]byte, error) {
	backend, err := p.backendFor()
	if err != nil {
		return nil, err
	}
	return backend.CopyFromFollow(ctx, nameOrID, srcPath)
}

// Subscribe receives Podman lifecycle events until ctx is cancelled or the
// service reports a terminal stream error.
func (p *Podman) Subscribe(ctx context.Context, filter EventFilter) EventSubscription {
	backend, err := p.backendFor()
	if err != nil {
		return failedEventSubscription(err)
	}
	return backend.Subscribe(ctx, filter)
}

func podmanHost() (string, error) {
	return resolvePodmanHost(os.Getenv, os.Geteuid(), os.Getuid())
}

func resolvePodmanHost(getenv func(string) string, euid, uid int) (string, error) {
	if host := strings.TrimSpace(getenv(podmanBackendEnv)); host != "" {
		return normalizePodmanHost(host)
	}
	if euid == 0 {
		return "unix:///run/podman/podman.sock", nil
	}
	if runtimeDir := strings.TrimSpace(getenv("XDG_RUNTIME_DIR")); runtimeDir != "" {
		if !filepath.IsAbs(runtimeDir) {
			return "", fmt.Errorf("XDG_RUNTIME_DIR %q is not absolute", runtimeDir)
		}
		return "unix://" + filepath.Join(runtimeDir, "podman", "podman.sock"), nil
	}
	if uid < 0 {
		return "", fmt.Errorf("cannot determine rootless Podman user ID")
	}
	return fmt.Sprintf("unix:///run/user/%d/podman/podman.sock", uid), nil
}

func normalizePodmanHost(host string) (string, error) {
	if strings.HasPrefix(host, "/") {
		if strings.ContainsAny(host, " \t\r\n") {
			return "", fmt.Errorf("%s=%q contains whitespace", podmanBackendEnv, host)
		}
		return "unix://" + host, nil
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return "", fmt.Errorf("%s=%q contains whitespace", podmanBackendEnv, host)
	}
	switch {
	case strings.HasPrefix(host, "unix://"), strings.HasPrefix(host, "tcp://"):
		return host, nil
	case strings.HasPrefix(host, "http://"), strings.HasPrefix(host, "https://"):
		return "", fmt.Errorf("%s must use unix:// or tcp://; HTTP URLs cannot support Podman exec streams", podmanBackendEnv)
	default:
		return "", fmt.Errorf("%s=%q must be an absolute Unix socket path, unix:// URI, or tcp:// URI", podmanBackendEnv, host)
	}
}
