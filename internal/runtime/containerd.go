package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/initproto"
	apievents "github.com/containerd/containerd/api/events"
	apitasks "github.com/containerd/containerd/api/services/tasks/v1"
	cd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	cevents "github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/oci"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	distref "github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	defaultContainerdEndpoint  = "/run/containerd/containerd.sock"
	defaultContainerdNamespace = "twinet"
	defaultSnapshotter         = "overlayfs"
	defaultContainerdStateRoot = "/run/twinet/containerd"
	defaultContainerdInit      = "/usr/local/bin/twinet-init"
	containerdInitDestination  = "/run/.twinet-init"
	containerdControlRoot      = "/run/.twinet-control"
	containerdInitSocket       = containerdControlRoot + "/exec.sock"

	containerdStartedLabel     = "twinet.containerd.started"
	containerdImageLabel       = "twinet.containerd.image"
	containerdImageDigestLabel = "twinet.containerd.image-digest"
	containerdStopSignalLabel  = "twinet.containerd.stop-signal"
	containerdListWorkers      = 32
)

// Containerd drives containerd directly through its native gRPC API. Every
// agent uses a dedicated namespace, so Twinet never lists or mutates Docker's
// moby namespace or another agent's objects.
type Containerd struct {
	endpoint  string
	namespace string
	stateRoot string

	once   sync.Once
	client *cd.Client
	err    error

	eventMu      sync.Mutex
	eventCancels map[uint64]context.CancelFunc
	eventLabels  map[string]map[string]string
	nextEventID  uint64
	eventsClosed bool
	execSequence atomic.Uint64
	taskLocks    [64]sync.Mutex
}

var _ EventRuntime = (*Containerd)(nil)
var _ EndpointRuntime = (*Containerd)(nil)
var _ StreamExecRuntime = (*Containerd)(nil)

func NewContainerd() *Containerd {
	return &Containerd{
		endpoint: defaultContainerdEndpoint, namespace: defaultContainerdNamespace,
		stateRoot:    defaultContainerdStateRoot,
		eventCancels: map[uint64]context.CancelFunc{}, eventLabels: map[string]map[string]string{},
	}
}

func (c *Containerd) Name() string { return "containerd" }

func (c *Containerd) SetRuntimeEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "unix://")
	if endpoint == "" || !filepath.IsAbs(endpoint) || strings.ContainsAny(endpoint, "\r\n\t ") {
		return fmt.Errorf("containerd runtime socket %q must be an absolute Unix socket path", endpoint)
	}
	c.endpoint = endpoint
	return nil
}

func (c *Containerd) RuntimeEndpoint() string {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = defaultContainerdEndpoint
	}
	return "unix://" + endpoint
}

func (c *Containerd) SetRuntimeNamespace(namespace string) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return errors.New("containerd namespace must not be empty")
	}
	for _, r := range namespace {
		if r != '-' && r != '_' && r != '.' &&
			(r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return fmt.Errorf("containerd namespace %q contains unsupported character %q", namespace, r)
		}
	}
	c.namespace = namespace
	return nil
}

func (c *Containerd) RuntimeNamespace() string {
	if c.namespace == "" {
		return defaultContainerdNamespace
	}
	return c.namespace
}

func (c *Containerd) initialize() {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = defaultContainerdEndpoint
	}
	namespace := c.RuntimeNamespace()
	client, err := cd.New(endpoint, cd.WithDefaultNamespace(namespace))
	if err != nil {
		c.err = err
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.NamespaceService().Create(ctx, namespace,
		map[string]string{"twinet.managed": "true"}); err != nil && !cerrdefs.IsAlreadyExists(err) {
		_ = client.Close()
		c.err = fmt.Errorf("create containerd namespace %q: %w", namespace, err)
		return
	}
	c.client = client
}

func (c *Containerd) clientFor() (*cd.Client, error) {
	c.once.Do(c.initialize)
	if c.err != nil {
		return nil, c.err
	}
	if c.client == nil {
		return nil, errors.New("containerd client was not initialized")
	}
	return c.client, nil
}

func (c *Containerd) Close() error {
	c.eventMu.Lock()
	c.eventsClosed = true
	cancels := make([]context.CancelFunc, 0, len(c.eventCancels))
	for _, cancel := range c.eventCancels {
		cancels = append(cancels, cancel)
	}
	c.eventCancels = map[uint64]context.CancelFunc{}
	c.eventMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	if c.client == nil {
		return nil
	}
	return c.client.Close()
}

// DeleteNamespace removes an empty containerd namespace and its image
// references. It is intended for isolated integration fixtures, not normal
// agent shutdown where retaining unpacked images avoids a cold restart.
func (c *Containerd) DeleteNamespace(ctx context.Context) error {
	client, err := c.clientFor()
	if err != nil {
		return err
	}
	containers, err := client.Containers(ctx)
	if err != nil {
		return err
	}
	if len(containers) != 0 {
		return fmt.Errorf("containerd namespace %q still has %d container(s)",
			c.RuntimeNamespace(), len(containers))
	}
	images, err := client.ListImages(ctx)
	if err != nil {
		return err
	}
	for _, image := range images {
		if err := client.ImageService().Delete(ctx, image.Name()); err != nil && !containerdNotFound(err) {
			return fmt.Errorf("delete containerd image %s: %w", image.Name(), err)
		}
	}
	if err := removeContainerdSnapshots(ctx, client.SnapshotService(defaultSnapshotter)); err != nil {
		return err
	}
	for {
		err := client.NamespaceService().Delete(ctx, c.RuntimeNamespace())
		if err == nil || containerdNotFound(err) {
			return nil
		}
		if !cerrdefs.IsFailedPrecondition(err) {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func removeContainerdSnapshots(ctx context.Context, snapshotter snapshots.Snapshotter) error {
	for {
		var current []snapshots.Info
		if err := snapshotter.Walk(ctx, func(ctx context.Context, info snapshots.Info) error {
			current = append(current, info)
			return nil
		}); err != nil {
			return fmt.Errorf("list containerd snapshots: %w", err)
		}
		if len(current) == 0 {
			return nil
		}
		children := map[string]int{}
		for _, info := range current {
			if info.Parent != "" {
				children[info.Parent]++
			}
		}
		removed := 0
		for _, info := range current {
			if children[info.Name] != 0 {
				continue
			}
			if err := snapshotter.Remove(ctx, info.Name); err != nil && !containerdNotFound(err) {
				continue
			}
			removed++
		}
		if removed == 0 {
			return fmt.Errorf("containerd namespace retains %d snapshot(s) with no removable leaf", len(current))
		}
	}
}

func (c *Containerd) Ping(ctx context.Context) (string, error) {
	client, err := c.clientFor()
	if err != nil {
		return "", err
	}
	version, err := client.Version(ctx)
	if err != nil {
		return "", fmt.Errorf("containerd ping: %w", err)
	}
	return version.Version, nil
}

func normalizeContainerdImage(ref string) (string, error) {
	named, err := distref.ParseNormalizedNamed(ref)
	if err != nil {
		return "", fmt.Errorf("containerd image %q: %w", ref, err)
	}
	return distref.TagNameOnly(named).String(), nil
}

func (c *Containerd) image(ctx context.Context, ref string) (cd.Image, error) {
	client, err := c.clientFor()
	if err != nil {
		return nil, err
	}
	if containerdDigestOnly(ref) {
		images, err := client.ListImages(ctx)
		if err != nil {
			return nil, fmt.Errorf("containerd list images for digest %s: %w", ref, err)
		}
		sort.Slice(images, func(i, j int) bool { return images[i].Name() < images[j].Name() })
		for _, image := range images {
			if image.Target().Digest.String() == ref {
				return image, nil
			}
		}
		return nil, fmt.Errorf("containerd image %q: %w", ref, cerrdefs.ErrNotFound)
	}
	normalized, err := normalizeContainerdImage(ref)
	if err != nil {
		return nil, err
	}
	image, err := client.GetImage(ctx, normalized)
	if err != nil {
		return nil, err
	}
	return image, nil
}

func containerdDigestOnly(ref string) bool {
	if len(ref) != len("sha256:")+64 || !strings.HasPrefix(ref, "sha256:") {
		return false
	}
	for _, char := range ref[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func (c *Containerd) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := c.image(ctx, ref)
	if containerdNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (c *Containerd) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
	client, err := c.clientFor()
	if err != nil {
		return err
	}
	normalized, err := normalizeContainerdImage(ref)
	if err != nil {
		return err
	}
	switch policy {
	case PullNever:
		return nil
	case PullIfMissing, "":
		if _, err := c.image(ctx, ref); err == nil {
			return nil
		} else if !containerdNotFound(err) {
			return fmt.Errorf("containerd inspect image %s: %w", normalized, err)
		}
	case PullAlways:
	default:
		return fmt.Errorf("unknown pull policy %q; use %q, %q or %q",
			policy, PullIfMissing, PullAlways, PullNever)
	}
	if _, err := client.Pull(ctx, normalized, cd.WithPullUnpack,
		cd.WithPullSnapshotter(defaultSnapshotter)); err != nil {
		return fmt.Errorf("containerd pull %s: %w", normalized, err)
	}
	return nil
}

func (c *Containerd) ImageDigest(ctx context.Context, ref string) (string, error) {
	image, err := c.image(ctx, ref)
	if err != nil {
		return "", err
	}
	return image.Target().Digest.String(), nil
}

func (c *Containerd) Create(ctx context.Context, spec *Spec) (string, error) {
	if spec == nil || spec.Name == "" {
		return "", errors.New("containerd create requires a named spec")
	}
	client, err := c.clientFor()
	if err != nil {
		return "", err
	}
	image, err := c.image(ctx, spec.Image)
	if err != nil {
		return "", fmt.Errorf("containerd image %s: %w", spec.Image, err)
	}
	imageSpec, err := image.Spec(ctx)
	if err != nil {
		return "", fmt.Errorf("containerd image config %s: %w", spec.Image, err)
	}
	if spec.Init {
		clone := *spec
		clone.Env = cloneStringMap(spec.Env)
		if clone.Env == nil {
			clone.Env = map[string]string{}
		}
		clone.Env["TWINET_INIT_SOCKET"] = containerdInitSocket
		spec = &clone
	}
	namespacePaths, err := c.containerdNamespacePaths(ctx, spec)
	if err != nil {
		return "", err
	}
	runtimeMounts, err := c.runtimeConfigMounts(spec)
	if err != nil {
		return "", err
	}
	labels := cloneStringMap(spec.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[containerdImageLabel] = spec.Image
	labels[containerdImageDigestLabel] = image.Target().Digest.String()
	labels[containerdStopSignalLabel] = spec.StopSignal
	snapshot := cd.WithNewSnapshot(spec.Name, image)
	if spec.ReadOnlyRootfs {
		// A writable overlay is both redundant and expensive when OCI already
		// mounts the root read-only and every legitimate write target is an
		// explicit tmpfs/bind. View snapshots preserve those semantics while
		// avoiding one mutable upper layer per primary and FRR sidecar.
		snapshot = cd.WithNewSnapshotView(spec.Name, image)
	}
	options := []cd.NewContainerOpts{
		cd.WithImage(image),
		cd.WithSnapshotter(defaultSnapshotter),
		snapshot,
		cd.WithContainerLabels(labels),
		cd.WithNewSpec(oci.WithImageConfig(image),
			containerdSpecOption(spec, imageSpec.Config, namespacePaths, runtimeMounts)),
	}
	if spec.RuntimeClass != "" {
		options = append(options, cd.WithRuntime(spec.RuntimeClass, nil))
	}
	container, err := client.NewContainer(ctx, spec.Name, options...)
	if err != nil {
		_ = client.SnapshotService(defaultSnapshotter).Remove(context.WithoutCancel(ctx), spec.Name)
		_ = os.RemoveAll(c.containerRoot(spec.Name))
		return "", fmt.Errorf("containerd create %s: %w", spec.Name, err)
	}
	c.rememberEventLabels(spec.Name, labels)
	return container.ID(), nil
}

func containerdSpecOption(spec *Spec, image ocispec.ImageConfig,
	namespacePaths map[specs.LinuxNamespaceType]string, runtimeMounts []specs.Mount,
) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, container *containers.Container, out *specs.Spec) error {
		args := append([]string(nil), image.Entrypoint...)
		if len(spec.Entrypoint) > 0 {
			args = append([]string(nil), spec.Entrypoint...)
		}
		command := image.Cmd
		if len(spec.Command) > 0 {
			command = spec.Command
		}
		args = append(args, command...)
		if spec.Init {
			args = append([]string{containerdInitDestination, "--"}, args...)
		}
		if len(args) == 0 {
			return fmt.Errorf("container %s has no command or image entrypoint", spec.Name)
		}
		out.Process.Args = args
		out.Process.Env = mergeEnv(out.Process.Env, spec.Env)
		if spec.Hostname != "" {
			out.Hostname = spec.Hostname
		}
		out.Root.Readonly = spec.ReadOnlyRootfs
		out.Process.NoNewPrivileges = containsSecurityOpt(spec.SecurityOpt, "no-new-privileges")
		if out.Linux == nil {
			out.Linux = &specs.Linux{}
		}
		out.Linux.MaskedPaths = append([]string(nil), spec.MaskedPaths...)
		out.Linux.ReadonlyPaths = append([]string(nil), spec.ReadonlyPaths...)
		out.Linux.Sysctl = cloneStringMap(spec.Sysctls)
		if out.Linux.Sysctl == nil {
			out.Linux.Sysctl = map[string]string{}
		}
		// Docker sets this inside every private network namespace. Preserve
		// that contract so an FRR daemon running as user frr can bind BGP/179
		// without granting NET_BIND_SERVICE to the student-facing router.
		if _, ok := out.Linux.Sysctl["net.ipv4.ip_unprivileged_port_start"]; !ok {
			out.Linux.Sysctl["net.ipv4.ip_unprivileged_port_start"] = "0"
		}
		if out.Linux.Resources == nil {
			out.Linux.Resources = &specs.LinuxResources{}
		}
		if spec.CPUs > 0 {
			period := uint64(100000)
			quota := int64(spec.CPUs * float64(period))
			out.Linux.Resources.CPU = &specs.LinuxCPU{Period: &period, Quota: &quota}
		}
		if spec.Memory != "" {
			bytes, err := ParseMemory(spec.Memory)
			if err != nil {
				return fmt.Errorf("container %s memory: %w", spec.Name, err)
			}
			out.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &bytes}
		}
		if spec.PidsLimit > 0 {
			limit := spec.PidsLimit
			out.Linux.Resources.Pids = &specs.LinuxPids{Limit: &limit}
		}
		caps := prefixedCapabilities(spec.Capabilities)
		out.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding: caps, Effective: caps, Inheritable: caps, Permitted: caps, Ambient: caps,
		}
		configureContainerdNamespaces(spec, namespacePaths, out)
		// Parent tmpfs mounts must precede child bind mounts. Appending /run
		// after /run/frr hides the shared FRR directory even though both mounts
		// appear in the OCI spec.
		for target, raw := range spec.Tmpfs {
			options := []string{"nosuid", "nodev"}
			for _, option := range strings.Split(raw, ",") {
				if option = strings.TrimSpace(option); option != "" {
					options = append(options, option)
				}
			}
			out.Mounts = append(out.Mounts, specs.Mount{
				Destination: target, Type: "tmpfs", Source: "tmpfs", Options: options,
			})
		}
		if spec.Labels["twinet.frr-control"] == "true" {
			// Alpine FRR writes transient zebra state under /lib/frr. The
			// router image supplies this otherwise-empty mountpoint so a view
			// snapshot can retain a read-only root while the sidecar gets only
			// the narrow writable directory it needs.
			out.Mounts = append(out.Mounts, specs.Mount{
				Destination: "/lib/frr", Type: "tmpfs", Source: "tmpfs",
				Options: []string{"rw", "nosuid", "nodev", "mode=0755"},
			})
		}
		for _, bind := range spec.Binds {
			options := []string{"rbind", "rprivate", "rw"}
			if bind.ReadOnly {
				options[2] = "ro"
			}
			out.Mounts = append(out.Mounts, specs.Mount{
				Destination: bind.Target, Type: "bind", Source: bind.Source, Options: options,
			})
		}
		out.Mounts = append(out.Mounts, runtimeMounts...)
		for _, option := range spec.SecurityOpt {
			switch {
			case option == "no-new-privileges":
			case option == "seccomp=default":
				if err := seccomp.WithDefaultProfile()(ctx, client, container, out); err != nil {
					return err
				}
			case strings.HasPrefix(option, "seccomp="):
				if err := seccomp.WithProfile(strings.TrimPrefix(option, "seccomp="))(
					ctx, client, container, out); err != nil {
					return err
				}
			case strings.HasPrefix(option, "apparmor="):
				if err := oci.WithApparmorProfile(strings.TrimPrefix(option, "apparmor="))(
					ctx, client, container, out); err != nil {
					return err
				}
			default:
				return fmt.Errorf("containerd does not support security option %q", option)
			}
		}

		if spec.Privileged {
			if err := oci.WithPrivileged(ctx, client, container, out); err != nil {
				return err
			}
		}
		if len(spec.Ports) > 0 {
			return fmt.Errorf("%w: native containerd port publishing is not configured", ErrUnsupported)
		}
		if spec.Health != nil {
			return fmt.Errorf("%w: native containerd OCI healthchecks are not configured", ErrUnsupported)
		}
		if spec.UsernsMode != "" && spec.UsernsMode != "host" {
			return fmt.Errorf("%w: containerd user namespace mode %q", ErrUnsupported, spec.UsernsMode)
		}
		return nil
	}
}

func (c *Containerd) containerRoot(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(c.stateRoot, c.RuntimeNamespace(), fmt.Sprintf("%x", sum[:8]))
}

func (c *Containerd) runtimeConfigMounts(spec *Spec) ([]specs.Mount, error) {
	if len(spec.DNS) == 0 && len(spec.DNSSearch) == 0 && len(spec.ExtraHosts) == 0 && !spec.Init {
		return nil, nil
	}
	root := c.containerRoot(spec.Name)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create containerd runtime state for %s: %w", spec.Name, err)
	}
	var mounts []specs.Mount
	if spec.Init {
		source := strings.TrimSpace(os.Getenv("TWINET_INIT_BINARY"))
		if source == "" {
			source = defaultContainerdInit
		}
		info, err := os.Stat(source)
		if err != nil {
			return nil, fmt.Errorf("containerd init binary %s: %w", source, err)
		}
		if info.Mode()&0o111 == 0 {
			return nil, fmt.Errorf("containerd init binary %s is not executable", source)
		}
		mounts = append(mounts, specs.Mount{
			Destination: containerdInitDestination, Type: "bind", Source: source,
			Options: []string{"rbind", "rprivate", "ro"},
		})
		controlRoot := filepath.Join(root, "control")
		if err := os.MkdirAll(controlRoot, 0o700); err != nil {
			return nil, err
		}
		mounts = append(mounts, specs.Mount{
			Destination: containerdControlRoot, Type: "bind", Source: controlRoot,
			Options: []string{"rbind", "rprivate", "rw"},
		})
	}
	writeMount := func(name, destination, content string) error {
		source := filepath.Join(root, name)
		if err := os.WriteFile(source, []byte(content), 0o644); err != nil {
			return err
		}
		mounts = append(mounts, specs.Mount{
			Destination: destination, Type: "bind", Source: source,
			Options: []string{"rbind", "rprivate", "ro"},
		})
		return nil
	}
	if len(spec.DNS) > 0 || len(spec.DNSSearch) > 0 {
		var lines []string
		for _, server := range spec.DNS {
			lines = append(lines, "nameserver "+server)
		}
		if len(spec.DNSSearch) > 0 {
			lines = append(lines, "search "+strings.Join(spec.DNSSearch, " "))
		}
		if err := writeMount("resolv.conf", "/etc/resolv.conf", strings.Join(lines, "\n")+"\n"); err != nil {
			return nil, fmt.Errorf("write containerd resolv.conf for %s: %w", spec.Name, err)
		}
	}
	if len(spec.ExtraHosts) > 0 {
		lines := []string{"127.0.0.1 localhost"}
		for _, entry := range spec.ExtraHosts {
			host, address, ok := strings.Cut(entry, ":")
			if !ok || host == "" || address == "" {
				return nil, fmt.Errorf("containerd extra host %q must be host:address", entry)
			}
			lines = append(lines, address+" "+host)
		}
		if err := writeMount("hosts", "/etc/hosts", strings.Join(lines, "\n")+"\n"); err != nil {
			return nil, fmt.Errorf("write containerd hosts for %s: %w", spec.Name, err)
		}
	}
	return mounts, nil
}

func mergeEnv(base []string, overrides map[string]string) []string {
	values := map[string]string{}
	for _, entry := range base {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	for key, value := range overrides {
		values[key] = value
	}
	return sortedEnv(values)
}

func prefixedCapabilities(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" || value == "ALL" {
			continue
		}
		if !strings.HasPrefix(value, "CAP_") {
			value = "CAP_" + value
		}
		out = append(out, value)
	}
	return out
}

func containsSecurityOpt(options []string, want string) bool {
	for _, option := range options {
		if option == want {
			return true
		}
	}
	return false
}

func configureContainerdNamespaces(spec *Spec,
	paths map[specs.LinuxNamespaceType]string, out *specs.Spec,
) {
	setNamespace := func(kind specs.LinuxNamespaceType, path string) {
		for i := range out.Linux.Namespaces {
			if out.Linux.Namespaces[i].Type == kind {
				out.Linux.Namespaces[i].Path = path
				return
			}
		}
		out.Linux.Namespaces = append(out.Linux.Namespaces, specs.LinuxNamespace{Type: kind, Path: path})
	}
	apply := func(mode string, kind specs.LinuxNamespaceType) {
		switch {
		case mode == "", mode == "private", mode == "none" && kind == specs.NetworkNamespace:
			return
		case mode == "host":
			filtered := out.Linux.Namespaces[:0]
			for _, namespace := range out.Linux.Namespaces {
				if namespace.Type != kind {
					filtered = append(filtered, namespace)
				}
			}
			out.Linux.Namespaces = filtered
			return
		case strings.HasPrefix(mode, "container:"):
			setNamespace(kind, paths[kind])
		}
	}
	apply(spec.NetworkMode, specs.NetworkNamespace)
	apply(spec.PidMode, specs.PIDNamespace)
}

func (c *Containerd) containerdNamespacePaths(ctx context.Context,
	spec *Spec,
) (map[specs.LinuxNamespaceType]string, error) {
	out := map[specs.LinuxNamespaceType]string{}
	resolve := func(mode string, kind specs.LinuxNamespaceType) error {
		switch {
		case mode == "", mode == "private", mode == "host",
			mode == "none" && kind == specs.NetworkNamespace:
			return nil
		case strings.HasPrefix(mode, "container:"):
			name := strings.TrimPrefix(mode, "container:")
			container, err := c.load(ctx, name)
			if err != nil {
				return fmt.Errorf("load namespace donor %s: %w", name, err)
			}
			task, err := container.Task(ctx, nil)
			if err != nil {
				return fmt.Errorf("load namespace donor task %s: %w", name, err)
			}
			nsName := "net"
			if kind == specs.PIDNamespace {
				nsName = "pid"
			}
			out[kind] = fmt.Sprintf("/proc/%d/ns/%s", task.Pid(), nsName)
			return nil
		default:
			return fmt.Errorf("%w: containerd namespace mode %q", ErrUnsupported, mode)
		}
	}
	if err := resolve(spec.NetworkMode, specs.NetworkNamespace); err != nil {
		return nil, err
	}
	if err := resolve(spec.PidMode, specs.PIDNamespace); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Containerd) load(ctx context.Context, name string) (cd.Container, error) {
	client, err := c.clientFor()
	if err != nil {
		return nil, err
	}
	container, err := client.LoadContainer(ctx, name)
	if err != nil {
		return nil, err
	}
	return container, nil
}

func (c *Containerd) Start(ctx context.Context, name string) error {
	sum := sha256.Sum256([]byte(name))
	taskLock := &c.taskLocks[int(sum[0])%len(c.taskLocks)]
	taskLock.Lock()
	defer taskLock.Unlock()

	container, err := c.load(ctx, name)
	if err != nil {
		return fmt.Errorf("containerd start %s: %w", name, err)
	}
	if task, err := container.Task(ctx, nil); err == nil {
		status, statusErr := task.Status(ctx)
		if statusErr != nil && !containerdNotFound(statusErr) {
			return fmt.Errorf("containerd inspect task %s: %w", name, statusErr)
		}
		if statusErr == nil {
			switch status.Status {
			case cd.Running:
				return c.recordContainerdStarted(ctx, container, name)
			case cd.Created:
				return c.startContainerdTask(ctx, container, task, name)
			}
		}
		_, _ = task.Delete(ctx, cd.WithProcessKill)
	} else if !containerdNotFound(err) {
		return fmt.Errorf("containerd load task %s: %w", name, err)
	}
	task, err := container.NewTask(ctx, cio.NullIO)
	if containerdAlreadyExists(err) {
		task, err = c.recoverContainerdTaskCreate(ctx, container, name)
	}
	if err != nil {
		return fmt.Errorf("containerd create task %s: %w", name, err)
	}
	return c.startContainerdTask(ctx, container, task, name)
}

func (c *Containerd) recoverContainerdTaskCreate(ctx context.Context, container cd.Container,
	name string,
) (cd.Task, error) {
	if task, err := container.Task(ctx, nil); err == nil {
		return task, nil
	} else if !containerdNotFound(err) {
		return nil, err
	}
	client, err := c.clientFor()
	if err != nil {
		return nil, err
	}
	for attempt := range 3 {
		// A shim can fail after reserving its runtime-v2 bundle but before the
		// task becomes observable. The native task-service delete is
		// containerd's supported cleanup for that orphaned create state.
		_, deleteErr := client.TaskService().Delete(ctx, &apitasks.DeleteTaskRequest{
			ContainerID: name,
		})
		if deleteErr != nil && !containerdNotFound(deleteErr) {
			return nil, fmt.Errorf("delete orphaned containerd task %s: %w", name, deleteErr)
		}
		task, createErr := container.NewTask(ctx, cio.NullIO)
		if createErr == nil {
			return task, nil
		}
		if !containerdAlreadyExists(createErr) {
			return nil, createErr
		}
		if task, loadErr := container.Task(ctx, nil); loadErr == nil {
			return task, nil
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("containerd task %s remained reserved after native cleanup", name)
}

func (c *Containerd) startContainerdTask(ctx context.Context, container cd.Container,
	task cd.Task, name string,
) error {
	if err := task.Start(ctx); err != nil {
		if status, statusErr := task.Status(ctx); statusErr == nil && status.Status == cd.Running {
			return c.recordContainerdStarted(ctx, container, name)
		}
		_, _ = task.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return fmt.Errorf("containerd start %s: %w", name, err)
	}
	return c.recordContainerdStarted(ctx, container, name)
}

func (c *Containerd) recordContainerdStarted(ctx context.Context, container cd.Container,
	name string,
) error {
	if _, err := container.SetLabels(ctx, map[string]string{containerdStartedLabel: "true"}); err != nil {
		return fmt.Errorf("containerd record started state %s: %w", name, err)
	}
	return nil
}

func (c *Containerd) Stop(ctx context.Context, name string, timeout time.Duration) error {
	container, err := c.load(ctx, name)
	if containerdNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("containerd stop %s: %w", name, err)
	}
	task, err := container.Task(ctx, nil)
	if containerdNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("containerd load task %s: %w", name, err)
	}
	wait, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("containerd wait task %s: %w", name, err)
	}
	signal := syscall.SIGTERM
	if status, statusErr := task.Status(ctx); statusErr == nil &&
		(status.Status == cd.Paused || status.Status == cd.Pausing) {
		if err := task.Resume(ctx); err != nil {
			return fmt.Errorf("containerd resume before stop %s: %w", name, err)
		}
	}
	if labels, labelErr := container.Labels(ctx); labelErr == nil {
		if parsed := parseSignal(labels[containerdStopSignalLabel]); parsed != 0 {
			signal = parsed
		}
	}
	if err := task.Kill(ctx, signal); err != nil && !containerdNotFound(err) {
		return fmt.Errorf("containerd stop %s: %w", name, err)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
		if err := task.Kill(ctx, syscall.SIGKILL); err != nil && !containerdNotFound(err) {
			return fmt.Errorf("containerd kill %s: %w", name, err)
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if _, err := task.Delete(ctx); err != nil && !containerdNotFound(err) {
		return fmt.Errorf("containerd delete stopped task %s: %w", name, err)
	}
	return nil
}

func parseSignal(value string) syscall.Signal {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "SIGTERM", "TERM":
		return syscall.SIGTERM
	case "SIGKILL", "KILL":
		return syscall.SIGKILL
	case "SIGINT", "INT":
		return syscall.SIGINT
	case "SIGHUP", "HUP":
		return syscall.SIGHUP
	case "SIGQUIT", "QUIT":
		return syscall.SIGQUIT
	default:
		if n, err := strconv.Atoi(value); err == nil {
			return syscall.Signal(n)
		}
		return 0
	}
}

func (c *Containerd) Pause(ctx context.Context, name string) error {
	container, err := c.load(ctx, name)
	if err != nil {
		return err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return err
	}
	return task.Pause(ctx)
}

func (c *Containerd) Unpause(ctx context.Context, name string) error {
	container, err := c.load(ctx, name)
	if err != nil {
		return err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return err
	}
	return task.Resume(ctx)
}

func (c *Containerd) Remove(ctx context.Context, name string, force bool) error {
	container, err := c.load(ctx, name)
	if containerdNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("containerd remove %s: %w", name, err)
	}
	if task, taskErr := container.Task(ctx, nil); taskErr == nil {
		status, _ := task.Status(ctx)
		if status.Status == cd.Running && !force {
			return fmt.Errorf("containerd remove %s: task is running", name)
		}
		if _, err := task.Delete(ctx, cd.WithProcessKill); err != nil && !containerdNotFound(err) {
			return fmt.Errorf("containerd remove task %s: %w", name, err)
		}
	} else if !containerdNotFound(taskErr) {
		return fmt.Errorf("containerd load task %s: %w", name, taskErr)
	}
	if err := container.Delete(ctx, cd.WithSnapshotCleanup); err != nil && !containerdNotFound(err) {
		return fmt.Errorf("containerd remove %s: %w", name, err)
	}
	if err := os.RemoveAll(c.containerRoot(name)); err != nil {
		return fmt.Errorf("containerd remove runtime state %s: %w", name, err)
	}
	return nil
}

func (c *Containerd) Inspect(ctx context.Context, name string) (Container, error) {
	container, err := c.load(ctx, name)
	if containerdNotFound(err) {
		return Container{Name: name, State: StateAbsent}, nil
	}
	if err != nil {
		return Container{}, fmt.Errorf("containerd inspect %s: %w", name, err)
	}
	return c.inspectContainer(ctx, container)
}

func (c *Containerd) inspectContainer(ctx context.Context, container cd.Container) (Container, error) {
	info, err := container.Info(ctx)
	if err != nil {
		return Container{}, err
	}
	return c.inspectContainerInfo(ctx, container, info)
}

func (c *Containerd) inspectContainerInfo(ctx context.Context, container cd.Container,
	info containers.Container,
) (Container, error) {
	labels := cloneStringMap(info.Labels)
	out := Container{
		ID: info.ID, Name: info.ID, Image: labels[containerdImageLabel],
		Labels: labels, State: StateCreated,
	}
	c.rememberEventLabels(info.ID, labels)
	out.ImageID = labels[containerdImageDigestLabel]
	if out.ImageID == "" {
		if image, imageErr := container.Image(ctx); imageErr == nil {
			out.ImageID = image.Target().Digest.String()
		}
	}
	task, err := container.Task(ctx, nil)
	if containerdNotFound(err) {
		if labels[containerdStartedLabel] == "true" {
			out.State = StateExited
			out.Status = string(StateExited)
		} else {
			out.Status = string(StateCreated)
		}
		return out, nil
	}
	if err != nil {
		return Container{}, err
	}
	status, err := task.Status(ctx)
	if err != nil {
		return Container{}, err
	}
	out.PID = int(task.Pid())
	out.Status = string(status.Status)
	switch status.Status {
	case cd.Created:
		out.State = StateCreated
	case cd.Running:
		out.State = StateRunning
	case cd.Paused, cd.Pausing:
		out.State = StatePaused
	case cd.Stopped:
		out.State = StateExited
	default:
		out.State = StateDead
	}
	return out, nil
}

func (c *Containerd) List(ctx context.Context, filter Filter) ([]Container, error) {
	client, err := c.clientFor()
	if err != nil {
		return nil, err
	}
	containers, err := client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("containerd list: %w", err)
	}
	type listResult struct {
		container Container
		err       error
		matched   bool
	}
	results := make([]listResult, len(containers))
	jobs := make(chan int)
	workers := min(containerdListWorkers, len(containers))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for index := range jobs {
				container := containers[index]
				info, inspectErr := container.Info(ctx)
				if inspectErr != nil {
					if !containerdNotFound(inspectErr) {
						results[index].err = fmt.Errorf("containerd inspect %s: %w",
							container.ID(), inspectErr)
					}
					continue
				}
				if !containerLabelsMatch(info.Labels, filter.Labels) {
					continue
				}
				observed, inspectErr := c.inspectContainerInfo(ctx, container, info)
				if inspectErr != nil {
					// A container or task may disappear after Containers returned
					// while an idempotent destroy is running. It is absent from
					// this observation, not a persistent list failure.
					if !containerdNotFound(inspectErr) {
						results[index].err = fmt.Errorf("containerd inspect %s: %w",
							container.ID(), inspectErr)
					}
					continue
				}
				if !filter.All && observed.State != StateRunning {
					continue
				}
				results[index] = listResult{container: observed, matched: true}
			}
		}()
	}
	for index := range containers {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	out := make([]Container, 0, len(containers))
	for _, result := range results {
		if result.err != nil {
			return nil, result.err
		}
		if result.matched {
			out = append(out, result.container)
		}
	}
	SortContainers(out)
	return out, nil
}

func containerLabelsMatch(got, want map[string]string) bool {
	for key, value := range want {
		if actual, ok := got[key]; !ok || value != "" && actual != value {
			return false
		}
	}
	return true
}

func containerdNotFound(err error) bool {
	if err == nil {
		return false
	}
	return cerrdefs.IsNotFound(err) ||
		strings.Contains(strings.ToLower(err.Error()), "not found")
}

func containerdAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	return cerrdefs.IsAlreadyExists(err) ||
		strings.Contains(strings.ToLower(err.Error()), "already exists")
}

func (c *Containerd) NSPath(ctx context.Context, name string) (string, error) {
	container, err := c.Inspect(ctx, name)
	if err != nil {
		return "", err
	}
	if !container.State.Joinable() || container.PID <= 0 {
		return "", fmt.Errorf("container %s is %s, so it has no joinable network namespace",
			name, container.State)
	}
	return fmt.Sprintf("/proc/%d/ns/net", container.PID), nil
}

func (c *Containerd) Exec(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
	if action := containerdFRRAction(cmd); action != "" {
		switch action {
		case "start":
			if ready, err := c.frrReady(ctx, name); err == nil && ready {
				return ExecResult{}, nil
			}
			return ExecResult{}, c.startFRR(ctx, name)
		case "restart":
			if ready, err := c.frrReady(ctx, name); err == nil && ready {
				return ExecResult{}, c.reloadFRR(ctx, name)
			}
			return ExecResult{}, c.startFRR(ctx, name)
		case "ensure":
			ready, err := c.frrReady(ctx, name)
			if err == nil && ready {
				return ExecResult{}, nil
			}
			return ExecResult{}, c.startFRR(ctx, name)
		case "stop":
			return ExecResult{}, c.stopFRR(ctx, name)
		}
	}
	return c.execRaw(ctx, name, cmd)
}

func (c *Containerd) reloadFRR(ctx context.Context, name string) error {
	available, err := c.execTaskRaw(ctx, name, ExecCmd{Cmd: []string{
		"test", "-x", "/usr/lib/frr/frr-reload.py",
	}})
	if err != nil {
		return fmt.Errorf("containerd inspect FRR reload support in %s: %w", name, err)
	}
	if available.ExitCode != 0 {
		// Alpine's FRR package omits frr-pythontools. A solved-reference
		// reconfiguration still needs exact replacement semantics rather than
		// a success-shaped no-op, so use the native bounded stop/start path.
		return c.startFRR(ctx, name)
	}
	result, err := c.execTaskRaw(ctx, name, ExecCmd{Cmd: []string{
		"/usr/lib/frr/frr-reload.py", "--reload",
		"--bindir", "/usr/lib/frr", "--confdir", "/etc/frr", "--rundir", "/run/frr",
		"/etc/frr/frr.conf",
	}})
	if err != nil {
		return fmt.Errorf("containerd reload FRR in %s: %w", name, err)
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("containerd reload FRR in %s: %w", name, err)
	}
	return nil
}

func (c *Containerd) ExecBatch(ctx context.Context, name string,
	commands []ExecCmd,
) ([]ExecResult, error) {
	results := make([]ExecResult, len(commands))
	var pending []int
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		var script strings.Builder
		script.WriteString("set +e\nroot=$(mktemp -d /tmp/twinet-batch.XXXXXX) || exit 125\n")
		script.WriteString("trap 'rm -rf \"$root\"' EXIT\n")
		for _, index := range pending {
			fmt.Fprintf(&script, "(\n")
			for key, value := range commands[index].Env {
				script.WriteString("export ")
				script.WriteString(shellQuote(key + "=" + value))
				script.WriteByte('\n')
			}
			if commands[index].WorkDir != "" {
				script.WriteString("cd ")
				script.WriteString(shellQuote(commands[index].WorkDir))
				script.WriteString(" || exit 125\n")
			}
			for _, arg := range commands[index].Cmd {
				script.WriteString(shellQuote(arg))
				script.WriteByte(' ')
			}
			fmt.Fprintf(&script, "\n) >\"$root/%d.out\" 2>\"$root/%d.err\"\n", index, index)
			script.WriteString("rc=$?\n")
			fmt.Fprintf(&script, "out=$(wc -c <\"$root/%d.out\")\n", index)
			fmt.Fprintf(&script, "err=$(wc -c <\"$root/%d.err\")\n", index)
			fmt.Fprintf(&script,
				"printf '__TWINET_BATCH__ %d %%s %%s %%s\\n' \"$rc\" \"$out\" \"$err\"\n",
				index)
			fmt.Fprintf(&script, "cat \"$root/%d.out\" \"$root/%d.err\"\n", index, index)
		}
		raw, err := c.execRaw(ctx, name, ExecCmd{Cmd: []string{"sh", "-c", script.String()}})
		if err != nil {
			return err
		}
		if raw.ExitCode != 0 {
			return fmt.Errorf("containerd batch broker exited %d: %s",
				raw.ExitCode, trim(raw.Stderr))
		}
		if strings.TrimSpace(raw.Stderr) != "" {
			return fmt.Errorf("containerd batch broker wrote unexpected stderr: %s",
				trim(raw.Stderr))
		}
		framed, err := parseContainerdBatchResults([]byte(raw.Stdout), pending)
		if err != nil {
			return err
		}
		for index, result := range framed {
			results[index] = result
		}
		pending = pending[:0]
		return nil
	}
	for index, command := range commands {
		batchable := command.Stdin == nil && command.User == "" && !command.TTY &&
			!command.Detach
		if batchable && containerdFRRAction(command) == "" {
			pending = append(pending, index)
			continue
		}
		if err := flush(); err != nil {
			return nil, err
		}
		result, err := c.Exec(ctx, name, command)
		if err != nil {
			return nil, fmt.Errorf("containerd batch exec command %d: %w", index, err)
		}
		results[index] = result
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return results, nil
}

func parseContainerdBatchResults(raw []byte, expected []int) (map[int]ExecResult, error) {
	const marker = "__TWINET_BATCH__ "
	results := make(map[int]ExecResult, len(expected))
	cursor := 0
	for _, want := range expected {
		if cursor >= len(raw) {
			return nil, fmt.Errorf("containerd batch output ended before command %d", want)
		}
		end := bytes.IndexByte(raw[cursor:], '\n')
		if end < 0 {
			return nil, fmt.Errorf("containerd batch command %d has no frame header", want)
		}
		header := string(raw[cursor : cursor+end])
		cursor += end + 1
		fields := strings.Fields(header)
		if len(fields) != 5 || fields[0]+" " != marker {
			return nil, fmt.Errorf("containerd batch command %d has invalid frame %q", want, header)
		}
		index, indexErr := strconv.Atoi(fields[1])
		code, codeErr := strconv.Atoi(fields[2])
		stdoutBytes, stdoutErr := strconv.Atoi(fields[3])
		stderrBytes, stderrErr := strconv.Atoi(fields[4])
		if indexErr != nil || codeErr != nil || stdoutErr != nil || stderrErr != nil ||
			index != want || stdoutBytes < 0 || stderrBytes < 0 ||
			stdoutBytes > len(raw)-cursor || stderrBytes > len(raw)-cursor-stdoutBytes {
			return nil, fmt.Errorf("containerd batch command %d has invalid frame %q", want, header)
		}
		stdout := string(raw[cursor : cursor+stdoutBytes])
		cursor += stdoutBytes
		stderr := string(raw[cursor : cursor+stderrBytes])
		cursor += stderrBytes
		results[index] = ExecResult{ExitCode: code, Stdout: stdout, Stderr: stderr}
	}
	if cursor != len(raw) {
		return nil, fmt.Errorf("containerd batch output has %d unframed byte(s)", len(raw)-cursor)
	}
	return results, nil
}

func (c *Containerd) execRaw(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
	if result, ok, err := c.execViaInit(ctx, name, cmd); ok {
		return result, err
	}
	return c.execTaskRaw(ctx, name, cmd)
}

// execTaskRaw bypasses the PID-1 broker for daemon lifecycle work. FRR
// deliberately daemonizes and manipulates process groups; keeping that control
// boundary in containerd's native task-exec path prevents a daemon transition
// from taking the long-lived broker down with its calling shell.
func (c *Containerd) execTaskRaw(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
	container, err := c.load(ctx, name)
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerd exec %s: %w", name, err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerd exec task %s: %w", name, err)
	}
	spec, err := task.Spec(ctx)
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerd exec spec %s: %w", name, err)
	}
	process := *spec.Process
	process.Args = append([]string(nil), cmd.Cmd...)
	process.Env = mergeEnv(process.Env, cmd.Env)
	process.Terminal = cmd.TTY
	if cmd.WorkDir != "" {
		process.Cwd = cmd.WorkDir
	}
	if cmd.User != "" {
		uid, gid, err := parseNumericUser(cmd.User)
		if err != nil {
			return ExecResult{}, err
		}
		process.User.UID, process.User.GID = uid, gid
	}
	execID := fmt.Sprintf("exec-%d", c.execSequence.Add(1))
	if cmd.Detach {
		proc, err := task.Exec(ctx, execID, &process, cio.NullIO)
		if err != nil {
			return ExecResult{}, fmt.Errorf("containerd exec %s: %w", name, err)
		}
		if err := proc.Start(ctx); err != nil {
			_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
			return ExecResult{}, fmt.Errorf("containerd exec %s: %w", name, err)
		}
		return ExecResult{Stdout: execID + "\n"}, nil
	}
	var stdout, stderr bytes.Buffer
	stdin := cmd.Stdin
	var stdinEOF <-chan struct{}
	if stdin != nil {
		reader := &eofSignallingReader{reader: stdin, done: make(chan struct{})}
		stdin, stdinEOF = reader, reader.done
	}
	ioOptions := []cio.Opt{cio.WithStreams(stdin, &stdout, &stderr)}
	if cmd.TTY {
		ioOptions = append(ioOptions, cio.WithTerminal)
	}
	proc, err := task.Exec(ctx, execID, &process, cio.NewCreator(ioOptions...))
	if err != nil {
		return ExecResult{}, fmt.Errorf("containerd exec %s: %w", name, err)
	}
	wait, err := proc.Wait(ctx)
	if err != nil {
		_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return ExecResult{}, fmt.Errorf("containerd exec wait %s: %w", name, err)
	}
	if err := proc.Start(ctx); err != nil {
		_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return ExecResult{}, fmt.Errorf("containerd exec start %s: %w", name, err)
	}
	if stdinEOF != nil {
		select {
		case <-stdinEOF:
			if err := proc.CloseIO(ctx, cd.WithStdinCloser); err != nil {
				_ = proc.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
				_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
				return ExecResult{}, fmt.Errorf("containerd exec close stdin %s: %w", name, err)
			}
		case <-ctx.Done():
			_ = proc.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
			_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
			return ExecResult{}, ctx.Err()
		}
	}
	var status cd.ExitStatus
	select {
	case status = <-wait:
	case <-ctx.Done():
		_ = proc.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
		proc.IO().Cancel()
		_, _ = proc.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}, ctx.Err()
	}
	waitContainerdIO(proc.IO())
	code, _, statusErr := status.Result()
	if _, err := proc.Delete(ctx); err != nil && !containerdNotFound(err) {
		return ExecResult{}, fmt.Errorf("containerd delete exec %s: %w", name, err)
	}
	if statusErr != nil {
		return ExecResult{}, statusErr
	}
	return ExecResult{ExitCode: int(code), Stdout: stdout.String(), Stderr: stderr.String()}, nil
}

func (c *Containerd) StreamExec(ctx context.Context, name string, cmd ExecCmd,
	rows, cols uint32, stdout, stderr io.Writer,
) (int, error) {
	if cmd.Detach {
		return 0, fmt.Errorf("%w: streamed containerd exec cannot detach", ErrUnsupported)
	}
	container, err := c.load(ctx, name)
	if err != nil {
		return 0, fmt.Errorf("containerd stream exec %s: %w", name, err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("containerd stream exec task %s: %w", name, err)
	}
	spec, err := task.Spec(ctx)
	if err != nil {
		return 0, fmt.Errorf("containerd stream exec spec %s: %w", name, err)
	}
	process := *spec.Process
	process.Args = append([]string(nil), cmd.Cmd...)
	process.Env = mergeEnv(process.Env, cmd.Env)
	process.Terminal = cmd.TTY
	if cmd.WorkDir != "" {
		process.Cwd = cmd.WorkDir
	}
	if cmd.User != "" {
		uid, gid, parseErr := parseNumericUser(cmd.User)
		if parseErr != nil {
			return 0, parseErr
		}
		process.User.UID, process.User.GID = uid, gid
	}

	stdin := cmd.Stdin
	var stdinEOF <-chan struct{}
	if stdin != nil {
		reader := &eofSignallingReader{reader: stdin, done: make(chan struct{})}
		stdin, stdinEOF = reader, reader.done
	}
	options := []cio.Opt{cio.WithStreams(stdin, stdout, stderr)}
	if cmd.TTY {
		options = append(options, cio.WithTerminal)
	}
	execID := fmt.Sprintf("attach-%d", c.execSequence.Add(1))
	processHandle, err := task.Exec(ctx, execID, &process, cio.NewCreator(options...))
	if err != nil {
		return 0, fmt.Errorf("containerd stream exec %s: %w", name, err)
	}
	wait, err := processHandle.Wait(ctx)
	if err != nil {
		_, _ = processHandle.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return 0, fmt.Errorf("containerd stream exec wait %s: %w", name, err)
	}
	if err := processHandle.Start(ctx); err != nil {
		_, _ = processHandle.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
		return 0, fmt.Errorf("containerd stream exec start %s: %w", name, err)
	}
	var status cd.ExitStatus
	exited := false
	if cmd.TTY && rows > 0 && cols > 0 {
		if err := processHandle.Resize(ctx, cols, rows); err != nil {
			// A short command can exit between Start and Resize. Its completed
			// result is authoritative; "cannot resize a stopped container" is
			// not an execution failure.
			select {
			case status = <-wait:
				exited = true
			default:
				_ = processHandle.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
				_, _ = processHandle.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
				return 0, fmt.Errorf("containerd stream exec resize %s: %w", name, err)
			}
		}
	}
	finished := make(chan struct{})
	if stdinEOF != nil {
		go func() {
			select {
			case <-stdinEOF:
				_ = processHandle.CloseIO(context.WithoutCancel(ctx), cd.WithStdinCloser)
			case <-finished:
			}
		}()
	}

	if !exited {
		select {
		case status = <-wait:
		case <-ctx.Done():
			_ = processHandle.Kill(context.WithoutCancel(ctx), syscall.SIGKILL)
			processHandle.IO().Cancel()
			_, _ = processHandle.Delete(context.WithoutCancel(ctx), cd.WithProcessKill)
			close(finished)
			return 0, ctx.Err()
		}
	}
	close(finished)
	waitContainerdIO(processHandle.IO())
	code, _, statusErr := status.Result()
	if _, err := processHandle.Delete(ctx); err != nil && !containerdNotFound(err) {
		return 0, fmt.Errorf("containerd delete streamed exec %s: %w", name, err)
	}
	if statusErr != nil {
		return 0, statusErr
	}
	return int(code), nil
}

func (c *Containerd) execViaInit(ctx context.Context, name string, cmd ExecCmd) (
	ExecResult, bool, error,
) {
	socket := filepath.Join(c.containerRoot(name), "control", "exec.sock")
	if _, err := os.Stat(socket); err != nil {
		return ExecResult{}, false, nil
	}
	var stdin []byte
	if cmd.Stdin != nil {
		content, err := io.ReadAll(cmd.Stdin)
		if err != nil {
			return ExecResult{}, true, err
		}
		stdin = content
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ExecResult{}, false, nil
		}
		return ExecResult{}, true, fmt.Errorf("containerd init exec %s: %w", name, err)
	}
	defer func() { _ = connection.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	request := initproto.Request{
		Command: append([]string(nil), cmd.Cmd...), Env: cloneStringMap(cmd.Env),
		User: cmd.User, WorkDir: cmd.WorkDir, TTY: cmd.TTY, Detach: cmd.Detach,
		Stdin: stdin,
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return ExecResult{}, true, fmt.Errorf("containerd init exec %s: %w", name, err)
	}
	var response initproto.Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return ExecResult{}, true, fmt.Errorf("containerd init exec %s: %w", name, err)
	}
	if response.Error != "" {
		return ExecResult{}, true, fmt.Errorf("containerd init exec %s: %s", name, response.Error)
	}
	result := ExecResult{
		ExitCode: response.ExitCode, Stdout: string(response.Stdout), Stderr: string(response.Stderr),
	}
	if cmd.Detach {
		result.Stdout = strconv.Itoa(response.PID) + "\n"
	}
	return result, true, nil
}

var containerdFRRLifecycleCommand = regexp.MustCompile(
	`(?:^|[;\n])[[:space:]]*/usr/lib/frr/frrinit\.sh[[:space:]]+(start|stop|restart)(?:[[:space:];&]|$)`,
)

func containerdFRRAction(cmd ExecCmd) string {
	if len(cmd.Cmd) != 3 || cmd.Cmd[0] != "sh" || cmd.Cmd[1] != "-c" {
		return ""
	}
	body := cmd.Cmd[2]
	var start, stop, restart bool
	for _, match := range containerdFRRLifecycleCommand.FindAllStringSubmatch(body, -1) {
		switch match[1] {
		case "start":
			start = true
		case "stop":
			stop = true
		case "restart":
			restart = true
		}
	}
	if restart || start && stop {
		return "restart"
	}
	if start && strings.Contains(body, "missing()") {
		return "ensure"
	}
	if start {
		return "start"
	}
	if stop {
		return "stop"
	}
	return ""
}

func (c *Containerd) frrReady(ctx context.Context, name string) (bool, error) {
	_, daemons, err := c.frrConfiguration(ctx, name)
	if err != nil {
		return false, err
	}
	return c.frrSocketsReady(ctx, name, daemons)
}

type frrDaemon struct {
	name    string
	options []string
}

func (c *Containerd) startFRR(ctx context.Context, name string) error {
	var firstErr error
	for attempt := range 2 {
		err := c.startFRRAttempt(ctx, name)
		if err == nil {
			return nil
		}
		if attempt == 1 || ctx.Err() != nil {
			if firstErr != nil {
				return fmt.Errorf("%v; retry failed: %w", firstErr, err)
			}
			return err
		}
		firstErr = err
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return firstErr
}

func (c *Containerd) startFRRAttempt(ctx context.Context, name string) error {
	if err := c.stopFRR(ctx, name); err != nil {
		return err
	}
	profile, daemons, err := c.frrConfiguration(ctx, name)
	if err != nil {
		return err
	}
	if len(daemons) == 0 {
		return nil
	}
	var starter strings.Builder
	starter.WriteString("set -e\n")
	for _, daemon := range daemons {
		args := []string{"/usr/lib/frr/" + daemon.name, "-F", profile}
		args = append(args, daemon.options...)
		args = append(args, "-d")
		for _, arg := range args {
			starter.WriteString(shellQuote(arg))
			starter.WriteByte(' ')
		}
		if daemon.name == "zebra" {
			starter.WriteByte('\n')
		} else {
			starter.WriteString("&\npids=\"$pids $!\"\n")
		}
	}
	starter.WriteString(`set +e
status=0
for pid in $pids; do wait "$pid" || status=1; done
exit "$status"
`)
	logPath := filepath.Join(c.containerRoot(name), "frr-supervisor.log")
	result, err := c.execTaskRaw(ctx, name, ExecCmd{
		Cmd: []string{"/bin/bash", "-c", starter.String()},
	})
	if err != nil {
		_ = c.stopFRR(context.WithoutCancel(ctx), name)
		return fmt.Errorf("start FRR supervisor in %s: %w", name, err)
	}
	_ = os.WriteFile(logPath, []byte(result.Stderr), 0o600)
	if err := result.Err(); err != nil {
		_ = c.stopFRR(context.WithoutCancel(ctx), name)
		_ = os.WriteFile(logPath, []byte(result.Stderr), 0o600)
		return fmt.Errorf("start FRR daemons in %s: %w", name, err)
	}
	for range 600 {
		if ready, readyErr := c.frrSocketsReady(ctx, name, daemons); readyErr == nil && ready {
			return c.applyFRRConfiguration(ctx, name)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	log, _ := os.ReadFile(logPath)
	return fmt.Errorf("FRR daemons did not become ready in %s: %s", name,
		trim(string(log)))
}

func (c *Containerd) applyFRRConfiguration(ctx context.Context, name string) error {
	var lastErr error
	for range 100 {
		result, err := c.execTaskRaw(ctx, name, ExecCmd{Cmd: []string{"vtysh", "-b"}})
		if err == nil {
			err = result.Err()
		}
		if err == nil {
			return nil
		}
		lastErr = err
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("apply integrated FRR configuration in %s: %w", name, lastErr)
}

func (c *Containerd) frrConfiguration(ctx context.Context, name string) (
	string, []frrDaemon, error,
) {
	result, err := c.execTaskRaw(ctx, name, ExecCmd{
		Cmd: []string{"cat", "/etc/frr/daemons"},
	})
	if err != nil {
		return "", nil, err
	}
	if err := result.Err(); err != nil {
		return "", nil, fmt.Errorf("read FRR daemon config for %s: %w", name, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	profile := values["frr_profile"]
	if profile == "" {
		profile = "traditional"
	}
	order := []string{
		"zebra", "mgmtd", "bgpd", "ripd", "ripngd", "ospfd", "ospf6d",
		"isisd", "babeld", "pimd", "pim6d", "ldpd", "nhrpd", "eigrpd",
		"sharpd", "pbrd", "staticd", "bfdd", "fabricd", "vrrpd", "pathd",
	}
	var daemons []frrDaemon
	for _, daemon := range order {
		if values[daemon] != "yes" {
			continue
		}
		daemons = append(daemons, frrDaemon{
			name: daemon, options: strings.Fields(values[daemon+"_options"]),
		})
	}
	return profile, daemons, nil
}

func (c *Containerd) frrSocketsReady(ctx context.Context, name string,
	daemons []frrDaemon,
) (bool, error) {
	var script strings.Builder
	for _, daemon := range daemons {
		script.WriteString("test -S ")
		script.WriteString(shellQuote("/run/frr/" + daemon.name + ".vty"))
		script.WriteString(" || exit 1\n")
	}
	result, err := c.execTaskRaw(ctx, name, ExecCmd{
		Cmd: []string{"sh", "-c", script.String()},
	})
	if err != nil {
		return false, err
	}
	return result.ExitCode == 0, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func (c *Containerd) stopFRR(ctx context.Context, name string) error {
	result, err := c.execTaskRaw(ctx, name, ExecCmd{Cmd: []string{
		"sh", "-c", `
processes="watchfrr zebra mgmtd bgpd ripd ripngd ospfd ospf6d isisd babeld pimd pim6d ldpd nhrpd eigrpd sharpd pbrd staticd bfdd fabricd vrrpd pathd"
pids="$(pidof $processes 2>/dev/null)"
[ -z "$pids" ] || kill -KILL $pids 2>/dev/null || true
rm -f /run/frr/*.pid /run/frr/*.vty /run/frr/*.api /run/frr/*.sock 2>/dev/null || true
`,
	}})
	if err != nil || result.ExitCode != 0 {
		if containerdNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

func waitContainerdIO(stream cio.IO) {
	done := make(chan struct{})
	go func() {
		stream.Wait()
		close(done)
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		stream.Cancel()
		<-done
	}
}

type eofSignallingReader struct {
	reader io.Reader
	done   chan struct{}
	once   sync.Once
}

func (r *eofSignallingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil {
		r.once.Do(func() { close(r.done) })
	}
	return n, err
}

func parseNumericUser(value string) (uint32, uint32, error) {
	uidRaw, gidRaw, hasGroup := strings.Cut(value, ":")
	uid, err := strconv.ParseUint(uidRaw, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: containerd exec requires numeric user, got %q", ErrUnsupported, value)
	}
	gid := uid
	if hasGroup {
		parsed, err := strconv.ParseUint(gidRaw, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: containerd exec requires numeric group, got %q", ErrUnsupported, value)
		}
		gid = parsed
	}
	return uint32(uid), uint32(gid), nil
}

func (c *Containerd) CopyTo(ctx context.Context, name, destination string, mode int64,
	content []byte,
) error {
	if mode == 0 {
		mode = 0o644
	}
	result, err := c.Exec(ctx, name, ExecCmd{
		Cmd: []string{"sh", "-c",
			`path=$1; mode=$2; dir=${path%/*}; [ "$dir" = "$path" ] && dir=.; mkdir -p "$dir" && cat >"$path" && chmod "$mode" "$path"`,
			"twinet-copy", destination, fmt.Sprintf("%o", mode)},
		Stdin: bytes.NewReader(content),
	})
	if err != nil {
		return fmt.Errorf("containerd copy into %s:%s: %w", name, destination, err)
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("containerd copy into %s:%s: %w", name, destination, err)
	}
	return nil
}

func (c *Containerd) CopyFrom(ctx context.Context, name, source string) ([]byte, error) {
	return c.CopyFromFollow(ctx, name, source)
}

func (c *Containerd) CopyFromFollow(ctx context.Context, name, source string) ([]byte, error) {
	result, err := c.Exec(ctx, name, ExecCmd{
		Cmd: []string{"sh", "-c", `cat -- "$1"`, "twinet-copy", source},
	})
	if err != nil {
		return nil, fmt.Errorf("containerd copy from %s:%s: %w", name, source, err)
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("containerd copy from %s:%s: %w", name, source, err)
	}
	return []byte(result.Stdout), nil
}

func (c *Containerd) Subscribe(ctx context.Context, filter EventFilter) EventSubscription {
	client, err := c.clientFor()
	if err != nil {
		return failedEventSubscription(err)
	}
	streamCtx, cancel := context.WithCancel(ctx)
	eventID, ok := c.registerEventStream(cancel)
	if !ok {
		cancel()
		return failedEventSubscription(ErrEventStreamClosed)
	}
	subscription, out, errs := newEventSubscription()
	envelopes, failures := client.Subscribe(streamCtx)
	go func() {
		defer func() {
			cancel()
			c.unregisterEventStream(eventID)
		}()
		for {
			select {
			case <-streamCtx.Done():
				finishEventSubscription(out, errs, streamCtx.Err())
				return
			case err, ok := <-failures:
				if !ok {
					finishEventSubscription(out, errs, ErrEventStreamClosed)
					return
				}
				finishEventSubscription(out, errs, err)
				return
			case envelope, ok := <-envelopes:
				if !ok {
					finishEventSubscription(out, errs, ErrEventStreamClosed)
					return
				}
				event, ok := c.containerdEvent(streamCtx, envelope)
				if !ok || !eventMatches(filter, event) {
					continue
				}
				select {
				case out <- event:
				case <-streamCtx.Done():
					finishEventSubscription(out, errs, streamCtx.Err())
					return
				}
			}
		}
	}()
	return subscription
}

func (c *Containerd) registerEventStream(cancel context.CancelFunc) (uint64, bool) {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if c.eventsClosed {
		return 0, false
	}
	c.nextEventID++
	c.eventCancels[c.nextEventID] = cancel
	return c.nextEventID, true
}

func (c *Containerd) unregisterEventStream(id uint64) {
	c.eventMu.Lock()
	delete(c.eventCancels, id)
	c.eventMu.Unlock()
}

func (c *Containerd) containerdEvent(ctx context.Context, envelope *cevents.Envelope) (Event, bool) {
	value, err := typeurl.UnmarshalAny(envelope.Event)
	if err != nil {
		return Event{}, false
	}
	var id string
	var action EventAction
	switch event := value.(type) {
	case *apievents.ContainerCreate:
		id, action = event.ID, EventCreate
	case *apievents.ContainerDelete:
		id, action = event.ID, EventDestroy
	case *apievents.TaskStart:
		id, action = event.ContainerID, EventStart
	case *apievents.TaskExit:
		if event.ID != "" && event.ID != event.ContainerID {
			if event.ID != "frr-supervisor" {
				return Event{}, false
			}
		}
		id, action = event.ContainerID, EventDie
	case *apievents.TaskOOM:
		id, action = event.ContainerID, EventOOM
	case *apievents.TaskPaused:
		id, action = event.ContainerID, EventStop
	case *apievents.TaskResumed:
		id, action = event.ContainerID, EventStart
	default:
		return Event{}, false
	}
	labels := map[string]string(nil)
	if container, loadErr := c.load(ctx, id); loadErr == nil {
		labels, _ = container.Labels(ctx)
	}
	if len(labels) == 0 {
		c.eventMu.Lock()
		labels = cloneStringMap(c.eventLabels[id])
		c.eventMu.Unlock()
	}
	if action == EventDestroy {
		c.eventMu.Lock()
		delete(c.eventLabels, id)
		c.eventMu.Unlock()
	}
	return Event{
		Container: id, Name: id, Action: action,
		Labels: labels, At: envelope.Timestamp,
	}, true
}

func (c *Containerd) rememberEventLabels(id string, labels map[string]string) {
	c.eventMu.Lock()
	if c.eventLabels == nil {
		c.eventLabels = map[string]map[string]string{}
	}
	c.eventLabels[id] = cloneStringMap(labels)
	c.eventMu.Unlock()
}
