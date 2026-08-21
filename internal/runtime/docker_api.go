package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	mobyclient "github.com/moby/moby/client"
)

const (
	listInspectWorkers = 16
	maxFollowLinks     = 40
)

type dockerAPI struct {
	client *mobyclient.Client
}

func newDockerAPI() (*dockerAPI, error) {
	// The Moby client negotiates its API version on the first request unless
	// DOCKER_API_VERSION explicitly pins one.
	client, err := mobyclient.New(mobyclient.FromEnv)
	if err != nil {
		return nil, err
	}
	return &dockerAPI{client: client}, nil
}

func (d *dockerAPI) Close() error {
	return d.client.Close()
}

func (d *dockerAPI) Ping(ctx context.Context) (string, error) {
	version, err := d.client.ServerVersion(ctx, mobyclient.ServerVersionOptions{})
	if err != nil {
		return "", fmt.Errorf("docker engine ping: %w", err)
	}
	return version.Version, nil
}

func (d *dockerAPI) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := d.client.ImageInspect(ctx, ref)
	return err == nil, nil
}

func (d *dockerAPI) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
	switch policy {
	case PullNever:
		return nil
	case PullIfMissing, "":
		ok, _ := d.ImageExists(ctx, ref)
		if ok {
			return nil
		}
	case PullAlways:
	default:
		return fmt.Errorf("unknown pull policy %q; use %q, %q or %q",
			policy, PullIfMissing, PullAlways, PullNever)
	}

	stream, err := d.client.ImagePull(ctx, ref, mobyclient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	defer stream.Close()
	if err := stream.Wait(ctx); err != nil {
		return fmt.Errorf("docker pull %s: %w", ref, err)
	}
	return nil
}

func (d *dockerAPI) Create(ctx context.Context, spec *Spec) (string, error) {
	config, hostConfig, err := dockerCreateConfig(spec)
	if err != nil {
		return "", err
	}
	created, err := d.client.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Config:     config,
		HostConfig: hostConfig,
		Name:       spec.Name,
	})
	if err != nil {
		return "", fmt.Errorf("docker create %s: %w", spec.Name, err)
	}
	return created.ID, nil
}

func dockerCreateConfig(spec *Spec) (*container.Config, *container.HostConfig, error) {
	if spec == nil {
		return nil, nil, fmt.Errorf("container spec is nil")
	}

	networkMode := spec.NetworkMode
	if networkMode == "" {
		networkMode = "none"
	}
	config := &container.Config{
		Hostname:   spec.Hostname,
		Image:      spec.Image,
		Env:        sortedEnv(spec.Env),
		Labels:     nonEmptyStringMap(spec.Labels),
		StopSignal: spec.StopSignal,
	}
	hostConfig := &container.HostConfig{
		Binds:          bindStrings(spec.Binds),
		NetworkMode:    container.NetworkMode(networkMode),
		CapAdd:         append([]string(nil), spec.Capabilities...),
		CapDrop:        cloneStrings(spec.CapDrop),
		SecurityOpt:    cloneStrings(spec.SecurityOpt),
		ReadonlyRootfs: spec.ReadOnlyRootfs,
		Runtime:        spec.RuntimeClass,
		UsernsMode:     container.UsernsMode(spec.UsernsMode),
		MaskedPaths:    cloneStrings(spec.MaskedPaths),
		ReadonlyPaths:  cloneStrings(spec.ReadonlyPaths),
		Privileged:     spec.Privileged,
		Tmpfs:          nonEmptyStringMap(spec.Tmpfs),
		Sysctls:        nonEmptyStringMap(spec.Sysctls),
		DNSSearch:      append([]string(nil), spec.DNSSearch...),
		ExtraHosts:     append([]string(nil), spec.ExtraHosts...),
	}

	if len(spec.Entrypoint) > 0 {
		config.Entrypoint = []string{spec.Entrypoint[0]}
		config.Cmd = append(append([]string(nil), spec.Entrypoint[1:]...), spec.Command...)
	} else {
		config.Cmd = append([]string(nil), spec.Command...)
	}
	if spec.StopTimeout != nil {
		timeout := *spec.StopTimeout
		config.StopTimeout = &timeout
	}
	if spec.Health != nil {
		config.Healthcheck = &container.HealthConfig{
			Test:        []string{"CMD-SHELL", strings.Join(spec.Health.Test, " ")},
			Interval:    spec.Health.Interval,
			Timeout:     spec.Health.Timeout,
			Retries:     spec.Health.Retries,
			StartPeriod: spec.Health.StartPeriod,
		}
	}
	if spec.CPUs > 0 {
		if spec.CPUs > math.MaxInt64/1e9 {
			return nil, nil, fmt.Errorf("container %s: CPUs %v exceed Docker's limit", spec.Name, spec.CPUs)
		}
		hostConfig.NanoCPUs = int64(math.Round(spec.CPUs * 1e9))
	}
	if spec.Memory != "" {
		memory, err := ParseMemory(spec.Memory)
		if err != nil {
			return nil, nil, fmt.Errorf("container %s: memory: %w", spec.Name, err)
		}
		hostConfig.Memory = memory
	}
	if spec.PidsLimit > 0 {
		limit := spec.PidsLimit
		hostConfig.PidsLimit = &limit
	}
	if spec.Restart != "" {
		policy, err := dockerRestartPolicy(spec.Restart)
		if err != nil {
			return nil, nil, fmt.Errorf("container %s: restart: %w", spec.Name, err)
		}
		hostConfig.RestartPolicy = policy
	}
	if spec.Init {
		init := true
		hostConfig.Init = &init
	}

	dns, err := dockerDNS(spec.DNS)
	if err != nil {
		return nil, nil, fmt.Errorf("container %s: DNS: %w", spec.Name, err)
	}
	hostConfig.DNS = dns

	ports, bindings, err := dockerPorts(spec.Ports)
	if err != nil {
		return nil, nil, fmt.Errorf("container %s: ports: %w", spec.Name, err)
	}
	if len(ports) > 0 {
		config.ExposedPorts = ports
		hostConfig.PortBindings = bindings
	}
	return config, hostConfig, nil
}

func sortedEnv(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := sortedKeys(values)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+values[key])
	}
	return out
}

func nonEmptyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	return values
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append(values[:0:0], values...)
}

func bindStrings(binds []Bind) []string {
	if len(binds) == 0 {
		return nil
	}
	out := make([]string, 0, len(binds))
	for _, bind := range binds {
		out = append(out, bind.String())
	}
	return out
}

func dockerDNS(values []string) ([]netip.Addr, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address: %w", value, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func dockerPorts(values []PortMap) (network.PortSet, network.PortMap, error) {
	if len(values) == 0 {
		return nil, nil, nil
	}
	ports := make(network.PortSet, len(values))
	bindings := make(network.PortMap, len(values))
	for _, value := range values {
		protocol := value.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		port, err := network.ParsePort(strconv.Itoa(value.Container) + "/" + protocol)
		if err != nil {
			return nil, nil, err
		}
		hostIP := netip.Addr{}
		if value.HostIP != "" {
			hostIP, err = netip.ParseAddr(value.HostIP)
			if err != nil {
				return nil, nil, fmt.Errorf("host IP %q: %w", value.HostIP, err)
			}
		}
		ports[port] = struct{}{}
		bindings[port] = append(bindings[port], network.PortBinding{
			HostIP:   hostIP,
			HostPort: strconv.Itoa(value.HostPort),
		})
	}
	return ports, bindings, nil
}

func dockerRestartPolicy(value string) (container.RestartPolicy, error) {
	name, retries, hasRetries := strings.Cut(value, ":")
	policy := container.RestartPolicy{Name: container.RestartPolicyMode(name)}
	if !hasRetries {
		return policy, nil
	}
	count, err := strconv.Atoi(retries)
	if err != nil {
		return container.RestartPolicy{}, fmt.Errorf("parse retry count %q: %w", retries, err)
	}
	policy.MaximumRetryCount = count
	return policy, nil
}

func (d *dockerAPI) Start(ctx context.Context, name string) error {
	_, err := d.client.ContainerStart(ctx, name, mobyclient.ContainerStartOptions{})
	if err != nil {
		return fmt.Errorf("docker start %s: %w", name, err)
	}
	return nil
}

func (d *dockerAPI) ImageDigest(ctx context.Context, ref string) (string, error) {
	image, err := d.client.ImageInspect(ctx, ref)
	if err != nil {
		return "", err
	}
	if len(image.RepoDigests) > 0 {
		return image.RepoDigests[0], nil
	}
	return image.ID, nil
}

func (d *dockerAPI) Pause(ctx context.Context, name string) error {
	_, err := d.client.ContainerPause(ctx, name, mobyclient.ContainerPauseOptions{})
	if err != nil {
		return fmt.Errorf("docker pause %s: %w", name, err)
	}
	return nil
}

func (d *dockerAPI) Unpause(ctx context.Context, name string) error {
	_, err := d.client.ContainerUnpause(ctx, name, mobyclient.ContainerUnpauseOptions{})
	if err != nil {
		return fmt.Errorf("docker unpause %s: %w", name, err)
	}
	return nil
}

func (d *dockerAPI) Stop(ctx context.Context, name string, timeout time.Duration) error {
	seconds := int(timeout.Seconds())
	if seconds <= 0 {
		seconds = 10
	}
	_, err := d.client.ContainerStop(ctx, name, mobyclient.ContainerStopOptions{Timeout: &seconds})
	if err != nil {
		return fmt.Errorf("docker stop %s: %w", name, err)
	}
	return nil
}

func (d *dockerAPI) Remove(ctx context.Context, name string, force bool) error {
	_, err := d.client.ContainerRemove(ctx, name, mobyclient.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         force,
	})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("docker rm %s: %w", name, err)
	}
	return nil
}

func (d *dockerAPI) Inspect(ctx context.Context, name string) (Container, error) {
	inspected, err := d.client.ContainerInspect(ctx, name, mobyclient.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return Container{Name: name, State: StateAbsent}, nil
	}
	if err != nil {
		return Container{}, fmt.Errorf("docker inspect %s: %w", name, err)
	}
	return fromAPIInspect(inspected.Container), nil
}

func fromAPIInspect(inspected container.InspectResponse) Container {
	out := Container{
		ID:      inspected.ID,
		Name:    strings.TrimPrefix(inspected.Name, "/"),
		ImageID: inspected.Image,
	}
	if inspected.Config != nil {
		out.Image = inspected.Config.Image
		out.Labels = inspected.Config.Labels
	}
	if inspected.State != nil {
		out.Status = string(inspected.State.Status)
		out.State = normaliseState(out.Status)
		out.PID = inspected.State.Pid
		if inspected.State.Health != nil {
			out.Health = string(inspected.State.Health.Status)
		}
	}
	return out
}

func (d *dockerAPI) List(ctx context.Context, filter Filter) ([]Container, error) {
	filters := make(mobyclient.Filters)
	for _, key := range sortedKeys(filter.Labels) {
		value := filter.Labels[key]
		if value == "" {
			filters.Add("label", key)
		} else {
			filters.Add("label", key+"="+value)
		}
	}
	listed, err := d.client.ContainerList(ctx, mobyclient.ContainerListOptions{
		All:     filter.All,
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	if len(listed.Items) == 0 {
		return nil, nil
	}

	// Docker's list response does not include the live PID. Keep List's
	// complete Container result while issuing the resulting inspect batch with
	// bounded concurrency instead of serially creating one process per item.
	containers := make([]Container, len(listed.Items))
	batchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int, len(listed.Items))
	for i := range listed.Items {
		jobs <- i
	}
	close(jobs)

	workers := min(listInspectWorkers, len(listed.Items))
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-batchCtx.Done():
					return
				case i, ok := <-jobs:
					if !ok {
						return
					}
					inspected, err := d.client.ContainerInspect(batchCtx, listed.Items[i].ID, mobyclient.ContainerInspectOptions{})
					if err != nil {
						fail(fmt.Errorf("docker inspect %s: %w", listed.Items[i].ID, err))
						return
					}
					containers[i] = fromAPIInspect(inspected.Container)
				}
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	SortContainers(containers)
	return containers, nil
}

func (d *dockerAPI) NSPath(ctx context.Context, name string) (string, error) {
	container, err := d.Inspect(ctx, name)
	if err != nil {
		return "", err
	}
	if !container.State.Joinable() {
		return "", fmt.Errorf("container %s is %s, so it has no joinable network namespace", name, container.State)
	}
	if container.PID <= 0 {
		return "", fmt.Errorf("container %s reports PID %d", name, container.PID)
	}
	return fmt.Sprintf("/proc/%d/ns/net", container.PID), nil
}

func (d *dockerAPI) Exec(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
	created, err := d.client.ExecCreate(ctx, name, mobyclient.ExecCreateOptions{
		User:         cmd.User,
		TTY:          cmd.TTY,
		AttachStdin:  cmd.Stdin != nil,
		AttachStdout: !cmd.Detach,
		AttachStderr: !cmd.Detach,
		Env:          sortedEnv(cmd.Env),
		WorkingDir:   cmd.WorkDir,
		Cmd:          append([]string(nil), cmd.Cmd...),
	})
	if err != nil {
		return ExecResult{}, fmt.Errorf("docker exec %s: %w", name, err)
	}
	if cmd.Detach {
		if _, err := d.client.ExecStart(ctx, created.ID, mobyclient.ExecStartOptions{Detach: true, TTY: cmd.TTY}); err != nil {
			return ExecResult{}, fmt.Errorf("docker exec %s: %w", name, err)
		}
		return ExecResult{Stdout: created.ID + "\n"}, nil
	}

	attached, err := d.client.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: cmd.TTY})
	if err != nil {
		return ExecResult{}, fmt.Errorf("docker exec %s: %w", name, err)
	}
	defer attached.Close()

	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			attached.Close()
		case <-finished:
		}
	}()

	var stdinDone <-chan error
	if cmd.Stdin != nil {
		done := make(chan error, 1)
		stdinDone = done
		go func() {
			_, err := io.Copy(attached.Conn, cmd.Stdin)
			if closeErr := attached.CloseWrite(); err == nil {
				err = closeErr
			}
			done <- err
		}()
	}

	var stdout, stderr bytes.Buffer
	if cmd.TTY {
		_, err = io.Copy(&stdout, attached.Reader)
	} else {
		_, err = stdcopy.StdCopy(&stdout, &stderr, attached.Reader)
	}
	result := ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("docker exec %s: read output: %w", name, err)
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if stdinDone != nil {
		select {
		case err := <-stdinDone:
			if err != nil {
				return result, fmt.Errorf("docker exec %s: write stdin: %w", name, err)
			}
		default:
		}
	}

	inspected, err := d.client.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
	if err != nil {
		return result, fmt.Errorf("docker exec %s: inspect: %w", name, err)
	}
	result.ExitCode = inspected.ExitCode
	return result, nil
}

func (d *dockerAPI) CopyTo(ctx context.Context, name, dst string, mode int64, content []byte) error {
	if mode == 0 {
		mode = 0o644
	}
	dir, base := splitPath(dst)

	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{
		Name:    base,
		Mode:    mode,
		Size:    int64(len(content)),
		ModTime: time.Unix(0, 0),
	}); err != nil {
		return fmt.Errorf("build archive for %s: %w", dst, err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("write archive for %s: %w", dst, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close archive for %s: %w", dst, err)
	}

	_, err := d.client.CopyToContainer(ctx, name, mobyclient.CopyToContainerOptions{
		DestinationPath: dir,
		Content:         bytes.NewReader(archive.Bytes()),
	})
	if err != nil {
		return fmt.Errorf("docker cp into %s:%s: %w", name, dir, err)
	}
	return nil
}

func (d *dockerAPI) CopyFrom(ctx context.Context, name, src string) ([]byte, error) {
	return d.copyFrom(ctx, name, src, false)
}

func (d *dockerAPI) CopyFromFollow(ctx context.Context, name, src string) ([]byte, error) {
	return d.copyFrom(ctx, name, src, true)
}

func (d *dockerAPI) copyFrom(ctx context.Context, name, src string, follow bool) ([]byte, error) {
	if follow {
		var err error
		src, err = d.resolveFinalLink(ctx, name, src)
		if err != nil {
			return nil, err
		}
	}
	archive, err := d.client.CopyFromContainer(ctx, name, mobyclient.CopyFromContainerOptions{SourcePath: src})
	if err != nil {
		return nil, fmt.Errorf("docker cp from %s:%s: %w", name, src, err)
	}
	defer drainAndClose(archive.Content)

	reader := tar.NewReader(archive.Content)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s:%s not found in the copied archive", name, src)
		}
		if err != nil {
			return nil, fmt.Errorf("read archive from %s:%s: %w", name, src, err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("read archive from %s:%s: %w", name, src, err)
		}
		return content, nil
	}
}

func (d *dockerAPI) resolveFinalLink(ctx context.Context, name, src string) (string, error) {
	seen := make(map[string]struct{}, maxFollowLinks)
	for range maxFollowLinks {
		if _, ok := seen[src]; ok {
			return "", fmt.Errorf("docker cp from %s:%s: symbolic link cycle", name, src)
		}
		seen[src] = struct{}{}

		stat, err := d.client.ContainerStatPath(ctx, name, mobyclient.ContainerStatPathOptions{Path: src})
		if err != nil {
			return "", fmt.Errorf("docker cp from %s:%s: %w", name, src, err)
		}
		if stat.Stat.LinkTarget == "" {
			return src, nil
		}
		if strings.HasPrefix(stat.Stat.LinkTarget, "/") {
			src = path.Clean(stat.Stat.LinkTarget)
		} else {
			src = path.Clean(path.Join(path.Dir(src), stat.Stat.LinkTarget))
		}
	}
	return "", fmt.Errorf("docker cp from %s:%s: too many symbolic links", name, src)
}

func drainAndClose(stream io.ReadCloser) {
	_, _ = io.Copy(io.Discard, stream)
	_ = stream.Close()
}
