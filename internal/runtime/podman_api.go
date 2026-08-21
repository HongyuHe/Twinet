package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

// Podman's documented Docker compatibility layer targets Docker API v1.40.
// Pinning this version avoids Docker SDK negotiation rejecting Podman's older
// compatibility version before it can make a request.
const podmanCompatAPIVersion = "1.40"

type podmanAPI struct {
	*dockerAPI
	host string
}

var _ engineBackend = (*podmanAPI)(nil)

func newPodmanAPI(host string) (*podmanAPI, error) {
	client, err := mobyclient.New(
		mobyclient.WithHost(host),
		mobyclient.WithAPIVersion(podmanCompatAPIVersion),
	)
	if err != nil {
		return nil, err
	}
	return &podmanAPI{
		dockerAPI: &dockerAPI{
			client:       client,
			engine:       "podman",
			eventCancels: make(map[uint64]context.CancelFunc),
		},
		host: host,
	}, nil
}

func (p *podmanAPI) Ping(ctx context.Context) (string, error) {
	version, err := p.client.ServerVersion(ctx, mobyclient.ServerVersionOptions{})
	if err != nil {
		return "", fmt.Errorf("podman API ping: %w", err)
	}
	return version.Version, nil
}

func (p *podmanAPI) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
	switch policy {
	case PullNever:
		return nil
	case PullIfMissing, "":
		ok, _ := p.ImageExists(ctx, ref)
		if ok {
			return nil
		}
	case PullAlways:
	default:
		return fmt.Errorf("unknown pull policy %q; use %q, %q or %q",
			policy, PullIfMissing, PullAlways, PullNever)
	}

	stream, err := p.client.ImagePull(ctx, ref, mobyclient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("podman pull %s: %w", ref, err)
	}
	defer stream.Close()
	if err := stream.Wait(ctx); err != nil {
		return fmt.Errorf("podman pull %s: %w", ref, err)
	}
	return nil
}

func (p *podmanAPI) ImageDigest(ctx context.Context, ref string) (string, error) {
	var raw bytes.Buffer
	image, err := p.client.ImageInspect(ctx, ref, mobyclient.ImageInspectWithRawResponse(&raw))
	if err != nil {
		return "", err
	}
	if len(image.RepoDigests) > 0 {
		return image.RepoDigests[0], nil
	}
	// Podman's inspect responses can expose a manifest digest as Digest rather
	// than Docker's RepoDigests array. Preserve it when the compatibility
	// response provides it instead of falling back to the config image ID.
	var podmanImage struct {
		Digest string `json:"Digest"`
	}
	if err := json.Unmarshal(raw.Bytes(), &podmanImage); err == nil && podmanImage.Digest != "" {
		return podmanImage.Digest, nil
	}
	return image.ID, nil
}

func (p *podmanAPI) Create(ctx context.Context, spec *Spec) (string, error) {
	if err := validatePodmanSpec(spec); err != nil {
		return "", err
	}
	config, hostConfig, err := dockerCreateConfig(spec)
	if err != nil {
		return "", err
	}
	created, err := p.client.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Config:     config,
		HostConfig: hostConfig,
		Name:       spec.Name,
	})
	if err != nil {
		return "", fmt.Errorf("podman create %s: %w", spec.Name, err)
	}
	return created.ID, nil
}

func validatePodmanSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("container spec is nil")
	}
	// Podman 4.9's Docker-compatible create API accepts the OCI system-path
	// lists. Keep them on the common Spec rather than dropping hardening for a
	// second backend; a backend that silently weakens /proc or /sys protection
	// is not a Twinet substrate.
	return nil
}

func (p *podmanAPI) Inspect(ctx context.Context, name string) (Container, error) {
	inspected, err := p.client.ContainerInspect(ctx, name, mobyclient.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return Container{Name: name, State: StateAbsent}, nil
	}
	if err != nil {
		return Container{}, fmt.Errorf("podman inspect %s: %w", name, err)
	}
	out, err := fromPodmanInspect(inspected.Container)
	if err != nil {
		return Container{}, fmt.Errorf("podman inspect %s: %w", name, err)
	}
	return out, nil
}

func fromPodmanInspect(inspected container.InspectResponse) (Container, error) {
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
		state, ok := normalisePodmanState(out.Status)
		if !ok {
			return Container{}, podmanUnsupported("container state " + fmt.Sprintf("%q", out.Status))
		}
		out.State = state
		out.PID = inspected.State.Pid
		if inspected.State.Health != nil {
			out.Health = string(inspected.State.Health.Status)
		}
	}
	return out, nil
}

func normalisePodmanState(state string) (State, bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "configured", "created", "initialized":
		return StateCreated, true
	case "running":
		return StateRunning, true
	case "paused":
		return StatePaused, true
	case "restarting":
		return StateRestarting, true
	case "stopping", "stopped", "exited":
		return StateExited, true
	case "dead", "unknown", "invalid":
		return StateDead, true
	case "removing":
		return StateAbsent, true
	}
	return StateAbsent, false
}

func (p *podmanAPI) List(ctx context.Context, filter Filter) ([]Container, error) {
	filters := make(mobyclient.Filters)
	for _, key := range sortedKeys(filter.Labels) {
		value := filter.Labels[key]
		if value == "" {
			filters.Add("label", key)
		} else {
			filters.Add("label", key+"="+value)
		}
	}
	listed, err := p.client.ContainerList(ctx, mobyclient.ContainerListOptions{
		All:     filter.All,
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("podman ps: %w", err)
	}
	if len(listed.Items) == 0 {
		return nil, nil
	}

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
					inspected, err := p.client.ContainerInspect(batchCtx, listed.Items[i].ID, mobyclient.ContainerInspectOptions{})
					if err != nil {
						fail(fmt.Errorf("podman inspect %s: %w", listed.Items[i].ID, err))
						return
					}
					container, err := fromPodmanInspect(inspected.Container)
					if err != nil {
						fail(fmt.Errorf("podman inspect %s: %w", listed.Items[i].ID, err))
						return
					}
					containers[i] = container
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

func (p *podmanAPI) NSPath(ctx context.Context, name string) (string, error) {
	container, err := p.Inspect(ctx, name)
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

func (p *podmanAPI) CopyFromFollow(ctx context.Context, name, src string) ([]byte, error) {
	content, err := p.dockerAPI.CopyFromFollow(ctx, name, src)
	if err != nil && strings.Contains(err.Error(), "symbolic link cycle") {
		// Podman 4.9's Docker-compat stat endpoint reports LinkTarget equal
		// to the path itself for some regular BusyBox hardlinks. Its archive
		// endpoint already follows that link and returns the regular file, so
		// retrying without client-side link walking is both safe and faithful.
		content, err = p.dockerAPI.copyFrom(ctx, name, src, false)
	}
	if err != nil && cerrdefs.IsNotImplemented(err) {
		return nil, fmt.Errorf("%w: Podman archive API does not expose symlink metadata: %w", ErrUnsupported, err)
	}
	return content, err
}

func podmanUnsupported(feature string) error {
	return fmt.Errorf("%w: Podman Docker-compatible API does not support %s", ErrUnsupported, feature)
}
