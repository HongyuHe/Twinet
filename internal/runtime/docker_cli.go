package runtime

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dockerCLI is the explicit compatibility backend for Docker installations
// where the Engine API cannot be used.
type dockerCLI struct {
	bin string

	eventMu      sync.Mutex
	eventCancels map[uint64]context.CancelFunc
	nextEventID  uint64
	eventsClosed bool
}

// Close stops active event streams.
func (d *dockerCLI) Close() error {
	d.eventMu.Lock()
	d.eventsClosed = true
	cancels := make([]context.CancelFunc, 0, len(d.eventCancels))
	for _, cancel := range d.eventCancels {
		cancels = append(cancels, cancel)
	}
	d.eventCancels = make(map[uint64]context.CancelFunc)
	d.eventMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return nil
}

func (d *dockerCLI) run(ctx context.Context, stdin io.Reader, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, d.bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.Stdin = stdin
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func (d *dockerCLI) mustRun(ctx context.Context, args ...string) (string, error) {
	out, errs, err := d.run(ctx, nil, args...)
	if err != nil {
		return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errs))
	}
	return out, nil
}

// Ping verifies the daemon is reachable.
func (d *dockerCLI) Ping(ctx context.Context) (string, error) {
	out, err := d.mustRun(ctx, "version", "--format", "{{.Server.Version}}")
	return strings.TrimSpace(out), err
}

func (d *dockerCLI) Subscribe(ctx context.Context, filter EventFilter) EventSubscription {
	filter = cloneEventFilter(filter)
	streamCtx, cancel := context.WithCancel(ctx)
	eventID, ok := d.registerEventStream(cancel)
	if !ok {
		cancel()
		return failedEventSubscription(ErrEventStreamClosed)
	}
	subscription, out, errs := newEventSubscription()
	go func() {
		terminal := ErrEventStreamClosed
		terminalSet := false
		defer func() {
			cancel()
			d.unregisterEventStream(eventID)
			finishEventSubscription(out, errs, terminal)
		}()

		cmd := exec.CommandContext(streamCtx, d.bin, dockerCLIEventArgs(filter)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			terminal = fmt.Errorf("docker events stdout: %w", err)
			return
		}
		if err := cmd.Start(); err != nil {
			terminal = fmt.Errorf("docker events: %w", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
	scan:
		for scanner.Scan() {
			var message dockerCLIEventMessage
			if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
				terminal = fmt.Errorf("parse docker event: %w", err)
				terminalSet = true
				cancel()
				break
			}
			if message.Type != "" && message.Type != "container" {
				continue
			}
			action := message.Action
			if action == "" {
				action = message.Status
			}
			containerID := message.Actor.ID
			if containerID == "" {
				containerID = message.ID
			}
			event, ok := normalizeContainerEvent(
				containerID,
				message.Actor.Attributes["name"],
				action,
				message.Actor.Attributes,
				message.Time,
				message.TimeNano,
			)
			if !ok || !eventMatches(filter, event) {
				continue
			}
			select {
			case out <- event:
			case <-streamCtx.Done():
				terminal = streamCtx.Err()
				terminalSet = true
				break scan
			}
		}

		scanErr := scanner.Err()
		if scanErr != nil && !terminalSet {
			cancel()
		}
		waitErr := cmd.Wait()
		if terminalSet {
			return
		}
		switch {
		case streamCtx.Err() != nil:
			terminal = streamCtx.Err()
		case scanErr != nil:
			terminal = fmt.Errorf("read docker events: %w", scanErr)
		case waitErr != nil:
			terminal = fmt.Errorf("docker events: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
		default:
			terminal = io.EOF
		}
	}()
	return subscription
}

func (d *dockerCLI) registerEventStream(cancel context.CancelFunc) (uint64, bool) {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	if d.eventsClosed {
		return 0, false
	}
	if d.eventCancels == nil {
		d.eventCancels = make(map[uint64]context.CancelFunc)
	}
	d.nextEventID++
	eventID := d.nextEventID
	d.eventCancels[eventID] = cancel
	return eventID, true
}

func (d *dockerCLI) unregisterEventStream(eventID uint64) {
	d.eventMu.Lock()
	delete(d.eventCancels, eventID)
	d.eventMu.Unlock()
}

func dockerCLIEventArgs(filter EventFilter) []string {
	args := []string{"events", "--format", "{{json .}}", "--filter", "type=container"}
	for _, key := range sortedKeys(filter.Labels) {
		value := filter.Labels[key]
		if value == "" {
			args = append(args, "--filter", "label="+key)
		} else {
			args = append(args, "--filter", "label="+key+"="+value)
		}
	}
	return args
}

type dockerCLIEventMessage struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Status string `json:"status"`
	ID     string `json:"id"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

// ImageExists reports whether an image is present locally.
func (d *dockerCLI) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, _, err := d.run(ctx, nil, "image", "inspect", ref)
	return err == nil, nil
}

// PullImage fetches an image according to the policy.
//
// An unrecognised policy is an error rather than a fallback to pulling. A typo
// that silently means "always" turns a lab built from local images into one
// that contacts a registry, and the failure surfaces far from its cause: as a
// pull denied for an image that is sitting on the machine already.
func (d *dockerCLI) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
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
	_, err := d.mustRun(ctx, "pull", "--quiet", ref)
	return err
}

// Create makes a container without starting it.
func (d *dockerCLI) Create(ctx context.Context, s *Spec) (string, error) {
	args, err := dockerCLICreateArgs(s)
	if err != nil {
		return "", err
	}
	out, err := d.mustRun(ctx, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func dockerCLICreateArgs(s *Spec) ([]string, error) {
	if s == nil {
		return nil, fmt.Errorf("container spec is nil")
	}
	pidMode, err := NormalizePIDMode(s.PidMode)
	if err != nil {
		return nil, fmt.Errorf("container %s: %w", s.Name, err)
	}
	args := []string{"create", "--name", s.Name}

	if s.Hostname != "" {
		args = append(args, "--hostname", s.Hostname)
	}
	// Every Twinet device starts with no network. Interfaces are attached by
	// netx from the model, so the engine's own IPAM never invents addresses
	// that the topology does not know about.
	nm := s.NetworkMode
	if nm == "" {
		nm = "none"
	}
	args = append(args, "--network", nm)

	for _, k := range sortedKeys(s.Env) {
		args = append(args, "--env", k+"="+s.Env[k])
	}
	for _, k := range sortedKeys(s.Labels) {
		args = append(args, "--label", k+"="+s.Labels[k])
	}
	for _, k := range sortedKeys(s.Sysctls) {
		args = append(args, "--sysctl", k+"="+s.Sysctls[k])
	}
	for _, b := range s.Binds {
		args = append(args, "--volume", b.String())
	}
	for _, c := range s.Capabilities {
		args = append(args, "--cap-add", c)
	}
	for _, c := range s.CapDrop {
		args = append(args, "--cap-drop", c)
	}
	for path, opts := range s.Tmpfs {
		if opts == "" {
			args = append(args, "--tmpfs", path)
		} else {
			args = append(args, "--tmpfs", path+":"+opts)
		}
	}
	if s.Privileged {
		args = append(args, "--privileged")
	}
	for _, opt := range dockerSecurityOptions(s.SecurityOpt) {
		args = append(args, "--security-opt", opt)
	}
	pathHardening, err := dockerCLIPathHardeningArgs(s)
	if err != nil {
		return nil, err
	}
	args = append(args, pathHardening...)
	if s.ReadOnlyRootfs {
		args = append(args, "--read-only")
	}
	if s.RuntimeClass != "" {
		args = append(args, "--runtime", s.RuntimeClass)
	}
	if s.UsernsMode != "" {
		args = append(args, "--userns", s.UsernsMode)
	}
	if pidMode != "" {
		args = append(args, "--pid", pidMode)
	}
	if s.CPUs > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(s.CPUs, 'f', -1, 64))
	}
	if s.Memory != "" {
		b, err := ParseMemory(s.Memory)
		if err != nil {
			return nil, fmt.Errorf("container %s: memory: %w", s.Name, err)
		}
		args = append(args, "--memory", FormatMemory(b))
	}
	if s.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.FormatInt(s.PidsLimit, 10))
	}
	if s.Restart != "" {
		args = append(args, "--restart", s.Restart)
	}
	for _, ns := range s.DNS {
		args = append(args, "--dns", ns)
	}
	for _, sd := range s.DNSSearch {
		args = append(args, "--dns-search", sd)
	}
	for _, h := range s.ExtraHosts {
		args = append(args, "--add-host", h)
	}
	for _, p := range s.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		spec := fmt.Sprintf("%d:%d/%s", p.HostPort, p.Container, proto)
		if p.HostIP != "" {
			spec = p.HostIP + ":" + spec
		}
		args = append(args, "--publish", spec)
	}
	if s.StopSignal != "" {
		args = append(args, "--stop-signal", s.StopSignal)
	}
	if s.StopTimeout != nil {
		args = append(args, "--stop-timeout", strconv.Itoa(*s.StopTimeout))
	}
	if s.Init {
		args = append(args, "--init")
	}
	if h := s.Health; h != nil {
		args = append(args, "--health-cmd", strings.Join(h.Test, " "))
		if h.Interval > 0 {
			args = append(args, "--health-interval", h.Interval.String())
		}
		if h.Timeout > 0 {
			args = append(args, "--health-timeout", h.Timeout.String())
		}
		if h.Retries > 0 {
			args = append(args, "--health-retries", strconv.Itoa(h.Retries))
		}
		if h.StartPeriod > 0 {
			args = append(args, "--health-start-period", h.StartPeriod.String())
		}
	}
	if len(s.Entrypoint) > 0 {
		args = append(args, "--entrypoint", s.Entrypoint[0])
	}

	args = append(args, s.Image)
	if len(s.Entrypoint) > 1 {
		args = append(args, s.Entrypoint[1:]...)
	}
	args = append(args, s.Command...)

	return args, nil
}

func dockerCLIPathHardeningArgs(s *Spec) ([]string, error) {
	if s.MaskedPaths == nil && s.ReadonlyPaths == nil {
		return nil, nil
	}
	if s.MaskedPaths != nil && s.ReadonlyPaths != nil &&
		len(s.MaskedPaths) == 0 && len(s.ReadonlyPaths) == 0 {
		for _, opt := range s.SecurityOpt {
			if opt == "systempaths=unconfined" {
				return nil, nil
			}
		}
		return []string{"--security-opt", "systempaths=unconfined"}, nil
	}
	return nil, fmt.Errorf("Docker CLI fallback cannot represent MaskedPaths or ReadonlyPaths; use the Engine API backend")
}

// Start starts a created container.
func (d *dockerCLI) Start(ctx context.Context, name string) error {
	_, err := d.mustRun(ctx, "start", name)
	return err
}

// Stop stops a running container.
// ImageDigest resolves an image reference to the digest actually in use.
//
// A tag is not an identity. The same tag rebuilt later is different software,
// and a grade produced against it cannot be compared with an earlier one. The
// digest is what makes a regrade reproducible and a dispute answerable.
func (d *dockerCLI) ImageDigest(ctx context.Context, ref string) (string, error) {
	out, _, err := d.run(ctx, nil, "image", "inspect", ref,
		"--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Pause freezes every process in a container without stopping it.
//
// This is what a crashed machine looks like from the network: the interfaces
// are still up and the addresses still assigned, but nothing answers, not even
// ARP. Taking the interfaces down instead produces a different and much easier
// puzzle, because the neighbours see the link go away.
func (d *dockerCLI) Pause(ctx context.Context, name string) error {
	_, err := d.mustRun(ctx, "pause", name)
	return err
}

// Unpause resumes a paused container.
func (d *dockerCLI) Unpause(ctx context.Context, name string) error {
	_, err := d.mustRun(ctx, "unpause", name)
	return err
}

func (d *dockerCLI) Stop(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout.Seconds())
	if secs <= 0 {
		secs = 10
	}
	_, err := d.mustRun(ctx, "stop", "--timeout", strconv.Itoa(secs), name)
	return err
}

// Remove deletes a container.
func (d *dockerCLI) Remove(ctx context.Context, name string, force bool) error {
	args := []string{"rm", "--volumes"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, name)
	_, errs, err := d.run(ctx, nil, args...)
	if err != nil {
		if strings.Contains(errs, "No such container") {
			return nil
		}
		return fmt.Errorf("docker rm %s: %w: %s", name, err, strings.TrimSpace(errs))
	}
	return nil
}

// dockerInspect is the subset of `docker inspect` output we consume.
type dockerInspect struct {
	ID string `json:"Id"`
	// ImageID is the image the container is actually running, which is not
	// the same thing as the reference it was created from: a tag moves, and a
	// container created before it moved still runs the older bytes.
	ImageID string `json:"Image"`
	Name    string `json:"Name"`
	State   struct {
		Status string `json:"Status"`
		Pid    int    `json:"Pid"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// Inspect returns one container, or StateAbsent when it does not exist.
func (d *dockerCLI) Inspect(ctx context.Context, name string) (Container, error) {
	out, errs, err := d.run(ctx, nil, "inspect", "--type", "container", name)
	if err != nil {
		if strings.Contains(errs, "No such") || strings.Contains(out, "No such") {
			return Container{Name: name, State: StateAbsent}, nil
		}
		return Container{}, fmt.Errorf("docker inspect %s: %w: %s", name, err, strings.TrimSpace(errs))
	}
	var raw []dockerInspect
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return Container{}, fmt.Errorf("parse docker inspect %s: %w", name, err)
	}
	if len(raw) == 0 {
		return Container{Name: name, State: StateAbsent}, nil
	}
	return fromInspect(raw[0]), nil
}

func fromInspect(r dockerInspect) Container {
	c := Container{
		ID:      r.ID,
		Name:    strings.TrimPrefix(r.Name, "/"),
		Image:   r.Config.Image,
		ImageID: r.ImageID,
		State:   normaliseState(r.State.Status),
		Status:  r.State.Status,
		PID:     r.State.Pid,
		Labels:  r.Config.Labels,
	}
	if r.State.Health != nil {
		c.Health = r.State.Health.Status
	}
	return c
}

func normaliseState(s string) State {
	switch s {
	case "running":
		return StateRunning
	case "created":
		return StateCreated
	case "paused":
		return StatePaused
	case "restarting":
		return StateRestarting
	case "exited":
		return StateExited
	case "dead":
		return StateDead
	default:
		return StateAbsent
	}
}

// List returns containers matching the filter.
//
// This is how Twinet answers "what is deployed". There is no state file: the
// container labels are the state, so a control-plane crash, a fresh shell on a
// different machine, or a node reboot all see the same truth.
func (d *dockerCLI) List(ctx context.Context, f Filter) ([]Container, error) {
	args := []string{"ps", "--no-trunc", "--format", "{{.Names}}"}
	if f.All {
		args = append(args, "--all")
	}
	for _, k := range sortedKeys(f.Labels) {
		v := f.Labels[k]
		if v == "" {
			args = append(args, "--filter", "label="+k)
		} else {
			args = append(args, "--filter", "label="+k+"="+v)
		}
	}
	out, err := d.mustRun(ctx, args...)
	if err != nil {
		return nil, err
	}
	names := splitLines(out)
	if len(names) == 0 {
		return nil, nil
	}

	// One batched inspect rather than N round trips: at class scale this is
	// the difference between a snappy `twinet inspect` and a ten-second wait.
	inspectArgs := append([]string{"inspect", "--type", "container"}, names...)
	raw, err := d.mustRun(ctx, inspectArgs...)
	if err != nil {
		return nil, err
	}
	var parsed []dockerInspect
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parse docker inspect: %w", err)
	}
	cs := make([]Container, 0, len(parsed))
	for _, r := range parsed {
		cs = append(cs, fromInspect(r))
	}
	SortContainers(cs)
	return cs, nil
}

// NSPath returns the network namespace path of a running container.
//
// The PID is read live every time. The legacy platform cached PIDs in a file
// that it sourced as bash, which was stale the moment a container restarted and
// was the root cause of its "reconnect the links" scripts.
func (d *dockerCLI) NSPath(ctx context.Context, name string) (string, error) {
	c, err := d.Inspect(ctx, name)
	if err != nil {
		return "", err
	}
	if !c.State.Joinable() {
		return "", fmt.Errorf("container %s is %s, so it has no joinable network namespace", name, c.State)
	}
	if c.PID <= 0 {
		return "", fmt.Errorf("container %s reports PID %d", name, c.PID)
	}
	return fmt.Sprintf("/proc/%d/ns/net", c.PID), nil
}

// Exec runs a command inside a container.
func (d *dockerCLI) Exec(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
	args := []string{"exec"}
	if cmd.Detach {
		args = append(args, "--detach")
	}
	if cmd.TTY {
		args = append(args, "--tty")
	}
	if cmd.Stdin != nil {
		args = append(args, "--interactive")
	}
	if cmd.User != "" {
		args = append(args, "--user", cmd.User)
	}
	if cmd.WorkDir != "" {
		args = append(args, "--workdir", cmd.WorkDir)
	}
	for _, k := range sortedKeys(cmd.Env) {
		args = append(args, "--env", k+"="+cmd.Env[k])
	}
	args = append(args, name)
	args = append(args, cmd.Cmd...)

	stdout, stderr, err := d.run(ctx, cmd.Stdin, args...)
	res := ExecResult{Stdout: stdout, Stderr: stderr}
	if err == nil {
		return res, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
		return res, nil // a non-zero exit is data, not a transport failure
	}
	return res, fmt.Errorf("docker exec %s: %w", name, err)
}

// CopyTo writes a file into a container by streaming a tar archive to stdin.
func (d *dockerCLI) CopyTo(ctx context.Context, name, dst string, mode int64, content []byte) error {
	if mode == 0 {
		mode = 0o644
	}
	dir, base := splitPath(dst)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:    base,
		Mode:    mode,
		Size:    int64(len(content)),
		ModTime: time.Unix(0, 0), // fixed, so copies are byte-reproducible
	}); err != nil {
		return fmt.Errorf("build archive for %s: %w", dst, err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("write archive for %s: %w", dst, err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close archive for %s: %w", dst, err)
	}

	_, errs, err := d.run(ctx, &buf, "cp", "-", name+":"+dir)
	if err != nil {
		if readonlyRootfsCopyError(errs) {
			if fallbackErr := writeReadonlyRootfsFile(ctx, d, name, dst, mode, content); fallbackErr == nil {
				return nil
			} else {
				return fmt.Errorf("docker cp into %s:%s: %w: %s; writable-mount fallback: %v",
					name, dir, err, strings.TrimSpace(errs), fallbackErr)
			}
		}
		return fmt.Errorf("docker cp into %s:%s: %w: %s", name, dir, err, strings.TrimSpace(errs))
	}
	return nil
}

// CopyFrom reads a single file out of a container.
func (d *dockerCLI) CopyFrom(ctx context.Context, name, src string) ([]byte, error) {
	return d.copyFrom(ctx, name, src, false)
}

// CopyFromFollow reads a single file out of a container, following a symbolic
// link at the end of the path.
//
// The unfollowed form returns the link itself, which arrives as an archive
// entry with no contents; a caller comparing a container against its image has
// to see the same bytes on both sides, and /bin/sh is a link in every image
// this project ships.
func (d *dockerCLI) CopyFromFollow(ctx context.Context, name, src string) ([]byte, error) {
	return d.copyFrom(ctx, name, src, true)
}

func (d *dockerCLI) copyFrom(ctx context.Context, name, src string, follow bool) ([]byte, error) {
	args := []string{"cp"}
	if follow {
		args = append(args, "-L")
	}
	args = append(args, name+":"+src, "-")
	cmd := exec.CommandContext(ctx, d.bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker cp from %s:%s: %w: %s", name, src, err, strings.TrimSpace(errb.String()))
	}
	tr := tar.NewReader(&out)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s:%s not found in the copied archive", name, src)
		}
		if err != nil {
			return nil, fmt.Errorf("read archive from %s:%s: %w", name, src, err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		return io.ReadAll(tr)
	}
}

func splitPath(p string) (dir, base string) {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ".", p
	}
	if i == 0 {
		return "/", p[1:]
	}
	return p[:i], p[i+1:]
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
