package runtime

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Docker drives the Docker engine through its CLI.
//
// Using the CLI rather than the Go SDK is a deliberate trade. The SDK pins a
// specific API version and drags in a large dependency tree that has repeatedly
// broken across Docker releases; the CLI is stable, present on every node by
// definition (we require Docker anyway), and every call here is either a
// one-shot lifecycle operation or an exec, none of which are hot paths — the
// hot path is netlink, which we do natively. In exchange the whole backend is
// a few hundred readable lines with no version pinning problem.
type Docker struct {
	bin string
}

// NewDocker constructs a Docker runtime.
func NewDocker() *Docker { return &Docker{bin: "docker"} }

// Name identifies the backend.
func (d *Docker) Name() string { return "docker" }

// Close is a no-op for the CLI backend.
func (d *Docker) Close() error { return nil }

func (d *Docker) run(ctx context.Context, stdin io.Reader, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, d.bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.Stdin = stdin
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func (d *Docker) mustRun(ctx context.Context, args ...string) (string, error) {
	out, errs, err := d.run(ctx, nil, args...)
	if err != nil {
		return out, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errs))
	}
	return out, nil
}

// Ping verifies the daemon is reachable.
func (d *Docker) Ping(ctx context.Context) (string, error) {
	out, err := d.mustRun(ctx, "version", "--format", "{{.Server.Version}}")
	return strings.TrimSpace(out), err
}

// ImageExists reports whether an image is present locally.
func (d *Docker) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, _, err := d.run(ctx, nil, "image", "inspect", ref)
	return err == nil, nil
}

// PullImage fetches an image according to the policy.
//
// An unrecognised policy is an error rather than a fallback to pulling. A typo
// that silently means "always" turns a lab built from local images into one
// that contacts a registry, and the failure surfaces far from its cause: as a
// pull denied for an image that is sitting on the machine already.
func (d *Docker) PullImage(ctx context.Context, ref string, policy PullPolicy) error {
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
func (d *Docker) Create(ctx context.Context, s *Spec) (string, error) {
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
	if s.CPUs > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(s.CPUs, 'f', -1, 64))
	}
	if s.Memory != "" {
		b, err := ParseMemory(s.Memory)
		if err != nil {
			return "", fmt.Errorf("container %s: memory: %w", s.Name, err)
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

	out, err := d.mustRun(ctx, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Start starts a created container.
func (d *Docker) Start(ctx context.Context, name string) error {
	_, err := d.mustRun(ctx, "start", name)
	return err
}

// Stop stops a running container.
func (d *Docker) Stop(ctx context.Context, name string, timeout time.Duration) error {
	secs := int(timeout.Seconds())
	if secs <= 0 {
		secs = 10
	}
	_, err := d.mustRun(ctx, "stop", "--timeout", strconv.Itoa(secs), name)
	return err
}

// Remove deletes a container.
func (d *Docker) Remove(ctx context.Context, name string, force bool) error {
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
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
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
func (d *Docker) Inspect(ctx context.Context, name string) (Container, error) {
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
		ID:     r.ID,
		Name:   strings.TrimPrefix(r.Name, "/"),
		Image:  r.Config.Image,
		State:  normaliseState(r.State.Status),
		Status: r.State.Status,
		PID:    r.State.Pid,
		Labels: r.Config.Labels,
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
func (d *Docker) List(ctx context.Context, f Filter) ([]Container, error) {
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
func (d *Docker) NSPath(ctx context.Context, name string) (string, error) {
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
func (d *Docker) Exec(ctx context.Context, name string, cmd ExecCmd) (ExecResult, error) {
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
func (d *Docker) CopyTo(ctx context.Context, name, dst string, mode int64, content []byte) error {
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
		return fmt.Errorf("docker cp into %s:%s: %w: %s", name, dir, err, strings.TrimSpace(errs))
	}
	return nil
}

// CopyFrom reads a single file out of a container.
func (d *Docker) CopyFrom(ctx context.Context, name, src string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, d.bin, "cp", name+":"+src, "-")
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
