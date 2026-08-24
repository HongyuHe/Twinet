//go:build containerd_integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestContainerdRuntimeLifecycle(t *testing.T) {
	if os.Getenv("TWINET_CONTAINERD_INTEGRATION") != "1" {
		t.Fatal("containerd_integration requires TWINET_CONTAINERD_INTEGRATION=1")
	}
	runtime, err := rt.NewRuntime("containerd")
	if err != nil {
		t.Fatal(err)
	}
	containerdRuntime, ok := runtime.(*rt.Containerd)
	if !ok {
		t.Fatalf("containerd registry returned %T", runtime)
	}
	endpoint := os.Getenv("TWINET_CONTAINERD_HOST")
	if endpoint == "" {
		endpoint = "unix:///run/containerd/containerd.sock"
	}
	namespace := fmt.Sprintf("twinet-integration-%d", os.Getpid())
	if initBinary := os.Getenv("TWINET_INIT_BINARY"); initBinary == "" {
		t.Fatal("containerd_integration requires TWINET_INIT_BINARY")
	}
	if err := rt.ConfigureEndpoint(runtime, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := rt.ConfigureNamespace(runtime, namespace); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		containers, _ := runtime.List(cleanupCtx, rt.Filter{All: true})
		for _, container := range containers {
			_ = runtime.Remove(cleanupCtx, container.Name, true)
		}
		_ = containerdRuntime.DeleteNamespace(cleanupCtx)
		_ = runtime.Close()
	})

	version, err := runtime.Ping(ctx)
	if err != nil || version == "" {
		t.Fatalf("containerd ping = %q, %v", version, err)
	}
	image := os.Getenv("TWINET_CONTAINERD_IMAGE")
	if image == "" {
		image = "docker.io/hyhe/twinet-host:0.1"
	}
	if err := runtime.PullImage(ctx, image, rt.PullIfMissing); err != nil {
		t.Fatal(err)
	}
	if ok, err := runtime.ImageExists(ctx, image); err != nil || !ok {
		t.Fatalf("containerd image exists = %t, %v", ok, err)
	}
	digest, err := runtime.ImageDigest(ctx, image)
	if err != nil || digest == "" {
		t.Fatalf("containerd image digest = %q, %v", digest, err)
	}

	lab := "containerd-live-" + fmt.Sprint(os.Getpid())
	name := lab + "-host"
	shared := t.TempDir()
	hostCanary := filepath.Join(t.TempDir(), "host-canary")
	if err := os.WriteFile(hostCanary, []byte("host-safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostCanary, filepath.Join(shared, "escape")); err != nil {
		t.Fatal(err)
	}
	events := runtime.(rt.EventRuntime).Subscribe(ctx, rt.EventFilter{
		Labels: map[string]string{deploy.LabelLab: lab},
	})
	spec := &rt.Spec{
		Name: name, Image: image, Hostname: "host",
		Entrypoint: []string{"/bin/sh", "-c"}, Command: []string{"sleep 600"},
		Labels: map[string]string{
			deploy.LabelManaged: "true", deploy.LabelLab: lab,
			deploy.LabelSpec: "integration-spec",
		},
		Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		CapDrop:      []string{"ALL"},
		SecurityOpt: []string{
			"no-new-privileges", "seccomp=default", "apparmor=docker-default",
		},
		ReadOnlyRootfs: true,
		MaskedPaths:    []string{"/proc/kcore"},
		ReadonlyPaths:  []string{"/proc/sys"},
		Tmpfs: map[string]string{
			"/run": "rw,nosuid,nodev", "/tmp": "rw,nosuid,nodev",
		},
		Binds:       []rt.Bind{{Source: shared, Target: "/run/shared"}},
		NetworkMode: "none", CPUs: 1, Memory: "128Mi", PidsLimit: 64, Init: true,
	}
	if _, err := runtime.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(ctx, name); err != nil {
		t.Fatal(err)
	}
	container, err := runtime.Inspect(ctx, name)
	if err != nil || container.State != rt.StateRunning || container.PID <= 0 {
		t.Fatalf("containerd inspect = %+v, %v", container, err)
	}
	if path, err := runtime.NSPath(ctx, name); err != nil ||
		path != fmt.Sprintf("/proc/%d/ns/net", container.PID) {
		t.Fatalf("containerd netns = %q, %v", path, err)
	}
	execResult, err := runtime.Exec(ctx, name, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "cat; printf err >&2"}, Stdin: strings.NewReader("stdin"),
	})
	if err != nil || execResult.ExitCode != 0 ||
		execResult.Stdout != "stdin" || execResult.Stderr != "err" {
		t.Fatalf("containerd exec = %+v, %v", execResult, err)
	}
	batch, ok := runtime.(rt.BatchExecRuntime)
	if !ok {
		t.Fatal("containerd runtime does not expose batch exec")
	}
	batchResults, err := batch.ExecBatch(ctx, name, []rt.ExecCmd{
		{Cmd: []string{"sh", "-c", "printf first; printf first-err >&2"}},
		{Cmd: []string{"sh", "-c", "printf second; printf second-err >&2; exit 7"}},
	})
	if err != nil || len(batchResults) != 2 ||
		batchResults[0].ExitCode != 0 || batchResults[0].Stdout != "first" ||
		batchResults[0].Stderr != "first-err" ||
		batchResults[1].ExitCode != 7 || batchResults[1].Stdout != "second" ||
		batchResults[1].Stderr != "second-err" {
		t.Fatalf("containerd batch exec = %+v, %v", batchResults, err)
	}
	if err := runtime.CopyTo(ctx, name, "/run/twinet-copy", 0o600, []byte("copy\n")); err != nil {
		t.Fatal(err)
	}
	if copied, err := runtime.CopyFrom(ctx, name, "/run/twinet-copy"); err != nil ||
		!bytes.Equal(copied, []byte("copy\n")) {
		t.Fatalf("containerd copy = %q, %v", copied, err)
	}
	_ = runtime.CopyTo(ctx, name, "/run/shared/escape", 0o600, []byte("escaped\n"))
	if canary, err := os.ReadFile(hostCanary); err != nil ||
		!bytes.Equal(canary, []byte("host-safe\n")) {
		t.Fatalf("containerd copy followed a container symlink onto the host: %q, %v",
			canary, err)
	}
	stream, ok := runtime.(rt.StreamExecRuntime)
	if !ok {
		t.Fatal("containerd runtime does not expose streamed exec")
	}
	var streamOut, streamErr bytes.Buffer
	streamCode, err := stream.StreamExec(ctx, name, rt.ExecCmd{
		Cmd:   []string{"sh", "-c", "read value; printf 'stream:%s' \"$value\"; printf stream-err >&2; exit 3"},
		Stdin: strings.NewReader("input\n"),
	}, 0, 0, &streamOut, &streamErr)
	if err != nil || streamCode != 3 || streamOut.String() != "stream:input" ||
		streamErr.String() != "stream-err" {
		t.Fatalf("containerd streamed exec = code %d stdout %q stderr %q, %v",
			streamCode, streamOut.String(), streamErr.String(), err)
	}
	var ttyOut, ttyErr bytes.Buffer
	ttyCode, err := stream.StreamExec(ctx, name, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "printf tty-ok; exit 7"}, TTY: true,
		Stdin: bytes.NewReader(nil),
	}, 24, 80, &ttyOut, &ttyErr)
	ttyOutput := ttyOut.String() + ttyErr.String()
	if err != nil || ttyCode != 7 || !strings.Contains(ttyOutput, "tty-ok") {
		t.Fatalf("containerd TTY exec = code %d output %q, %v",
			ttyCode, ttyOutput, err)
	}
	if err := runtime.Pause(ctx, name); err != nil {
		t.Fatal(err)
	}
	if paused, err := runtime.Inspect(ctx, name); err != nil || paused.State != rt.StatePaused {
		t.Fatalf("containerd paused state = %+v, %v", paused, err)
	}
	if err := runtime.Unpause(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(ctx, name, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if stopped, err := runtime.Inspect(ctx, name); err != nil || stopped.State != rt.StateExited {
		t.Fatalf("containerd stopped state = %+v, %v", stopped, err)
	}
	if err := runtime.Start(ctx, name); err != nil {
		t.Fatal(err)
	}
	listed, err := runtime.List(ctx, rt.Filter{
		All: true, Labels: map[string]string{deploy.LabelLab: lab},
	})
	if err != nil || len(listed) != 1 || listed[0].Name != name {
		t.Fatalf("containerd list = %+v, %v", listed, err)
	}
	if err := runtime.Remove(ctx, name, true); err != nil {
		t.Fatal(err)
	}
	if absent, err := runtime.Inspect(ctx, name); err != nil || absent.State != rt.StateAbsent {
		t.Fatalf("containerd absent state = %+v, %v", absent, err)
	}
	digestSpec := *spec
	digestSpec.Name = lab + "-digest"
	digestSpec.Image = digest
	digestSpec.Labels = map[string]string{
		deploy.LabelManaged: "true", deploy.LabelLab: lab,
		deploy.LabelSpec: "digest-spec",
	}
	if _, err := runtime.Create(ctx, &digestSpec); err != nil {
		t.Fatalf("containerd create by digest-only image ID: %v", err)
	}
	if err := runtime.Start(ctx, digestSpec.Name); err != nil {
		t.Fatalf("containerd start by digest-only image ID: %v", err)
	}
	if err := runtime.Remove(ctx, digestSpec.Name, true); err != nil {
		t.Fatalf("containerd remove digest-only image container: %v", err)
	}
	waitForContainerdEvents(t, events)
	runContainerdRoutedEngine(t, ctx, runtime, workRoot(t), image)
}

func waitForContainerdEvents(t *testing.T, subscription rt.EventSubscription) {
	t.Helper()
	want := map[rt.EventAction]bool{
		rt.EventCreate: true, rt.EventStart: true, rt.EventDie: true, rt.EventDestroy: true,
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for len(want) > 0 {
		select {
		case event := <-subscription.Events:
			delete(want, event.Action)
		case err := <-subscription.Errors:
			t.Fatalf("containerd event stream ended: %v", err)
		case <-deadline.C:
			t.Fatalf("containerd events missing: %v", want)
		}
	}
}

func runContainerdRoutedEngine(t *testing.T, ctx context.Context, runtime rt.Runtime,
	root, image string,
) {
	t.Helper()
	startedAt := time.Now()
	lab := fmt.Sprintf("containerd-routed-%d", os.Getpid())
	routerImage := strings.Replace(image, "twinet-host", "twinet-router", 1)
	if routerImage == image {
		t.Fatalf("cannot derive router image from %q", image)
	}
	if err := runtime.PullImage(ctx, routerImage, rt.PullIfMissing); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "."+lab)
	if err := os.RemoveAll(work); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	manifestText := fmt.Sprintf(`apiVersion: twinet.dev/v1
kind: Lab
metadata: {name: %s}
images: {mode: development}
defaults: {restart: "no", cpus: 2, memory: 512Mi, pids: 256}
kinds:
  router:
    image: %s
    capabilities: [NET_ADMIN, NET_RAW]
    sysctls: {net.ipv4.ip_forward: "1"}
  host:
    image: %s
    capabilities: [NET_ADMIN, NET_RAW]
addressing:
  as_block: "{{ .AS }}.0.0.0/8"
  router_loopback: "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24"
  router_router: "{{ .AS }}.0.{{ .LinkIndex }}.0/24"
  router_host: "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24"
  inter_as: "179.{{ .Low }}.{{ .High }}.0/24"
templates:
  pair:
    routers: {R1: {id: 1}, R2: {id: 2}}
    internal_links: [[R1, R2]]
autonomous_systems:
  - {list: [1], role: staff, template: pair}
placement:
  strategy: single-node
  runtime: containerd
  nodes: [{name: %s, front: true}]
`, lab, routerImage, image, integrationHostname(t))
	if err := os.WriteFile(filepath.Join(work, "twinet.yaml"), []byte(manifestText), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := manifest.Load(work)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	expanded, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := images.Apply(expanded.Topology); err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(expanded.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	top := expanded.Topology
	before := containerdHostLinks(t)
	timed := &timedContainerdRuntime{Runtime: runtime, batch: runtime.(rt.BatchExecRuntime)}
	engine := &deploy.Engine{
		Runtime: timed, Node: integrationHostname(t),
		Renderer:      render.New(top, render.ModeSolve),
		Authoritative: true, WritesReference: true,
		ObservationRoot: filepath.Join(work, "observed"),
		FRRControlRoot:  filepath.Join(work, "control"),
		WritableRoot:    filepath.Join(work, "writable"),
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = engine.Destroy(cleanupCtx, lab)
	})
	deployment, err := engine.BuildContext(ctx, top)
	if err != nil {
		t.Fatal(err)
	}
	report, err := deployment.Execute(ctx, plan.Options{Workers: 1, ContinueOnError: true})
	for _, result := range report.Results {
		t.Logf("containerd routed step %s: %s", result.Step.ID,
			result.Duration.Round(time.Millisecond))
	}
	timed.log(t)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed() {
		t.Fatal(report.Err())
	}
	t.Logf("containerd routed apply completed in %s", time.Since(startedAt).Round(time.Millisecond))
	device := top.Devices["as1/R1"]
	if device == nil {
		t.Fatal("routed fixture lost R1")
	}
	result, err := runtime.Exec(ctx, device.Container,
		rt.ExecCmd{Cmd: []string{"ip", "link", "show", "port_R2"}})
	if err != nil || result.Err() != nil {
		t.Fatalf("containerd routed link: %+v, %v", result, err)
	}
	loopback, ok := device.IfaceByName("lo")
	if !ok || loopback.Addr4 == "" {
		t.Fatal("containerd routed fixture lost its loopback contract")
	}
	result, err = runtime.Exec(ctx, device.Container,
		rt.ExecCmd{Cmd: []string{"ip", "-o", "addr", "show", "dev", "lo"}})
	if err != nil || result.Err() != nil || !strings.Contains(result.Stdout, loopback.Addr4) {
		t.Fatalf("containerd routed loopback %s is absent: %+v, %v", loopback.Addr4, result, err)
	}
	result, err = runtime.Exec(ctx, device.Container,
		rt.ExecCmd{Cmd: []string{"vtysh", "-c", "show running-config"}})
	if err != nil || result.Err() != nil || !strings.Contains(result.Stdout, "router ospf") {
		t.Fatalf("containerd routed FRR configuration was not loaded: %+v, %v", result, err)
	}
	control := deploy.FRRControlContainer(device)
	result, err = runtime.Exec(ctx, control, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "pidof watchfrr >/dev/null && pidof ospfd && test -S /run/frr/ospfd.vty"},
	})
	if err != nil || result.Err() != nil {
		t.Fatalf("containerd FRR watchdog is not supervising ospfd: %+v, %v", result, err)
	}
	oldPID := strings.TrimSpace(result.Stdout)
	result, err = runtime.Exec(ctx, control, rt.ExecCmd{
		Cmd: []string{"sh", "-c", `pid="$(pidof ospfd)" && kill -KILL "$pid"`},
	})
	if err != nil || result.Err() != nil {
		t.Fatalf("kill supervised containerd ospfd: %+v, %v", result, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		result, err = runtime.Exec(ctx, control, rt.ExecCmd{
			Cmd: []string{"sh", "-c", "pidof ospfd && test -S /run/frr/ospfd.vty"},
		})
		if err == nil && result.Err() == nil && strings.TrimSpace(result.Stdout) != oldPID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watchfrr did not restart ospfd: %+v, %v", result, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for {
		result, err = runtime.Exec(ctx, device.Container,
			rt.ExecCmd{Cmd: []string{"vtysh", "-c", "show running-config"}})
		if err == nil && result.Err() == nil && strings.Contains(result.Stdout, "router ospf") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watchfrr restart did not restore OSPF configuration: %+v, %v", result, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	result, err = runtime.Exec(ctx, control, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "/usr/lib/frr/frrinit.sh restart"},
	})
	if err != nil || result.Err() != nil {
		t.Fatalf("containerd ready FRR restart fallback: %+v, %v", result, err)
	}
	if err := engine.Destroy(ctx, lab); err != nil {
		t.Fatal(err)
	}
	t.Logf("containerd routed apply+destroy completed in %s", time.Since(startedAt).Round(time.Millisecond))
	remaining, err := runtime.List(ctx, rt.Filter{
		All: true, Labels: map[string]string{deploy.LabelLab: lab},
	})
	if err != nil || len(remaining) != 0 {
		t.Fatalf("containerd routed destroy left %+v, %v", remaining, err)
	}
	for name := range containerdHostLinks(t) {
		if !before[name] {
			t.Fatalf("containerd routed lifecycle left host netdev %s", name)
		}
	}
}

type timedContainerdRuntime struct {
	rt.Runtime
	batch rt.BatchExecRuntime
	mu    sync.Mutex
	calls map[string][]time.Duration
}

func (r *timedContainerdRuntime) record(name string, started time.Time) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string][]time.Duration{}
	}
	r.calls[name] = append(r.calls[name], time.Since(started))
	r.mu.Unlock()
}

func (r *timedContainerdRuntime) Exec(ctx context.Context, name string,
	command rt.ExecCmd,
) (rt.ExecResult, error) {
	started := time.Now()
	defer r.record("exec", started)
	return r.Runtime.Exec(ctx, name, command)
}

func (r *timedContainerdRuntime) ExecBatch(ctx context.Context, name string,
	commands []rt.ExecCmd,
) ([]rt.ExecResult, error) {
	started := time.Now()
	defer r.record(fmt.Sprintf("exec_batch_%d", len(commands)), started)
	return r.batch.ExecBatch(ctx, name, commands)
}

func (r *timedContainerdRuntime) CopyTo(ctx context.Context, name, path string,
	mode int64, content []byte,
) error {
	started := time.Now()
	defer r.record("copy_to", started)
	return r.Runtime.CopyTo(ctx, name, path, mode, content)
}

func (r *timedContainerdRuntime) CopyFrom(ctx context.Context, name, path string) ([]byte, error) {
	started := time.Now()
	defer r.record("copy_from", started)
	return r.Runtime.CopyFrom(ctx, name, path)
}

func (r *timedContainerdRuntime) log(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, calls := range r.calls {
		var total time.Duration
		for _, call := range calls {
			total += call
		}
		t.Logf("containerd runtime %s: calls=%d total=%s mean=%s",
			name, len(calls), total.Round(time.Millisecond),
			(total / time.Duration(len(calls))).Round(time.Millisecond))
	}
}

func workRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("could not locate repository root")
		}
		dir = next
	}
}

func integrationHostname(t *testing.T) string {
	t.Helper()
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(host, ".")[0]
}

func containerdHostLinks(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool, len(entries))
	for _, entry := range entries {
		out[entry.Name()] = true
	}
	return out
}
