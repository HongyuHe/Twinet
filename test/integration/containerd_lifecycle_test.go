//go:build containerd_integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/images"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
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
  - {list: [1], role: student, template: pair}
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
	requireRoutedAddresses(t, ctx, runtime, device, "after the first apply")
	requireFullOSPFNeighbour(t, ctx, runtime, device, "after the first apply", 90*time.Second)
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
	// The repair a live node performs is an ordinary deploy, not a solving
	// one, and the lab it performs it on is a restored teaching submission
	// rather than the reference. Both halves of that matter: solve mode
	// re-applies every reference address on every pass, and a lab it has just
	// deployed carries those addresses in its routing configuration, so either
	// one on its own papers over a repair that restores none of them.
	store, err := state.Open(filepath.Join(work, "state"))
	if err != nil {
		t.Fatal(err)
	}
	installSignedSubmissionState(t, ctx, runtime, top, store, lab)
	teaching := &deploy.Engine{
		Runtime: timed, Node: integrationHostname(t), State: store,
		Renderer:        render.New(top, render.ModePlatform),
		ObservationRoot: filepath.Join(work, "observed"),
		FRRControlRoot:  filepath.Join(work, "control"),
		WritableRoot:    filepath.Join(work, "writable"),
	}
	assertContainerdSidecarRebindsAfterRestart(t, ctx, runtime, teaching, top, device)
	assertContainerdBaselineDemandsProof(t, ctx, runtime, teaching, top, device,
		filepath.Join(work, "observed"))
	assertContainerdBaselineSeesEveryNamespaceObject(t, ctx, runtime, teaching, top, device,
		store, lab, filepath.Join(work, "observed"))
	assertContainerdCaptureOutsideADeployRefusesAReplacedNamespace(t, ctx, runtime, teaching,
		top, device, store, lab, filepath.Join(work, "observed"))
	assertContainerdRepairPutsTheNeighbourBackToo(t, ctx, runtime, teaching, top, device,
		store, lab, filepath.Join(work, "observed"))
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

// Unwrap exposes the containerd backend behind this timing decorator. Embedding
// rt.Runtime satisfies the core interface and hides every capability beyond it,
// exactly as the explicit batch field above compensates for ExecBatch.
func (r *timedContainerdRuntime) Unwrap() rt.Runtime { return r.Runtime }

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

// assertContainerdSidecarRebindsAfterRestart reproduces the fault a SIGKILLed
// router produces on a live containerd node and proves it is both visible and
// repaired.
//
// A restarted task gets a new network namespace. The private FRR control
// sidecar was created against the previous task and keeps running in the old
// one: its daemons are all up, its vty answers, its running configuration is
// correct, and it is attached to a namespace holding a loopback and no cables.
// Nothing that reads the sidecar alone can tell the difference, so the proof
// here is the namespace identity on either side of the repair.
func assertContainerdSidecarRebindsAfterRestart(t *testing.T, ctx context.Context,
	runtime rt.Runtime, engine *deploy.Engine, top *model.Topology, device *model.Device,
) {
	t.Helper()
	control := deploy.FRRControlContainer(device)
	primaryBefore, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("containerd cannot prove the router's network namespace: %v", err)
	}
	controlBefore, err := rt.NetnsIdentityOf(ctx, runtime, control)
	if err != nil {
		t.Fatalf("containerd cannot prove the sidecar's network namespace: %v", err)
	}
	if !primaryBefore.SameAs(controlBefore) {
		t.Fatalf("a freshly deployed sidecar is already split: router %s, sidecar %s",
			primaryBefore, controlBefore)
	}

	// The reported reproduction: the router's PID 1 dies and containerd brings
	// the task back. Stop+Start is the same transition through the runtime API.
	if err := runtime.Stop(ctx, device.Container, 10*time.Second); err != nil {
		t.Fatalf("stopping the router task: %v", err)
	}
	if err := runtime.Start(ctx, device.Container); err != nil {
		t.Fatalf("restarting the router task: %v", err)
	}
	sidecar, err := runtime.Inspect(ctx, control)
	if err != nil || !sidecar.State.Joinable() {
		t.Fatalf("the sidecar did not survive the router restart: %+v, %v", sidecar, err)
	}
	primaryOrphaned, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("proving the restarted router's namespace: %v", err)
	}
	controlOrphaned, err := rt.NetnsIdentityOf(ctx, runtime, control)
	if err != nil {
		t.Fatalf("proving the surviving sidecar's namespace: %v", err)
	}
	if primaryOrphaned.SameAs(controlOrphaned) {
		t.Fatalf("containerd kept the sidecar with its router across a restart (%s); "+
			"the fixture no longer reproduces the split", primaryOrphaned)
	}
	t.Logf("router restarted into %s, sidecar orphaned in %s", primaryOrphaned, controlOrphaned)

	repair, err := engine.BuildContext(ctx, top)
	if err != nil {
		t.Fatal(err)
	}
	diff := engine.LastBuildDiff()
	if !diff.Create[device.ID] {
		t.Fatal("an ordinary deploy reported no work while the router's control sidecar was orphaned")
	}
	report, err := repair.Execute(ctx, plan.Options{Workers: 1, ContinueOnError: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed() {
		t.Fatal(report.Err())
	}

	primaryAfter, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("proving the repaired router's namespace: %v", err)
	}
	controlAfter, err := rt.NetnsIdentityOf(ctx, runtime, control)
	if err != nil {
		t.Fatalf("proving the rebuilt sidecar's namespace: %v", err)
	}
	if !primaryAfter.SameAs(controlAfter) {
		t.Fatalf("the repair left the sidecar in %s while the router is in %s",
			controlAfter, primaryAfter)
	}
	if controlAfter.SameAs(controlOrphaned) {
		t.Fatalf("the sidecar was not rebuilt: it is still in %s", controlOrphaned)
	}

	result, err := runtime.Exec(ctx, control, rt.ExecCmd{Cmd: []string{
		"sh", "-c", "pidof zebra >/dev/null && pidof ospfd >/dev/null && test -S /run/frr/ospfd.vty",
	}})
	if err != nil || result.Err() != nil {
		t.Fatalf("the rebuilt sidecar has no daemon set or vty socket: %+v, %v", result, err)
	}
	wired := ""
	for _, iface := range device.Ifaces {
		if iface.Link != nil {
			wired = iface.Name
			break
		}
	}
	if wired == "" {
		t.Fatal("the routed fixture has no wired interface to prove against")
	}
	result, err = runtime.Exec(ctx, control, rt.ExecCmd{
		Cmd: []string{"sh", "-c", "ip -o link show " + wired},
	})
	if err != nil || result.Err() != nil {
		t.Fatalf("the rebuilt sidecar cannot see %s: %+v, %v", wired, result, err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		result, err = runtime.Exec(ctx, control, rt.ExecCmd{
			Cmd: []string{"vtysh", "-c", "show ip ospf interface " + wired},
		})
		if err == nil && result.Err() == nil && strings.Contains(result.Stdout, wired) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rebuilt control plane never ran OSPF on %s: %+v, %v", wired, result, err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Daemons, a vty and an interface list are what the sidecar can report
	// about itself. None of them is the control plane working. A restarted
	// router is rewired with bare interfaces, and a student-owned address is
	// applied by the configuration rather than by the wiring, so a repair that
	// stops at the namespace leaves a router with every cable, every daemon and
	// no address -- and no adjacency, which is the thing the lab is for.
	requireRoutedAddresses(t, ctx, runtime, device, "after the sidecar repair")
	requireFullOSPFNeighbour(t, ctx, runtime, device, "after the sidecar repair", 120*time.Second)
}

// routedAddressesPresent reports the modelled addresses a device is missing
// from its own network namespace.
//
// A student-owned address is not applied by the wiring: the platform creates
// the interface bare and the address arrives with the configuration. That makes
// it the half of a repair that no interface listing and no daemon count can
// stand in for -- a router with every cable, every daemon and no address is
// indistinguishable from a healthy one until its adjacencies fail to form.
func routedAddressesPresent(ctx context.Context, runtime rt.Runtime,
	device *model.Device,
) ([]string, error) {
	result, err := runtime.Exec(ctx, device.Container,
		rt.ExecCmd{Cmd: []string{"ip", "-o", "-4", "addr", "show"}})
	if err != nil {
		return nil, err
	}
	if err := result.Err(); err != nil {
		return nil, err
	}
	var missing []string
	for _, iface := range device.Ifaces {
		if iface.Addr4 == "" {
			continue
		}
		if !strings.Contains(result.Stdout, iface.Addr4) {
			missing = append(missing, iface.Name+"="+iface.Addr4)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return missing, fmt.Errorf("%s is missing %s; it has:\n%s",
			device.ID, strings.Join(missing, ", "), result.Stdout)
	}
	return nil, nil
}

func requireRoutedAddresses(t *testing.T, ctx context.Context, runtime rt.Runtime,
	device *model.Device, stage string,
) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		missing, err := routedAddressesPresent(ctx, runtime, device)
		if err == nil && len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			dumpControlDiagnostics(t, ctx, runtime, device)
			t.Fatalf("%s: %v", stage, err)
		}
		time.Sleep(time.Second)
	}
}

// requireFullOSPFNeighbour waits for a routed adjacency, which is the only
// evidence that the control plane is working rather than merely running.
func requireFullOSPFNeighbour(t *testing.T, ctx context.Context, runtime rt.Runtime,
	device *model.Device, stage string, wait time.Duration,
) {
	t.Helper()
	control := deploy.FRRControlContainer(device)
	deadline := time.Now().Add(wait)
	var last string
	for {
		result, err := runtime.Exec(ctx, control,
			rt.ExecCmd{Cmd: []string{"vtysh", "-c", "show ip ospf neighbor"}})
		if err == nil && result.Err() == nil {
			last = result.Stdout
			if strings.Contains(result.Stdout, "Full") {
				return
			}
		} else if err != nil {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			dumpControlDiagnostics(t, ctx, runtime, device)
			t.Fatalf("%s: %s has no Full OSPF neighbour after %s:\n%s",
				stage, device.ID, wait, last)
		}
		time.Sleep(time.Second)
	}
}

// dumpControlDiagnostics prints what an operator would have to collect by hand
// from a router whose control plane is running and not working. It is read-only
// on purpose: a probe that repairs what it is measuring destroys the evidence.
func dumpControlDiagnostics(t *testing.T, ctx context.Context, runtime rt.Runtime,
	device *model.Device,
) {
	t.Helper()
	control := deploy.FRRControlContainer(device)
	for _, probe := range []struct{ container, label, command string }{
		{device.Container, "primary addresses", "ip -o addr show"},
		{device.Container, "primary links", "ip -o link show"},
		{device.Container, "primary frr.conf", "cat /etc/frr/frr.conf"},
		{control, "sidecar addresses", "ip -o addr show"},
		{control, "sidecar frr.conf", "cat /etc/frr/frr.conf"},
		{control, "sidecar running-config", "vtysh -c 'show running-config'"},
		{control, "sidecar processes", "ps -o pid,args 2>/dev/null || ps"},
		{control, "sidecar reload errors", "grep -iE 'error|fail' /var/log/frr/frr-reload.log | tail -n 30"},
		{control, "sidecar watchfrr vtysh log", "cat /tmp/twinet-vtysh-watchfrr.log 2>/dev/null || true"},
		{control, "sidecar capabilities", "grep Cap /proc/self/status"},
		{control, "sidecar enabled daemons", "cat /etc/frr/daemons"},
		{control, "sidecar boot log", "cat /tmp/twinet-vtysh-boot.log 2>/dev/null || true"},
	} {
		result, err := runtime.Exec(ctx, probe.container,
			rt.ExecCmd{Cmd: []string{"sh", "-c", probe.command}})
		t.Logf("--- %s (%s): err=%v exit=%d\n%s%s", probe.label, probe.container,
			err, result.ExitCode, result.Stdout, result.Stderr)
	}
}

// installSignedSubmissionState puts the lab into the state a restored teaching
// submission is in, which is where the reported failure happened and is not
// where a freshly solved lab is.
//
// A COS-461 group's router interfaces and loopbacks belong to them, so the
// platform renders no `ip address` for any of them: the model carries the
// addresses so the grader and `--solve` agree on what they should be, and the
// running lab has them only because somebody configured them. That is what an
// archive's two halves are -- protocol configuration in the .conf, and the
// addressing as the ip(8) commands that recreate it in the .sh -- and after a
// restore it is what the router holds: a routing configuration with no address
// in it, and addresses that exist in the kernel and in the state store and
// nowhere else.
//
// Solving the lab is what produces those addresses in the first place, so the
// fixture solves, saves what solving built, strips the addressing out of the
// saved routing configuration exactly as a saved submission has it, and puts
// the router onto that pair. The distinction is the whole point of the test:
// with the addresses still in the routing configuration, a rebuilt control
// plane reads them off the disk and the repair looks complete whether or not
// anything replayed the student's state.
func installSignedSubmissionState(t *testing.T, ctx context.Context, runtime rt.Runtime,
	top *model.Topology, store *state.Store, lab string,
) {
	t.Helper()
	for _, device := range routedFixtureRouters(top) {
		snaps, err := deploy.Capture(ctx, runtime, device, lab, top.Hash)
		if err != nil {
			t.Fatalf("saving %s: %v", device.ID, err)
		}
		var protocols string
		for _, snap := range snaps {
			if snap.Kind == state.KindFRR {
				protocols = withoutAddressLines(string(snap.Content))
				snap.Content = []byte(protocols)
				snap.Digest, snap.Bytes = "", 0
			}
			if _, err := store.Put(snap); err != nil {
				t.Fatalf("saving %s %s: %v", device.ID, snap.Kind, err)
			}
		}
		if protocols == "" || !strings.Contains(protocols, "router ospf") {
			t.Fatalf("the saved configuration of %s carries no protocol configuration", device.ID)
		}
		if addresses, err := store.Current(lab, device.ID, state.KindAddrs); err != nil {
			t.Fatalf("the saved addressing of %s: %v", device.ID, err)
		} else if !bytes.Contains(addresses.Content, []byte(modelledLoopback(t, device))) {
			t.Fatalf("the saved addressing of %s does not carry its loopback:\n%s",
				device.ID, addresses.Content)
		}
	}
	// Put each router onto its submission: the protocol configuration on disk,
	// FRR restarted onto it so nothing is left holding the addresses it used
	// to be told about, and then the addressing replayed by the same restore
	// path that loads an archive.
	for _, device := range routedFixtureRouters(top) {
		snap, err := store.Current(lab, device.ID, state.KindFRR)
		if err != nil {
			t.Fatalf("reading back the saved configuration of %s: %v", device.ID, err)
		}
		writeSubmissionConfig(t, ctx, runtime, device, snap.Content)
	}
	for _, device := range routedFixtureRouters(top) {
		if _, err := deploy.Restore(ctx, runtime, device, lab, store); err != nil {
			t.Fatalf("restoring the submission of %s: %v", device.ID, err)
		}
	}
	for _, device := range routedFixtureRouters(top) {
		requireNoConfiguredAddresses(t, ctx, runtime, device)
		requireRoutedAddresses(t, ctx, runtime, device, "after restoring the submission")
	}
	requireFullOSPFNeighbour(t, ctx, runtime, routedFixtureRouters(top)[0],
		"after restoring the submission", 120*time.Second)
}

func routedFixtureRouters(top *model.Topology) []*model.Device {
	var out []*model.Device
	for _, d := range top.Devices {
		if d.Kind == model.KindRouter {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func modelledLoopback(t *testing.T, device *model.Device) string {
	t.Helper()
	loopback, ok := device.IfaceByName("lo")
	if !ok || loopback.Addr4 == "" {
		t.Fatalf("%s has no modelled loopback", device.ID)
	}
	return loopback.Addr4
}

// withoutAddressLines is what a saved submission's routing configuration looks
// like beside its addressing script: the addresses are captured as the ip(8)
// commands that recreate them, not as configuration lines, so an interface
// stanza that held nothing else goes with them entirely -- header, body and
// terminator. Leaving a stanza's `exit` behind produces a file vtysh stops
// reading at, which is a different fault from the one under test.
func withoutAddressLines(config string) string {
	lines := strings.Split(config, "\n")
	kept := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "interface ") {
			kept = append(kept, lines[i])
			continue
		}
		stanza, next := interfaceStanza(lines, i)
		i = next - 1
		if body := stanzaWithoutAddresses(stanza); body != nil {
			kept = append(kept, body...)
		}
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n"
}

// interfaceStanza returns one `interface` block and the index after it,
// including the `exit` that closes it and the `!` that follows.
func interfaceStanza(lines []string, start int) ([]string, int) {
	end := start + 1
	for end < len(lines) {
		trimmed := strings.TrimSpace(lines[end])
		end++
		if trimmed == "exit" {
			break
		}
		if trimmed != "" && !strings.HasPrefix(lines[end-1], " ") {
			// A file written without terminators: the stanza ends where the
			// next top-level line begins.
			end--
			break
		}
	}
	if end < len(lines) && strings.TrimSpace(lines[end]) == "!" {
		end++
	}
	return lines[start:end], end
}

// stanzaWithoutAddresses returns the stanza with its address lines removed, or
// nil if nothing but addresses was in it.
func stanzaWithoutAddresses(stanza []string) []string {
	kept := make([]string, 0, len(stanza))
	configured := false
	for _, line := range stanza {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ip address ") || strings.HasPrefix(trimmed, "ipv6 address ") {
			continue
		}
		if strings.HasPrefix(line, " ") && trimmed != "" {
			configured = true
		}
		kept = append(kept, line)
	}
	if !configured {
		return nil
	}
	return kept
}

// writeSubmissionConfig installs a routing configuration the way a restore
// does and restarts FRR onto it, so nothing is left running that still knows
// about addresses the configuration no longer mentions.
func writeSubmissionConfig(t *testing.T, ctx context.Context, runtime rt.Runtime,
	device *model.Device, body []byte,
) {
	t.Helper()
	if err := runtime.CopyTo(ctx, device.Container, "/etc/frr/frr.conf", 0o640, body); err != nil {
		t.Fatalf("installing the submission configuration of %s: %v", device.ID, err)
	}
	control := deploy.FRRControlContainer(device)
	result, err := runtime.Exec(ctx, control, rt.ExecCmd{Cmd: []string{"sh", "-c",
		"chown frr:frr /etc/frr/frr.conf && /usr/lib/frr/frrinit.sh restart"}})
	if err != nil || result.Err() != nil {
		t.Fatalf("restarting %s onto its submission: %+v, %v", device.ID, result, err)
	}
}

// requireNoConfiguredAddresses proves the persistence boundary this test
// exists for. If the routing configuration still carries the addresses, the
// router can recover them from a file no matter what the deployment does, and
// every assertion after this one would pass without the state store being
// consulted at all.
func requireNoConfiguredAddresses(t *testing.T, ctx context.Context, runtime rt.Runtime,
	device *model.Device,
) {
	t.Helper()
	for _, probe := range []struct {
		what string
		cmd  []string
	}{
		{"on disk", []string{"cat", "/etc/frr/frr.conf"}},
		{"in the running configuration", []string{"vtysh", "-c", "show running-config"}},
	} {
		result, err := runtime.Exec(ctx, deploy.FRRControlContainer(device),
			rt.ExecCmd{Cmd: probe.cmd})
		if err != nil || result.Err() != nil {
			t.Fatalf("reading the routing configuration of %s %s: %+v, %v",
				device.ID, probe.what, result, err)
		}
		for _, line := range strings.Split(result.Stdout, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "ip address ") {
				t.Fatalf("the submission of %s still configures addresses %s: %q",
					device.ID, probe.what, strings.TrimSpace(line))
			}
		}
	}
}

// assertContainerdBaselineDemandsProof erases every recorded namespace, which
// is the state an upgrade to this code leaves a node in, and proves the
// baselines come back only on a positive reading of what is in the namespace.
//
// The reading is the part a fake cannot stand in for. It parses real iproute2
// output out of a real container and compares it against a real state store, so
// a change to either -- the output shape, the canonical fact spelling, the
// sections addrCapture prints -- shows up here rather than as a node that
// quietly stops protecting itself.
func assertContainerdBaselineDemandsProof(t *testing.T, ctx context.Context, runtime rt.Runtime,
	engine *deploy.Engine, top *model.Topology, device *model.Device, observedRoot string,
) {
	t.Helper()
	forgetContainerdNamespaces(t, observedRoot)

	live, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("proving the healthy router's namespace: %v", err)
	}
	if !containerdNoOpDeploy(t, ctx, engine, top, device, "baselining an upgraded node") {
		return
	}
	recorded, ok := recordedContainerdNamespace(t, observedRoot, device.ID)
	if !ok {
		t.Fatal("an upgraded node ran an ordinary deploy over a healthy lab and recorded " +
			"no namespace for its router, so the router's next restart is invisible")
	}
	if !recorded.SameAs(live) {
		t.Fatalf("the recorded namespace %s is not the one the router is in (%s)", recorded, live)
	}

	// The other half. A namespace that has lost what the store says was in it
	// is exactly the namespace a restart leaves behind, and it must not become
	// the baseline every later pass compares against.
	forgetContainerdNamespaces(t, observedRoot)
	loopback := modelledLoopback(t, device)
	control := deploy.FRRControlContainer(device)
	result, err := runtime.Exec(ctx, control, rt.ExecCmd{
		Cmd: []string{"ip", "addr", "del", loopback, "dev", "lo"}})
	if err != nil || result.Err() != nil {
		t.Fatalf("removing %s from %s: %+v, %v", loopback, device.ID, result, err)
	}
	defer func() {
		result, err := runtime.Exec(ctx, control, rt.ExecCmd{
			Cmd: []string{"ip", "addr", "replace", loopback, "dev", "lo"}})
		if err != nil || result.Err() != nil {
			t.Fatalf("putting %s back on %s: %+v, %v", loopback, device.ID, result, err)
		}
	}()
	if !containerdNoOpDeploy(t, ctx, engine, top, device, "refusing an unprovable baseline") {
		return
	}
	if recorded, ok := recordedContainerdNamespace(t, observedRoot, device.ID); ok {
		t.Fatalf("a router missing the addressing its own saved state says it had was "+
			"baselined at %s; the emptiness is now what every later pass compares against",
			recorded)
	}
	if reason := engine.UnprovenNamespaceDevices()[device.ID]; !strings.Contains(reason, loopback) {
		t.Fatalf("the refusal did not name the missing address %s: %q", loopback, reason)
	}
}

// assertContainerdBaselineSeesEveryNamespaceObject proves the reading covers
// more than addresses, against a real kernel.
//
// A VLAN sub-interface is a namespace object in its own right: it is captured
// alongside the addressing because the addressing depends on it, and it goes
// with the namespace when a task is replaced. A proof that compared only
// addresses would find every address in place -- they are on the interfaces the
// platform rewired -- and record a namespace that has lost the student's VLANs
// as the one their work was done in. `ip -d -o link show type vlan` is also
// exactly the kind of output a fake gets subtly wrong, so it is worth reading
// from a container that really has one.
func assertContainerdBaselineSeesEveryNamespaceObject(t *testing.T, ctx context.Context,
	runtime rt.Runtime, engine *deploy.Engine, top *model.Topology, device *model.Device,
	store *state.Store, lab, observedRoot string,
) {
	t.Helper()
	port := ""
	for _, iface := range device.Ifaces {
		if iface != nil && iface.Link != nil && iface.Name != "" && iface.Name != "lo" {
			port = iface.Name
			break
		}
	}
	if port == "" {
		t.Fatalf("%s has no wired interface to stack a VLAN on", device.ID)
	}
	vlan := port + ".42"
	control := deploy.FRRControlContainer(device)
	run := func(what string, args ...string) {
		t.Helper()
		result, err := runtime.Exec(ctx, control, rt.ExecCmd{Cmd: args})
		if err != nil || result.Err() != nil {
			t.Fatalf("%s: %+v, %v", what, result, err)
		}
	}
	run("creating "+vlan, "ip", "link", "add", "link", port, "name", vlan, "type", "vlan", "id", "42")
	defer func() {
		_, _ = runtime.Exec(ctx, control, rt.ExecCmd{Cmd: []string{"ip", "link", "del", vlan}})
	}()

	// Saved the way a submission is saved: read out of the kernel by the same
	// capture, canonicalised by the same code, into the same store.
	snaps, err := deploy.Capture(ctx, runtime, device, lab, top.Hash)
	if err != nil {
		t.Fatalf("saving %s: %v", device.ID, err)
	}
	saved := false
	for _, snap := range snaps {
		if snap.Kind != state.KindAddrs {
			continue
		}
		if !bytes.Contains(snap.Content, []byte("link vlan "+vlan+" "+port+" 42")) {
			t.Fatalf("a capture of %s did not record the VLAN it is carrying:\n%s",
				device.ID, snap.Content)
		}
		if _, err := store.Put(snap); err != nil {
			t.Fatalf("saving the addressing of %s: %v", device.ID, err)
		}
		saved = true
	}
	if !saved {
		t.Fatalf("capturing %s produced no addressing snapshot", device.ID)
	}

	forgetContainerdNamespaces(t, observedRoot)
	if !containerdNoOpDeploy(t, ctx, engine, top, device, "baselining a router with its VLAN") {
		return
	}
	if _, ok := recordedContainerdNamespace(t, observedRoot, device.ID); !ok {
		t.Fatalf("a router carrying exactly the VLAN its saved state records was refused "+
			"a baseline: %q", engine.UnprovenNamespaceDevices()[device.ID])
	}

	// And with the VLAN gone, which is what a replaced task leaves behind: the
	// netdev went with the namespace, every address is back on the interfaces
	// the reconcile rewired, and the student's VLAN is only in the store.
	run("removing "+vlan, "ip", "link", "del", vlan)
	forgetContainerdNamespaces(t, observedRoot)
	if !containerdNoOpDeploy(t, ctx, engine, top, device, "refusing a router that lost its VLAN") {
		return
	}
	if recorded, ok := recordedContainerdNamespace(t, observedRoot, device.ID); ok {
		t.Fatalf("a router that lost the VLAN its saved state records was baselined at %s; "+
			"the next capture would file that loss over the student's work", recorded)
	}
	if reason := engine.UnprovenNamespaceDevices()[device.ID]; !strings.Contains(reason, vlan) {
		t.Fatalf("the refusal did not name the missing VLAN %s: %q", vlan, reason)
	}
}

// assertContainerdCaptureOutsideADeployRefusesAReplacedNamespace proves the
// guard is on the capture rather than on the deployment that used to arm it.
//
// Every assertion above reaches the namespace check through a build: the
// deployment observes the node, finds what moved, and the capture at the end of
// the pass consults what it found. Nothing else that captures does any of that.
// The durability timer, the boundary before a destructive apply, a destroy and
// a fresh export each construct an engine for the purpose and call the capture
// API directly, and on a real node the timer is the one that gets to a
// restarted router first -- it runs every capture interval, and nothing has to
// have gone wrong for it to run.
//
// So this restarts the task for real and then captures from an engine that has
// never observed anything, which is what those callers hold.
func assertContainerdCaptureOutsideADeployRefusesAReplacedNamespace(t *testing.T,
	ctx context.Context, runtime rt.Runtime, engine *deploy.Engine, top *model.Topology,
	device *model.Device, store *state.Store, lab, observedRoot string,
) {
	t.Helper()
	loopback := modelledLoopback(t, device)
	// Bring the store back into step with the namespace, so a baseline can be
	// taken and the only thing that changes afterwards is the restart.
	snaps, err := deploy.Capture(ctx, runtime, device, lab, top.Hash)
	if err != nil {
		t.Fatalf("saving %s: %v", device.ID, err)
	}
	for _, snap := range snaps {
		if _, err := store.Put(snap); err != nil {
			t.Fatalf("saving the %s of %s: %v", snap.Kind, device.ID, err)
		}
	}
	requireSavedAddress(t, store, lab, device, loopback)
	forgetContainerdNamespaces(t, observedRoot)
	if !containerdNoOpDeploy(t, ctx, engine, top, device, "baselining before a restart") {
		return
	}
	baseline, ok := recordedContainerdNamespace(t, observedRoot, device.ID)
	if !ok {
		t.Fatal("a router holding exactly its saved state was refused a baseline")
	}

	// The fault: pid 1 dies, containerd brings the task back, and the
	// namespace it comes back into holds nothing at all.
	if err := runtime.Stop(ctx, device.Container, 10*time.Second); err != nil {
		t.Fatalf("stopping the router task: %v", err)
	}
	if err := runtime.Start(ctx, device.Container); err != nil {
		t.Fatalf("restarting the router task: %v", err)
	}
	replaced, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("proving the restarted router's namespace: %v", err)
	}
	if replaced.SameAs(baseline) {
		t.Fatalf("the task came back in the namespace it left (%s); the fixture no longer "+
			"reproduces the replacement", baseline)
	}
	t.Logf("router restarted out of %s into %s with a capture due", baseline, replaced)

	// What the durability timer holds: a runtime, a node, a store, and nothing
	// else. No build, no observation of this pass, no findings.
	timer := &deploy.Engine{
		Runtime: runtime, Node: engine.Node, State: store,
		Renderer: engine.Renderer, ObservationRoot: observedRoot,
	}
	if _, err := timer.CaptureDevices(ctx, top, store, []string{device.ID}); err != nil {
		t.Fatalf("capturing after the restart: %v", err)
	}
	requireSavedAddress(t, store, lab, device, loopback)
	if _, err := store.Current(lab, device.ID, state.KindFRR); err != nil {
		t.Fatalf("the same capture withheld the routing configuration, which is a file and "+
			"survived the restart: %v", err)
	}

	// And the same capture with no baseline to compare against, which is what
	// an upgraded node has for every device it has never configured. There the
	// refusal has to be reported, because nothing else will say it.
	forgetContainerdNamespaces(t, observedRoot)
	unbaselined := &deploy.Engine{
		Runtime: runtime, Node: engine.Node, State: store,
		Renderer: engine.Renderer, ObservationRoot: observedRoot,
	}
	if _, err := unbaselined.CaptureDevices(ctx, top, store, []string{device.ID}); err != nil {
		t.Fatalf("capturing after the restart with no baseline: %v", err)
	}
	requireSavedAddress(t, store, lab, device, loopback)
	reason, reported := unbaselined.UnprovenNamespaceDevices()[device.ID]
	if !reported || strings.TrimSpace(reason) == "" {
		t.Fatalf("a capture that withheld a router's state did not report why: %q", reason)
	}
	// The reason is whichever part of the namespace it looked for first and did
	// not find, which for a task that came back into an empty one is the
	// wiring rather than the addressing on it.
	t.Logf("the capture refused the restarted router: %s", reason)
	if recorded, ok := recordedContainerdNamespace(t, observedRoot, device.ID); ok {
		t.Fatalf("the empty namespace was recorded as the baseline anyway (%s)", recorded)
	}
}

// requireSavedAddress insists the store still holds an address, in the
// canonical form a restore replays.
func requireSavedAddress(t *testing.T, store *state.Store, lab string, device *model.Device,
	address string,
) {
	t.Helper()
	snapshot, err := store.Current(lab, device.ID, state.KindAddrs)
	if err != nil {
		t.Fatalf("reading the saved addressing of %s: %v", device.ID, err)
	}
	if !strings.Contains(string(snapshot.Content), " lo "+address) {
		t.Fatalf("the saved addressing of %s no longer holds %s:\n%s",
			device.ID, address, snapshot.Content)
	}
}

// containerdNoOpDeploy runs the deploy an operator runs and insists it stayed a
// no-op, so a baseline recorded either side of it came from reading the
// namespace rather than from configuring the device.
func containerdNoOpDeploy(t *testing.T, ctx context.Context, engine *deploy.Engine,
	top *model.Topology, device *model.Device, what string,
) bool {
	t.Helper()
	p, err := engine.BuildContext(ctx, top)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if diff := engine.LastBuildDiff(); diff.Create[device.ID] || diff.Configure[device.ID] {
		t.Fatalf("%s: the deploy was not a no-op, so nothing here is about baselining: %#v",
			what, diff.Counts())
	}
	report, err := p.Execute(ctx, plan.Options{Workers: 1, ContinueOnError: true})
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if report.Failed() {
		t.Fatalf("%s: %v", what, report.Err())
	}
	return true
}

// forgetContainerdNamespaces strips the recorded namespaces from the node's
// observation while leaving every hash in it alone, which is exactly what an
// upgrade from a build without them looks like: a converged node whose next
// deploy is a no-op and which can prove nothing about where anything is.
func forgetContainerdNamespaces(t *testing.T, observedRoot string) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(observedRoot, "*.json"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no node observation was persisted under %s: %v", observedRoot, err)
	}
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var observed map[string]any
		if err := json.Unmarshal(raw, &observed); err != nil {
			t.Fatal(err)
		}
		delete(observed, "namespaces")
		body, err := json.Marshal(observed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func recordedContainerdNamespace(t *testing.T, observedRoot, id string) (rt.NetnsIdentity, bool) {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(observedRoot, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var observed struct {
			Namespaces map[string]rt.NetnsIdentity `json:"namespaces"`
		}
		if err := json.Unmarshal(raw, &observed); err != nil {
			t.Fatal(err)
		}
		if identity, ok := observed.Namespaces[id]; ok && identity.Known() {
			return identity, true
		}
	}
	return rt.NetnsIdentity{}, false
}

// assertContainerdRepairPutsTheNeighbourBackToo is the lab-scope half of the
// repair, on a live containerd node.
//
// A veth pair is rebuilt as a pair, so repairing the router whose task was
// replaced deletes and recreates its neighbours' ends of the cables between
// them. The neighbours were not restarted, nothing observed them as broken, and
// on a restored teaching submission a router's address is not in any rendered
// file: it is in the kernel and in the state store and nowhere else. So a
// repair that stops at the device it was asked about leaves its neighbours with
// interfaces that are up, carry no address, and form no adjacency -- which is
// exactly what a live three-node lab was left with, while the agent logged
// "device repaired and its configuration put back".
//
// The fault is already in place when this runs: the assertion above left the
// router's task replaced and its namespace empty. The repair here is the one
// production entry point, called once, with the production replay.
func assertContainerdRepairPutsTheNeighbourBackToo(t *testing.T, ctx context.Context,
	runtime rt.Runtime, engine *deploy.Engine, top *model.Topology, device *model.Device,
	store *state.Store, lab, observedRoot string,
) {
	t.Helper()
	peers := deploy.LocalRewirePeers(top, engine.Node, device)
	if len(peers) == 0 {
		t.Fatalf("the routed fixture gives %s no same-node neighbours, so there is nothing "+
			"here about the neighbours a rewire unplugs", device.ID)
	}
	var neighbour *model.Device
	for _, peer := range peers {
		if peer.ID == device.ID {
			t.Fatal("the fixture expanded a rewire to the device being rewired")
		}
		if peer.Kind == model.KindRouter {
			neighbour = peer
		}
	}
	if neighbour == nil {
		t.Fatalf("none of %s's same-node neighbours is a router, so no adjacency can be "+
			"proven across a rebuilt cable", device.ID)
	}
	// The neighbours are intact, and the router among them keeps its addressing
	// in the store rather than in any file: that is what makes rebuilding its
	// interface destructive.
	intact := map[string]bool{}
	for _, peer := range peers {
		if missing, err := routedAddressesPresent(ctx, runtime, peer); err == nil && len(missing) == 0 {
			intact[peer.ID] = true
		}
	}
	if !intact[neighbour.ID] {
		t.Fatalf("%s does not hold its modelled addressing before the repair, so nothing "+
			"here would prove it survived one", neighbour.ID)
	}
	requireNoConfiguredAddresses(t, ctx, runtime, neighbour)
	before := map[string]rt.NetnsIdentity{}
	for _, peer := range peers {
		identity, err := rt.NetnsIdentityOf(ctx, runtime, peer.Container)
		if err != nil {
			t.Fatalf("proving the network namespace of %s: %v", peer.ID, err)
		}
		before[peer.ID] = identity
	}
	if missing, err := routedAddressesPresent(ctx, runtime, device); err == nil && len(missing) == 0 {
		t.Fatal("the router still holds its addressing, so its task was not replaced and " +
			"there is no repair here to make")
	}

	var replayed []string
	if err := engine.RewireDeviceAndPeers(ctx, top, device,
		func(ctx context.Context, d *model.Device) error {
			replayed = append(replayed, d.ID)
			_, err := deploy.Restore(ctx, runtime, d, lab, store)
			return err
		}); err != nil {
		dumpControlDiagnostics(t, ctx, runtime, device)
		t.Fatalf("repairing %s and everything its repair unplugs: %v", device.ID, err)
	}
	want := []string{device.ID}
	for _, peer := range peers {
		want = append(want, peer.ID)
	}
	if strings.Join(replayed, ",") != strings.Join(want, ",") {
		t.Fatalf("the repair replayed %v, want %v: the device it repaired first and then "+
			"every neighbour whose cable it rebuilt", replayed, want)
	}

	// The neighbours' containers were not replaced: only their ends of the
	// cables were, and their other links and their namespaces are their own.
	for _, peer := range peers {
		after, err := rt.NetnsIdentityOf(ctx, runtime, peer.Container)
		if err != nil {
			t.Fatalf("proving the network namespace of %s after the repair: %v", peer.ID, err)
		}
		if !after.SameAs(before[peer.ID]) {
			t.Fatalf("the repair moved %s from %s to %s; it may rebuild a cable, not a "+
				"container", peer.ID, before[peer.ID], after)
		}
	}
	requireRoutedAddresses(t, ctx, runtime, device, "after the neighbour-aware repair")
	for _, peer := range peers {
		if !intact[peer.ID] {
			continue
		}
		requireRoutedAddresses(t, ctx, runtime, peer,
			"after the neighbour-aware repair of "+device.ID)
	}
	requireFullOSPFNeighbour(t, ctx, runtime, device, "after the neighbour-aware repair",
		120*time.Second)
	requireFullOSPFNeighbour(t, ctx, runtime, neighbour, "after the neighbour-aware repair",
		120*time.Second)

	// A repair also has to hand the device back to everything else that reads
	// it. The record still names the namespace that died with the old task
	// unless the repair rewrites it, and every later capture compares against
	// the record: it would find a mismatch, call the namespace replaced, and
	// withhold this router's addressing from the store from now on. The device
	// would be repaired, reported repaired, and quietly never backed up again.
	repaired, err := rt.NetnsIdentityOf(ctx, runtime, device.Container)
	if err != nil {
		t.Fatalf("proving the network namespace of %s after the repair: %v", device.ID, err)
	}
	recorded, known := recordedContainerdNamespace(t, observedRoot, device.ID)
	if !known || !recorded.SameAs(repaired) {
		t.Fatalf("the repair put %s back in %s and the record says %v/%s; every later "+
			"capture compares against the record", device.ID, repaired, known, recorded)
	}
	for _, affected := range append([]*model.Device{device}, peers...) {
		result, err := runtime.Exec(ctx, affected.Container,
			rt.ExecCmd{Cmd: []string{"test", "-f", "/etc/twinet/restore-pending"}})
		if err != nil {
			t.Fatalf("asking %s whether it still owes a restore: %v", affected.ID, err)
		}
		if result.ExitCode == 0 {
			t.Fatalf("%s was repaired and is still marked as owing its saved state, so "+
				"nothing will capture from it again", affected.ID)
		}
	}
	// And the proof of both: a capture by an engine that did none of the above,
	// which is what periodic durability is, stores what is on the repaired
	// router now.
	fresh := &deploy.Engine{
		Runtime: runtime, Node: engine.Node, State: store,
		Renderer:        engine.Renderer,
		ObservationRoot: observedRoot,
		FRRControlRoot:  engine.FRRControlRoot,
		WritableRoot:    engine.WritableRoot,
	}
	if _, err := fresh.CaptureDevices(ctx, top, store, []string{device.ID}); err != nil {
		t.Fatalf("capturing %s after the repair: %v", device.ID, err)
	}
	requireSavedAddress(t, store, lab, device, modelledLoopback(t, device))
	if unproven := fresh.UnprovenNamespaceDevices(); len(unproven) > 0 {
		t.Fatalf("a capture after the repair still cannot vouch for %v", unproven)
	}
	if dirty := fresh.DirtyNamespaceStateDevices(); len(dirty) > 0 {
		t.Fatalf("a capture after the repair still treats %v as having lost its namespace, "+
			"so its addressing is being withheld from the store", dirty)
	}
}
