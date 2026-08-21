//go:build podman_integration

package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/HongyuHe/twinet/internal/agent"
	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/netx"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// TestPodmanRoutedLabLifecycle is intentionally a real substrate gate rather
// than a Runtime-method smoke test. It starts a Podman-selected agent, drives a
// source-built routed lab through the single-node CLI, consumes its lifecycle
// events, saves state, and proves cleanup leaves no managed containers,
// overlays, or newly-created host netdevs.
func TestPodmanRoutedLabLifecycle(t *testing.T) {
	if os.Getenv("TWINET_PODMAN_INTEGRATION") != "1" {
		t.Fatal("podman_integration requires TWINET_PODMAN_INTEGRATION=1; refusing a vacuous pass")
	}
	binary := os.Getenv("TWINET_BIN")
	if binary == "" {
		t.Fatal("podman_integration requires TWINET_BIN built from this source tree")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("source-built Twinet binary %s: %v", binary, err)
	}
	root := integrationRoot(t)
	work := filepath.Join(root, fmt.Sprintf(".podman-routed-lab-%d", os.Getpid()))
	if err := os.RemoveAll(work); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })

	runtimeSocket := os.Getenv("TWINET_PODMAN_HOST")
	if runtimeSocket == "" {
		runtimeSocket = "unix:///run/podman/podman.sock"
	}
	registry, tag := os.Getenv("REGISTRY"), os.Getenv("TAG")
	if registry == "" {
		registry = "hyhe"
	}
	if tag == "" {
		tag = "0.1"
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	host = strings.Split(host, ".")[0]
	lab := "podman-live-" + fmt.Sprint(os.Getpid())
	if err := os.WriteFile(filepath.Join(work, "twinet.yaml"),
		[]byte(podmanLabManifest(lab, host, runtimeSocket, registry, tag)), 0o600); err != nil {
		t.Fatal(err)
	}

	beforeLinks := hostLinks(t)
	address := freeLoopbackAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := agent.New(agent.Config{
		Node: host, Listen: address, Token: "podman-integration-token",
		Runtime: "podman", RuntimeSocket: runtimeSocket, Insecure: true,
		StateDir: filepath.Join(work, "agent-state"),
	})
	if err != nil {
		t.Fatalf("start Podman-selected agent: %v", err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Serve(ctx) }()
	node := client.NewNode(host, address, "podman-integration-token")
	waitForPodmanStatus(t, node, runtimeSocket)

	runtime, err := rt.NewRuntime("podman")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.ConfigureEndpoint(runtime, runtimeSocket); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		engine := &deploy.Engine{Runtime: runtime, Node: host}
		_ = engine.Destroy(cleanupCtx, lab)
		if overlays, listErr := netx.ListOverlaysOfLab(lab); listErr == nil {
			_ = engine.DestroyOverlays(overlays)
		}
	})

	runTwinet(t, work, binary, "deploy", "--solve", "--quiet")
	runTwinet(t, work, binary, "exec", "as1/R1", "--", "ip", "link", "show", "port_R2")
	runTwinet(t, work, binary, "save", "--as", "1", "--out", filepath.Join(work, "saved"))
	waitForPodmanEvents(t, node, lab)
	runTwinet(t, work, binary, "destroy", "--yes")

	containers, err := runtime.List(context.Background(), rt.Filter{
		All: true, Labels: map[string]string{deploy.LabelLab: lab},
	})
	if err != nil {
		t.Fatalf("list Podman containers after destroy: %v", err)
	}
	if len(containers) != 0 {
		t.Fatalf("Podman destroy left managed containers: %#v", containers)
	}
	if overlays, err := netx.ListOverlaysOfLab(lab); err != nil {
		t.Fatalf("list overlays after destroy: %v", err)
	} else if len(overlays) != 0 {
		t.Fatalf("Podman destroy left overlays %v", overlays)
	}
	for name := range hostLinks(t) {
		if !beforeLinks[name] {
			t.Fatalf("Podman lifecycle left host netdev %s", name)
		}
	}

	cancel()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("stop Podman-selected agent: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Podman-selected agent did not stop")
	}
}

func integrationRoot(t *testing.T) string {
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

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForPodmanStatus(t *testing.T, node *client.Node, socket string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		status, err := node.Status(context.Background())
		if err == nil && status.Runtime == "podman" && status.RuntimeSocket == socket &&
			status.RuntimeVer != "" && !status.Compatibility.Empty() {
			return
		}
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("runtime=%q socket=%q version=%q contracts=%+v",
				status.Runtime, status.RuntimeSocket, status.RuntimeVer, status.Compatibility)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Podman-selected agent never reported a healthy Podman runtime status: %s", last)
}

func waitForPodmanEvents(t *testing.T, node *client.Node, lab string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		page, err := node.Events(context.Background(), lab, 0, 100)
		if err == nil && len(page.Events) > 0 {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("Podman lifecycle produced no agent event for the lab")
}

func hostLinks(t *testing.T) map[string]bool {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool, len(links))
	for _, link := range links {
		out[link.Attrs().Name] = true
	}
	return out
}

func runTwinet(t *testing.T, directory, binary string, args ...string) {
	t.Helper()
	command := exec.Command(binary, append([]string{"--manifest", directory}, args...)...)
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func podmanLabManifest(lab, node, socket, registry, tag string) string {
	return fmt.Sprintf(`apiVersion: twinet.dev/v1
kind: Lab
metadata:
  name: %s
images:
  mode: development
defaults:
  restart: "no"
kinds:
  router:
    image: %s/twinet-router:%s
    capabilities: [NET_ADMIN, NET_RAW]
    sysctls:
      net.ipv4.ip_forward: "1"
  host:
    image: %s/twinet-host:%s
    capabilities: [NET_ADMIN, NET_RAW]
addressing:
  as_block: "{{ .AS }}.0.0.0/8"
  router_loopback: "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24"
  router_router: "{{ .AS }}.0.{{ .LinkIndex }}.0/24"
  router_host: "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24"
  inter_as: "179.{{ .Low }}.{{ .High }}.0/24"
templates:
  small:
    routers:
      R1: {id: 1}
      R2: {id: 2}
    internal_links:
      - [R1, R2]
autonomous_systems:
  - list: [1]
    template: small
    role: student
placement:
  strategy: single-node
  runtime: podman
  nodes:
    - {name: %s, front: true, runtime: podman, runtime_socket: %q}
`, lab, registry, tag, registry, tag, node, socket)
}
