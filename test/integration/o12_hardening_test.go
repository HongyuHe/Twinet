//go:build o12integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

type o12Inspect struct {
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
	HostConfig struct {
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		SecurityOpt    []string `json:"SecurityOpt"`
		Binds          []string `json:"Binds"`
	} `json:"HostConfig"`
}

// TestO12DockerRouterAndSidecarIsolation is deliberately not skip-based. The
// Makefile gate first checks the explicit destructive acknowledgement and
// Docker daemon, while this test proves the runtime properties against real
// Linux namespaces and capabilities.
func TestO12DockerRouterAndSidecarIsolation(t *testing.T) {
	if os.Getenv("TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE") != "1" {
		t.Fatal("O12 integration needs TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE=1")
	}
	if err := runO12("info"); err != nil {
		t.Fatalf("Docker is required for O12 integration: %v", err)
	}
	registry, tag := os.Getenv("REGISTRY"), os.Getenv("TAG")
	if registry == "" {
		registry = "hyhe"
	}
	if tag == "" {
		tag = "0.1"
	}
	image := registry + "/twinet-router:" + tag
	suffix := strconv.Itoa(os.Getpid())
	router, sidecar := "twinet-o12-router-"+suffix, "twinet-o12-frr-"+suffix
	t.Cleanup(func() {
		_ = runO12("rm", "-f", sidecar)
		_ = runO12("rm", "-f", router)
	})

	if err := runO12("run", "-d", "--name", router, "--network", "none",
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--cap-add", "NET_BIND_SERVICE", "--cap-add", "DAC_OVERRIDE",
		"--security-opt", "no-new-privileges",
		"--read-only", "--tmpfs", "/run:rw,nosuid,nodev,size=64m",
		"--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", image, "sleep", "infinity"); err != nil {
		t.Fatal(err)
	}
	if err := runO12("run", "-d", "--name", sidecar, "--network", "container:"+router,
		"--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW", "--cap-add", "NET_BIND_SERVICE", "--cap-add", "DAC_OVERRIDE",
		"--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
		"--cap-add", "KILL",
		"--cap-add", "SYS_ADMIN",
		"--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/run:rw,nosuid,nodev,size=64m", "--tmpfs", "/sidecar-only:rw,nosuid,nodev,size=8m",
		image, "sh", "-c", "touch /sidecar-only/proof && exec sleep infinity"); err != nil {
		t.Fatal(err)
	}
	routerInspect := inspectO12(t, router)
	sidecarInspect := inspectO12(t, sidecar)
	if routerInspect.HostConfig.NetworkMode != "none" || !routerInspect.HostConfig.ReadonlyRootfs ||
		!hasO12(routerInspect.HostConfig.CapDrop, "ALL") ||
		hasO12(routerInspect.HostConfig.CapAdd, "SYS_ADMIN") {
		t.Fatalf("router is not least-privilege isolated: %#v", routerInspect.HostConfig)
	}
	if !strings.HasPrefix(sidecarInspect.HostConfig.NetworkMode, "container:") ||
		sidecarInspect.HostConfig.PidMode != "" ||
		!hasO12(sidecarInspect.HostConfig.CapAdd, "SYS_ADMIN") {
		t.Fatalf("FRR sidecar isolation contract is absent: %#v", sidecarInspect.HostConfig)
	}
	for _, bind := range routerInspect.HostConfig.Binds {
		if strings.Contains(strings.ToLower(bind), "docker.sock") {
			t.Fatalf("router received Docker socket bind %q", bind)
		}
	}
	if routerInspect.State.Pid <= 0 || sidecarInspect.State.Pid <= 0 {
		t.Fatalf("router/sidecar did not have host PIDs: router=%#v sidecar=%#v",
			routerInspect.State, sidecarInspect.State)
	}
	if routerNet, sidecarNet := namespaceO12(t, routerInspect.State.Pid, "net"),
		namespaceO12(t, sidecarInspect.State.Pid, "net"); routerNet != sidecarNet {
		t.Fatalf("sidecar does not share router network namespace: %s != %s", routerNet, sidecarNet)
	}
	if routerPID, sidecarPID := namespaceO12(t, routerInspect.State.Pid, "pid"),
		namespaceO12(t, sidecarInspect.State.Pid, "pid"); routerPID == sidecarPID {
		t.Fatalf("sidecar shares router PID namespace: %s", routerPID)
	}
	hostPID := strconv.Itoa(sidecarInspect.State.Pid)
	// Root inside the router is intentionally still able to configure its own
	// network, but cannot mount, see the sidecar PID, see sidecar-only storage,
	// reach a Docker socket, or obtain a default/host-underlay route.
	command := fmt.Sprintf(
		"test ! -e /var/run/docker.sock && test ! -e /proc/%s && test ! -e /sidecar-only/proof && "+
			"! ip route | grep -q '^default' && mkdir -p /run/o12-mount && ! mount -t tmpfs none /run/o12-mount",
		hostPID)
	if err := runO12("exec", router, "sh", "-c", command); err != nil {
		t.Fatalf("router root escaped its O12 boundary: %v", err)
	}
}

func namespaceO12(t *testing.T, pid int, kind string) string {
	t.Helper()
	value, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
	if err != nil {
		t.Fatalf("read namespace %s for PID %d: %v", kind, pid, err)
	}
	return value
}

func inspectO12(t *testing.T, name string) o12Inspect {
	t.Helper()
	command := exec.Command("docker", "inspect", name)
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	var values []o12Inspect
	if err := json.Unmarshal(raw, &values); err != nil || len(values) != 1 {
		t.Fatalf("decode inspect %s: %v (%s)", name, err, raw)
	}
	return values[0]
}

func runO12(args ...string) error {
	command := exec.Command("docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func hasO12(values []string, want string) bool {
	want = strings.TrimPrefix(want, "CAP_")
	for _, value := range values {
		if strings.TrimPrefix(value, "CAP_") == want {
			return true
		}
	}
	return false
}
