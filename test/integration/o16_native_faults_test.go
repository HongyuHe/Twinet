//go:build faultintegration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestO16NativeFaultsRoundTrip is deliberately destructive and does not skip
// when Docker, root, an image, a daemon, or an injector is unavailable. The
// mixed lab is a real BMv2/OpenFlow/load/label substrate: every O16-native
// fault must inject, manifest, verify, resolve, and leave no ledger entry.
//
// Deploying twice is intentional. A first deployment that creates/wires every
// container but leaves FRR daemons dead is not a converged lab; the second
// deployment must be a no-change convergence, not the first successful start.
func TestO16NativeFaultsRoundTrip(t *testing.T) {
	requireFaultIntegration(t)
	root := filepath.Clean(filepath.Join("..", ".."))
	manifest := filepath.Join(root, "examples", "mixed-substrate")
	binary := os.Getenv("TWINET_BIN")
	if binary == "" {
		binary = filepath.Join(root, "bin", "twinet")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("faultintegration needs a built controller at %s: %v", binary, err)
	}

	destroy := func() {
		if out, err := runTwinet(binary, 3*time.Minute, "destroy", "-m", manifest, "--yes"); err != nil {
			t.Errorf("destroy mixed substrate lab: %v\n%s", err, out)
		}
		if err := os.RemoveAll(filepath.Join(manifest, ".twinet")); err != nil {
			t.Errorf("remove mixed-substrate control-plane state: %v", err)
		}
	}
	// A prior failed acceptance cannot be allowed to supply the baseline for
	// this one. Destroy must itself succeed; silently continuing would make
	// a stale injection look like a passing reset.
	destroy()
	defer destroy()

	deploy := func(pass int) {
		out, err := runTwinet(binary, 8*time.Minute,
			"deploy", "-m", manifest, "--solve", "--pull", "never", "--workers", "4")
		if err != nil {
			t.Fatalf("deploy pass %d failed: %v\n%s", pass, err, out)
		}
		verifyRequiredDaemons(t, binary, manifest)
	}
	deploy(1)
	deploy(2)
	verifyRouterPrivilegeSplit(t)
	verifyRoutingContract(t, binary, manifest)

	cases := []struct {
		name string
		args []string
	}{
		{"p4_table_entry_missing", []string{"--as", "1", "--device", "P4"}},
		{"p4_table_entry_misconfig", []string{"--as", "1", "--device", "P4"}},
		{"p4_aggressive_detection_thresholds", []string{"--as", "1", "--device", "P4"}},
		{"p4_compilation_error_parser_state", []string{"--as", "1", "--device", "P4"}},
		{"p4_header_definition_error", []string{"--as", "1", "--device", "P4"}},
		{"bmv2_switch_down", []string{"--as", "1", "--device", "P4"}},
		{"sdn_controller_crash", []string{"--device", "svc/of"}},
		{"southbound_port_block", []string{"--device", "svc/of"}},
		{"southbound_port_mismatch", []string{"--as", "1", "--device", "FAB_S1"}},
		{"load_balancer_overload", []string{"--device", "svc/lb"}},
		{"mpls_label_limit_exceeded", []string{"--as", "1", "--device", "R1", "--param", "limit=64"}},
		// The sidecar must not regress the pre-existing FRR lifecycle fault.
		{"frr_service_down", []string{"--as", "1", "--device", "R1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"fault", "inject", "-m", manifest, tc.name}, tc.args...)
			if out, err := runTwinet(binary, 4*time.Minute, args...); err != nil {
				t.Fatalf("inject failed: %v\n%s", err, out)
			}
			if out, err := runTwinet(binary, 3*time.Minute,
				"fault", "verify", "-m", manifest, tc.name); err != nil {
				t.Fatalf("manifest verify failed: %v\n%s", err, out)
			}
			if out, err := runTwinet(binary, 5*time.Minute,
				"fault", "resolve", "-m", manifest, "--all"); err != nil {
				t.Fatalf("resolve/baseline verification failed: %v\n%s", err, out)
			}
		})
	}

	out, err := runTwinet(binary, time.Minute, "fault", "status", "-m", manifest)
	if err != nil {
		t.Fatalf("read final fault ledger: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing is injected") {
		t.Fatalf("native round trips left live fault state:\n%s", out)
	}
}

func requireFaultIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("TWINET_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE") != "1" {
		t.Fatal("faultintegration requires TWINET_FAULT_INTEGRATION_ALLOW_DESTRUCTIVE=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("faultintegration requires root; namespace wiring and label-space operations are privileged")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("faultintegration requires docker")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Fatalf("faultintegration requires a reachable Docker daemon: %v", err)
	}
}

func verifyRequiredDaemons(t *testing.T, _ string, _ string) {
	t.Helper()
	const check = `for d in zebra bgpd ospfd ospf6d ldpd; do
  pidof "$d" >/dev/null || { echo "missing $d" >&2; exit 1; }
done`
	for _, container := range []string{
		"twinet-mixed-substrate-as1-r1-frr",
		"twinet-mixed-substrate-as1-r2-frr",
	} {
		out, err := runDocker(time.Minute, "exec", container, "sh", "-c", check)
		if err != nil {
			t.Fatalf("%s does not keep every manifest-required daemon running: %v\n%s", container, err, out)
		}
	}
}

func verifyRouterPrivilegeSplit(t *testing.T) {
	t.Helper()
	for _, router := range []string{
		"twinet-mixed-substrate-as1-r1",
		"twinet-mixed-substrate-as1-r2",
	} {
		out, err := runDocker(time.Minute, "inspect", router, "--format", "{{json .HostConfig.CapAdd}}")
		if err != nil {
			t.Fatalf("inspect %s capabilities: %v\n%s", router, err, out)
		}
		if strings.Contains(out, "SYS_ADMIN") {
			t.Fatalf("student router shell %s has forbidden SYS_ADMIN: %s", router, out)
		}
		processes, err := runDocker(time.Minute, "exec", router, "sh", "-c", "pidof zebra || true")
		if err != nil {
			t.Fatalf("inspect %s process namespace: %v\n%s", router, err, processes)
		}
		if strings.TrimSpace(processes) != "" {
			t.Fatalf("student router shell %s can see private FRR daemon PID(s): %s", router, processes)
		}
	}
	for _, control := range []string{
		"twinet-mixed-substrate-as1-r1-frr",
		"twinet-mixed-substrate-as1-r2-frr",
	} {
		out, err := runDocker(time.Minute, "inspect", control, "--format", "{{json .HostConfig.CapAdd}}")
		if err != nil {
			t.Fatalf("inspect %s capabilities: %v\n%s", control, err, out)
		}
		if !strings.Contains(out, "SYS_ADMIN") {
			t.Fatalf("private FRR control %s lacks the capability Alpine FRR requires: %s", control, out)
		}
	}
}

func verifyRoutingContract(t *testing.T, binary, manifest string) {
	t.Helper()
	config, err := runTwinet(binary, time.Minute, "exec", "-m", manifest, "as1/R1", "--",
		"vtysh", "-c", "show running-config")
	if err != nil {
		t.Fatalf("vtysh cannot reach the private FRR control socket: %v\n%s", err, config)
	}
	for _, want := range []string{"router bgp 1", "router ospf", "mpls ldp"} {
		if !strings.Contains(config, want) {
			t.Fatalf("vtysh configuration lacks %q:\n%s", want, config)
		}
	}

	deadline := time.Now().Add(2 * time.Minute)
	var bgp, ospf string
	for time.Now().Before(deadline) {
		bgp, _ = runTwinet(binary, time.Minute, "exec", "-m", manifest, "as1/R1", "--",
			"vtysh", "-c", "show ip bgp summary")
		ospf, _ = runTwinet(binary, time.Minute, "exec", "-m", manifest, "as1/R1", "--",
			"vtysh", "-c", "show ip ospf neighbor")
		if strings.Contains(ospf, "Full") && strings.Contains(bgp, "1.150.0.2") &&
			!strings.Contains(bgp, " Active") && !strings.Contains(bgp, " Idle") {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !strings.Contains(ospf, "Full") {
		t.Fatalf("OSPF did not converge through the P4 data plane:\n%s", ospf)
	}
	if !strings.Contains(bgp, "1.150.0.2") || strings.Contains(bgp, " Active") || strings.Contains(bgp, " Idle") {
		t.Fatalf("iBGP did not converge through the P4 data plane:\n%s", bgp)
	}
	// Zebra can report the OSPF route before the kernel FIB transaction is
	// visible to a freshly exec'd probe, especially while a hardened OVS
	// datapath finishes its handler startup. Prove the data plane rather than
	// mistaking that short control-plane/FIB handoff for a routing failure.
	var (
		ping    string
		pingErr error
	)
	pingDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(pingDeadline) {
		ping, pingErr = runTwinet(binary, time.Minute, "exec", "-m", manifest, "as1/R1", "--",
			"ping", "-n", "-c", "2", "-W", "1", "1.150.0.2")
		if pingErr == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("routed loopback data-plane probe failed: %v\n%s", pingErr, ping)
}

func runDocker(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("docker %s: %w", strings.Join(args, " "), ctx.Err())
	}
	return string(out), err
}

func runTwinet(binary string, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: %w", strings.Join(args, " "), ctx.Err())
	}
	return string(out), err
}
