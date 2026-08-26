//go:build linux

package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// The unit tests assert what the replay builder emits. This one asserts that a
// real kernel accepts it.
//
// It builds a namespace that looks like a converged router -- nexthop objects
// with a group over two links, an ECMP route through it, a 6in4 tunnel with
// IPv6 routes over it, a VLAN sub-interface, a VRF, and blackhole/unreachable
// routes -- reads it with the production capture, replays it into a namespace
// that has only the interfaces, and requires every command to be accepted and
// the result to match the capture fact for fact.
//
// Deliberately root-gated, like the netx overlay test: it exercises the kernel
// rather than an implementation detail.
func TestCapturedStateReplaysIntoARealNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is not installed")
	}
	source := namespaceRuntime(t, "twinet-replay-src")
	for _, command := range []string{
		"ip link add port_NYC type dummy",
		"ip link add port_CHI type dummy",
		"ip link set port_NYC up",
		"ip link set port_CHI up",
		"ip addr add 9.0.1.1/24 dev port_NYC",
		"ip addr add 9.0.2.1/24 dev port_CHI",
		"ip link add link port_NYC name port_NYC.10 type vlan id 10",
		"ip link set port_NYC.10 up",
		"ip addr add 9.10.0.1/24 dev port_NYC.10",
		"ip link add vrf-blue type vrf table 100",
		"ip link set vrf-blue up",
		"ip tunnel add tun6 mode sit remote 9.0.1.2 local 9.0.1.1 ttl 64",
		"ip link set tun6 up",
		"ip -6 addr add 2001:db8:1::1/64 dev tun6",
		// FRR installs through nexthop objects, so the capture must survive
		// both the single-path and the grouped spelling of one.
		"ip nexthop add id 128 via 9.0.1.2 dev port_NYC",
		"ip nexthop add id 129 via 9.0.2.2 dev port_CHI",
		"ip nexthop add id 140 group 128/129",
		"ip route add 1.0.0.0/8 nhid 128 metric 20",
		"ip route add 9.0.11.0/24 nhid 140 metric 20",
		"ip route add 9.0.12.0/24 via 9.0.1.2 dev port_NYC metric 20 src 9.0.1.1",
		"ip route add default via 9.0.1.2 dev port_NYC metric 100",
		"ip route add blackhole 9.9.9.0/24",
		"ip route add unreachable 9.9.8.0/24 metric 5",
		"ip route add 9.0.13.0/24 via 9.0.3.2 dev port_CHI metric 20 onlink",
		"ip -6 route add 10:201:1::/48 dev tun6 metric 1024",
		"ip -6 route add 2001:db8:9::/64 metric 100 nexthop via 2001:db8:1::2 dev tun6 weight 1 " +
			"nexthop via 2001:db8:1::3 dev tun6 weight 2",
	} {
		mustRun(t, source, command)
	}

	device := &model.Device{ID: "as9/MSP", ASN: 9, Kind: model.KindHost, Container: "msp"}
	captured, err := Capture(context.Background(), source, device, "cos461", "topology")
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, snapshot := range captured {
		if snapshot.Kind == state.KindAddrs {
			body = string(snapshot.Content)
		}
	}
	if body == "" {
		t.Fatal("the namespace was captured as empty")
	}
	t.Logf("captured facts:\n%s", body)
	if strings.Contains(body, "nhid") || strings.Contains(body, `\`) {
		t.Fatalf("the kernel's own bookkeeping survived into the snapshot:\n%s", body)
	}

	// A replacement container: the interfaces the platform wires, and nothing
	// the student put on them.
	destination := namespaceRuntime(t, "twinet-replay-dst")
	for _, command := range []string{
		"ip link add port_NYC type dummy",
		"ip link add port_CHI type dummy",
		"ip link set port_NYC up",
		"ip link set port_CHI up",
		// The tunnel is the student's, so the restore has to build it.
		"ip tunnel add tun6 mode sit remote 9.0.1.2 local 9.0.1.1 ttl 64",
		"ip link set tun6 up",
		"ip -6 addr add 2001:db8:1::1/64 dev tun6",
	} {
		mustRun(t, destination, command)
	}
	commands := addrReplay(body)
	if len(commands) == 0 {
		t.Fatal("the snapshot replayed as nothing")
	}
	for _, command := range commands {
		result, err := destination.Exec(context.Background(), device.Container,
			rt.ExecCmd{Cmd: []string{"sh", "-c", command}})
		if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("a real kernel rejected a replayed command:\n  %s\n  exit %d: %s",
				command, result.ExitCode, strings.TrimSpace(result.Stderr))
		}
	}

	// The restore is only exact if reading the destination back gives the same
	// facts, which is the same comparison the durability verifier makes.
	replayed, err := Capture(context.Background(), destination, device, "cos461", "topology")
	if err != nil {
		t.Fatal(err)
	}
	var after string
	for _, snapshot := range replayed {
		if snapshot.Kind == state.KindAddrs {
			after = string(snapshot.Content)
		}
	}
	if after != body {
		t.Fatalf("the replayed namespace does not match the captured one:\n%s\n--- replayed ---\n%s",
			body, after)
	}
}

// namespaceRuntime runs commands inside a throwaway network namespace, which
// is enough of a Runtime for Capture and the replay to work against.
func namespaceRuntime(t *testing.T, name string) *netnsRuntime {
	t.Helper()
	name = fmt.Sprintf("%s-%d", name, os.Getpid())
	_ = exec.Command("ip", "netns", "del", name).Run()
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Skipf("cannot create a network namespace: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	return &netnsRuntime{name: name}
}

func mustRun(t *testing.T, r *netnsRuntime, command string) {
	t.Helper()
	result, err := r.Exec(context.Background(), "", rt.ExecCmd{Cmd: []string{"sh", "-c", command}})
	if err != nil {
		t.Fatalf("%q: %v", command, err)
	}
	if result.ExitCode != 0 {
		t.Skipf("this kernel cannot build the fixture (%q exited %d: %s)",
			command, result.ExitCode, strings.TrimSpace(result.Stderr))
	}
}

type netnsRuntime struct {
	rt.Runtime
	name string
}

func (n *netnsRuntime) Exec(ctx context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	args := append([]string{"netns", "exec", n.name}, cmd.Cmd...)
	command := exec.CommandContext(ctx, "ip", args...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	result := rt.ExecResult{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errorsAs(err, &exitErr):
		result.ExitCode = exitErr.ExitCode()
	default:
		return result, err
	}
	return result, nil
}

func (n *netnsRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func errorsAs(err error, target **exec.ExitError) bool {
	exitErr, ok := err.(*exec.ExitError)
	if ok {
		*target = exitErr
	}
	return ok
}
