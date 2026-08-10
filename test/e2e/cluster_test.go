//go:build e2e

// Package e2e exercises Twinet against a real cluster.
//
// These tests exist because the failures that matter in this system are not
// reachable by unit test. Every serious bug found during development came from
// running against real containers: a token bucket whose burst was interpreted
// in scheduler ticks, a VXLAN that duplicated every flooded frame, a fault that
// reported success without taking effect because busybox's pgrep matches
// nothing, an undo that left a link faster than the topology says. None of
// those are visible from a mock.
//
// They are behind a build tag because they need a cluster. Run them with
// `make e2e`, having set TWINET_LAB to a deployed lab manifest and TWINET_TOKEN
// to the agent token.
package e2e

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func labDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TWINET_LAB")
	if dir == "" {
		dir = "../../examples/cos461"
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no lab at %s: %v", dir, err)
	}
	if os.Getenv("TWINET_TOKEN") == "" {
		t.Skip("TWINET_TOKEN is not set; these tests need a running cluster")
	}
	return dir
}

func twinet(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	bin := os.Getenv("TWINET_BIN")
	if bin == "" {
		bin = "../../bin/twinet"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestClusterIsHealthy(t *testing.T) {
	dir := labDir(t)
	out, err := twinet(t, "node", "status", "-m", dir)
	if err != nil {
		t.Fatalf("node status failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[1] != "ok" {
			t.Errorf("node %s is %s, not ok", f[0], f[1])
		}
	}
}

// Every registered fault must inject, be observable, and be undone. A fault
// that cannot be undone contaminates every later episode, and the contamination
// is invisible: the next episode's result is attributed to whatever it injected.
func TestEveryFaultRoundTrips(t *testing.T) {
	dir := labDir(t)

	list, err := twinet(t, "fault", "list")
	if err != nil {
		t.Fatalf("listing faults: %v\n%s", err, list)
	}

	type spec struct {
		name string
		args []string
	}
	var specs []spec
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "FAULT" || strings.Contains(line, "registered") {
			continue
		}
		name := f[0]
		args := []string{"--as", "5", "--device", "CHI"}
		switch {
		case strings.HasPrefix(name, "host_"):
			args = []string{"--as", "5", "--device", "CHI_host"}
		}
		// Faults that need a subject are given one, rather than being skipped:
		// an untested fault is one that will fail the first time it matters.
		switch name {
		case "host_ip_conflict":
			args = append(args, "--param", "victim=as5/CHI")
		case "bgp_hijacking":
			args = []string{"--as", "5", "--device", "MSP", "--peer", "3"}
		case "bgp_peer_asn_misconfig":
			// Only a border router has an external neighbour to misconfigure.
			args = []string{"--as", "5", "--device", "MSP"}
		}
		specs = append(specs, spec{name, args})
	}
	if len(specs) < 15 {
		t.Fatalf("only found %d faults; the list output was not understood:\n%s", len(specs), list)
	}

	for _, s := range specs {
		t.Run(s.name, func(t *testing.T) {
			args := append([]string{"fault", "inject", "-m", dir, s.name}, s.args...)
			if out, err := twinet(t, args...); err != nil {
				t.Fatalf("inject: %v\n%s", err, out)
			}
			// Resolve re-verifies and fails closed, so a clean exit here is
			// evidence that the fault is genuinely gone rather than merely
			// that an undo command ran.
			out, err := twinet(t, "fault", "resolve", "-m", dir, "--all")
			if err != nil {
				t.Fatalf("resolve: %v\n%s", err, out)
			}
			if strings.Contains(out, "could not be resolved") {
				t.Fatalf("the lab was left contaminated:\n%s", out)
			}
		})
	}
}

// An agent being evaluated on root-cause analysis runs inside the lab. If the
// answer is reachable from in there, the measurement is worthless, and the leak
// would be silent: the score would simply be higher than it should be.
func TestGroundTruthIsNotReachableFromInsideTheLab(t *testing.T) {
	dir := labDir(t)

	if out, err := twinet(t, "fault", "inject", "-m", dir,
		"ospf_neighbor_missing", "--as", "5", "--device", "CHI"); err != nil {
		t.Fatalf("inject: %v\n%s", err, out)
	}
	defer func() {
		if out, err := twinet(t, "fault", "resolve", "-m", dir, "--all"); err != nil {
			t.Errorf("cleanup failed, the lab is contaminated: %v\n%s", err, out)
		}
	}()

	for _, probe := range []string{"ospf_neighbor_missing", "root_cause", "ground_truth", "twinet.fault"} {
		out, _ := twinet(t, "exec", "-m", dir, "as5/CHI", "--",
			"sh", "-c", "grep -rl '"+probe+"' /etc /run /var 2>/dev/null | head -3; env | grep -i '"+probe+"'")
		if strings.TrimSpace(stripCLINoise(out)) != "" {
			t.Errorf("the answer is readable from inside the lab via %q:\n%s", probe, out)
		}
	}
}

func stripCLINoise(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "twinet:") || strings.TrimSpace(l) == "" {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

// A traffic-control fault replaces the root qdisc, which is also where the
// link's own bandwidth and delay live. An undo that merely deletes it leaves
// the link faster and closer than the topology says, and nothing reports it.
func TestUndoingAShapingFaultRestoresTheDeclaredLink(t *testing.T) {
	dir := labDir(t)
	const dev, iface = "as5/CHI", "port_MSP"

	before, err := twinet(t, "exec", "-m", dir, dev, "--", "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		t.Fatalf("reading the baseline: %v\n%s", err, before)
	}

	if out, err := twinet(t, "fault", "inject", "-m", dir, "link_bandwidth_throttling",
		"--as", "5", "--device", "CHI", "--iface", iface); err != nil {
		t.Fatalf("inject: %v\n%s", err, out)
	}
	if out, err := twinet(t, "fault", "resolve", "-m", dir, "--all"); err != nil {
		t.Fatalf("resolve: %v\n%s", err, out)
	}

	after, err := twinet(t, "exec", "-m", dir, dev, "--", "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		t.Fatalf("reading the restored link: %v\n%s", err, after)
	}
	if normaliseQdisc(before) != normaliseQdisc(after) {
		t.Errorf("the link was not restored to what the topology declares.\nbefore:\n%s\nafter:\n%s",
			normaliseQdisc(before), normaliseQdisc(after))
	}
}

// normaliseQdisc drops the fields that legitimately differ between two
// identical qdiscs: netem seeds a fresh generator each time it is installed.
func normaliseQdisc(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(l, "qdisc") {
			continue
		}
		f := strings.Fields(l)
		var out []string
		for i := 0; i < len(f); i++ {
			if f[i] == "seed" {
				i++
				continue
			}
			out = append(out, f[i])
		}
		keep = append(keep, strings.Join(out, " "))
	}
	return strings.Join(keep, "\n")
}
