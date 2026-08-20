package grade

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// The datagram probes are the only ones in the grader with no retransmission
// under them. A ping sends two echo requests and asks for one; a connection is
// retried by the kernel inside the timeout it is given. A datagram is sent
// once, and if it is dropped -- by a full socket buffer, a neighbour entry
// being resolved, a scheduler delay on a loaded node -- the check reports that
// something on the path is filtering by protocol.
//
// That is not hypothetical. Grading sixteen copies of the reference solution
// through two class runs deducted a mark from two of them, on a different pair
// of hosts each time.
//
// These tests run the script the probe actually builds, through a real shell,
// against a stub `nc` that records how it was called. Asserting on the string
// would prove only that the string had not changed; running it proves the
// shell is valid and that the probe does what its comment claims.

// stubNC puts an `nc` on PATH that appends its arguments to a log and behaves
// as the test asks, and returns the directory holding both.
func stubNC(t *testing.T, body string) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	log = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n" + body + "\n"
	path := filepath.Join(dir, "nc")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, log
}

// runningEnv answers a probe by running the command through a real shell with
// the stub `nc` ahead of everything else on PATH.
func runningEnv(t *testing.T, dir string) *Env {
	t.Helper()
	return &Env{Exec: func(ctx context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) != 3 || cmd[0] != "sh" || cmd[1] != "-c" {
			t.Fatalf("a datagram probe should be one shell command, got %q", cmd)
		}
		c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd[2])
		c.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("the probe script did not run: %v\n%s\n%s", err, cmd[2], out)
		}
		return rt.ExecResult{Stdout: string(out)}, nil
	}}
}

func callsIn(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// One datagram is not evidence that a network discards the protocol.
func TestADatagramIsSentMoreThanOnce(t *testing.T) {
	dir, log := stubNC(t, "exit 0")
	env := runningEnv(t, dir)

	if !sendDatagrams(context.Background(), env, "as3/BOS_host", datagramProbe{
		srcAddr: "3.101.0.1", dstAddr: "3.102.0.1", port: "33456",
	}) {
		t.Fatal("the sender got its datagrams away; it should say so")
	}
	calls := callsIn(t, log)
	if len(calls) != datagramAttempts {
		t.Fatalf("want %d datagrams behind a claim that none arrived, got %d:\n%s",
			datagramAttempts, len(calls), strings.Join(calls, "\n"))
	}
	if datagramAttempts < 2 {
		t.Fatal("a single attempt is the defect this exists to prevent")
	}
}

// Finding 116, which is easy to repeat here: a source port is not a path. Where
// equal-cost paths exist, a retry from a fresh port is hashed afresh and lands
// on whichever path works, so a fault that discards one path clears itself.
func TestEveryAttemptLeavesFromTheSameSourcePort(t *testing.T) {
	dir, log := stubNC(t, "exit 0")
	env := runningEnv(t, dir)

	sendDatagrams(context.Background(), env, "as3/BOS_host", datagramProbe{
		srcAddr: "3.101.0.1", dstAddr: "3.102.0.1", port: "33456",
	})
	ports := map[string]bool{}
	for _, c := range callsIn(t, log) {
		f := strings.Fields(c)
		for i, a := range f {
			if a == "-p" && i+1 < len(f) {
				ports[f[i+1]] = true
			}
		}
	}
	if len(ports) != 1 {
		t.Fatalf("every attempt must take the path the first one took, so all of them "+
			"must leave from one source port; got %d distinct: %v", len(ports), ports)
	}
	for p := range ports {
		if n, err := strconv.Atoi(p); err != nil || n <= 1024 {
			t.Fatalf("source port %q is not a usable ephemeral port", p)
		}
	}
}

// A datagram that could not be sent is not a datagram that was lost. The
// grader picks the source port, so a collision is the grader's fault, and a
// probe that cannot bind falls back rather than accusing the submission.
func TestABindCollisionFallsBackInsteadOfAccusing(t *testing.T) {
	dir, log := stubNC(t, `case "$*" in
  *-p*) echo "nc: bind: Address already in use" >&2; exit 1 ;;
  *) exit 0 ;;
esac`)
	env := runningEnv(t, dir)

	if !sendDatagrams(context.Background(), env, "as3/BOS_host", datagramProbe{
		srcAddr: "3.101.0.1", dstAddr: "3.102.0.1", port: "33456",
	}) {
		t.Fatal("the unbound attempts got away; a bind collision is not a lost datagram")
	}
	var unbound int
	for _, c := range callsIn(t, log) {
		if !strings.Contains(c, "-p ") {
			unbound++
		}
	}
	if unbound != datagramAttempts {
		t.Fatalf("every attempt that could not bind should have been sent anyway, "+
			"want %d unbound, got %d", datagramAttempts, unbound)
	}
}

// And when nothing at all could be sent, the caller must be told, so that it
// stays silent rather than reporting a filter it has no evidence for.
func TestASenderThatSentNothingIsNotEvidence(t *testing.T) {
	dir, _ := stubNC(t, `echo "nc: bind: Cannot assign requested address" >&2; exit 1`)
	env := runningEnv(t, dir)

	if sendDatagrams(context.Background(), env, "as3/BOS_host", datagramProbe{
		srcAddr: "3.101.0.1", dstAddr: "3.102.0.1", port: "33456",
	}) {
		t.Fatal("no datagram left the sender, so there is nothing to conclude")
	}
}

// A caller that does not know the sender's address cannot pin the port, and
// must still send something rather than nothing.
func TestAProbeWithNoKnownSourceAddressStillSends(t *testing.T) {
	dir, log := stubNC(t, "exit 0")
	env := runningEnv(t, dir)

	if !sendDatagrams(context.Background(), env, "as1/site_host", datagramProbe{
		dstAddr: "10.0.0.1", port: "33456",
	}) {
		t.Fatal("the datagrams were sent")
	}
	calls := callsIn(t, log)
	if len(calls) != datagramAttempts {
		t.Fatalf("want %d attempts, got %d", datagramAttempts, len(calls))
	}
	for _, c := range calls {
		if strings.Contains(c, "-s ") || strings.Contains(c, "-p ") {
			t.Fatalf("nothing to bind to, so nothing should be bound: %q", c)
		}
	}
}

// The IPv6 tunnel check sends its datagram over v6, and a probe that quietly
// sent it over v4 would report on a path the question is not about.
func TestAnIPv6ProbeIsSentOverIPv6(t *testing.T) {
	dir, log := stubNC(t, "exit 0")
	env := runningEnv(t, dir)

	sendDatagrams(context.Background(), env, "as1/HOST", datagramProbe{
		dstAddr: "2001:db8::1", port: "33456", v6: true,
	})
	calls := callsIn(t, log)
	if len(calls) == 0 {
		t.Fatal("no datagram was sent at all")
	}
	for _, c := range calls {
		if !strings.Contains(c, "-6") {
			t.Fatalf("the v6 probe must go over v6: %q", c)
		}
	}
}
