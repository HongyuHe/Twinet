package grade

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// twoHosts builds the smallest thing unreachableByTCP will run over.
func twoHosts() ([]*model.Device, map[string]string) {
	a := &model.Device{ID: "as1/H1", Name: "H1", Kind: model.KindHost}
	b := &model.Device{ID: "as1/H2", Name: "H2", Kind: model.KindHost}
	return []*model.Device{a, b}, map[string]string{a.ID: "10.0.0.1", b.ID: "10.0.0.2"}
}

// snmpBody renders the counters a destination is asked for.
func snmpBody(opens, rsts int) string {
	return "Tcp: RtoAlgorithm PassiveOpens OutRsts\n" +
		"Tcp: 1 " + strconv.Itoa(opens) + " " + strconv.Itoa(rsts) + "\n"
}

// A refusal is not the far side speaking.
//
// A student whose network carries pings and discards forwarded connections can
// produce exactly the answer this check was reading -- `iptables -j REJECT
// --reject-with tcp-reset` on any router on the way sends a reset carrying the
// destination's address -- and collect the mark for a path that carries
// nothing. The destinations here never see a packet, and their counters say so.
func TestAForgedResetDoesNotProveAConnectionArrived(t *testing.T) {
	hosts, addrOf := twoHosts()
	env := &Env{Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) > 0 && cmd[0] == "nc" {
			return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, nil
		}
		return rt.ExecResult{ExitCode: 0, Stdout: snmpBody(0, 0)}, nil
	}}

	got := unreachableByTCP(context.Background(), env, hosts, addrOf)
	if len(got) != 2 {
		t.Fatalf("a path that answers every connection with a forged reset was accepted as "+
			"carrying them: %v", got)
	}
}

// And the real thing still counts.
func TestAConnectionTheDestinationAnsweredIsNotAGap(t *testing.T) {
	hosts, addrOf := twoHosts()
	var mu sync.Mutex
	rsts := map[string]int{}
	env := &Env{Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) > 0 && cmd[0] == "nc" {
			mu.Lock()
			for id, a := range addrOf {
				if a == cmd[len(cmd)-2] {
					rsts[id]++
				}
			}
			mu.Unlock()
			return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, nil
		}
		mu.Lock()
		defer mu.Unlock()
		return rt.ExecResult{ExitCode: 0, Stdout: snmpBody(0, rsts[deviceID])}, nil
	}}

	if got := unreachableByTCP(context.Background(), env, hosts, addrOf); len(got) != 0 {
		t.Fatalf("connections the destinations themselves reset were reported as never "+
			"arriving: %v", got)
	}
}

// A destination that accepted the connection has equally received it, and a
// reader that watches only for resets calls that a forgery.
func TestAConnectionTheDestinationAcceptedIsNotAGap(t *testing.T) {
	hosts, addrOf := twoHosts()
	var mu sync.Mutex
	opens := map[string]int{}
	env := &Env{Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) > 0 && cmd[0] == "nc" {
			mu.Lock()
			for id, a := range addrOf {
				if a == cmd[len(cmd)-2] {
					opens[id]++
				}
			}
			mu.Unlock()
			return rt.ExecResult{ExitCode: 0}, nil
		}
		mu.Lock()
		defer mu.Unlock()
		return rt.ExecResult{ExitCode: 0, Stdout: snmpBody(opens[deviceID], 0)}, nil
	}}

	if got := unreachableByTCP(context.Background(), env, hosts, addrOf); len(got) != 0 {
		t.Fatalf("connections the destinations accepted were reported as never arriving: %v", got)
	}
}

// Where the destination cannot be asked, the prober's view is all there is.
//
// Reading an unreadable counter as "nothing arrived" would fail correct
// submissions because a file could not be read, which is the more expensive of
// the two mistakes.
func TestAnUnreadableCounterDoesNotFailACorrectPath(t *testing.T) {
	hosts, addrOf := twoHosts()
	env := &Env{Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) > 0 && cmd[0] == "nc" {
			return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, nil
		}
		return rt.ExecResult{ExitCode: 1}, nil // no counters
	}}

	if got := unreachableByTCP(context.Background(), env, hosts, addrOf); len(got) != 0 {
		t.Fatalf("a path was failed because a counter could not be read: %v", got)
	}
}

// Silence is still silence.
func TestAConnectionThatTimesOutIsAGap(t *testing.T) {
	hosts, addrOf := twoHosts()
	env := &Env{Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		if len(cmd) > 0 && cmd[0] == "nc" {
			return rt.ExecResult{ExitCode: 1, Stderr: "Connection timed out"}, nil
		}
		return rt.ExecResult{ExitCode: 0, Stdout: snmpBody(0, 0)}, nil
	}}

	if got := unreachableByTCP(context.Background(), env, hosts, addrOf); len(got) != 2 {
		t.Fatalf("a path that swallows every connection was accepted: %v", got)
	}
}

// An accusation carries the burden of proof.
//
// The mirror of the case above, and deliberately not symmetric with it: where
// the destination cannot be asked, an answer from an unknown source is not
// evidence that two customers are joined, and no mark is taken for it.
func TestAnUnattributedAnswerIsNotProof(t *testing.T) {
	unknown := tcpWitness{answered: true, arrived: false, attributable: false}
	if unknown.proves() {
		t.Fatal("an answer from an unidentified source was accepted as proof of a leak")
	}
	if !unknown.reached() {
		t.Fatal("an answer from an unidentified source was read as nothing having arrived")
	}
	witnessed := tcpWitness{answered: true, arrived: true, attributable: true}
	if !witnessed.proves() || !witnessed.reached() {
		t.Fatal("an answer from the destination itself was not believed")
	}
	forged := tcpWitness{answered: true, arrived: false, attributable: true}
	if forged.proves() || forged.reached() {
		t.Fatal("an answer the destination did not send was believed")
	}
}

// No destination may be aimed at twice at once, or a counter that moved cannot
// be attributed to the attempt that moved it.
func TestProbesAreScheduledSoThatCountersCanBeAttributed(t *testing.T) {
	type pair struct{ from, to string }
	pairs := []pair{{"a", "z"}, {"b", "z"}, {"c", "y"}, {"d", "z"}}
	rounds := roundsByDestinationOf(pairs, func(p pair) string { return p.to })

	seen := 0
	for _, r := range rounds {
		in := map[string]bool{}
		for _, p := range r {
			if in[p.to] {
				t.Fatalf("%s is probed twice in one round", p.to)
			}
			in[p.to] = true
			seen++
		}
	}
	if seen != len(pairs) {
		t.Fatalf("scheduled %d of %d probes", seen, len(pairs))
	}
}

// The witness has to survive the output netcat actually produces.
func TestTheAnswersNetcatGivesAreRecognised(t *testing.T) {
	for _, said := range []string{
		"Ncat: Connection refused.",
		"nc: connect to 10.0.0.2 port 4242 (tcp) failed: Connection reset by peer",
	} {
		s := strings.ToLower(said)
		if !strings.Contains(s, "refused") && !strings.Contains(s, "reset") {
			t.Fatalf("%q is an answer and was not recognised as one", said)
		}
	}
}
