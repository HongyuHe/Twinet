package grade

import (
	"context"
	"strings"
)

// Who answered a connection.
//
// A program making a TCP connection learns whether it got an answer. It does
// not learn who sent it, and it cannot: a reset carries the destination's
// address because whoever wrote it put that address on it. `iptables -j REJECT
// --reject-with tcp-reset` on any router along the way forges one, an ICMP
// unreachable from a router is reported to the caller in the same words, and
// both are indistinguishable from the destination declining the connection.
//
// So "refused" is not the far side speaking. It is somebody speaking. Checks
// that read it as the far side were wrong in both directions at once: one read
// a forged reset as proof that two customers who are properly separated were
// exchanging traffic, and two read it as proof that packets arrive somewhere
// they never reached.
//
// The destination's own kernel is the witness that cannot be forged from the
// path. It counts the resets it sends and the connections it accepts, and
// neither moves unless the packets got there.

// tcpWitness is what one connection attempt established.
type tcpWitness struct {
	// answered is what the prober saw: an answer of some kind, from somebody.
	answered bool
	// arrived is what the destination recorded: the attempt reached it.
	arrived bool
	// attributable is whether the destination could be asked at all. Without
	// it, arrived is not a negative finding, merely an unknown.
	attributable bool
}

// reached reports whether the attempt is known to have got there.
//
// Where the destination could be asked, its answer settles it. Where it could
// not, the prober's view is all there is; treating that as "did not arrive"
// would fail correct submissions because a file could not be read.
func (w tcpWitness) reached() bool {
	if w.attributable {
		return w.arrived
	}
	return w.answered
}

// proves reports whether the attempt is evidence strong enough to take a mark
// away with.
//
// The opposite direction from reached, and deliberately not its mirror. An
// accusation carries the burden of proof: where the destination could not be
// asked, an answer from an unknown source establishes nothing, and a submission
// is not penalised for it. Isolation has two other witnesses -- the routing
// tables and the datagram counters -- so nothing rests on this alone.
func (w tcpWitness) proves() bool {
	return w.attributable && w.arrived
}

// tcpAnswers reads a host's own record of connection attempts that reached it:
// the resets it sent, plus the connections it accepted. Nothing on the path can
// raise either without the packets arriving.
func tcpAnswers(ctx context.Context, env *Env, device string) (int, bool) {
	res, err := env.Probe(ctx, device, []string{"cat", "/proc/net/snmp"})
	if err != nil || res.ExitCode != 0 {
		return 0, false
	}
	rsts, okR := snmpCounter(res.Stdout, "Tcp:", "OutRsts")
	opens, okO := snmpCounter(res.Stdout, "Tcp:", "PassiveOpens")
	if !okR || !okO {
		return 0, false
	}
	return rsts + opens, true
}

// tryConnection makes one connection from src to addr and reports both what the
// prober saw and what the host owning that address recorded.
//
// The destination is read before and after, so a counter that moved is the
// attempt that moved it -- which holds only if nothing else is aimed at that
// destination at the same time. Callers probing many pairs at once must
// schedule them so that no destination appears twice in a round.
func tryConnection(ctx context.Context, env *Env, src, dstDevice, addr, port string) (
	tcpWitness, bool) {
	before, okB := tcpAnswers(ctx, env, dstDevice)
	res, err := env.Probe(ctx, src, []string{"nc", "-v", "-w", "3", "-z", addr, port})
	if err != nil {
		return tcpWitness{}, false // the machinery failed, which is not a verdict
	}
	after, okA := tcpAnswers(ctx, env, dstDevice)

	said := strings.ToLower(res.Stderr + res.Stdout)
	return tcpWitness{
		answered: res.ExitCode == 0 ||
			strings.Contains(said, "refused") || strings.Contains(said, "reset"),
		arrived:      okB && okA && after > before,
		attributable: okB && okA,
	}, true
}

// roundsByDestinationOf schedules directed probes so that no destination is
// aimed at twice at once, which is what makes a counter that moved
// attributable to the attempt that moved it.
func roundsByDestinationOf[T any](items []T, dst func(T) string) [][]T {
	var rounds [][]T
	left := append([]T(nil), items...)
	for len(left) > 0 {
		seen := map[string]bool{}
		var round, rest []T
		for _, it := range left {
			if seen[dst(it)] {
				rest = append(rest, it)
				continue
			}
			seen[dst(it)] = true
			round = append(round, it)
		}
		rounds = append(rounds, round)
		left = rest
	}
	return rounds
}
