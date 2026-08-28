package grade

import (
	"context"
	"errors"
	"strings"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// stillRunning marks a capture that was still watching when it was read. It is
// what the reader writes ahead of the capture's own output; a capture that had
// already stopped is marked EARLY=1 and is not a witness to anything.
func stillRunning(out string) string { return "EARLY=0\n" + out }

// The banner tcpdump writes to standard error when a capture starts, taken
// verbatim from a lab router.
const tapBanner = `tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
`

// Frames captured on a lab router, verbatim.
const (
	frameFromNYC = "22:48:24.720723 port_NYC In  IP 3.152.0.1.39125 > 3.154.0.1.33434: " +
		"Flags [S], seq 3356439781, win 64860, options [mss 1410], length 0\n"
	frameFromATL = "22:50:59.162973 port_ATL In  IP 3.156.0.1.36229 > 3.153.0.1.33477: " +
		"Flags [S], seq 1323386754, win 64860, options [mss 1410], length 0\n"
	frameSelfLoopback = "22:51:30.545810 lo    In  IP 127.0.0.1.36553 > 127.0.0.1.33478: " +
		"Flags [S], seq 3739766967, win 65495, options [mss 65495], length 0\n"
	// A connection to the machine's own routable address: the source looks
	// like a real router but the kernel delivered it over the loopback.
	frameSelfRoutable = "22:51:30.546911 lo    In  IP 3.154.0.1.35201 > 3.154.0.1.33478: " +
		"Flags [S], seq 468695774, win 65495, options [mss 65495], length 0\n"
	frameSelfUDP = "22:51:30.548261 lo    In  IP 127.0.0.1.43931 > 127.0.0.1.33478: " +
		"UDP, length 2\n"
	frameUDPFromNYC = "22:51:31.100000 port_NYC In  IP 3.152.0.1.43931 > 3.154.0.1.33478: " +
		"UDP, length 7\n"
)

func TestCountTapFramesCreditsArrivalsOnRealInterfaces(t *testing.T) {
	got := countTapFrames(frameFromNYC + frameFromATL + frameUDPFromNYC)
	if got.tcp != 2 || got.udp != 1 {
		t.Fatalf("want 2 TCP and 1 UDP arrivals, got %+v", got)
	}
}

func TestCountTapFramesIgnoresLoopback(t *testing.T) {
	got := countTapFrames(frameSelfLoopback + frameSelfRoutable + frameSelfUDP)
	if got.tcp != 0 || got.udp != 0 {
		t.Fatalf("traffic a machine sent to itself is not an arrival, got %+v", got)
	}
}

// The attack that scored full marks: a loop connecting to the machine's own
// closed ports while every connection from the network is dropped.
func TestCountTapFramesLoopbackFloodCreditsNothing(t *testing.T) {
	body := ""
	for i := 0; i < 40; i++ {
		body += frameSelfLoopback + frameSelfUDP
	}
	if got := countTapFrames(body); got.tcp != 0 || got.udp != 0 {
		t.Fatalf("a loopback flood is not an arrival, got %+v", got)
	}
}

func TestParseTapOutputNeedsTheCaptureToHaveRun(t *testing.T) {
	if _, ok := parseTapOutput(stillRunning("---\n" + frameFromNYC)); ok {
		t.Fatal("a capture that never announced itself must not be a witness")
	}
	if _, ok := parseTapOutput(stillRunning(tapBanner + frameFromNYC)); ok {
		t.Fatal("output with no separator must not be a witness")
	}
}

func TestParseTapOutputNeedsInterfaceNames(t *testing.T) {
	old := "tcpdump: verbose output suppressed\n" +
		"listening on any, link-type LINUX_SLL (Linux cooked v1), snapshot length 262144\n"
	if _, ok := parseTapOutput(stillRunning(old + "---\n" + frameFromNYC)); ok {
		t.Fatal("a capture that cannot name the interface cannot tell loopback from arrival")
	}
}

func TestParseTapOutputEmptyCaptureIsAWitness(t *testing.T) {
	got, ok := parseTapOutput(stillRunning(tapBanner + "---\n"))
	if !ok {
		t.Fatal("a capture that ran and saw nothing is evidence of non-arrival")
	}
	if got.tcp != 0 || got.udp != 0 {
		t.Fatalf("want nothing seen, got %+v", got)
	}
}

func TestParseTapOutputCountsRealArrivals(t *testing.T) {
	got, ok := parseTapOutput(stillRunning(tapBanner + "---\n" + frameFromATL + frameSelfLoopback))
	if !ok {
		t.Fatal("the capture ran, so it is a witness")
	}
	if got.tcp != 1 {
		t.Fatalf("want the one frame that arrived from off the machine, got %+v", got)
	}
}

// Measured on a lab router: three connections to 127.0.0.1 moved OutRsts by 3
// and the loopback device by 6, two datagrams moved NoPorts by 2 and the
// loopback by 4, and one connection from another router moved OutRsts by 1 and
// the loopback not at all.
func TestOffBoxDeltaMeasuredCounters(t *testing.T) {
	cases := []struct {
		name          string
		before, after counterWitness
		want          int
	}{
		{"three self-connections", counterWitness{79, 0}, counterWitness{82, 6}, 0},
		{"two self-datagrams", counterWitness{0, 6}, counterWitness{2, 10}, 0},
		{"one connection from another router", counterWitness{78, 0}, counterWitness{79, 0}, 1},
		{"nothing at all", counterWitness{78, 0}, counterWitness{78, 0}, 0},
		{"counters restarted", counterWitness{500, 40}, counterWitness{3, 0}, 0},
		{"a flood drowning one real arrival", counterWitness{551, 100},
			counterWitness{582, 160}, 0},
	}
	for _, c := range cases {
		if got := offBoxDelta(c.before, c.after); got != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, got)
		}
	}
}

func TestArrivalRequiresBothWitnessesWhenBothAreAvailable(t *testing.T) {
	cases := []struct {
		name string
		a    arrival
		want bool
	}{
		{"frame arrived and kernel took it",
			arrival{tapped: 1, tapLive: true, counted: 1, counterOK: true}, true},
		{"counter inflated but no frame arrived",
			arrival{tapped: 0, tapLive: true, counted: 30, counterOK: true}, false},
		{"frame arrived but the host dropped it",
			arrival{tapped: 2, tapLive: true, counted: 0, counterOK: true}, false},
		{"no capture, counter alone",
			arrival{tapLive: false, counted: 1, counterOK: true}, true},
		{"no capture and the counter did not move",
			arrival{tapLive: false, counted: 0, counterOK: true}, false},
		{"no counter, capture alone",
			arrival{tapped: 1, tapLive: true, counterOK: false}, true},
		{"neither witness",
			arrival{}, false},
	}
	for _, c := range cases {
		if got := c.a.arrived(); got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, got)
		}
	}
}

func TestArrivalAttributable(t *testing.T) {
	if (arrival{}).attributable() {
		t.Fatal("with no witness at all nothing is attributable")
	}
	if !(arrival{tapLive: true}).attributable() {
		t.Fatal("a live capture is a witness")
	}
	if !(arrival{counterOK: true}).attributable() {
		t.Fatal("a readable counter is a witness")
	}
}

// An accusation asks for all of what was sent, so that one stray packet in the
// window does not convict a correctly separated pair of customers.
func TestArrivalAtLeastNeedsTheWholeBurst(t *testing.T) {
	full := arrival{tapped: 3, tapLive: true, counted: 3, counterOK: true}
	if !full.arrivedAtLeast(3) {
		t.Fatal("three of three arrived")
	}
	short := arrival{tapped: 1, tapLive: true, counted: 3, counterOK: true}
	if short.arrivedAtLeast(3) {
		t.Fatal("only one frame arrived, so the counter's three are somebody else's")
	}
	inflated := arrival{tapped: 0, tapLive: true, counted: 99, counterOK: true}
	if inflated.arrivedAtLeast(3) {
		t.Fatal("a counter the destination raised by itself is not a leak")
	}
}

func TestNilTapIsNotAWitness(t *testing.T) {
	var t0 *arrivalTap
	if _, ok := t0.seen(context.TODO(), nil); ok {
		t.Fatal("a capture that was never started says nothing")
	}
	if _, ok := (&arrivalTap{}).seen(context.TODO(), nil); ok {
		t.Fatal("a capture that failed to start says nothing")
	}
}

func TestFailedTapStartIsCleanedUp(t *testing.T) {
	var calls []string
	env := &Env{Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		calls = append(calls, strings.Join(cmd, " "))
		if len(calls) == 1 {
			return rt.ExecResult{ExitCode: 4}, nil
		}
		return rt.ExecResult{}, nil
	}}
	tap := startArrivalTap(t.Context(), env, "as3/BOS", "33456")
	if tap.begun {
		t.Fatal("failed capture start was marked live")
	}
	if len(calls) != 2 || !strings.Contains(calls[1], "kill -TERM") ||
		!strings.Contains(calls[1], "rm -f") {
		t.Fatalf("failed capture was not stopped and removed: %#v", calls)
	}
}

func TestFailedTapReadUsesUncancelledCleanupContext(t *testing.T) {
	var calls int
	var cleanupContextLive bool
	env := &Env{Exec: func(ctx context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		calls++
		switch calls {
		case 1:
			return rt.ExecResult{}, nil
		case 2:
			return rt.ExecResult{}, errors.New("read interrupted")
		default:
			cleanupContextLive = ctx.Err() == nil &&
				strings.Contains(strings.Join(cmd, " "), "kill -TERM")
			return rt.ExecResult{}, nil
		}
	}}
	tap := startArrivalTap(t.Context(), env, "as3/BOS", "33456")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, ok := tap.seen(ctx, env); ok {
		t.Fatal("failed read was treated as a witness")
	}
	if !cleanupContextLive {
		t.Fatal("failed read did not clean up with a live context")
	}
}

func TestParseTapOutputAStoppedCaptureIsNoWitness(t *testing.T) {
	// A capture that ended before it was read -- its own timeout expired, or
	// it hit its frame limit -- was not watching for the whole of the flow.
	// Its silence is not evidence that nothing arrived, and reading it as such
	// once reported a working IPv6 tunnel as filtering datagrams.
	if _, ok := parseTapOutput("EARLY=1\n" + tapBanner + "---\n"); ok {
		t.Fatal("a capture that had already stopped must not be a witness")
	}
	// Not even when it saw something: it may have stopped before the rest.
	if _, ok := parseTapOutput("EARLY=1\n" + tapBanner + "---\n" + frameFromATL); ok {
		t.Fatal("a capture that had already stopped must not be a witness")
	}
	// And output with no marker at all is a read that did not happen.
	if _, ok := parseTapOutput(tapBanner + "---\n" + frameFromATL); ok {
		t.Fatal("output without the running marker must not be a witness")
	}
}

// A sweep aims many flows at one port and tells them apart by where they came
// from, so the reader has to group the arrivals by source port and has to
// leave out the frames that are not arrivals at all.
func TestTapSourcePortsGroupsArrivalsByTheirSourcePort(t *testing.T) {
	got := tapSourcePorts(frameFromNYC + frameFromATL + frameUDPFromNYC +
		frameSelfLoopback + frameSelfRoutable + frameSelfUDP)
	want := map[string]int{"39125": 1, "36229": 1, "43931": 1}
	if len(got) != len(want) {
		t.Fatalf("source ports = %v, want %v", got, want)
	}
	for p, n := range want {
		if got[p] != n {
			t.Errorf("port %s = %d, want %d", p, got[p], n)
		}
	}
	// The loopback frames carry source ports too, and crediting them would
	// let a machine answer for a flow that never left it.
	for _, p := range []string{"36553", "35201"} {
		if got[p] != 0 {
			t.Errorf("loopback source port %s was credited", p)
		}
	}
}

// Two frames of one flow are one flow, not two: the caller asks whether a port
// arrived at all, and a retransmitted SYN must not read as a second arrival.
func TestTapSourcePortsCountsEveryFrameOfAFlow(t *testing.T) {
	got := tapSourcePorts(frameFromNYC + frameFromNYC)
	if got["39125"] != 2 {
		t.Fatalf("frames from 39125 = %d, want 2", got["39125"])
	}
	if len(got) != 1 {
		t.Fatalf("flows = %d, want 1", len(got))
	}
}

func TestDepartureTapCreditsOnlyRealOutboundInterfaces(t *testing.T) {
	outbound := strings.Replace(frameFromATL, " In  ", " Out ", 1)
	loopback := strings.Replace(frameSelfRoutable, " In  ", " Out ", 1)
	_, ports, ok := parseTapFlowsDirection(
		stillRunning(tapBanner+"---\n"+outbound+loopback), "out",
	)
	if !ok || ports["36229"] != 1 {
		t.Fatalf("outbound capture: ok=%v ports=%v", ok, ports)
	}
	if ports["35201"] != 0 {
		t.Fatalf("loopback source was credited as a departure: %v", ports)
	}
	if got := tapSourcePorts(outbound); len(got) != 0 {
		t.Fatalf("an inbound reader credited an outbound frame: %v", got)
	}
}

// A line whose source field cannot be read is left out rather than guessed at.
// Counting a flow as lost is an accusation, and it has to rest on the capture
// rather than on a parser that fell through.
func TestTapSourcePortsIgnoresLinesItCannotRead(t *testing.T) {
	for _, line := range []string{
		"22:48:24.720723 port_NYC In  IP 3.152.0.1 > 3.154.0.1: ICMP echo request, length 8\n",
		"22:48:24.720723 port_NYC In  ARP, Request who-has 3.0.1.1 tell 3.0.1.2, length 28\n",
		"garbage\n",
		"22:48:24.720723 port_NYC Out IP 3.152.0.1.39125 > 3.154.0.1.33434: Flags [S], length 0\n",
	} {
		if got := tapSourcePorts(line); len(got) != 0 {
			t.Errorf("line %q yielded %v, want nothing", line, got)
		}
	}
}

// The whole reading is void when the capture stopped before it was asked, and
// the per-flow view has to be void with it -- otherwise a sweep would read
// every one of its flows as lost.
func TestSeenFlowsIsVoidWhenTheCaptureStoppedEarly(t *testing.T) {
	if _, _, ok := parseTapFlows("EARLY=1\n" + tapBanner + "---\n" + frameFromATL); ok {
		t.Fatal("a capture that stopped early testified about its flows")
	}
	_, ports, ok := parseTapFlows(stillRunning(tapBanner + "---\n" + frameFromATL))
	if !ok || ports["36229"] != 1 {
		t.Fatalf("live capture: ok=%v ports=%v", ok, ports)
	}
}
