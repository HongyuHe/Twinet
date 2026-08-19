package grade

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
)

// What a machine's own counters can and cannot witness.
//
// A global counter -- the resets it sent, the datagrams it took delivery of for
// a closed port, the echo requests it answered -- rises for every packet of
// that kind the kernel handled, whoever sent it and wherever it came from. Read
// before and after a probe it looks like proof that the probe arrived, and it
// is not. The machine is the submission's to run programs on, and a loop
// connecting to 127.0.0.1 raises the same counter as fast as it likes: measured
// on a lab router, `nc -z 127.0.0.1 1` in a loop moved `OutRsts` thirty times in
// three seconds and `NoPorts` twenty-one times, while every connection from the
// other side of the network was being dropped and the question about whether
// the paths carry traffic scored full marks.
//
// Two things are different now, and the second is what settles it.
//
// The counters are read together with the loopback device's packet count, and a
// packet a machine sends to itself is counted there as well -- twice, in fact,
// since the request and the answer are both delivered over `lo`. Subtracting
// the one from the other leaves movement the machine cannot have generated on
// its own. That is a lower bound and deliberately so: it can fail to credit an
// arrival, but it cannot invent one.
//
// A submission has more machines than one, though, and a connection to a closed
// port from any of them raises the counter without touching the loopback. So
// the counter is no longer the witness where a better one can be had. The
// destination watches its own interfaces for the exact flow the grader is about
// to create -- on a port drawn at random for that one probe, which nothing else
// has reason to send to -- and tcpdump names the interface each frame arrived
// on. Traffic a machine sends to itself names itself: even a connection to the
// machine's own routable address is delivered over `lo` and is reported as
// such, so it is excluded rather than counted.
//
// The two are required together. The tap sees a frame reach the interface,
// which is what the questions about paths and tunnels and transit are asking;
// the counter says the kernel took delivery of it, which is what the questions
// about reachability are asking. A submission that satisfies one and not the
// other has not carried the traffic, and neither witness alone was enough.

// counterWitness is a kernel counter read together with the loopback device's
// packet count, taken at the same instant so the two can be subtracted.
type counterWitness struct {
	global int
	loopRx int
}

// offBoxDelta is how much of a counter's movement between two readings cannot
// be explained by traffic the machine sent to itself.
func offBoxDelta(before, after counterWitness) int {
	n := (after.global - before.global) - (after.loopRx - before.loopRx)
	if n < 0 {
		return 0
	}
	return n
}

// readCounter reads one named counter out of a machine's SNMP statistics
// together with its loopback packet count, in a single visit.
func readCounter(ctx context.Context, env *Env, device, file string,
	pick func(string) (int, bool)) (counterWitness, bool) {

	res, err := env.Probe(ctx, device, []string{"cat", file, "/proc/net/dev"})
	if err != nil || res.ExitCode != 0 {
		return counterWitness{}, false
	}
	n, ok := pick(res.Stdout)
	if !ok {
		return counterWitness{}, false
	}
	return counterWitness{global: n, loopRx: loopbackRx(res.Stdout)}, true
}

// tapSeconds bounds how long a capture can outlive the grader that started it.
// It is a leak guard and nothing more: the capture is stopped explicitly when
// it is read, so this only matters if the grading run is interrupted between
// the two.
//
// It used to be the window itself, at fifteen seconds, chosen to outlast the
// probes it watches for. That was a guess about how long several round trips
// to a machine on another node would take, and on a loaded cluster the guess
// was sometimes wrong: the capture had already exited when the last probe was
// sent, reported no frames, and the check called a working path filtered.
const tapSeconds = 180

// tapFrames bounds how many frames a capture records, so that nothing
// unbounded is written to a machine being graded. Reaching the limit ends the
// capture early, which now voids the witness rather than silencing it, so the
// number is set well above what the probes can produce.
const tapFrames = 64

// arrivalTap watches one machine's interfaces for the frames of a single flow.
type arrivalTap struct {
	device string
	file   string
	begun  bool
}

// startArrivalTap begins watching a machine for frames addressed to a port,
// whatever protocol carries them, and returns once the capture is listening.
//
// The wait is not optional. A capture that is still starting when the probe
// goes past records nothing, and a working path would be reported broken; the
// loop watches for tcpdump's own announcement that it is listening rather than
// guessing at a delay.
//
// The capture also records the moment it stops, in a marker file. Whether it
// was still running when the probes went past is the difference between "no
// packet arrived" and "nobody was watching", and only one of those is evidence.
func startArrivalTap(ctx context.Context, env *Env, device, port string) *arrivalTap {
	t := &arrivalTap{
		device: device,
		file:   fmt.Sprintf("/tmp/twinet-tap-%d-%d", rand.Uint32(), rand.Uint32()),
	}
	script := fmt.Sprintf(
		"command -v tcpdump >/dev/null 2>&1 || exit 3; "+
			"rm -f %[1]s %[1]s.err %[1]s.pid %[1]s.end; "+
			"( ( timeout %[3]d tcpdump -i any -n -l -Q in -c %[4]d 'dst port %[2]s' "+
			">%[1]s 2>%[1]s.err & echo $! >%[1]s.pid; wait; : >%[1]s.end ) "+
			">/dev/null 2>&1 & ); "+
			"n=0; while [ $n -lt 100 ]; do "+
			"grep -q 'listening on' %[1]s.err 2>/dev/null && exit 0; "+
			"n=$((n+1)); sleep 0.05; done; exit 4",
		t.file, port, tapSeconds, tapFrames)
	res, err := env.Probe(ctx, device, []string{"sh", "-c", script})
	t.begun = err == nil && res.ExitCode == 0
	return t
}

// tapCounts is how many frames of each kind arrived on a real interface.
type tapCounts struct {
	tcp int
	udp int
}

// seen reports the frames of the watched flow that arrived from off the
// machine, and whether the capture was running to be able to say so.
//
// A capture that could not be read, or that cannot name the interface a frame
// arrived on, reports nothing rather than nothing-arrived: the difference
// matters, because the second would fail a submission over a missing tool.
//
// The capture is stopped here rather than left to expire, so that the window
// it watched covers the probes by construction instead of by estimate. If it
// stopped on its own beforehand -- its own timeout, or its frame limit -- it
// was not watching for the whole of the flow and its silence proves nothing.
func (t *arrivalTap) seen(ctx context.Context, env *Env) (tapCounts, bool) {
	if t == nil || !t.begun {
		return tapCounts{}, false
	}
	res, err := env.Probe(ctx, t.device, []string{"sh", "-c",
		fmt.Sprintf("early=0; [ -f %[1]s.end ] && early=1; "+
			"[ -f %[1]s.pid ] && kill -TERM \"$(cat %[1]s.pid)\" 2>/dev/null; "+
			"n=0; while [ $n -lt 40 ] && [ ! -f %[1]s.end ]; do n=$((n+1)); sleep 0.05; done; "+
			"echo \"EARLY=$early\"; cat %[1]s.err 2>/dev/null; echo '---'; "+
			"cat %[1]s 2>/dev/null; "+
			"rm -f %[1]s %[1]s.err %[1]s.pid %[1]s.end; exit 0", t.file)})
	if err != nil || res.ExitCode != 0 {
		return tapCounts{}, false
	}
	return parseTapOutput(res.Stdout)
}

// parseTapOutput separates what tcpdump said about itself from what it
// captured, and reports nothing rather than nothing-arrived where the capture
// cannot be trusted to tell the difference.
func parseTapOutput(out string) (tapCounts, bool) {
	marker, rest, ok := strings.Cut(out, "\n")
	if !ok || !strings.HasPrefix(marker, "EARLY=") {
		return tapCounts{}, false
	}
	// The capture had already stopped before it was asked, so the window it
	// watched does not cover the flow and it has nothing to testify to.
	if strings.TrimPrefix(marker, "EARLY=") != "0" {
		return tapCounts{}, false
	}
	head, body, ok := strings.Cut(rest, "---\n")
	if !ok || !strings.Contains(head, "listening on") {
		return tapCounts{}, false
	}
	// Without the cooked-v2 header there is no interface name on the line, and
	// a loopback frame is indistinguishable from an arrival. Better to have no
	// witness than a witness that cannot tell the two apart.
	if !strings.Contains(head, "LINUX_SLL2") {
		return tapCounts{}, false
	}
	return countTapFrames(body), true
}

// countTapFrames reads tcpdump's `-i any` output, whose second field is the
// interface a frame arrived on and whose third says which way it went.
//
// Frames delivered over the loopback device are the machine talking to itself
// and are not arrivals.
func countTapFrames(body string) tapCounts {
	var c tapCounts
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "In" || f[1] == "lo" {
			continue
		}
		switch {
		case strings.Contains(line, "UDP,"):
			c.udp++
		case strings.Contains(line, "Flags ["):
			c.tcp++
		}
	}
	return c
}

// tapReading is what one capture saw, and whether it was running to see it.
type tapReading struct {
	counts tapCounts
	live   bool
}

// startTaps begins a capture on each of several machines at once, each watching
// for the port that machine's own probe will be aimed at.
func startTaps(ctx context.Context, env *Env, ports map[string]string) map[string]*arrivalTap {
	out := map[string]*arrivalTap{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for device, port := range ports {
		wg.Add(1)
		go func(device, port string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t := startArrivalTap(ctx, env, device, port)
			mu.Lock()
			out[device] = t
			mu.Unlock()
		}(device, port)
	}
	wg.Wait()
	return out
}

// readTaps collects what every capture saw and clears them off the machines.
func readTaps(ctx context.Context, env *Env,
	taps map[string]*arrivalTap) map[string]tapReading {

	out := map[string]tapReading{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for device, t := range taps {
		wg.Add(1)
		go func(device string, t *arrivalTap) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			counts, live := t.seen(ctx, env)
			mu.Lock()
			out[device] = tapReading{counts: counts, live: live}
			mu.Unlock()
		}(device, t)
	}
	wg.Wait()
	return out
}

// arrival is what one probe established about whether it got there.
type arrival struct {
	// frames matching the flow that reached a real interface.
	tapped int
	// tapLive is whether the capture was running to be able to say so.
	tapLive bool
	// counted is the counter movement the machine cannot have generated itself.
	counted int
	// counterOK is whether the counter could be read at all.
	counterOK bool
}

// arrived reports whether the probe is known to have got there.
//
// Where both witnesses are available both are required: the frame has to have
// reached an interface from off the machine, and the kernel has to have taken
// delivery of it. Where only one is available it decides alone, which is the
// weaker test the checks used to make everywhere.
func (a arrival) arrived() bool { return a.arrivedAtLeast(1) }

// arrivedAtLeast is arrived, for callers that sent several packets and want
// them all accounted for -- which is what an accusation should ask, so that one
// stray packet in the window is not a verdict.
func (a arrival) arrivedAtLeast(n int) bool {
	switch {
	case a.tapLive && a.counterOK:
		return a.tapped >= n && a.counted >= n
	case a.tapLive:
		return a.tapped >= n
	case a.counterOK:
		return a.counted >= n
	}
	return false
}

// attributable is whether the destination could be asked at all. Without it,
// arrived is not a negative finding, merely an unknown.
func (a arrival) attributable() bool { return a.tapLive || a.counterOK }

// why describes a failure to arrive in the terms of whichever witness saw it,
// so that a report says what was actually established.
func (a arrival) why() string {
	switch {
	case a.tapLive && a.tapped == 0:
		return "no packet of it reached any interface"
	case a.counterOK && a.counted == 0:
		return "it reached the interface but the kernel took no delivery of it"
	}
	return "it did not arrive"
}
