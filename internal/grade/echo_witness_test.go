package grade

import "testing"

// A ping proves something answered, not that the right machine did. The
// witness that it was the right machine is the host's own count of what the
// kernel delivered to it -- which counts the host's pings to itself too, so
// the count on its own witnesses nothing.

// procNetDev is the real format, taken from a lab host.
const procNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     880      26    0    0    0     0          0         0      880      26    0    0    0     0       0          0
  host:  102378     893    0    0    0     0          0         0    98122     871    0    0    0     0       0          0
`

func TestLoopbackPacketsAreRead(t *testing.T) {
	if got := loopbackRx(procNetDev); got != 26 {
		t.Fatalf("loopback received %d packets, want the 26 in the table", got)
	}
}

func TestABusyLoopbackDoesNotHideItself(t *testing.T) {
	// A device whose byte count runs into the name, which /proc/net/dev does
	// once the counter is wide enough, must still be read.
	const wide = "    lo:1234567890   4096    0    0    0     0          0         0\n"
	if got := loopbackRx(wide); got != 4096 {
		t.Fatalf("read %d packets from a wide counter, want 4096", got)
	}
}

func TestNoLoopbackLineReadsAsNone(t *testing.T) {
	if got := loopbackRx("Icmp: InMsgs InEchos\nIcmp: 1 2\n"); got != 0 {
		t.Fatalf("read %d loopback packets where there is no loopback line", got)
	}
}

func TestPingingYourselfIsNotAnArrival(t *testing.T) {
	// Measured on a lab host: five pings to 127.0.0.1 raised the echo counter
	// by five and the loopback device by ten, the request and the reply.
	before := hostTraffic{echoes: 1498, loopRx: 16}
	after := hostTraffic{echoes: 1503, loopRx: 26}
	if got := arrivedFromOffBox(before, after); got != 0 {
		t.Fatalf("five pings a host sent to itself counted as %d arrivals", got)
	}
}

func TestAnArrivalFromElsewhereCounts(t *testing.T) {
	// Measured on the same host: five pings from another host raised the echo
	// counter by five and left the loopback device alone.
	before := hostTraffic{echoes: 1503, loopRx: 26}
	after := hostTraffic{echoes: 1508, loopRx: 26}
	if got := arrivedFromOffBox(before, after); got != 5 {
		t.Fatalf("five pings from another host counted as %d arrivals, want 5", got)
	}
}

func TestProbingOthersDoesNotCreditYourself(t *testing.T) {
	// The hosts are probe sources as well as destinations. Measured: five
	// pings sent to another host moved neither counter, so a host cannot earn
	// its own witness by taking part in the probing.
	before := hostTraffic{echoes: 1508, loopRx: 26}
	after := hostTraffic{echoes: 1508, loopRx: 26}
	if got := arrivedFromOffBox(before, after); got != 0 {
		t.Fatalf("probing other hosts credited %d arrivals to the prober", got)
	}
}

func TestDrowningTheCounterInLoopbackTrafficCreditsNothing(t *testing.T) {
	// The attack in full: the echo requests are diverted away by a DNAT rule
	// and a background flood of self-pings is left running to move the
	// counter. It must not be readable as traffic that arrived.
	before := hostTraffic{echoes: 24000, loopRx: 40000}
	after := hostTraffic{echoes: 24520, loopRx: 41040}
	if got := arrivedFromOffBox(before, after); got != 0 {
		t.Fatalf("a loopback flood counted as %d arrivals", got)
	}
}

func TestCountersThatWrapOrResetCreditNothing(t *testing.T) {
	after := hostTraffic{echoes: 3, loopRx: 0}
	before := hostTraffic{echoes: 900, loopRx: 0}
	if got := arrivedFromOffBox(before, after); got != 0 {
		t.Fatalf("a counter that went backwards credited %d arrivals", got)
	}
}
