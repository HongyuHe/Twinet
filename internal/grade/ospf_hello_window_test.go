package grade

import "testing"

// The dead timer falls in real time and jumps back to the dead interval on
// every hello. Over a window, a live adjacency loses the window less one
// interval for each hello that arrived; a silent one loses the whole window.
// These are the two populations the check has to tell apart, at whatever
// interval the student chose.

// simulate returns the fall in a dead timer over elapsed ms when a hello
// arrives every hello ms, or the whole of elapsed if the adjacency is silent.
// It is the worst case for a live adjacency: the last hello before the window
// opened landed just before the first reading, so only one arrives inside it.
func simulate(elapsed, hello int64, live bool) int64 {
	if !live {
		return elapsed
	}
	n := elapsed / hello
	if n == 0 {
		n = 1
	}
	return elapsed - n*hello
}

func TestALiveAdjacencyIsNotCalledDeadAtAnyInterval(t *testing.T) {
	// Ten seconds is OSPF's default; RFC 2328 specifies thirty for
	// non-broadcast networks. Neither, nor anything between, may be mistaken
	// for silence.
	for _, hello := range []int64{1000, 2000, 5000, 10000, 15000, 30000, 40000} {
		elapsed := watchFor(hello)
		drop := simulate(elapsed, hello, true)
		if missedHello(drop, 0, elapsed, hello) {
			t.Fatalf("hello=%dms: a live adjacency lost %dms of dead time over %dms and was called dead",
				hello, drop, elapsed)
		}
	}
}

func TestASilentAdjacencyIsStillCaught(t *testing.T) {
	for _, hello := range []int64{1000, 2000, 5000, 10000, 15000, 30000, 40000} {
		elapsed := watchFor(hello)
		drop := simulate(elapsed, hello, false)
		if !missedHello(drop, 0, elapsed, hello) {
			t.Fatalf("hello=%dms: an adjacency that sent nothing for %dms was not noticed",
				hello, elapsed)
		}
	}
}

func TestTheWindowOutlastsAnInterval(t *testing.T) {
	// If the window is shorter than the gap between hellos it can contain
	// none, and observing nothing would be read as nothing being sent. That
	// is the whole defect.
	for _, hello := range []int64{1000, 10000, 15000, 30000, 42000} {
		if w := watchFor(hello); w < hello+2000 {
			t.Fatalf("hello=%dms is watched for only %dms, so a live adjacency can go unseen",
				hello, w)
		}
	}
}

func TestTheDefaultCaseIsUnchangedAndQuick(t *testing.T) {
	// The three shipped labs all use the default interval. Deriving the window
	// must not make grading them any slower than the twelve seconds it was.
	if w := watchFor(10000); w != 12000 {
		t.Fatalf("the default interval is now watched for %dms, want the 12000ms it was", w)
	}
}

func TestWaitingIsBounded(t *testing.T) {
	// The interval is a number the student picks. It must not decide how long
	// the grader stands and waits.
	for _, hello := range []int64{60000, 600000, 65535000} {
		if w := watchFor(hello); w > maxWatchMsec {
			t.Fatalf("hello=%dms would have the grader wait %dms", hello, w)
		}
	}
}
