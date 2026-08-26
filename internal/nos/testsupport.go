package nos

import "time"

// FRRStartWaitForTest shortens how long the FRR provider waits for daemons to
// bind and returns a function restoring the shipped budget.
//
// It is exported for the CLI's loader tests, whose subject is the verdict on a
// submission that kills a daemon rather than the length of the wait for one
// that never returns.
func FRRStartWaitForTest(d time.Duration) func() {
	previous := frrStartWait
	frrStartWait = d
	return func() { frrStartWait = previous }
}

// BIRDStartWaitForTest is FRRStartWaitForTest for the BIRD provider.
func BIRDStartWaitForTest(d time.Duration) func() {
	previous := birdStartWait
	birdStartWait = d
	return func() { birdStartWait = previous }
}
