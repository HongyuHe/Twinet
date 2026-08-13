package cli

import (
	"os"
	"strings"
	"testing"
)

// The hand-back at the end of a grading run used to discard its result. A
// hand-back that fails leaves every node's repair loop switched off for the
// rest of the lease, and the next thing anybody does to the lab is refused with
// a message naming a process that has already exited -- which is exactly what
// was seen on this cluster after a class run.
func TestAFailedHandBackIsNotSilent(t *testing.T) {
	src := readSource(t, "grade_hold.go")
	rel := src[strings.Index(src, "release: func()"):]
	if strings.Contains(rel, "_ = ask(rel, 0)") {
		t.Error("the hand-back discards its result, so a lab that stays held after " +
			"grading looks exactly like one that was handed back")
	}
	if !strings.Contains(rel, "could not be handed back") {
		t.Error("nothing tells the operator that the lab is still held")
	}
	if !strings.Contains(rel, "for attempt :=") {
		t.Error("the hand-back is attempted once; a single lost packet then costs the " +
			"cluster its repair loop for the rest of the lease")
	}
}

// readSource reads a file of this package.
//
// Asserting on the source is a poor substitute for asserting on behaviour, and
// it is used here because the alternative is a fake cluster of three HTTP
// servers to observe one deferred call. What it does catch is the exact
// regression: somebody restoring the discarded result.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
