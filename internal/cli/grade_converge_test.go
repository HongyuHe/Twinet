package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// `grade run --converge-timeout` set an option nothing read. The flag promised
// a wait, `grade batch` and `grade class` performed one, and the single
// command with nobody to converge the lab for it silently did not: a lab
// deployed a moment earlier was read while its adjacencies were still forming.
func TestGradeRunAsksForTheConvergenceWaitItAdvertises(t *testing.T) {
	opts := liveGradeRunOptions(4*time.Minute, 8, 4, false)
	if !opts.WaitForConvergence {
		t.Fatal("grade run does not ask for the wait its flag documents")
	}
	if opts.ConvergeTimeout != 4*time.Minute {
		t.Fatalf("the budget was not passed through: %s", opts.ConvergeTimeout)
	}
}

// Zero is an operator saying "read the lab as it stands", and it must not
// become a four-minute sleep somewhere below.
func TestAZeroConvergeTimeoutTurnsTheWaitOff(t *testing.T) {
	opts := liveGradeRunOptions(0, 8, 4, false)
	if opts.WaitForConvergence || opts.ConvergeTimeout != 0 {
		t.Fatalf("--converge-timeout 0 still asks for a wait: %#v", opts)
	}
}

// Batch and class grading wait for each submission themselves before grading
// it. Asking for the wait again here would wait for every submission twice:
// per submission, a second whole-control-plane wait is the largest fixed cost
// in a class run, and it would observe nothing the first one did not.
func TestPreConvergedGradingNeverAsksForASecondWait(t *testing.T) {
	opts := preConvergedRunOptions(4 * time.Minute)
	if opts.WaitForConvergence {
		t.Fatal("a submission that was already converged would be waited for twice")
	}
}

// And the flag says so, because an operator reading --help is entitled to know
// that a grading run may spend minutes waiting before it reads anything.
func TestGradeRunDocumentsTheWaitAndHowToSkipIt(t *testing.T) {
	run := findCommand(t, Root(), "grade", "run")
	flag := run.Flags().Lookup("converge-timeout")
	if flag == nil {
		t.Fatal("grade run has no --converge-timeout")
	}
	if !strings.Contains(flag.Usage, "0") {
		t.Fatalf("--converge-timeout does not say how to turn the wait off: %q", flag.Usage)
	}
	if !strings.Contains(run.Long, "--converge-timeout") {
		t.Fatalf("grade run does not explain that it waits:\n%s", run.Long)
	}
}

func findCommand(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()
	current := root
	for _, name := range path {
		found := false
		for _, child := range current.Commands() {
			if child.Name() == name {
				current, found = child, true
				break
			}
		}
		if !found {
			t.Fatalf("no command %q under %q", name, current.Name())
		}
	}
	return current
}
