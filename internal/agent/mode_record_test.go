package agent

import "testing"

// The mode is what tells a node whether the configuration on its devices is the
// reference answer or a class's work, and a lab recorded as solved has its
// snapshotting suppressed. Writing it from an apply that did not build the
// whole lab is therefore how a term's work stops being preserved.
//
// The in-memory record was guarded and the one on disk was not, so `--solve
// --only as=3` left "solve" on disk. The disk copy is what a restarted agent
// reads, so the guard held only until the next restart.
func TestOnlyACompleteApplyMaySayHowTheLabWasBuilt(t *testing.T) {
	cases := []struct {
		name          string
		authoritative bool
		wantMode      string
		wantUngraded  int
	}{
		{"a complete, successful apply", true, "solve", 2},
		{"scoped or failed", false, "", 0},
	}
	for _, c := range cases {
		mode, ungraded := modeToPersist(c.authoritative, "solve", 2, "", 0)
		if mode != c.wantMode || ungraded != c.wantUngraded {
			t.Errorf("%s: recorded mode %q ungraded %d, want %q and %d",
				c.name, mode, ungraded, c.wantMode, c.wantUngraded)
		}
	}
}
