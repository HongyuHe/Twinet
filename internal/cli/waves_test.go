package cli

import (
	"github.com/HongyuHe/twinet/internal/grade"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func labFor(t *testing.T, dir string) *model.Topology {
	t.Helper()
	l, err := manifest.Load(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	r, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatalf("expand %s: %v", dir, err)
	}
	return r.Topology
}

func studentSubs(top *model.Topology) []submission {
	var out []submission
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as.Role != model.RoleStudent {
			continue
		}
		name := as.OwnerGroup
		if name == "" {
			name = "as" + itoa(asn)
		}
		out = append(out, submission{Group: name, AS: asn})
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The whole argument for grading in waves is that the number of waves is a
// property of the topology's shape rather than of the class size: adding
// students adds autonomous systems, not adjacency. If waves grew with the
// class, this would be no better than grading one submission at a time.
func TestWavesDoNotGrowWithTheClass(t *testing.T) {
	small := labFor(t, "../../examples/cos461")
	smallSubs := studentSubs(small)
	smallWaves := independentWaves(small, smallSubs)

	big := labFor(t, "../../examples/scale")
	bigSubs := studentSubs(big)
	bigWaves := independentWaves(big, bigSubs)

	t.Logf("%d submissions -> %d waves", len(smallSubs), len(smallWaves))
	t.Logf("%d submissions -> %d waves", len(bigSubs), len(bigWaves))

	if len(bigSubs) < 5*len(smallSubs) {
		t.Fatalf("the large lab has only %d submissions; this proves nothing", len(bigSubs))
	}
	// Ten times the class must not cost ten times the waves. A small constant
	// is what makes this approach worth having.
	if len(bigWaves) > len(smallWaves)+4 {
		t.Errorf("waves grew from %d to %d as the class grew from %d to %d submissions",
			len(smallWaves), len(bigWaves), len(smallSubs), len(bigSubs))
	}
}

// Within a wave, no two submissions may be neighbours: that is the property
// that makes a wave as isolating as a private lab.
func TestNoTwoSubmissionsInAWaveAreNeighbours(t *testing.T) {
	for _, dir := range []string{"../../examples/cos461", "../../examples/scale"} {
		top := labFor(t, dir)
		subs := studentSubs(top)
		waves := independentWaves(top, subs)

		adjacent := map[[2]int]bool{}
		for _, l := range top.Links {
			if !l.InterAS || l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
				continue
			}
			a, b := l.A.Device.ASN, l.B.Device.ASN
			adjacent[[2]int{a, b}] = true
			adjacent[[2]int{b, a}] = true
		}

		seen := map[int]bool{}
		total := 0
		for _, w := range waves {
			for i := range w {
				if seen[w[i].AS] {
					t.Errorf("%s: AS %d appears in more than one wave", dir, w[i].AS)
				}
				seen[w[i].AS] = true
				total++
				for j := range w {
					if i == j {
						continue
					}
					if adjacent[[2]int{w[i].AS, w[j].AS}] {
						t.Errorf("%s: AS %d and AS %d are neighbours and share a wave, so each is "+
							"marked against the other's work", dir, w[i].AS, w[j].AS)
					}
				}
			}
		}
		if total != len(subs) {
			t.Errorf("%s: %d submissions were placed into waves, but there are %d", dir, total, len(subs))
		}
	}
}

// A wave that could not be returned to the reference solution contaminates
// every wave after it: those submissions are graded across an AS still holding
// the previous student's work, and their marks move accordingly.
//
// The old behaviour was to print a warning and carry on. A mark that is wrong
// and labelled correct is worse than no mark at all: the student has no reason
// to appeal it and the grader has no reason to look at it. The remaining waves
// are now held for review instead.
func TestAFailedRestoreHoldsTheRemainingWaves(t *testing.T) {
	waves := [][]submission{
		{{Group: "group5", AS: 5}, {Group: "group7", AS: 7}},
		{{Group: "group9", AS: 9}},
	}
	held := quarantine(waves, 10, "AS 3 could not be reset")
	if len(held) != 3 {
		t.Fatalf("held %d submissions, want all 3", len(held))
	}
	for _, r := range held {
		if !r.NeedsReview {
			t.Errorf("%s was not held for review", r.Submission)
		}
		if r.Total != 0 || r.Err == "" {
			t.Errorf("%s carries a mark (%v) rather than a reason", r.Submission, r.Total)
		}
		if !strings.Contains(r.Err, "could not be returned to the reference") {
			t.Errorf("%s does not say why it was held: %q", r.Submission, r.Err)
		}
		if !strings.Contains(r.Err, "AS 3 could not be reset") {
			t.Errorf("%s does not carry the underlying cause: %q", r.Submission, r.Err)
		}
	}

	// And a held report must not be releasable as a grade.
	sum := grade.Summarise("t", held, time.Second)
	if len(sum.Quarantined()) != 3 {
		t.Errorf("%d of 3 held reports were quarantined; the rest could be imported as marks",
			len(sum.Quarantined()))
	}
}
