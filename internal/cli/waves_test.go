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

// Waves must stay far cheaper than grading one submission at a time.
//
// The original claim was stronger -- that the wave count is a property of the
// topology's shape and not of the class size -- and it was true only while
// submissions conflicted on direct adjacency alone. That rule let two students
// hanging off the same reference transit be graded together, which is not
// isolation: AS1 re-advertises what its customers send it, so one student's bad
// announcement reaches the other's table.
//
// Requiring distance two costs waves, because in a tiered topology most
// students do share a transit. 80 submissions go from 6 waves to 42. That is
// still six times better than a lab per submission, and each of those 42 waves
// grades every submission in it concurrently.
//
// The trade was measured before it was made. On the live cluster, AS5 scored
// 10/10 with the class at reference; with AS3 -- non-adjacent, sharing transit
// AS1 -- withdrawing its prefix entirely, AS5 still scored 10/10; and with AS3
// hijacking 5.0.0.0/8, AS5 still scored 10/10. So for this rubric the weaker
// rule would have been adequate. It is not kept, because "no contamination was
// observed for the checks this rubric happens to use" is not the same as "a
// student cannot lose marks for another student's work", and the second is what
// a grading system has to be able to say.
func TestWavesStayFarCheaperThanALabPerSubmission(t *testing.T) {
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
	// The point of waves is concurrency, so the measure that matters is how
	// many submissions each wave carries, not how many waves there are.
	perWave := float64(len(bigSubs)) / float64(len(bigWaves))
	if perWave < 1.5 {
		t.Errorf("%d submissions took %d waves (%.1f per wave); at that density the "+
			"waves are barely better than grading one submission at a time, and "+
			"`twinet grade batch` would give real isolation for a similar cost",
			len(bigSubs), len(bigWaves), perWave)
	}
	t.Logf("%.1f submissions per wave", perWave)
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

// Restoring one wave must not reinstall the reference solution on every other
// autonomous system in the lab.
//
// It used to. The restore discarded its scope argument and ran an
// authoritative solve over the whole topology, so a student whose neighbour
// failed to load had their own work replaced by the model answer and was then
// marked on it: ten out of ten for a submission nobody had read, with nothing
// flagged for review. Verified on the live cluster before the fix -- a marker
// planted in AS 5 was gone after restoring AS 3 -- and after it, where the
// marker survived.
func TestRestoringOneWaveDoesNotTouchTheOthers(t *testing.T) {
	only := restoreScopes([]string{"as3", "as7"})

	for _, want := range []string{"as3", "as7"} {
		if !contains(only, want) {
			t.Errorf("the restore does not cover %s, which it was asked to restore", want)
		}
	}
	// The peering scope must be included: an inter-AS link belongs to neither
	// system, so leaving it out rebuilds a router without rewiring its
	// external links.
	if !contains(only, "peering") {
		t.Error("the restore omits the peering scope, so external links are not rewired")
	}
	// And nothing else may be touched.
	for _, forbidden := range []string{"as4", "as5", "as6", "as8", "as9", "as10"} {
		if contains(only, forbidden) {
			t.Errorf("restoring as3 and as7 would also overwrite %s", forbidden)
		}
	}
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

// The reason waves are safe was "everything a submission can see is either its
// own work or the reference". That is false as soon as two students hang off
// the same reference transit: AS3 and AS5 are not neighbours, but both attach
// to AS1 and AS2, which run ordinary BGP and re-advertise what their customers
// send them. A bad announcement from one arrives in the other's table.
//
// This test is the counter-example that was found, kept so the rule cannot
// quietly weaken back to direct adjacency.
func TestSubmissionsSharingATransitAreNotGradedTogether(t *testing.T) {
	top := labFor(t, "../../examples/cos461")

	neighbours := map[int]map[int]bool{}
	for _, l := range top.Links {
		if !l.InterAS || l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		a, b := l.A.Device.ASN, l.B.Device.ASN
		if a == b {
			continue
		}
		if neighbours[a] == nil {
			neighbours[a] = map[int]bool{}
		}
		if neighbours[b] == nil {
			neighbours[b] = map[int]bool{}
		}
		neighbours[a][b], neighbours[b][a] = true, true
	}

	subs := studentSubs(top)
	if len(subs) < 2 {
		t.Skip("needs at least two student systems")
	}

	for _, wave := range independentWaves(top, subs) {
		for i := 0; i < len(wave); i++ {
			for j := i + 1; j < len(wave); j++ {
				a, b := wave[i].AS, wave[j].AS
				for n := range neighbours[a] {
					if !neighbours[b][n] {
						continue
					}
					t.Errorf("AS %d and AS %d are graded in the same wave, and both attach "+
						"to AS %d.\nAS %d runs ordinary BGP and re-advertises what its "+
						"customers send it, so a bad announcement from one of them reaches "+
						"the other's routing table and changes the paths it is marked on. "+
						"A correct student loses marks for someone else's mistake, and "+
						"nothing in the report says so.", a, b, n, n)
				}
			}
		}
	}
}

// --per-wave N means at most N at a time. It used to mean "as many as the
// colouring allows", so --per-wave 2 and --per-wave 100 behaved identically
// and an operator asking for a cautious amount of parallelism got all of it.
func TestPerWaveLimitsHowManyRunTogether(t *testing.T) {
	wide := [][]submission{
		{{Group: "a", AS: 1}, {Group: "b", AS: 2}, {Group: "c", AS: 3}, {Group: "d", AS: 4}, {Group: "e", AS: 5}},
		{{Group: "f", AS: 6}},
	}
	got := capWaves(wide, 2)
	for i, w := range got {
		if len(w) > 2 {
			t.Errorf("wave %d has %d submissions, more than the 2 that were asked for", i, len(w))
		}
	}
	total := 0
	for _, w := range got {
		total += len(w)
	}
	if total != 6 {
		t.Errorf("%d submissions survived the split, not 6; someone would go unmarked", total)
	}
	if len(got) != 4 {
		t.Errorf("6 submissions capped at 2 gave %d waves, want 4", len(got))
	}
}

func TestPerWaveLeavesSmallWavesAlone(t *testing.T) {
	in := [][]submission{{{Group: "a", AS: 1}}, {{Group: "b", AS: 2}}}
	if got := capWaves(in, 8); len(got) != 2 {
		t.Errorf("waves already smaller than the cap were split into %d", len(got))
	}
}
