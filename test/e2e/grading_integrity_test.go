//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gradeAS grades one autonomous system and returns the awarded mark per
// question.
func gradeAS(t *testing.T, dir string, as int) (map[string]float64, map[string]float64, string) {
	t.Helper()
	out := t.TempDir()
	res, err := twinet(t, "grade", "run", "-m", dir, "--as", itoa(as),
		"-o", out, "--converge-timeout", "6m")
	if err != nil {
		t.Fatalf("grading AS %d: %v\n%s", as, err, res)
	}
	raw, err := os.ReadFile(filepath.Join(out, "group"+itoa(as)+".json"))
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	var rep struct {
		NeedsReview bool   `json:"needs_review"`
		Err         string `json:"error"`
		Questions   []struct {
			ID      string  `json:"id"`
			Awarded float64 `json:"awarded"`
			Points  float64 `json:"points"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("the report does not parse: %v", err)
	}
	if rep.NeedsReview || rep.Err != "" {
		t.Fatalf("grading did not complete cleanly: needs_review=%v err=%q", rep.NeedsReview, rep.Err)
	}
	awarded := map[string]float64{}
	points := map[string]float64{}
	for _, q := range rep.Questions {
		awarded[q.ID] = q.Awarded
		points[q.ID] = q.Points
	}
	return awarded, points, string(raw)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// vtysh runs configuration commands on a router of the lab.
func vtysh(t *testing.T, dir, device string, cmds ...string) {
	t.Helper()
	args := []string{"exec", "-m", dir, device, "--", "vtysh"}
	for _, c := range cmds {
		args = append(args, "-c", c)
	}
	if out, err := twinet(t, args...); err != nil {
		t.Fatalf("configuring %s: %v\n%s", device, err, out)
	}
}

// That the reference scores full marks proves the rubric is satisfiable. It
// does not prove the rubric is discriminating: a check that always passes looks
// exactly the same from that direction, and so does one that is measuring
// something other than what its name says.
//
// This is the other direction. Each case breaks one specific thing and asserts
// that the question about that thing loses marks -- and, just as importantly,
// that the other questions do not, because a check that fails whenever anything
// at all is wrong is not measuring what it claims either, and would take marks
// off a student for a mistake they did not make.
//
// Every case restores the reference afterwards, so a failure part way through
// cannot leave the lab in a state that fails everything after it.
func TestABrokenSubmissionLosesTheRightMarks(t *testing.T) {
	dir := labDir(t)
	const as = 3

	solveAS(t, dir, as)
	baseline, points, _ := gradeAS(t, dir, as)
	for id, p := range points {
		if baseline[id] < p {
			t.Fatalf("the reference does not score full marks on %s (%.2f of %.2f); "+
				"nothing below can be attributed to the breakage", id, baseline[id], p)
		}
	}

	cases := []struct {
		name string
		// question that must lose marks.
		question string
		// break it.
		apply func(t *testing.T)
	}{
		{
			name:     "an inter-AS subnet advertised into OSPF",
			question: "q1.2",
			apply: func(t *testing.T) {
				vtysh(t, dir, "as3/ATL", "configure terminal", "router ospf",
					"network 179.0.0.0/8 area 0", "end")
			},
		},
		{
			name:     "an iBGP session removed",
			question: "q2.1",
			apply: func(t *testing.T) {
				// Whichever internal neighbour ATL has, taken out of the mesh.
				out, err := twinet(t, "exec", "-m", dir, "as3/ATL", "--",
					"vtysh", "-c", "show running-config")
				if err != nil {
					t.Fatalf("reading the configuration: %v\n%s", err, out)
				}
				peer := firstIBGPPeer(out)
				if peer == "" {
					t.Skip("no iBGP neighbour found to remove")
				}
				vtysh(t, dir, "as3/ATL", "configure terminal", "router bgp 3",
					"no neighbor "+peer, "end")
			},
		},
		{
			name:     "the local-preference policy removed",
			question: "q2.3",
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/ATL", "--",
					"vtysh", "-c", "show running-config")
				if err != nil {
					t.Fatalf("reading the configuration: %v\n%s", err, out)
				}
				// Detach every import policy on every external neighbour, so
				// no relationship is preferred over another.
				n := 0
				for _, line := range strings.Split(out, "\n") {
					f := strings.Fields(strings.TrimSpace(line))
					if len(f) >= 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
						vtysh(t, dir, "as3/ATL", "configure terminal", "router bgp 3",
							"no neighbor "+f[1]+" route-map "+f[3]+" in", "end")
						n++
					}
				}
				if n == 0 {
					t.Skip("no import route-map is bound on this router")
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveAS(t, dir, as)
			c.apply(t)

			after, _, report := gradeAS(t, dir, as)
			if after[c.question] >= baseline[c.question] {
				t.Errorf("%s still scored %.2f of %.2f after %q; the check does not "+
					"measure what its name says, and a student could skip this work\n%s",
					c.question, after[c.question], points[c.question], c.name, report)
			}
			// Collateral damage is its own failure: a correct student must not
			// lose a mark because something unrelated is wrong.
			for id, p := range points {
				if id == c.question {
					continue
				}
				if unrelated(id, c.question) && after[id] < baseline[id] {
					t.Errorf("%s fell from %.2f to %.2f of %.2f because of %q, which is "+
						"about %s; a student would lose a mark for work they did correctly",
						id, baseline[id], after[id], p, c.name, c.question)
				}
			}
		})
	}
}

// unrelated reports whether two questions are independent enough that breaking
// one must not affect the other.
//
// Some genuinely are coupled: the data-plane questions depend on routing, so
// removing an iBGP session legitimately breaks reachability too. Those pairs
// are excluded rather than asserted, because asserting them would be asserting
// something false about networks.
func unrelated(id, broken string) bool {
	coupled := map[string][]string{
		// Everything that needs routes to exist depends on the routing ones.
		"q2.1": {"q2.2", "q2.3", "q2.4", "q2.5", "q2.6", "q1.2", "q1.3"},
		"q2.3": {"q2.4", "q2.5", "q2.6"},
		"q1.2": {"q1.3", "q2.1", "q2.2", "q2.3", "q2.4", "q2.5", "q2.6"},
	}
	for _, c := range coupled[broken] {
		if c == id {
			return false
		}
	}
	return true
}

// firstIBGPPeer finds a neighbour in the router's own AS.
func firstIBGPPeer(cfg string) string {
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 4 && f[0] == "neighbor" && f[2] == "remote-as" && f[3] == "3" {
			return f[1]
		}
	}
	return ""
}
