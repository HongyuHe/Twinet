//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMixedNOSReferenceScoresTwiceCleanly is the O10 acceptance gate. The
// transit references use BIRD while AS 3 remains an ordinary FRR submission
// topology, so this catches a provider that renders a plausible session but
// drops the declared invalid-origin route or changes grading semantics.
func TestMixedNOSReferenceScoresTwiceCleanly(t *testing.T) {
	dir := labDir(t)
	topology := topologyForCluster(t, dir)
	for _, asn := range []int{1, 2} {
		as := topology.ASes[asn]
		if as == nil || len(as.Routers) != 1 || as.Routers[0].EffectiveNOS() != "bird" {
			t.Fatalf("AS %d is not the expected BIRD staff reference", asn)
		}
	}

	for run := 1; run <= 2; run++ {
		solveAS(t, dir, 3)
		out := e2eArtifactDir(t, fmt.Sprintf("live-mixed-nos-reference-%d", run))
		result, err := twinet(t, "grade", "run", "-m", dir, "--as", "3",
			"-o", out, "--converge-timeout", "6m")
		if err != nil {
			t.Fatalf("mixed-NOS reference run %d: %v\n%s", run, err, result)
		}
		raw, err := os.ReadFile(filepath.Join(out, "group3.json"))
		if err != nil {
			t.Fatalf("mixed-NOS reference run %d wrote no group3 report: %v", run, err)
		}
		var report struct {
			Total       float64 `json:"total"`
			MaxTotal    float64 `json:"max_total"`
			NeedsReview bool    `json:"needs_review"`
			Err         string  `json:"error"`
			Questions   []struct {
				Results []struct {
					Check    string `json:"check"`
					Status   string `json:"status"`
					Duration string `json:"duration"`
				} `json:"results"`
			} `json:"questions"`
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatalf("parse mixed-NOS report %d: %v", run, err)
		}
		if report.NeedsReview || report.Err != "" || report.Total != 10 || report.MaxTotal != 10 {
			t.Fatalf("mixed-NOS run %d = %.2f/%.2f needs_review=%v err=%q\n%s",
				run, report.Total, report.MaxTotal, report.NeedsReview, report.Err, raw)
		}
		for _, question := range report.Questions {
			for _, check := range question.Results {
				if check.Status != "pass" {
					t.Fatalf("mixed-NOS run %d: %s is %s", run, check.Check, check.Status)
				}
				if check.Check != "dataplane.internal_reachability" && check.Check != "bgp.next_hop_self" {
					continue
				}
				duration, err := time.ParseDuration(check.Duration)
				if err != nil || duration <= 0 || duration >= 2*time.Minute {
					t.Fatalf("mixed-NOS run %d: %s duration %q is not comfortably below 2m",
						run, check.Check, check.Duration)
				}
			}
		}
		t.Logf("mixed-NOS reference run %d report: %s", run, filepath.Join(out, "group3.json"))
	}
}
