package agent

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
)

func TestApplyResponseIncludesObservedDiffAndMutationStats(t *testing.T) {
	resp := ApplyResponse{}
	attachDeploymentStats(&resp, deploy.DeploymentStats{
		ObserveMS: 12,
		DiffMS:    7,
		Dirty:     map[string]int{"wire": 1},
		Mutations: map[string]int{"qdisc": 2},
	}, nil)
	if resp.PhaseMS["observe"] != 12 || resp.PhaseMS["diff"] != 7 {
		t.Fatalf("phase timings = %#v", resp.PhaseMS)
	}
	if resp.PhaseMS["image"] != 0 || resp.PhaseMS["verify"] != 0 || resp.PhaseMS["capture"] != 0 {
		t.Fatalf("missing zero-valued visible phases: %#v", resp.PhaseMS)
	}
	if resp.Dirty["wire"] != 1 || resp.Mutations["qdisc"] != 2 {
		t.Fatalf("response dirty/mutations = %#v / %#v", resp.Dirty, resp.Mutations)
	}
}
