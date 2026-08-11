package cli

import (
	"strings"
	"testing"
)

// A student's devices must not run different software depending on which node
// their autonomous system was scheduled onto.
//
// The image resolver accepted the first node's answer and stopped asking.
// Measured on this cluster: all four images differed between node-0 and the
// other two, while every report said the deployment was current. A mark that
// depends on where a container happened to be placed is not a mark, and nothing
// downstream could have detected it.
func TestADeployRefusesWhenTheNodesDisagreeOnAnImage(t *testing.T) {
	skewed := map[string]map[string]string{
		"hyhe/twinet-router:0.1": {
			"node-0": "sha256:26d10acd7dcc11112222",
			"node-1": "sha256:43372cd01d7c33334444",
			"node-2": "sha256:43372cd01d7c33334444",
		},
	}
	err := sameEverywhere(skewed)
	if err == nil {
		t.Fatal("a deployment was allowed to proceed with different images on different nodes")
	}
	for _, want := range []string{"hyhe/twinet-router:0.1", "node-0", "node-1,node-2", "26d10acd7dcc", "43372cd01d7c"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so the operator cannot act on it:\n%s", want, err)
		}
	}
}

func TestAgreementIsNotMistakenForSkew(t *testing.T) {
	agreed := map[string]map[string]string{
		"hyhe/twinet-router:0.1": {
			"node-0": "sha256:06350bc44aee",
			"node-1": "sha256:06350bc44aee",
			"node-2": "sha256:06350bc44aee",
		},
		// A node that has not pulled an image yet reports nothing and is not
		// recorded, so a first deployment is still possible.
		"hyhe/twinet-host:0.1": {"node-0": "sha256:23b9bb8fea9b"},
	}
	if err := sameEverywhere(agreed); err != nil {
		t.Errorf("a consistent cluster was refused: %v", err)
	}
}
