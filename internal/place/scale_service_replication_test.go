package place

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// The scale manifest is the regression guard for O6's original symptom: its
// old singleton services produced 204 cross-fabric service links (64%). A
// replica on each declared node makes every attach-to-every-AS link local.
func TestScaleServiceLinksStayLocalWithPerNodeReplicas(t *testing.T) {
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := Place(result.Topology, Options{})
	if err != nil {
		t.Fatal(err)
	}
	locality := assignment.Locality[model.LinkClassService]
	if locality.Local == 0 {
		t.Fatal("scale topology has no service links to measure")
	}
	if locality.CrossNode != 0 {
		t.Fatalf("scale service links are %d local / %d cross-node; per-node replicas should reduce the old 64%% cross-link star to zero",
			locality.Local, locality.CrossNode)
	}
}
