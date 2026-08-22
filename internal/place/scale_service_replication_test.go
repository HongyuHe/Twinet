package place

import (
	"math"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// The scale manifest is the regression guard for O6's original symptom: its
// old singleton services produced 204 cross-fabric service links (64%). A
// replica on each declared node makes every attach-to-every-AS link local.
func TestScaleServiceLinksStayLocalWithPerNodeReplicas(t *testing.T) {
	top := loadScaleForCapacity(t, 3)
	assignment, err := Place(top, Options{})
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

// The three-worker O1 target has 3 x 50.4 allocatable CPU after host
// headroom. Router requests intentionally include the private FRR control
// sidecar: 0.04 shell + 0.08 control = 0.12 aggregate. This test prevents a
// harmless-looking default change from making strict admission either reject
// the target cluster or silently forget the sidecar cost.
func TestScaleCapacityFitsThreeWorkersButRefusesTwo(t *testing.T) {
	three := loadScaleForCapacity(t, 3)
	assignment, err := Place(three, Options{Strict: true})
	if err != nil {
		t.Fatalf("three-node scale target was refused: %v", err)
	}
	summary := SummarizeCapacity(three)
	if got, want := summary.Controls.CPUs, 51.52; math.Abs(got-want) > 1e-9 {
		t.Fatalf("FRR controls reserve %.2f CPU, want %.2f; sidecars were not accounted for", got, want)
	}
	for node, pressure := range summary.Pressure {
		if pressure.Ratio > 0.80 {
			t.Errorf("%s is %.1f%% full on %s; scale requires at least 20%% headroom",
				node, 100*pressure.Ratio, pressure.Dimension)
		}
	}
	if len(assignment.ByAS) != len(three.ASes) {
		t.Fatalf("placed %d ASes, want %d", len(assignment.ByAS), len(three.ASes))
	}

	two := loadScaleForCapacity(t, 2)
	if _, err := Place(two, Options{Strict: true}); err == nil {
		t.Fatal("two workers admitted the three-worker scale request")
	} else if !strings.Contains(strings.ToLower(err.Error()), "cpu") {
		t.Fatalf("two-worker refusal did not identify CPU pressure: %v", err)
	}
}

func loadScaleForCapacity(t *testing.T, nodes int) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	if nodes < len(loaded.Lab.Placement.Nodes) {
		loaded.Lab.Placement.Nodes = append([]model.NodeSpec(nil), loaded.Lab.Placement.Nodes[:nodes]...)
		for name := range loaded.Lab.Placement.Reserve {
			if _, ok := loaded.Lab.NodeByName(name); !ok {
				delete(loaded.Lab.Placement.Reserve, name)
			}
		}
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology
}
