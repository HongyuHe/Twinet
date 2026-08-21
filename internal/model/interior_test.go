package model

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInteriorYAMLAcceptsCompactRouterSetsAndBooleanHub(t *testing.T) {
	var ring ASTemplate
	if err := yaml.Unmarshal([]byte(`
interior:
  kind: ring
  routers: 3
  prefix: R
  hub: true
`), &ring); err != nil {
		t.Fatal(err)
	}
	if err := ring.ValidateInterior(); err != nil {
		t.Fatalf("counted ring was rejected: %v", err)
	}
	names, err := ring.Interior.RouterNames()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"R1", "R2", "R3"}; !reflect.DeepEqual(names, want) {
		t.Errorf("ring names = %v, want %v", names, want)
	}
	if ring.Interior.Hub != HubName("hub") {
		t.Errorf("hub: true decoded as %q, want hub", ring.Interior.Hub)
	}

	var tier ASTemplate
	if err := yaml.Unmarshal([]byte(`
interior:
  kind: two-tier
  core: [C1, C2]
  edge: 2
  edge_uplinks: 1
`), &tier); err != nil {
		t.Fatal(err)
	}
	if err := tier.ValidateInterior(); err != nil {
		t.Fatalf("named/count two-tier was rejected: %v", err)
	}
	core, edge, err := tier.Interior.TwoTierRouterNames()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(core, []string{"C1", "C2"}) || !reflect.DeepEqual(edge, []string{"edge1", "edge2"}) {
		t.Errorf("two-tier names = core %v edge %v", core, edge)
	}

	var bad ASTemplate
	if err := yaml.Unmarshal([]byte(`
interior:
  kind: ring
  routers: {count: 3, typo: 1}
`), &bad); err == nil {
		t.Error("router-set mapping silently accepted an unknown field")
	}
}
