package fault

import (
	_ "embed"
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// nikaTypes is the taxonomy this platform is measured against: each root cause
// and the category it belongs to.
//
// Vendored rather than read from wherever NIKA happens to be checked out, so
// the conformance test runs everywhere rather than skipping quietly on the one
// machine that matters. Regenerate with the command in
// docs/10_fault_injection.md when the taxonomy changes.
//
//go:embed nika_types.json
var nikaTypes []byte

// A fault Twinet shares with the taxonomy has to sit in the same category.
//
// The category travels in the ground truth, so a scenario that expects
// `dns_service_down` under link_failure and receives it under
// network_node_error is comparing a diagnosis against a different answer than
// the one the benchmark defines. The test that existed checked only that each
// category was a member of the enum, which every category is by construction,
// so six faults sat in the wrong one and nothing said so.
func TestSharedFaultsSitInTheSameCategoryAsTheTaxonomy(t *testing.T) {
	var want map[string]string
	if err := json.Unmarshal(nikaTypes, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != 60 {
		t.Fatalf("the pinned NIKA taxonomy has %d types, want 60", len(want))
	}
	shared := 0
	for _, f := range All() {
		w, ok := want[f.Name]
		if !ok {
			continue
		}
		shared++
		if string(f.Category) != w {
			t.Errorf("%s is %q here and %q in the taxonomy; the category travels in the "+
				"ground truth, so a diagnosis would be scored against a different answer",
				f.Name, f.Category, w)
		}
	}
	if shared != len(want) {
		t.Errorf("only %d of %d pinned NIKA faults are registered; O16 requires 60/60",
			shared, len(want))
	}
}

// And the vendored copy has to still be the taxonomy. Skipped where NIKA is not
// checked out, which is honest: the assertion is about drift, and a machine
// without the source cannot see drift.
func TestTheVendoredTaxonomyMatchesItsSource(t *testing.T) {
	const src = "/users/hy/nika/docs/failure-types.md"
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("the taxonomy is not checked out here: %v", err)
	}
	var want map[string]string
	if err := json.Unmarshal(nikaTypes, &want); err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\|\\s*`([^`]+)`\\s*\\|\\s*`([^`]+)`\\s*\\|")
	found := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(string(raw), -1) {
		found[m[2]] = m[1]
	}
	if len(found) != len(want) {
		t.Errorf("the taxonomy has %d types and the vendored copy %d; regenerate it",
			len(found), len(want))
	}
	for name, cat := range found {
		if want[name] != cat {
			t.Errorf("%s is %q in the taxonomy and %q in the vendored copy; regenerate it",
				name, cat, want[name])
		}
	}
}
