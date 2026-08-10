package grade

import (
	"encoding/json"
	"os"
	"testing"
)

// These fixtures are real output captured from the FRR version the platform
// ships, from a running lab. They exist because a shape mismatch that produced
// an empty map and no error turned two policy checks into unconditional passes:
// every student appeared to have a correct export policy.
//
// Any FRR upgrade should refresh them and re-run this test.

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	return b
}

// The main table maps a prefix to an array of paths, with next hops in a list.
func TestDecodeShowIPBGP(t *testing.T) {
	var doc bgpRouteJSON
	if err := json.Unmarshal(loadFixture(t, "bgp_table.json"), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !doc.Decoded() {
		t.Fatal("the document was not recognised as a BGP table")
	}
	table := doc.Table()
	if len(table) == 0 {
		t.Fatal("no routes decoded")
	}
	found := false
	for prefix, paths := range table {
		if len(paths) == 0 {
			t.Errorf("prefix %s decoded with no paths", prefix)
			continue
		}
		for _, p := range paths {
			if len(p.NextHops()) > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Error("no next hop decoded from any path; the nexthops field is not being read")
	}
}

// Advertised routes use a different top-level key, a bare object per prefix,
// and a scalar next hop. All three differences are silent if unhandled.
func TestDecodeAdvertisedRoutes(t *testing.T) {
	var doc bgpRouteJSON
	if err := json.Unmarshal(loadFixture(t, "advertised_routes.json"), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !doc.Decoded() {
		t.Fatal("the document was not recognised as a BGP table")
	}
	table := doc.Table()
	if len(table) == 0 {
		t.Fatal("no advertised routes decoded; this is the bug that made policy checks pass unconditionally")
	}
	for prefix, paths := range table {
		if len(paths) != 1 {
			t.Errorf("prefix %s decoded into %d paths, expected exactly 1", prefix, len(paths))
		}
		for _, p := range paths {
			if len(p.NextHops()) == 0 {
				t.Errorf("prefix %s decoded with no next hop; the scalar nextHop field is not being read", prefix)
			}
			if p.Network == "" {
				t.Errorf("prefix %s decoded with no network field", prefix)
			}
		}
	}
}

// A route the AS originates has an empty AS path; one learned from a neighbour
// does not. Several policy checks turn on exactly this distinction.
func TestOriginatedDistinguishesLocalFromLearned(t *testing.T) {
	var doc bgpRouteJSON
	if err := json.Unmarshal(loadFixture(t, "advertised_routes.json"), &doc); err != nil {
		t.Fatal(err)
	}
	var originated, learned int
	for _, paths := range doc.Table() {
		for _, p := range paths {
			if p.Originated() {
				originated++
			} else {
				learned++
			}
		}
	}
	if learned == 0 {
		t.Error("no learned routes found in the fixture; the path field is not being read")
	}
}

func TestBGPSummaryDecodes(t *testing.T) {
	var doc bgpSummaryJSON
	if err := json.Unmarshal(loadFixture(t, "bgp_summary.json"), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(doc.IPv4Unicast.Peers) == 0 {
		t.Fatal("no peers decoded from the summary")
	}
	established := 0
	for addr, p := range doc.IPv4Unicast.Peers {
		if p.RemoteAs == 0 {
			t.Errorf("peer %s decoded with no remote AS", addr)
		}
		if p.State == "Established" {
			established++
		}
	}
	if established == 0 {
		t.Error("no established peer decoded; the state field is not being read")
	}
}

// A malformed or unrecognised document must be reported, never mistaken for an
// empty table, or a grader fault becomes a student's zero.
func TestUnrecognisedOutputIsNotAnEmptyTable(t *testing.T) {
	var doc bgpRouteJSON
	if err := json.Unmarshal([]byte(`{"someOtherShape":{"a":1}}`), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Decoded() {
		t.Error("an unrecognised document must not report itself as decoded")
	}
	if doc.Table() != nil {
		t.Error("an unrecognised document must not yield a table")
	}
}
