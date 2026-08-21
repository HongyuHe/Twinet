package place

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every command that has to find a device -- exec, grade, save, restore, the
// gateway -- recomputes placement from the manifest. So the answer must not
// change while a lab is running, and it changed for entirely ordinary reasons:
// adding one student to a term already under way moved seven of the other ten
// autonomous systems. The containers stayed where they were, so every one of
// those commands then looked on the wrong node and reported "no such
// container", which reads as a broken lab rather than as arithmetic that has
// drifted.
func TestAddingAStudentLeavesTheOthersWhereTheyAre(t *testing.T) {
	before := peeringLab(20, 3, 10)
	a, err := Place(before, Options{Strategy: "pack-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	rec := a.Record("t", "pack-by-as")

	// Without the record, the placement is free to change, and does.
	after := peeringLab(21, 3, 10)
	fresh, err := Place(after, Options{Strategy: "pack-by-as"})
	if err != nil {
		t.Fatal(err)
	}
	drifted := 0
	for asn, node := range rec.ByAS {
		if fresh.ByAS[asn] != node {
			drifted++
		}
	}
	if drifted == 0 {
		t.Skip("this topology happens not to drift; the test cannot demonstrate the fix")
	}

	// With it, nothing that was already placed moves.
	after = peeringLab(21, 3, 10)
	held, err := Place(after, Options{Strategy: "pack-by-as", Fixed: rec})
	if err != nil {
		t.Fatal(err)
	}
	for asn, node := range rec.ByAS {
		if held.ByAS[asn] != node {
			t.Errorf("AS %d was on %s and moved to %s; its containers would be rebuilt",
				asn, node, held.ByAS[asn])
		}
	}
	if held.ByAS[21] == "" {
		t.Error("the new AS was not placed")
	}
	if len(held.Moved) != 0 {
		t.Errorf("nothing should have had to move: %v", held.Moved)
	}
}

// A rebalance is the one way an AS moves without a reason forced on it, so it
// has to be explicit.
func TestRebalanceIgnoresTheRecord(t *testing.T) {
	top := peeringLab(20, 3, 10)
	if _, err := Place(top, Options{Strategy: "pack-by-as"}); err != nil {
		t.Fatal(err)
	}
	// A record that puts everything on one node: honoured normally, ignored
	// under rebalance.
	rec := &Record{Lab: "t", ByAS: map[int]string{}, ByService: map[string]string{}}
	for asn := 1; asn <= 20; asn++ {
		rec.ByAS[asn] = "node-0"
	}

	held, err := Place(peeringLab(20, 3, 10), Options{Strategy: "pack-by-as", Fixed: rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(held.Load) != 1 {
		t.Errorf("the record put everything on node-0 and was not honoured: %v", held.Load)
	}

	fresh, err := Place(peeringLab(20, 3, 10),
		Options{Strategy: "pack-by-as", Fixed: rec, Rebalance: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Load) < 2 {
		t.Errorf("--rebalance still obeyed the record: %v", fresh.Load)
	}
}

// A node removed from the manifest is the one case where an AS has to move.
// That must be reported, because it costs the student their containers.
func TestARemovedNodeIsReportedRatherThanObeyed(t *testing.T) {
	rec := &Record{Lab: "t", ByAS: map[int]string{1: "node-9"}, ByService: map[string]string{}}
	top := peeringLab(6, 2, 4)
	a, err := Place(top, Options{Strategy: "pack-by-as", Fixed: rec})
	if err != nil {
		t.Fatal(err)
	}
	if a.ByAS[1] == "node-9" {
		t.Fatal("an AS was placed on a node that is not in the manifest")
	}
	if len(a.Moved) != 1 {
		t.Fatalf("the move was not reported: %v", a.Moved)
	}
}

func TestRecordSurvivesARoundTrip(t *testing.T) {
	dir := t.TempDir()
	if r, err := LoadRecord(dir, "t"); err != nil || r != nil {
		t.Fatalf("a lab that has never been deployed should read as no record: %v, %v", r, err)
	}
	in := &Record{Lab: "t", Strategy: "pack-by-as",
		ByAS: map[int]string{3: "node-1"}, ByService: map[string]string{"dns": "node-0"}}
	if err := SaveRecord(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadRecord(dir, "t")
	if err != nil {
		t.Fatal(err)
	}
	if out.ByAS[3] != "node-1" || out.ByService["dns"] != "node-0" {
		t.Errorf("read back %+v", out)
	}

	// A record belonging to another lab must not be applied to this one: it
	// would pin ASes to nodes chosen for a different topology.
	if _, err := LoadRecord(dir, "other"); err == nil {
		t.Error("a record from lab \"t\" was accepted for lab \"other\"")
	}

	// A corrupt record is not the same as no record. Treating it as absent
	// would recompute a placement that disagrees with the running containers,
	// which is exactly what the record exists to prevent.
	if err := os.WriteFile(filepath.Join(dir, RecordName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecord(dir, "t"); err == nil {
		t.Error("a corrupt record was read as an absent one")
	}
}

func TestAtomicRecordEncodingDoesNotGainGroupFields(t *testing.T) {
	r := (&Assignment{
		ByAS:      map[int]string{3: "node-1"},
		ByGroup:   map[string]string{},
		ByService: map[string]string{"dns": "node-0"},
	}).Record("t", "pack-by-as")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "by_group") {
		t.Errorf("ordinary placement record changed wire format: %s", raw)
	}
}
