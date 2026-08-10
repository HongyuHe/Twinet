package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func snap(lab, device string, body string) Snapshot {
	return Snapshot{
		Lab: lab, Device: device, Kind: KindFRR, AS: 3,
		TakenAt: time.Now().UTC(), Content: []byte(body),
	}
}

// This store holds the only copy of a class's work between a container being
// destroyed and rebuilt. Every property below is one that, if broken, loses
// something no one can reconstruct.
func TestASnapshotSurvivesAndCanBeReadBack(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("cos461", "as3/MSP", "router bgp 3\n")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Current("cos461", "as3/MSP", KindFRR)
	if err != nil {
		t.Fatalf("a snapshot that was written could not be read back: %v", err)
	}
	if string(got.Content) != "router bgp 3\n" {
		t.Errorf("content changed in the store: %q", got.Content)
	}
	if !s.Has("cos461", "as3/MSP", KindFRR) {
		t.Error("Has says a stored snapshot is absent")
	}
}

// Two labs may legitimately have a device with the same name -- a grading
// harness is a copy of a class lab -- and one must never read or overwrite the
// other's work.
func TestLabsCannotSeeEachOthersWork(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("cos461", "as3/MSP", "the class")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("cos461-g3", "as3/MSP", "one submission")); err != nil {
		t.Fatal(err)
	}
	a, err := s.Current("cos461", "as3/MSP", KindFRR)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Content) != "the class" {
		t.Errorf("a harness overwrote the class lab's snapshot: %q", a.Content)
	}
	b, err := s.Current("cos461-g3", "as3/MSP", KindFRR)
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Content) != "one submission" {
		t.Errorf("the harness read the wrong snapshot: %q", b.Content)
	}
}

// A lab name arrives from a manifest, and a manifest is a file someone edits.
// A name containing a path separator must not write outside the store.
func TestAHostileLabNameCannotEscapeTheStore(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("../../etc/escaped", "as3/MSP", "x")); err != nil {
		// Refusing is also a correct answer.
		return
	}
	outside := filepath.Join(filepath.Dir(filepath.Dir(root)), "etc", "escaped")
	if _, err := os.Stat(outside); err == nil {
		t.Fatalf("a lab name wrote outside the store, to %s", outside)
	}
	var found bool
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.Contains(p, "escaped") {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("the snapshot went somewhere neither inside the store nor refused")
	}
}

// Forget is what makes a grading harness disposable. Leaving a snapshot behind
// means the next run under the same name replays the previous submission's
// configuration and marks a student on work they did not hand in.
func TestForgetRemovesALabEntirely(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("cos461-g3", "as3/MSP", "old attempt")); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget("cos461-g3"); err != nil {
		t.Fatal(err)
	}
	if s.Has("cos461-g3", "as3/MSP", KindFRR) {
		t.Error("a forgotten lab still has snapshots, which a later run would replay")
	}
	// Forgetting something that was never there is not an error: a destroy
	// that failed because there was nothing to clean up would block teardown.
	if err := s.Forget("never-existed"); err != nil {
		t.Errorf("forgetting an unknown lab failed: %v", err)
	}
}

// The topology record is what a destroy consults to know whose work to capture.
// Losing it silently is how a class's configuration disappears.
func TestTopologySurvivesAndIsForgottenSeparately(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(snap("cos461", "as3/MSP", "work worth keeping")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTopology("cos461", []byte(`{"lab":"cos461"}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := s.Topology("cos461")
	if err != nil || !strings.Contains(string(raw), "cos461") {
		t.Fatalf("the topology record did not survive: %v %q", err, raw)
	}
	labs, err := s.Labs()
	if err != nil {
		t.Fatal(err)
	}
	if len(labs) != 1 || labs[0] != "cos461" {
		t.Errorf("Labs() returned %v; a restart would forget what this node hosts", labs)
	}

	// Destroying a lab drops the record but keeps the work captured from it.
	if err := s.ForgetTopology("cos461"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Labs(); len(got) != 0 {
		t.Errorf("a destroyed lab is still listed as hosted: %v", got)
	}
	if !s.Has("cos461", "as3/MSP", KindFRR) {
		t.Error("clearing the topology record also discarded the student work")
	}
}

// A second identical capture must not be recorded as a new version, or the
// history fills with duplicates and pruning discards real revisions.
func TestAnUnchangedSnapshotIsNotRecordedTwice(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Put(snap("cos461", "as3/MSP", "same"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Put(snap("cos461", "as3/MSP", "same"))
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Error("the first capture was not recorded")
	}
	if second {
		t.Error("an identical capture was recorded as a new version")
	}
	hist, err := s.History("cos461", "as3/MSP", KindFRR)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Errorf("history has %d entries for one distinct configuration", len(hist))
	}
}
