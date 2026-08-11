package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/fault"
	"github.com/HongyuHe/twinet/internal/model"
)

func ledgerLab(t *testing.T) *model.Topology {
	t.Helper()
	return &model.Topology{Name: "t", Lab: &model.Lab{Dir: t.TempDir()}}
}

// The record is the only thing that knows a fault is running and how to undo
// it. Writing it in place means a crash halfway through leaves live faults that
// nothing can name, and the next episode runs on a network already broken in a
// way its own ground truth does not mention.
func TestTheInjectionRecordIsReplacedAtomically(t *testing.T) {
	top := ledgerLab(t)
	first := []*fault.Injection{{Fault: "link_down", Target: fault.Target{AS: 5, Device: "NYC"}}}
	if err := saveInjections(top, first); err != nil {
		t.Fatal(err)
	}
	// No partial file may be left behind for a reader to find.
	entries, err := os.ReadDir(filepath.Join(top.Lab.Dir, ".twinet"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 1 && e.Name()[0] == '.' && e.Name() != ".twinet" {
			t.Errorf("a temporary file %q was left beside the record", e.Name())
		}
	}
	got, err := loadInjections(top)
	if err != nil {
		t.Fatalf("the record could not be read back: %v", err)
	}
	if len(got) != 1 || got[0].Fault != "link_down" {
		t.Errorf("the record did not survive the round trip: %+v", got)
	}
}

// A record that cannot be read is not an empty one. Treating them alike meant
// every fault already on the lab was forgotten, left running, and could never
// be resolved because nothing knew it was there.
func TestAnUnreadableRecordIsAnError(t *testing.T) {
	top := ledgerLab(t)
	p := injectionsPath(top)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInjections(top); err == nil {
		t.Fatal("a corrupt record was reported as an empty one, so the faults it holds " +
			"would be left running with nothing able to name them")
	}
}

// An absent record is genuinely empty, and must not be an error: that is a lab
// on which nothing has been injected yet.
func TestAnAbsentRecordIsEmpty(t *testing.T) {
	got, err := loadInjections(ledgerLab(t))
	if err != nil {
		t.Fatalf("a lab with no injections was reported as broken: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no injections, got %d", len(got))
	}
}

// Two injections at once must not lose one of them.
func TestConcurrentInjectionsDoNotLoseEachOther(t *testing.T) {
	top := ledgerLab(t)
	if err := saveInjections(top, nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for i, name := range []string{"link_down", "icmp_acl_block"} {
		go func(i int, name string) {
			unlock, err := lockInjections(top)
			if err != nil {
				done <- err
				return
			}
			defer unlock()
			cur, err := loadInjections(top)
			if err != nil {
				done <- err
				return
			}
			done <- saveInjections(top, append(cur,
				&fault.Injection{Fault: name, Target: fault.Target{AS: 5 + i}}))
		}(i, name)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(injectionsPath(top))
	if err != nil {
		t.Fatal(err)
	}
	var got []*fault.Injection
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the record was corrupted by concurrent writers: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("%d of 2 injections survived; a lost one stays on the lab with nothing "+
			"able to name or undo it", len(got))
	}
}
