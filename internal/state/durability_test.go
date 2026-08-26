package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func countTemporaries(t *testing.T, root string) int {
	t.Helper()
	found := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if isStateTemporary(filepath.Base(path)) {
			found++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestAFailedAtomicWriteLeavesNoTemporaryBehind(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	// A rename into a path whose parent is a file cannot succeed. Before the
	// deferred cleanup, that path returned the error and left the temporary
	// on the one disk that holds the only copy of a class's work.
	occupied := filepath.Join(root, "occupied")
	if err := os.WriteFile(occupied, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(occupied, "impossible.json")
	if err := writeAtomic(target, []byte("{}"), 0o600); err == nil {
		t.Fatal("writing through a file as if it were a directory succeeded")
	}
	if found := countTemporaries(t, root); found != 0 {
		t.Fatalf("a failed atomic write left %d temporary file(s) behind", found)
	}
	_ = s
}

func TestStartupSweepsAbandonedTemporariesAndKeepsFreshOnes(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatal(err)
	}
	lab := filepath.Join(root, "cos461")
	if err := os.MkdirAll(lab, 0o700); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(lab, ".topology.json.tmp-1234567")
	inflight := filepath.Join(lab, ".topology.json.tmp-7654321")
	real := filepath.Join(lab, "topology.json")
	unrelated := filepath.Join(lab, ".hidden-but-not-ours")
	for _, path := range []string{abandoned, inflight, real, unrelated} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleTempAge)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	removed, sweepErr := reopened.SweptTemporaries()
	if sweepErr != nil {
		t.Fatal(sweepErr)
	}
	if removed != 1 {
		t.Fatalf("startup swept %d files, want exactly the abandoned one", removed)
	}
	if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
		t.Fatal("an abandoned temporary survived startup")
	}
	for _, path := range []string{inflight, real, unrelated} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("startup removed %s, which it must not touch: %v", filepath.Base(path), err)
		}
	}
}

func TestOnlyThisPackagesTemporaryNamesAreSwept(t *testing.T) {
	ours := []string{
		".topology.json.tmp-12345",
		".current.tmp-9",
		".20260101T000000.000-abcdef123456.body.tmp-x",
	}
	theirs := []string{
		"topology.json", ".tmp-12345", "tmp-12345", ".topology.json",
		".topology.json.tmp-", "..tmp-1", "current",
	}
	for _, name := range ours {
		if !isStateTemporary(name) {
			t.Errorf("%q is one of ours and would never be swept", name)
		}
	}
	for _, name := range theirs {
		if isStateTemporary(name) {
			t.Errorf("%q is not ours and would be deleted", name)
		}
	}
}

func TestEventJournalAppendsRatherThanRewritingEverything(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	const events = 64
	for i := range events {
		raw, err := json.Marshal(map[string]int{"sequence": i})
		if err != nil {
			t.Fatal(err)
		}
		rotate, err := s.AppendEventJournal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if rotate {
			t.Fatalf("a %d-event journal asked to be compacted; the bound is far larger", i)
		}
	}
	lines, err := s.EventJournalLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != events {
		t.Fatalf("read back %d events, want %d", len(lines), events)
	}
	var last map[string]int
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatal(err)
	}
	if last["sequence"] != events-1 {
		t.Fatalf("the journal is out of order: last sequence %d", last["sequence"])
	}
}

func TestAppendingIsBoundedByTheEventNotByTheHistory(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"detail":"` + strings.Repeat("x", 512) + `"}`)
	// The array form rewrote the whole retained history for every event, so the
	// bytes written grew quadratically with how long the node had been up.
	// Appending writes exactly one record, so the file after n events is n
	// records long and each write is the size of its own event.
	const events = 48
	for range events {
		if _, err := s.AppendEventJournal(raw); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(root, eventJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	want := int64(events * (len(raw) + 1))
	if info.Size() != want {
		t.Fatalf("journal is %d bytes after %d appends, want %d", info.Size(), events, want)
	}
}

func TestCompactionReplacesTheLogAndRetiresTheLegacyFile(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutEventJournal([]byte(`[{"sequence":1}]`)); err != nil {
		t.Fatal(err)
	}
	for i := range 10 {
		raw, _ := json.Marshal(map[string]int{"sequence": i})
		if _, err := s.AppendEventJournal(raw); err != nil {
			t.Fatal(err)
		}
	}
	retained := [][]byte{[]byte(`{"sequence":8}`), []byte(`{"sequence":9}`)}
	if err := s.RotateEventJournal(retained); err != nil {
		t.Fatal(err)
	}
	lines, err := s.EventJournalLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("compaction kept %d events, want 2", len(lines))
	}
	if _, err := os.Stat(filepath.Join(root, "events.json")); !os.IsNotExist(err) {
		t.Fatal("the superseded array-form journal survived compaction and would be replayed")
	}
	if found := countTemporaries(t, root); found != 0 {
		t.Fatalf("compaction left %d temporary file(s)", found)
	}
}

func TestATruncatedFinalAppendDoesNotLoseTheEventsBeforeIt(t *testing.T) {
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		raw, _ := json.Marshal(map[string]int{"sequence": i})
		if _, err := s.AppendEventJournal(raw); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, eventJournalFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"sequence":3`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	lines, err := s.EventJournalLines()
	if err != nil {
		t.Fatalf("a crash mid-append made the whole journal unreadable: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("read back %d complete events, want 3", len(lines))
	}
}
