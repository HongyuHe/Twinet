package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/HongyuHe/twinet/internal/client"
	"github.com/HongyuHe/twinet/internal/place"
)

func stagedPlacement(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	record := &place.Record{
		Lab: "cos461", Strategy: "spread-by-as",
		ByAS:      map[int]string{1: "node-0", 2: "node-1"},
		ByService: map[string]string{},
	}
	if err := place.StageRecord(dir, record); err != nil {
		t.Fatal(err)
	}
	return dir
}

func recordedPlacement(t *testing.T, dir string) *place.Record {
	t.Helper()
	record, err := place.LoadRecord(dir, "cos461")
	if err != nil {
		t.Fatalf("load placement record: %v", err)
	}
	return record
}

// A deployment that committed on every node is live. Its placement record is
// the only thing that says which machine holds which autonomous system, so
// discarding it because finalization failed would leave every later exec,
// grade, save, and destroy looking on the wrong nodes.
func TestPostCommitFailureKeepsThePlacementItCommitted(t *testing.T) {
	dir := stagedPlacement(t)
	deployErr := errors.New("finalization did not complete")

	if err := settleStagedRecord(dir, errors.Join(client.ErrCommitted, deployErr), false); err != nil {
		t.Fatal(err)
	}
	record := recordedPlacement(t, dir)
	if record == nil || record.ByAS[1] != "node-0" || record.ByAS[2] != "node-1" {
		t.Fatalf("committed placement was not recorded: %+v", record)
	}
	if _, err := os.Stat(filepath.Join(dir, place.PendingRecordName)); !os.IsNotExist(err) {
		t.Errorf("staged placement was left pending: %v", err)
	}
}

// A failure before commit applied nothing, so the staged assignment describes
// a lab that does not exist and must not survive.
func TestPreCommitFailureDiscardsTheStagedPlacement(t *testing.T) {
	dir := stagedPlacement(t)

	if err := settleStagedRecord(dir, errors.New("apply node-1: no such image"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, place.PendingRecordName)); !os.IsNotExist(err) {
		t.Errorf("staged placement survived a failure that changed nothing: %v", err)
	}
	if record := recordedPlacement(t, dir); record != nil {
		t.Errorf("a lab that was never deployed has a placement record: %+v", record)
	}
}

// A dry run stages nothing and must settle nothing.
func TestDryRunLeavesTheStagedPlacementAlone(t *testing.T) {
	dir := stagedPlacement(t)

	if err := settleStagedRecord(dir, errors.New("planned only"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, place.PendingRecordName)); err != nil {
		t.Errorf("a dry run touched the staged placement: %v", err)
	}
}
