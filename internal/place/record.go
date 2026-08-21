package place

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The record of where a lab was actually deployed.
//
// Placement is recomputed from the manifest by every command that has to find a
// device: exec, grade, save, restore, the gateway. For that to work, the answer
// must never change while a lab is running -- and it changed for all sorts of
// ordinary reasons. Adding one student to a term already under way moved seven
// of the other ten autonomous systems; so did any improvement to the placer
// itself. The containers stayed where they were, so every command then looked
// for them on the wrong node and reported "no such container", which reads like
// a broken lab rather than arithmetic that has drifted.
//
// Writing the assignment down at deploy time and reading it back afterwards is
// what makes the answer stable. It also makes a rebalance an explicit act with
// a visible cost, rather than something that happens by accident.

// RecordName is the file the assignment is written to inside the lab's private
// directory.
const RecordName = "placement.json"

// PendingRecordName is an uncommitted placement prepared before a fenced
// cluster mutation. It is never treated as active placement: committing it is
// the last step after every node acknowledged the durable apply.
const PendingRecordName = "placement.pending.json"

// LoadRecord reads the recorded placement for a lab.
//
// A missing record is not an error: the lab has simply not been deployed yet.
// An unreadable one is, because carrying on would recompute a placement that
// disagrees with the containers already running -- the exact failure the record
// exists to prevent, arrived at by ignoring the evidence that it happened.
func LoadRecord(dir, lab string) (*Record, error) {
	if _, err := os.Stat(filepath.Join(dir, PendingRecordName)); err == nil {
		return nil, fmt.Errorf("an unfinalized placement transaction exists at %s; refusing to use the older record "+
			"because the cluster may already have committed the staged assignment. Complete or explicitly recover "+
			"the transaction before issuing another placement-sensitive command",
			filepath.Join(dir, PendingRecordName))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("checking staged placement record: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, RecordName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the recorded placement: %w", err)
	}
	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("the recorded placement in %s is corrupt (%w); "+
			"delete it and redeploy with --rebalance if the lab is not running",
			filepath.Join(dir, RecordName), err)
	}
	if r.Lab != "" && lab != "" && r.Lab != lab {
		return nil, fmt.Errorf("the recorded placement in %s belongs to lab %q, not %q",
			filepath.Join(dir, RecordName), r.Lab, lab)
	}
	if r.ByAS == nil {
		r.ByAS = map[int]string{}
	}
	if r.ByGroup == nil {
		r.ByGroup = map[string]string{}
	}
	if r.ByService == nil {
		r.ByService = map[string]string{}
	}
	return &r, nil
}

// SaveRecord writes the assignment, atomically.
//
// A half-written record is worse than none: it would place some ASes and
// silently recompute the rest, which is the drift this is meant to stop, in a
// form that looks deliberate.
func SaveRecord(dir string, r *Record) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+RecordName+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, RecordName))
}

// StageRecord writes an intended placement without making it authoritative.
// A controller crash leaves evidence for diagnosis but never causes later
// commands to route to a placement that did not commit.
func StageRecord(dir string, r *Record) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return writePlacementFile(filepath.Join(dir, PendingRecordName), raw)
}

// CommitStagedRecord atomically promotes the intended placement after the
// cluster transaction has committed. Rename keeps readers from ever observing
// a half-written assignment.
func CommitStagedRecord(dir string) error {
	pending := filepath.Join(dir, PendingRecordName)
	if _, err := os.Stat(pending); err != nil {
		return fmt.Errorf("committing staged placement: %w", err)
	}
	if err := os.Chmod(pending, 0o640); err != nil {
		return err
	}
	return os.Rename(pending, filepath.Join(dir, RecordName))
}

// DiscardStagedRecord clears a placement that did not commit. A cleanup error
// is returned because retaining ambiguous controller evidence should be loud,
// not silently mistaken for a successful deployment.
func DiscardStagedRecord(dir string) error {
	err := os.Remove(filepath.Join(dir, PendingRecordName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writePlacementFile(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
