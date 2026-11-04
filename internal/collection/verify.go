package collection

import (
	"fmt"
	"os"
	"path/filepath"
)

// Verify checks the entire retained journal against its sequence and summary.
// Live sessions are checked through their last complete event.
func Verify(root, id string) error {
	m, err := ReadMetadata(root, id)
	if err != nil {
		return err
	}
	var count uint64
	var previous int64
	var last Event
	if err := ReadEvents(root, id, func(e Event) error {
		if e.TimeNS < previous {
			return fmt.Errorf("event %d moves backwards in time", e.Seq)
		}
		previous = e.TimeNS
		count++
		last = e
		return nil
	}); err != nil {
		return err
	}
	if m.Status == "recording" {
		return nil
	}
	dir, _ := sessionDir(root, id)
	stat, err := os.Stat(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	if m.Bytes != stat.Size() || m.Events != count {
		return fmt.Errorf("session %s summary differs from journal", id)
	}
	hash, err := fileHash(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	if hash != m.SHA256 {
		return fmt.Errorf("session %s checksum mismatch", id)
	}
	if m.Status == "complete" && last.Type != "session_end" {
		return fmt.Errorf("completed session %s has no final event", id)
	}
	return nil
}
