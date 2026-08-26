// Package state persists the configuration a student owns.
//
// This exists because of a hard-won rule: a deployment must never be able to
// destroy a student's work. Everything else in Twinet is derived and can be
// recreated at will; the contents of a student's routers, hosts and switches
// cannot. A node reboot, a container crash, a manifest edit that changes one
// link's delay, or an operator repairing a single AS must all leave three weeks
// of a group's work exactly where it was.
//
// The store is deliberately dumb: a directory of timestamped snapshots per
// device, content-addressed, never overwritten in place, with a `current`
// pointer written atomically last. That makes it inspectable with ls, backed up
// with rsync, recoverable by hand, and impossible to corrupt with a partial
// write.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Kind classifies a stored artefact, so restore knows how to replay it.
type Kind string

const (
	// KindFRR is a router's running configuration.
	KindFRR Kind = "frr"
	// KindBIRD is a BIRD router configuration. It is separate from KindFRR
	// because replaying one vendor's syntax through the other is destructive,
	// not a compatibility fallback.
	KindBIRD Kind = "bird"
	// KindAddrs is a host's interface addressing and routes.
	KindAddrs Kind = "addrs"
	// KindOVS is a switch's port and VLAN configuration.
	KindOVS Kind = "ovs"
	// KindTunnels is a router's tunnel devices, which FRR does not manage.
	KindTunnels Kind = "tunnels"
)

// AllKinds is every artefact kind, for iteration.
var AllKinds = []Kind{KindFRR, KindBIRD, KindAddrs, KindOVS, KindTunnels}

// Snapshot is one captured artefact.
type Snapshot struct {
	Lab      string    `json:"lab"`
	AS       int       `json:"as"`
	Device   string    `json:"device"`
	Kind     Kind      `json:"kind"`
	TakenAt  time.Time `json:"taken_at"`
	Digest   string    `json:"digest"`
	Bytes    int       `json:"bytes"`
	Topology string    `json:"topology_hash,omitempty"`
	Content  []byte    `json:"-"`
}

// Store is a directory of snapshots.
type Store struct {
	root             string
	sweptTemporaries int
	sweepErr         error
}

// Open prepares a store rooted at dir and clears anything a previous process
// was killed in the middle of writing.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state: no directory given")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", dir, err)
	}
	s := &Store{root: dir}
	// Startup is the one moment where an abandoned temporary can be
	// distinguished from one in flight with certainty about our own process,
	// and it is still bounded by age so another agent sharing the directory is
	// safe. A failure here is reported to the caller's log, never fatal: a
	// node must still come up holding a class's work.
	if removed, err := s.SweepStaleTemporaries(time.Now().Add(-staleTempAge)); err != nil {
		s.sweepErr = err
	} else {
		s.sweptTemporaries = removed
	}
	return s, nil
}

// SweptTemporaries reports what Open cleared, and why it could not.
func (s *Store) SweptTemporaries() (int, error) { return s.sweptTemporaries, s.sweepErr }

// Root returns the store's directory.
func (s *Store) Root() string { return s.root }

// Healthy verifies the state root still exists and is a directory. It is a
// lightweight health signal for placement: a node with a running agent but a
// missing state disk must be treated as unavailable for durable rescheduling.
func (s *Store) Healthy() error {
	info, err := os.Stat(s.root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("state root %s is not a directory", s.root)
	}
	return nil
}

func (s *Store) deviceDir(lab, device string) string {
	return filepath.Join(s.root, safe(lab), safe(device))
}

func snapBase(t time.Time, digest string) string {
	return t.UTC().Format("20060102T150405.000") + "-" + digest[:12]
}

// Put stores a snapshot, unless an identical one is already current.
//
// Skipping an unchanged write keeps the history meaningful: a snapshot exists
// because something changed, not because a timer fired.
func (s *Store) Put(snap Snapshot) (bool, error) {
	if snap.Lab == "" || snap.Device == "" || snap.Kind == "" {
		return false, errors.New("state: a snapshot needs a lab, device and kind")
	}
	sum := sha256.Sum256(snap.Content)
	digest := hex.EncodeToString(sum[:])
	if snap.Digest != "" && snap.Digest != digest {
		return false, fmt.Errorf("state: snapshot %s/%s claims digest %s but its content is %s",
			snap.Device, snap.Kind, snap.Digest, digest)
	}
	if snap.Bytes != 0 && snap.Bytes != len(snap.Content) {
		return false, fmt.Errorf("state: snapshot %s/%s says it has %d bytes but has %d",
			snap.Device, snap.Kind, snap.Bytes, len(snap.Content))
	}
	snap.Digest = digest
	snap.Bytes = len(snap.Content)
	if snap.TakenAt.IsZero() {
		snap.TakenAt = time.Now().UTC()
	}

	if cur, err := s.Current(snap.Lab, snap.Device, snap.Kind); err == nil && cur.Digest == snap.Digest {
		return false, nil
	}

	dir := filepath.Join(s.deviceDir(snap.Lab, snap.Device), string(snap.Kind))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("state: create %s: %w", dir, err)
	}

	base := filepath.Join(dir, snapBase(snap.TakenAt, snap.Digest))
	if err := writeAtomic(base+".body", snap.Content, 0o640); err != nil {
		return false, err
	}
	meta, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return false, err
	}
	if err := writeAtomic(base+".json", meta, 0o640); err != nil {
		return false, err
	}
	// The pointer is written last and atomically, so a crash mid-save leaves
	// the previous snapshot current rather than a half-written one.
	return true, writeAtomic(filepath.Join(dir, "current"),
		[]byte(filepath.Base(base)), 0o640)
}

// Current returns the most recent snapshot of a device artefact.
func (s *Store) Current(lab, device string, kind Kind) (Snapshot, error) {
	dir := filepath.Join(s.deviceDir(lab, device), string(kind))
	ptr, err := os.ReadFile(filepath.Join(dir, "current"))
	if err != nil {
		return Snapshot{}, err
	}
	base := filepath.Join(dir, strings.TrimSpace(string(ptr)))
	meta, err := os.ReadFile(base + ".json")
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(meta, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("state: parse %s: %w", base+".json", err)
	}
	body, err := os.ReadFile(base + ".body")
	if err != nil {
		return Snapshot{}, err
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if snap.Digest == "" || snap.Digest != got {
		return Snapshot{}, fmt.Errorf("state: snapshot %s/%s digest does not match its body",
			device, kind)
	}
	if snap.Bytes != 0 && snap.Bytes != len(body) {
		return Snapshot{}, fmt.Errorf("state: snapshot %s/%s byte count does not match its body",
			device, kind)
	}
	snap.Bytes = len(body)
	snap.Content = body
	return snap, nil
}

// Has reports whether any snapshot exists for a device artefact.
func (s *Store) Has(lab, device string, kind Kind) bool {
	_, err := os.Stat(filepath.Join(s.deviceDir(lab, device), string(kind), "current"))
	return err == nil
}

// History lists a device artefact's snapshots, newest first.
func (s *Store) History(lab, device string, kind Kind) ([]Snapshot, error) {
	dir := filepath.Join(s.deviceDir(lab, device), string(kind))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Snapshot
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(raw, &snap); err != nil {
			continue
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TakenAt.After(out[j].TakenAt) })
	return out, nil
}

// Devices lists the devices with stored state for a lab.
func (s *Store) Devices(lab string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, safe(lab)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Prune keeps the newest n snapshots of each artefact and removes the rest.
// Forget removes every snapshot belonging to a lab.
//
// It exists for disposable labs. A grading harness is created, marked and
// destroyed, and its snapshots must not survive: a later run under the same
// name would replay the previous run's configuration into a fresh container
// and mark a student on work they did not submit this time.
func (s *Store) Forget(lab string) error {
	dir := filepath.Join(s.root, safe(lab))
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.RemoveAll(dir)
}

func (s *Store) Prune(lab string, keep int) (int, error) {
	if keep < 1 {
		keep = 1
	}
	devices, err := s.Devices(lab)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, d := range devices {
		for _, k := range AllKinds {
			hist, err := s.History(lab, d, k)
			if err != nil || len(hist) <= keep {
				continue
			}
			dir := filepath.Join(s.deviceDir(lab, d), string(k))
			for _, old := range hist[keep:] {
				base := snapBase(old.TakenAt, old.Digest)
				_ = os.Remove(filepath.Join(dir, base+".body"))
				if err := os.Remove(filepath.Join(dir, base+".json")); err == nil {
					removed++
				}
			}
		}
	}
	return removed, nil
}

// tempPrefix and tempMarker bracket the temporary name every atomic write
// uses. They are the only thing that identifies a leftover as ours, so the
// startup sweep below can be certain it is not removing somebody else's file.
func tempPrefix(base string) string { return "." + base + tempMarker }

const tempMarker = ".tmp-"

// writeAtomic writes a file by rename, and never leaves its temporary behind.
//
// The cleanup used to be repeated at each error return, which meant the two
// paths that did not repeat it -- a failed rename, and a Close that reported an
// error after a successful write -- leaked. Over a term of periodic captures
// that is a directory of hidden files nobody ever looks at, on the one disk
// that must not fill up: it holds the only copy of a class's work. A deferred
// cleanup keyed on whether the rename happened cannot be forgotten by a future
// error path.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	// A fixed ".tmp" name turns two periodic captures into one writer
	// truncating the other's body before either rename. Keep temporary files
	// beside their target for atomic rename, but make each writer unique.
	f, err := os.CreateTemp(dir, tempPrefix(base)+"*")
	if err != nil {
		return fmt.Errorf("state: open %s: %w", path, err)
	}
	tmp := f.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("state: chmod %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("state: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("state: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("state: rename %s: %w", path, err)
	}
	renamed = true
	return nil
}

// staleTempAge is how long a temporary file must have gone untouched before a
// sweep treats it as abandoned rather than as a write in flight.
//
// It is deliberately far longer than any single write. The cost of waiting is
// one stale file for an hour; the cost of being wrong is deleting the
// half-written snapshot of a student's configuration out from under the
// process that is writing it.
const staleTempAge = time.Hour

// SweepStaleTemporaries removes abandoned temporary files left by a process
// that was killed mid-write.
//
// A crash between CreateTemp and rename leaves a file no future run will ever
// look at again, and nothing was removing them. Only names this package
// produces are considered, and only those older than staleTempAge, so a
// concurrent writer -- including one in another agent process sharing the
// directory -- is never touched. The count of removed files is returned for
// the caller to log; a failure to remove one is not fatal.
func (s *Store) SweepStaleTemporaries(before time.Time) (int, error) {
	removed := 0
	// An unreadable subtree is skipped rather than failing the sweep: a
	// startup path must not refuse to run because one lab directory cannot be
	// listed. Nothing is removed on that path, so skipping is fail-closed.
	walk := func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil //nolint:nilerr // an unreadable entry is skipped, never removed
		}
		if !abandonedTemporary(entry, before) {
			return nil
		}
		if removeErr := os.Remove(path); removeErr == nil {
			removed++
		}
		return nil
	}
	if err := filepath.WalkDir(s.root, walk); err != nil {
		return removed, fmt.Errorf("state: sweep temporary files under %s: %w", s.root, err)
	}
	return removed, nil
}

// abandonedTemporary reports whether an entry is one of this package's
// temporary files and has gone untouched long enough to be certain no writer
// still owns it. An entry whose metadata cannot be read is never abandoned.
func abandonedTemporary(entry fs.DirEntry, before time.Time) bool {
	if entry.IsDir() || !isStateTemporary(entry.Name()) {
		return false
	}
	info, err := entry.Info()
	if err != nil {
		return false
	}
	return info.ModTime().Before(before)
}

// isStateTemporary recognises only the shape os.CreateTemp produces for this
// package: a dot, the target's own name, ".tmp-", and a random suffix.
func isStateTemporary(name string) bool {
	if !strings.HasPrefix(name, ".") {
		return false
	}
	marker := strings.LastIndex(name, tempMarker)
	if marker <= 0 {
		return false
	}
	// The target base name must be non-empty and the random suffix must be
	// present, or this is not a name this package wrote.
	return marker > 1 && len(name) > marker+len(tempMarker)
}

// safe turns an identifier into a path component.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	return out
}

// PutTopology records the topology a lab was last applied with.
//
// The agent's own memory is not a safe place for this. It is what a destroy
// consults to know which devices hold student work worth capturing, and what a
// restart needs to know which labs the node is hosting. An agent restarted for
// any reason -- an upgrade, a crash, a reboot -- would otherwise come back
// believing the node is empty, and the next destroy would take a class's work
// with it without noticing there was anything to save.
func (s *Store) PutTopology(lab string, raw []byte) error {
	dir := filepath.Join(s.root, safe(lab))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "topology.json"), raw, 0o600); err != nil {
		return err
	}
	// topology.json remains the local-hosting marker read on restart. The
	// immutable record is the replica payload: it survives removal of the
	// local marker after migration and can be recovered from another node.
	_, err := s.PutRecord(Record{Lab: lab, Kind: RecordTopology, Content: raw})
	return err
}

// Topology returns the recorded topology for a lab, if there is one.
func (s *Store) Topology(lab string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, safe(lab), "topology.json"))
}

// PutExemptions records the devices of a lab that are broken on purpose.
//
// It lives on the node, beside the lab's other state, and deliberately not
// inside the containers. A marker in the device under test tells an agent being
// evaluated on root-cause analysis both that a fault was injected and which
// one, which is the whole answer.
func (s *Store) PutExemptions(lab string, raw []byte) error {
	dir := filepath.Join(s.root, safe(lab))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "exempt.json"), raw, 0o600); err != nil {
		return err
	}
	_, err := s.PutRecord(Record{Lab: lab, Kind: RecordExemptions, Content: raw})
	return err
}

// Exemptions returns the recorded exemptions for a lab, if there are any.
func (s *Store) Exemptions(lab string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, safe(lab), "exempt.json"))
}

// PutHolds persists active repair holds. It deliberately uses a separate
// local marker from the immutable record so an agent only rehydrates a hold
// while it still hosts the lab, while replicas can retain the safe-repair
// evidence after migration.
func (s *Store) PutHolds(lab string, raw []byte) error {
	dir := filepath.Join(s.root, safe(lab))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "holds.json"), raw, 0o600); err != nil {
		return err
	}
	_, err := s.PutRecord(Record{Lab: lab, Kind: RecordHolds, Content: raw})
	return err
}

// Holds returns persisted repair holds.
func (s *Store) Holds(lab string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, safe(lab), "holds.json"))
}

// Labs lists every lab the store knows about, which after a restart is how the
// agent rediscovers what this node is hosting.
func (s *Store) Labs() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.root, e.Name(), "topology.json")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// ForgetTopology drops the record that this node hosts a lab, while keeping the
// snapshots of student work. A destroyed lab must not be resurrected by a later
// restart, but the work captured from it is still worth having.
func (s *Store) ForgetTopology(lab string) error {
	err := os.Remove(filepath.Join(s.root, safe(lab), "topology.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PutCoordination records node-local coordination metadata.
//
// Unlike a topology or a snapshot this data belongs to the agent itself: it
// contains fencing high-water marks and overlay claims shared by every lab on
// this node. Keeping it in the state store makes an agent restart invalidate
// old lease tokens without allowing an old controller to become current again.
func (s *Store) PutCoordination(raw []byte) error {
	return writeAtomic(filepath.Join(s.root, "coordination.json"), raw, 0o600)
}

// Coordination returns the node-local coordination metadata.
func (s *Store) Coordination() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, "coordination.json"))
}

// The event journal is node-local operational history, not a replicated lab
// artefact: it must survive an agent restart so an operator can trace a
// failure across that restart, but copying another node's events into this
// node would make a merged stream report the same event twice.
//
// It used to be one JSON array rewritten in full for every event. With the
// default four-thousand-event retention, every event marshalled, wrote and
// fsynced the entire retained history -- and an agent under load emits events
// faster than it does anything else: every repair, every reservation, every
// destroy. The durability is unchanged (one fsync per event either way), but
// the work per event is now the size of that event rather than the size of
// everything the node has ever recorded. Compaction rewrites the whole history
// only when the file passes a size bound, which is once per many thousand
// events.
const (
	eventJournalFile = "events.log"
	// eventJournalMaxBytes bounds the log between compactions. It is chosen so
	// compaction is rare relative to appends while the file stays small enough
	// to read back quickly at startup.
	eventJournalMaxBytes = 8 << 20
)

// AppendEventJournal durably records one encoded event and reports whether the
// log has grown past the point where it should be compacted.
func (s *Store) AppendEventJournal(raw []byte) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	path := filepath.Join(s.root, eventJournalFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("state: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	line := make([]byte, 0, len(raw)+1)
	line = append(line, raw...)
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return false, fmt.Errorf("state: append %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("state: sync %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		return false, nil
	}
	return info.Size() > eventJournalMaxBytes, nil
}

// RotateEventJournal replaces the log with exactly the retained history. It is
// an atomic rename, so an interrupted compaction leaves the previous log
// intact rather than a truncated one.
func (s *Store) RotateEventJournal(lines [][]byte) error {
	total := 0
	for _, line := range lines {
		total += len(line) + 1
	}
	buf := make([]byte, 0, total)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := writeAtomic(filepath.Join(s.root, eventJournalFile), buf, 0o600); err != nil {
		return err
	}
	// The pre-rotation array form is superseded once a log exists. Removing it
	// keeps startup from replaying a stale history behind a current one.
	if err := os.Remove(filepath.Join(s.root, "events.json")); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("state: remove superseded event journal: %w", err)
	}
	return nil
}

// EventJournalLines returns the retained encoded events, oldest first. A
// trailing partial line -- the signature of a crash mid-append -- is dropped
// rather than reported as corruption: the events before it are still exact.
func (s *Store) EventJournalLines() ([][]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, eventJournalFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out [][]byte
	for len(raw) > 0 {
		end := bytes.IndexByte(raw, '\n')
		if end < 0 {
			break
		}
		line := bytes.TrimSpace(raw[:end])
		if len(line) > 0 {
			out = append(out, append([]byte(nil), line...))
		}
		raw = raw[end+1:]
	}
	return out, nil
}

// PutEventJournal persists the whole retained journal in the pre-rotation
// array form. It remains for callers and tests written against that contract.
func (s *Store) PutEventJournal(raw []byte) error {
	if len(raw) == 0 {
		raw = []byte("[]")
	}
	return writeAtomic(filepath.Join(s.root, "events.json"), raw, 0o600)
}

// EventJournal returns the last persisted array-form journal, which is what an
// agent upgraded from a build that predates the log reads once at startup.
func (s *Store) EventJournal() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, "events.json"))
}

// KnownLabs returns every lab directory, including one whose topology marker
// was removed after destroy but whose retained snapshots or replica journal
// still need a grace-period cleanup.
func (s *Store) KnownLabs() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// GarbageCollectLabRecords removes stale hosting and replication records only
// after its caller has independently proved that the lab is no longer active
// and its generation cannot be resumed. Student snapshots are deliberately
// retained: a lab record is reconstructable control-plane state, while a
// student's configuration is not.
func (s *Store) GarbageCollectLabRecords(lab string, before time.Time, generationProven bool) (int, error) {
	if lab == "" || before.IsZero() {
		return 0, nil
	}
	if !generationProven {
		return 0, errors.New("state: refusing to garbage-collect lab records without generation proof")
	}
	dir := filepath.Join(s.root, safe(lab))
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.ModTime().Before(before) {
		return 0, nil
	}
	removed := 0
	for _, name := range []string{"topology.json", "holds.json", "exempt.json", "replication.json"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.ModTime().Before(before) {
			if err := os.Remove(path); err == nil {
				removed++
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
	}
	records := filepath.Join(dir, "_records")
	if info, err := os.Stat(records); err == nil && info.ModTime().Before(before) {
		if err := os.RemoveAll(records); err != nil {
			return removed, err
		}
		removed++
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return removed, err
	}
	// An entirely empty lab directory carries no retained student state, so it
	// is safe to remove. Do not remove a directory merely because it holds
	// snapshots: those are intentionally durable after an abandoned lab.
	if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
		if err := os.Remove(dir); err == nil {
			removed++
		}
	}
	return removed, nil
}
