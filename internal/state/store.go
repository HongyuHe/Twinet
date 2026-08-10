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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	// KindAddrs is a host's interface addressing and routes.
	KindAddrs Kind = "addrs"
	// KindOVS is a switch's port and VLAN configuration.
	KindOVS Kind = "ovs"
	// KindTunnels is a router's tunnel devices, which FRR does not manage.
	KindTunnels Kind = "tunnels"
)

// AllKinds is every artefact kind, for iteration.
var AllKinds = []Kind{KindFRR, KindAddrs, KindOVS, KindTunnels}

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
type Store struct{ root string }

// Open prepares a store rooted at dir.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("state: no directory given")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("state: create %s: %w", dir, err)
	}
	return &Store{root: dir}, nil
}

// Root returns the store's directory.
func (s *Store) Root() string { return s.root }

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
	snap.Digest = hex.EncodeToString(sum[:])
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

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("state: open %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("state: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("state: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
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
	return writeAtomic(filepath.Join(dir, "topology.json"), raw, 0o600)
}

// Topology returns the recorded topology for a lab, if there is one.
func (s *Store) Topology(lab string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.root, safe(lab), "topology.json"))
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
