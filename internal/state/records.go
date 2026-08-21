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

// RecordKind identifies durable non-container state. These records are
// content-addressed just like snapshots: a topology, mode, exemption, or hold
// acknowledged on one node must be recoverable after that node disappears.
type RecordKind string

const (
	RecordTopology   RecordKind = "topology"
	RecordExemptions RecordKind = "exemptions"
	RecordHolds      RecordKind = "holds"
)

// Record is one immutable durable control-plane artefact.
type Record struct {
	Lab     string     `json:"lab"`
	Kind    RecordKind `json:"kind"`
	TakenAt time.Time  `json:"taken_at"`
	Digest  string     `json:"digest"`
	Bytes   int        `json:"bytes"`
	Content []byte     `json:"-"`
}

// ArtifactMeta describes a current durable object without transferring its
// body. Agents exchange this first and send only objects a replica lacks.
type ArtifactMeta struct {
	Key     string    `json:"key"`
	Lab     string    `json:"lab"`
	Device  string    `json:"device,omitempty"`
	Kind    string    `json:"kind"`
	Record  bool      `json:"record,omitempty"`
	TakenAt time.Time `json:"taken_at"`
	Digest  string    `json:"digest"`
	Bytes   int       `json:"bytes"`
}

// ReplicaAck is persisted evidence that a peer verified an object digest.
// It is audit material rather than the source of truth for recovery: a
// surviving replica is always read and re-hashed before it is used.
type ReplicaAck struct {
	Node          string    `json:"node"`
	FailureDomain string    `json:"failure_domain"`
	Digest        string    `json:"digest"`
	Acknowledged  time.Time `json:"acknowledged"`
}

// ReplicaStatus keeps the most recent acknowledgement set per artifact key.
type ReplicaStatus struct {
	Lab     string                  `json:"lab"`
	Updated time.Time               `json:"updated"`
	Acks    map[string][]ReplicaAck `json:"acks"`
}

func (s *Store) recordDir(lab string, kind RecordKind) string {
	return filepath.Join(s.root, safe(lab), "_records", safe(string(kind)))
}

func recordBase(t time.Time, digest string) string {
	return t.UTC().Format("20060102T150405.000") + "-" + digest[:12]
}

func checkRecord(record Record) (Record, error) {
	if record.Lab == "" || record.Kind == "" {
		return Record{}, errors.New("state: a record needs a lab and kind")
	}
	switch record.Kind {
	case RecordTopology, RecordExemptions, RecordHolds:
	default:
		return Record{}, fmt.Errorf("state: unknown durable record kind %q", record.Kind)
	}
	sum := sha256.Sum256(record.Content)
	got := hex.EncodeToString(sum[:])
	if record.Digest != "" && record.Digest != got {
		return Record{}, fmt.Errorf("state: %s record digest %s does not match its content %s",
			record.Kind, record.Digest, got)
	}
	if record.Bytes != 0 && record.Bytes != len(record.Content) {
		return Record{}, fmt.Errorf("state: %s record says it has %d bytes but has %d",
			record.Kind, record.Bytes, len(record.Content))
	}
	record.Digest, record.Bytes = got, len(record.Content)
	if record.TakenAt.IsZero() {
		record.TakenAt = time.Now().UTC()
	}
	return record, nil
}

// PutRecord stores a durable control-plane record unless its digest is already
// current. The current pointer is written last, so an interrupted write keeps
// the prior acknowledged record usable.
func (s *Store) PutRecord(record Record) (bool, error) {
	record, err := checkRecord(record)
	if err != nil {
		return false, err
	}
	if cur, err := s.CurrentRecord(record.Lab, record.Kind); err == nil && cur.Digest == record.Digest {
		return false, nil
	}
	dir := s.recordDir(record.Lab, record.Kind)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("state: create %s: %w", dir, err)
	}
	base := filepath.Join(dir, recordBase(record.TakenAt, record.Digest))
	if err := writeAtomic(base+".body", record.Content, 0o640); err != nil {
		return false, err
	}
	meta, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return false, err
	}
	if err := writeAtomic(base+".json", meta, 0o640); err != nil {
		return false, err
	}
	return true, writeAtomic(filepath.Join(dir, "current"), []byte(filepath.Base(base)), 0o640)
}

// CurrentRecord reads and verifies a current durable control-plane record.
func (s *Store) CurrentRecord(lab string, kind RecordKind) (Record, error) {
	dir := s.recordDir(lab, kind)
	ptr, err := os.ReadFile(filepath.Join(dir, "current"))
	if err != nil {
		return Record{}, err
	}
	base := filepath.Join(dir, strings.TrimSpace(string(ptr)))
	raw, err := os.ReadFile(base + ".json")
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(raw, &record); err != nil {
		return Record{}, fmt.Errorf("state: parse %s: %w", base+".json", err)
	}
	record.Content, err = os.ReadFile(base + ".body")
	if err != nil {
		return Record{}, err
	}
	return checkRecord(record)
}

// CurrentRecords lists the current copy of every durable control-plane record.
func (s *Store) CurrentRecords(lab string) ([]Record, error) {
	dir := filepath.Join(s.root, safe(lab), "_records")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		record, err := s.CurrentRecord(lab, RecordKind(entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}

// CurrentSnapshots lists every current captured artefact for a lab.
func (s *Store) CurrentSnapshots(lab string) ([]Snapshot, error) {
	devices, err := s.Devices(lab)
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	for _, device := range devices {
		for _, kind := range AllKinds {
			snapshot, err := s.Current(lab, device, kind)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("state: current %s/%s: %w", device, kind, err)
			}
			out = append(out, snapshot)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

// CurrentArtifactMeta inventories current objects without loading their bodies.
func (s *Store) CurrentArtifactMeta(lab string) ([]ArtifactMeta, error) {
	snapshots, err := s.CurrentSnapshots(lab)
	if err != nil {
		return nil, err
	}
	records, err := s.CurrentRecords(lab)
	if err != nil {
		return nil, err
	}
	out := make([]ArtifactMeta, 0, len(snapshots)+len(records))
	for _, snapshot := range snapshots {
		out = append(out, ArtifactMeta{
			Key: snapshotKey(snapshot.Device, snapshot.Kind), Lab: lab, Device: snapshot.Device,
			Kind: string(snapshot.Kind), TakenAt: snapshot.TakenAt, Digest: snapshot.Digest, Bytes: snapshot.Bytes,
		})
	}
	for _, record := range records {
		out = append(out, ArtifactMeta{
			Key: recordKey(record.Kind), Lab: lab, Kind: string(record.Kind), Record: true,
			TakenAt: record.TakenAt, Digest: record.Digest, Bytes: record.Bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// snapshotKey and recordKey remain stable across the peer protocol and audit
// journal. Values are path-safe because device and kind identifiers are
// already restricted by the topology model.
func snapshotKey(device string, kind Kind) string { return "snapshot/" + device + "/" + string(kind) }
func recordKey(kind RecordKind) string            { return "record/" + string(kind) }

// PutReplicaStatus atomically records acknowledgements observed by an agent.
func (s *Store) PutReplicaStatus(status ReplicaStatus) error {
	if status.Lab == "" {
		return errors.New("state: replica status needs a lab")
	}
	if status.Acks == nil {
		status.Acks = map[string][]ReplicaAck{}
	}
	if status.Updated.IsZero() {
		status.Updated = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(s.root, safe(status.Lab))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "replication.json"), raw, 0o600)
}

// ReplicaStatus returns the persisted peer acknowledgement journal.
func (s *Store) ReplicaStatus(lab string) (ReplicaStatus, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, safe(lab), "replication.json"))
	if err != nil {
		return ReplicaStatus{}, err
	}
	var status ReplicaStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return ReplicaStatus{}, fmt.Errorf("state: parse replication journal: %w", err)
	}
	if status.Acks == nil {
		status.Acks = map[string][]ReplicaAck{}
	}
	return status, nil
}

// PruneRetained removes non-current history only after the caller has proved a
// current replica quorum. The boolean is intentionally explicit: callers may
// not turn a timed cleanup into deletion merely by forgetting to check quorum.
func (s *Store) PruneRetained(lab string, before time.Time, quorumVerified bool) (int, error) {
	if !quorumVerified {
		return 0, errors.New("state: refusing to garbage-collect without proof of a replica quorum")
	}
	if before.IsZero() {
		return 0, nil
	}
	removed := 0
	devices, err := s.Devices(lab)
	if err != nil {
		return 0, err
	}
	for _, device := range devices {
		for _, kind := range AllKinds {
			history, err := s.History(lab, device, kind)
			if err != nil {
				return removed, err
			}
			current, err := s.Current(lab, device, kind)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return removed, err
			}
			dir := filepath.Join(s.deviceDir(lab, device), string(kind))
			for _, old := range history {
				if old.Digest == current.Digest || !old.TakenAt.Before(before) {
					continue
				}
				base := snapBase(old.TakenAt, old.Digest)
				_ = os.Remove(filepath.Join(dir, base+".body"))
				if err := os.Remove(filepath.Join(dir, base+".json")); err == nil {
					removed++
				}
			}
		}
	}
	records, err := s.CurrentRecords(lab)
	if err != nil {
		return removed, err
	}
	for _, current := range records {
		dir := s.recordDir(lab, current.Kind)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return removed, err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return removed, err
			}
			var old Record
			if err := json.Unmarshal(raw, &old); err != nil {
				return removed, err
			}
			if old.Digest == current.Digest || !old.TakenAt.Before(before) {
				continue
			}
			base := recordBase(old.TakenAt, old.Digest)
			_ = os.Remove(filepath.Join(dir, base+".body"))
			if err := os.Remove(filepath.Join(dir, base+".json")); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}
