// Package collection stores terminal recordings and structured session events.
// The JSONL journal is authoritative; replay formats are derived from it.
package collection

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const Schema = 1
const MaxEventBytes = 128 << 10

var validID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Metadata is the searchable, small summary of one SSH channel.
type Metadata struct {
	Schema            int        `json:"schema"`
	ID                string     `json:"id"`
	Lab               string     `json:"lab"`
	Group             string     `json:"group"`
	AS                int        `json:"as"`
	Actor             string     `json:"actor"`
	AuthMethod        string     `json:"auth_method"`
	KeyFingerprint    string     `json:"key_fingerprint,omitempty"`
	RemoteAddress     string     `json:"remote_address,omitempty"`
	Gateway           string     `json:"gateway"`
	Started           time.Time  `json:"started"`
	Ended             *time.Time `json:"ended,omitempty"`
	Status            string     `json:"status"`
	Reason            string     `json:"reason,omitempty"`
	CaptureInput      bool       `json:"capture_input"`
	ShellEvents       bool       `json:"shell_events"`
	ApplicationEvents bool       `json:"application_events"`
	TTY               bool       `json:"tty"`
	Rows              int        `json:"rows"`
	Cols              int        `json:"cols"`
	Events            uint64     `json:"events"`
	Bytes             int64      `json:"bytes"`
	SHA256            string     `json:"sha256,omitempty"`
}

// Event preserves exact stream bytes as base64 through encoding/json's []byte
// encoding. TimeNS is monotonic elapsed time, independent of clock adjustments.
type Event struct {
	Schema  int            `json:"schema"`
	Session string         `json:"session"`
	Seq     uint64         `json:"seq"`
	TimeNS  int64          `json:"time_ns"`
	Type    string         `json:"type"`
	Device  string         `json:"device,omitempty"`
	Segment string         `json:"segment,omitempty"`
	Data    []byte         `json:"data,omitempty"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type Options struct {
	Dir             string
	SyncInterval    time.Duration
	MaxSessionBytes int64
	MaxTotalBytes   int64
}

// Store owns a gateway spool exclusively. Readers and the collector can use
// the exported read functions without opening a writer Store.
type Store struct {
	starts  sync.WaitGroup
	used    atomic.Int64
	options Options
	lock    *os.File
	mu      sync.Mutex
	active  map[string]*Recording
	stop    chan struct{}
	done    chan struct{}
	closed  bool
}

type Recording struct {
	mu              sync.Mutex
	store           *Store
	meta            Metadata
	file            journalFile
	start           time.Time
	seq             uint64
	bytes           int64
	device, segment string
	err             error
	broken          bool
	closed          bool
}

type journalFile interface {
	io.WriteCloser
	io.Seeker
	Sync() error
	Truncate(int64) error
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func sessionDir(root, id string) (string, error) {
	if !validID.MatchString(id) {
		return "", errors.New("invalid session ID")
	}
	return filepath.Join(root, id), nil
}

func Open(options Options) (*Store, error) {
	if options.Dir == "" {
		return nil, errors.New("collection directory is required")
	}
	if options.SyncInterval == 0 {
		options.SyncInterval = time.Second
	}
	if options.SyncInterval < 0 {
		return nil, errors.New("sync interval must be positive")
	}
	if options.MaxSessionBytes == 0 {
		options.MaxSessionBytes = 256 << 20
	}
	if options.MaxTotalBytes == 0 {
		options.MaxTotalBytes = 10 << 30
	}
	if options.MaxTotalBytes < options.MaxSessionBytes {
		return nil, errors.New("total byte limit must be at least the session byte limit")
	}
	if options.MaxSessionBytes < 4096 {
		return nil, errors.New("session byte limit must be at least 4096")
	}
	if err := os.MkdirAll(options.Dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(options.Dir, ".writer.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("collection directory already has a writer: %w", err)
	}
	s := &Store{options: options, lock: lock, active: map[string]*Recording{}, stop: make(chan struct{}), done: make(chan struct{})}
	err = filepath.WalkDir(options.Dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && entry.Name() == "events.jsonl" {
			stat, err := entry.Info()
			if err != nil {
				return err
			}
			s.used.Add(stat.Size())
		}
		return nil
	})
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := s.recover(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	go s.syncLoop()
	return s, nil
}

func (s *Store) Start(meta Metadata) (*Recording, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("collection store is closed")
	}
	s.starts.Add(1)
	s.mu.Unlock()
	defer s.starts.Done()
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	meta.Schema, meta.ID, meta.Started, meta.Status = Schema, id, time.Now().UTC(), "recording"
	dir, _ := sessionDir(s.options.Dir, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	started := false
	defer func() {
		if !started {
			_ = os.RemoveAll(dir)
		}
	}()
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	r := &Recording{store: s, meta: meta, file: f, start: time.Now()}
	defer func() {
		if !started {
			s.used.Add(-r.bytes)
		}
	}()
	if err := writeMetadata(dir, meta); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := r.Add("session_start", nil, nil); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	s.mu.Lock()
	s.active[id] = r
	s.mu.Unlock()
	started = true
	return r, nil
}

func (r *Recording) ID() string { return r.meta.ID }

func (r *Recording) Select(device, segment string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.device, r.segment = device, segment
}

func (r *Recording) Add(kind string, data []byte, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("recording is closed")
	}
	if r.err != nil {
		return r.err
	}
	return r.append(kind, data, fields, false)
}

func (r *Recording) append(kind string, data []byte, fields map[string]any, finishing bool) error {
	e := Event{Schema: Schema, Session: r.meta.ID, Seq: r.seq + 1, TimeNS: time.Since(r.start).Nanoseconds(), Type: kind, Device: r.device, Segment: r.segment, Data: data, Fields: fields}
	b, err := json.Marshal(e)
	if err == nil && len(b) > MaxEventBytes {
		err = errors.New("collection event exceeds size limit")
	}
	if err == nil && !finishing && r.bytes+int64(len(b)+1) > r.store.options.MaxSessionBytes {
		err = errors.New("collection session reached byte limit")
	}
	if err != nil {
		r.err = err
		return err
	}
	b = append(b, '\n')
	reserved := int64(len(b))
	if total := r.store.used.Add(reserved); !finishing && total > r.store.options.MaxTotalBytes {
		r.store.used.Add(-reserved)
		r.err = errors.New("collection spool reached total byte limit")
		return r.err
	}
	n, err := r.file.Write(b)
	r.store.used.Add(int64(n) - reserved)
	r.bytes += int64(n)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// A failed append must never leave half a JSON object before the final
		// event. If rollback fails, leave metadata unfinished for recovery.
		offset := r.bytes - int64(n)
		rollbackErr := r.file.Truncate(offset)
		if rollbackErr == nil {
			_, rollbackErr = r.file.Seek(offset, io.SeekStart)
		}
		if rollbackErr == nil {
			r.bytes = offset
			r.store.used.Add(-int64(n))
		} else {
			r.broken = true
			err = errors.Join(err, rollbackErr)
		}
		r.err = err
		return err
	}
	r.seq++
	return nil
}

func (r *Recording) Err() error { r.mu.Lock(); defer r.mu.Unlock(); return r.err }

func (r *Recording) Close(status, reason string, code int) error {
	r.mu.Lock()
	if r.closed {
		err := r.err
		r.mu.Unlock()
		return err
	}
	if r.err != nil {
		status, reason = "incomplete", r.err.Error()
	}
	finishErr := r.err
	if !r.broken {
		finishErr = r.append("session_end", nil, map[string]any{"status": status, "reason": reason, "exit_code": code}, true)
	}
	finalized := finishErr == nil
	if finishErr != nil {
		status, reason = "incomplete", finishErr.Error()
	}
	if err := r.file.Sync(); err != nil {
		r.err = err
		finalized = false
		status, reason = "incomplete", err.Error()
	}
	_ = r.file.Close()
	r.closed = true
	now := time.Now().UTC()
	r.meta.Ended, r.meta.Status, r.meta.Reason = &now, status, reason
	r.meta.Bytes, r.meta.Events = r.bytes, r.seq
	dir, _ := sessionDir(r.store.options.Dir, r.meta.ID)
	if finalized {
		r.meta.SHA256, finishErr = fileHash(filepath.Join(dir, "events.jsonl"))
		if finishErr == nil {
			finishErr = writeMetadata(dir, r.meta)
		}
	}
	if finishErr != nil {
		r.err = finishErr
	}
	err := r.err
	r.mu.Unlock()
	r.store.mu.Lock()
	delete(r.store.active, r.meta.ID)
	r.store.mu.Unlock()
	return err
}

func (s *Store) syncLoop() {
	defer close(s.done)
	ticker := time.NewTicker(s.options.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			for _, r := range s.recordings() {
				r.mu.Lock()
				if !r.closed && r.err == nil {
					r.err = r.file.Sync()
				}
				r.mu.Unlock()
			}
		}
	}
}

func (s *Store) recordings() []*Recording {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Recording
	for _, r := range s.active {
		out = append(out, r)
	}
	return out
}

func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.stop)
	s.mu.Unlock()
	<-s.done
	s.starts.Wait()
	var result error
	for _, r := range s.recordings() {
		result = errors.Join(result, r.Close("incomplete", "gateway shutdown", -1))
	}
	return errors.Join(result, s.lock.Close())
}

func writeMetadata(dir string, meta Metadata) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return atomicFile(filepath.Join(dir, "session.json"), append(b, '\n'))
}

func atomicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ReadMetadata(root, id string) (Metadata, error) {
	var m Metadata
	dir, err := sessionDir(root, id)
	if err != nil {
		return m, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	if err == nil && (m.ID != id || m.Schema != Schema) {
		err = errors.New("invalid session metadata")
	}
	return m, err
}

func List(root string) ([]Metadata, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := []Metadata{}
	for _, e := range entries {
		if !e.IsDir() || !validID.MatchString(e.Name()) {
			continue
		}
		m, err := ReadMetadata(root, e.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("session %s: %w", e.Name(), err)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

// ReadEvents ignores an unfinished final line while a recording is live.
func ReadEvents(root, id string, visit func(Event) error) error {
	dir, err := sessionDir(root, id)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	reader := bufio.NewReaderSize(f, MaxEventBytes+1)
	var seq uint64
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		if e.Schema != Schema || e.Session != id || e.Seq != seq+1 {
			return errors.New("invalid event sequence or schema")
		}
		seq = e.Seq
		if err := visit(e); err != nil {
			return err
		}
	}
}

func (s *Store) recover() error {
	metas, err := List(s.options.Dir)
	if err != nil {
		return err
	}
	for _, m := range metas {
		if m.Status != "recording" {
			continue
		}
		dir, _ := sessionDir(s.options.Dir, m.ID)
		path := filepath.Join(dir, "events.jsonl")
		f, err := os.OpenFile(path, os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		reader := bufio.NewReaderSize(f, MaxEventBytes+1)
		var offset int64
		var last Event
		for {
			line, readErr := reader.ReadSlice('\n')
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = f.Close()
				return readErr
			}
			var event Event
			if err := json.Unmarshal(line, &event); err != nil || event.Seq != last.Seq+1 || event.Session != m.ID || event.Schema != Schema {
				_ = f.Close()
				return fmt.Errorf("corrupt completed event in session %s", m.ID)
			}
			offset += int64(len(line))
			last = event
		}
		if err := f.Truncate(offset); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return err
		}
		r := &Recording{store: s, meta: m, file: f, seq: last.Seq, bytes: offset, start: time.Now().Add(-time.Duration(last.TimeNS))}
		if err := r.Close("incomplete", "gateway stopped before session was finalized", -1); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Directory() string { return s.options.Dir }
