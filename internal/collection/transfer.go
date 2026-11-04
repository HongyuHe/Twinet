package collection

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const transferChunk = 1 << 20

//go:embed web/*
var webFiles embed.FS

// Handler serves authenticated collection APIs and a self-contained viewer.
// The same handler can browse a gateway spool read-only or receive uploads in
// a separate directory. Tokens are never accepted in URL parameters.
func Handler(root, token string, receive bool) (http.Handler, error) {
	if len(token) < 24 {
		return nil, errors.New("collection token must contain at least 24 characters")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	var locks [64]sync.Mutex
	mux := http.NewServeMux()
	files, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(files)))
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r, token) {
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		metas, err := List(root)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		filtered := []Metadata{}
		for _, m := range metas {
			q := r.URL.Query()
			if v := q.Get("lab"); v != "" && v != m.Lab {
				continue
			}
			if v := q.Get("group"); v != "" && v != m.Group {
				continue
			}
			if v := q.Get("as"); v != "" && v != strconv.Itoa(m.AS) {
				continue
			}
			filtered = append(filtered, m)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(filtered)
	})
	mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(w, r, token) {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/sessions/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id, resource := parts[0], parts[1]
		dir, err := sessionDir(root, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodGet {
			if resource == "session.json" {
				m, err := ReadMetadata(root, id)
				if err != nil {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(m)
				return
			}
			format := map[string]string{"events.jsonl": "events", "commands.jsonl": "commands", "activity.jsonl": "activity", "activity.csv": "csv", "replay.cast": "cast"}[resource]
			if format == "" {
				http.NotFound(w, r)
				return
			}
			if _, err := ReadMetadata(root, id); err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			if format == "csv" {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
			}
			if err := Export(root, id, format, w); err != nil {
				return
			}
			return
		}
		if !receive || r.Method != http.MethodPut {
			http.Error(w, "uploads are disabled", http.StatusMethodNotAllowed)
			return
		}
		lock := &locks[int(id[0]+id[1])%len(locks)]
		lock.Lock()
		defer lock.Unlock()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if resource == "session.json" {
			var m Metadata
			err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&m)
			if err != nil || m.ID != id || m.Schema != Schema || (m.Status != "recording" && m.Status != "complete" && m.Status != "incomplete") {
				http.Error(w, "invalid metadata", http.StatusBadRequest)
				return
			}
			if old, err := ReadMetadata(root, id); err == nil {
				if old.Lab != m.Lab || old.Group != m.Group || !old.Started.Equal(m.Started) {
					http.Error(w, "session identity conflict", http.StatusConflict)
					return
				}
				if old.Status != "recording" {
					if old.SHA256 == m.SHA256 && old.Bytes == m.Bytes && old.Status == m.Status {
						w.WriteHeader(204)
						return
					}
					http.Error(w, "session is finalized", http.StatusConflict)
					return
				}
			}
			if m.Status != "recording" {
				stat, err := os.Stat(filepath.Join(dir, "events.jsonl"))
				if err != nil || stat.Size() != m.Bytes {
					http.Error(w, "journal size mismatch", http.StatusConflict)
					return
				}
				hash, err := fileHash(filepath.Join(dir, "events.jsonl"))
				if err != nil || hash != m.SHA256 {
					http.Error(w, "journal checksum mismatch", http.StatusConflict)
					return
				}
				var count uint64
				if err := ReadEvents(root, id, func(e Event) error { count++; return nil }); err != nil || count != m.Events {
					http.Error(w, "invalid journal sequence", http.StatusConflict)
					return
				}
			}
			if err := writeMetadata(dir, m); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(204)
			return
		}
		if resource != "events.jsonl" {
			http.NotFound(w, r)
			return
		}
		m, err := ReadMetadata(root, id)
		if err != nil {
			http.Error(w, "metadata is required first", http.StatusConflict)
			return
		}
		offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if err != nil || offset < 0 {
			http.Error(w, "invalid offset", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, transferChunk))
		if err != nil || len(body) == 0 || body[len(body)-1] != '\n' {
			http.Error(w, "invalid journal chunk", http.StatusBadRequest)
			return
		}
		if offset+int64(len(body)) > 1<<30 {
			http.Error(w, "collector session limit is 1 GiB", http.StatusRequestEntityTooLarge)
			return
		}
		f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() { _ = f.Close() }()
		stat, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Collection-Offset", strconv.FormatInt(stat.Size(), 10))
		if offset < stat.Size() {
			overlap := min(int64(len(body)), stat.Size()-offset)
			existing := make([]byte, overlap)
			if _, err := f.ReadAt(existing, offset); err != nil || !bytes.Equal(existing, body[:overlap]) {
				http.Error(w, "journal overlap differs", http.StatusConflict)
				return
			}
			if overlap == int64(len(body)) {
				w.WriteHeader(204)
				return
			}
			if m.Status != "recording" {
				http.Error(w, "session is finalized", http.StatusConflict)
				return
			}
			if _, err := f.WriteAt(body[overlap:], stat.Size()); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := f.Sync(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(204)
			return
		}
		if offset != stat.Size() || m.Status != "recording" {
			http.Error(w, "journal offset conflict", http.StatusConflict)
			return
		}
		if _, err := f.WriteAt(body, offset); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := f.Sync(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Collection-Offset", strconv.FormatInt(offset+int64(len(body)), 10))
		w.WriteHeader(204)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		mux.ServeHTTP(w, r)
	}), nil
}

func authorized(w http.ResponseWriter, r *http.Request, token string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return false
	}
	return true
}

type Uploader struct {
	Root, URL, Token string
	Client           *http.Client
}

func (u *Uploader) Validate() error {
	v, err := url.Parse(u.URL)
	if err != nil || v.Host == "" || v.User != nil || v.RawQuery != "" || v.Fragment != "" {
		return errors.New("invalid collector URL")
	}
	if v.Scheme != "https" {
		ip := net.ParseIP(v.Hostname())
		if v.Scheme != "http" || (v.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return errors.New("collector URL requires HTTPS outside loopback")
		}
	}
	if len(u.Token) < 24 {
		return errors.New("collector token must contain at least 24 characters")
	}
	return nil
}

// Sync retries from the receiver's durable byte offset. Completed sessions are
// skipped using a local acknowledgement written only after checksum validation.
func (u *Uploader) Sync(ctx context.Context) error {
	if err := u.Validate(); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(u.Root, ".upload.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("another upload is running: %w", err)
	}

	metas, err := List(u.Root)
	if err != nil {
		return err
	}
	var result error
	var mu sync.Mutex
	var wg sync.WaitGroup
	work := make(chan Metadata)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := range work {
				if err := u.syncOne(ctx, m); err != nil {
					mu.Lock()
					result = errors.Join(result, fmt.Errorf("session %s: %w", m.ID, err))
					mu.Unlock()
				}
			}
		}()
	}
	for _, m := range metas {
		if ctx.Err() != nil {
			break
		}
		work <- m
	}
	close(work)
	wg.Wait()
	result = errors.Join(result, ctx.Err())
	return result
}

func (u *Uploader) request(ctx context.Context, method, path string, body []byte) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(u.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+u.Token)
	req.Header.Set("Content-Type", "application/json")
	c := u.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header, nil
}

func (u *Uploader) syncOne(ctx context.Context, m Metadata) error {
	dir, _ := sessionDir(u.Root, m.ID)
	ackPath := filepath.Join(dir, "uploaded.json")
	var ack struct {
		URL, Hash string
		Offset    int64
	}
	if b, err := os.ReadFile(ackPath); err == nil {
		_ = json.Unmarshal(b, &ack)
	}
	if ack.URL != u.URL {
		ack.Offset, ack.Hash = 0, ""
	}
	if m.Status != "recording" && ack.Hash == m.SHA256 && ack.Hash != "" {
		return nil
	}
	base := "/api/sessions/" + m.ID + "/"
	initial := m
	initial.Status, initial.Ended, initial.SHA256, initial.Bytes, initial.Events = "recording", nil, "", 0, 0
	b, _ := json.Marshal(initial)
	status, _, err := u.request(ctx, "PUT", base+"session.json", b)
	if err != nil {
		return err
	}
	if status == 409 && m.Status != "recording" {
		b, _ = json.Marshal(m)
		status, _, err = u.request(ctx, "PUT", base+"session.json", b)
		if err == nil && status == 204 {
			ack.URL, ack.Hash = u.URL, m.SHA256
			b, _ = json.Marshal(ack)
			return atomicFile(ackPath, b)
		}
	}
	if status != 204 {
		return fmt.Errorf("collector metadata returned HTTP %d", status)
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	for ack.Offset < stat.Size() {
		chunk := make([]byte, transferChunk)
		n, readErr := f.ReadAt(chunk, ack.Offset)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		chunk = chunk[:n]
		end := bytes.LastIndexByte(chunk, '\n') + 1
		if end == 0 {
			break
		}
		chunk = chunk[:end]
		status, headers, err := u.request(ctx, "PUT", base+"events.jsonl?offset="+strconv.FormatInt(ack.Offset, 10), chunk)
		if err != nil {
			return err
		}
		if status == 409 {
			offset, parseErr := strconv.ParseInt(headers.Get("X-Collection-Offset"), 10, 64)
			if parseErr == nil && offset < ack.Offset {
				ack.Offset = offset
				continue
			}
		}
		if status != 204 {
			return fmt.Errorf("collector data returned HTTP %d", status)
		}
		ack.Offset += int64(len(chunk))
	}
	if m.Status != "recording" && ack.Offset == m.Bytes {
		b, _ = json.Marshal(m)
		status, _, err = u.request(ctx, "PUT", base+"session.json", b)
		if err != nil {
			return err
		}
		if status != 204 {
			return fmt.Errorf("collector finalize returned HTTP %d", status)
		}
		ack.Hash = m.SHA256
	}
	ack.URL = u.URL
	b, _ = json.Marshal(ack)
	return atomicFile(ackPath, b)
}
