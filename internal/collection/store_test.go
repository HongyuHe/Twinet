package collection

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRecordingPreservesBytesAndConcurrentOrder(t *testing.T) {
	s := newStore(t)
	r, err := s.Start(Metadata{Lab: "lab", Group: "group3", AS: 3})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if err := r.Add("output", []byte{0xff, 0, 'x'}, nil); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if err := r.Close("complete", "", 0); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := ReadEvents(s.options.Dir, r.ID(), func(e Event) error {
		if e.Type == "output" {
			count++
			if !bytes.Equal(e.Data, []byte{0xff, 0, 'x'}) {
				t.Errorf("bytes changed: %x", e.Data)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 2000 {
		t.Fatalf("got %d output events", count)
	}
	m, err := ReadMetadata(s.options.Dir, r.ID())
	if err != nil || m.Status != "complete" || m.Events != 2002 || m.SHA256 == "" {
		t.Fatalf("metadata: %+v %v", m, err)
	}
	if _, err := Open(s.options); err == nil {
		t.Fatal("second spool writer accepted")
	}
}

func TestRecoveryKeepsCompleteEventsAndMarksInterrupted(t *testing.T) {
	s := newStore(t)
	r, err := s.Start(Metadata{Lab: "recovery"})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add("output", []byte("saved"), nil); err != nil {
		t.Fatal(err)
	}
	close(s.stop)
	<-s.done
	if _, err := r.file.Write([]byte(`{"torn":`)); err != nil {
		t.Fatal(err)
	}
	_ = r.file.Close()
	_ = s.lock.Close()
	s.closed = true
	recovered, err := Open(s.options)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	m, err := ReadMetadata(s.options.Dir, r.ID())
	if err != nil || m.Status != "incomplete" || m.Events != 3 {
		t.Fatalf("metadata %+v %v", m, err)
	}
	var data []byte
	if err := ReadEvents(s.options.Dir, r.ID(), func(e Event) error { data = append(data, e.Data...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(data) != "saved" {
		t.Fatalf("recovered output: %q", data)
	}
}

func TestSessionLimitIsVisible(t *testing.T) {
	s := newStore(t)
	s.options.MaxSessionBytes = 4096
	r, err := s.Start(Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add("output", make([]byte, 4096), nil); err == nil {
		t.Fatal("byte limit not enforced")
	}
	if err := r.Close("complete", "", 0); err == nil {
		t.Fatal("recording failure hidden")
	}
	m, err := ReadMetadata(s.options.Dir, r.ID())
	if err != nil || m.Status != "incomplete" {
		t.Fatalf("metadata %+v %v", m, err)
	}
}

func TestIncrementalUploadRetriesAndVerifiesFinalBytes(t *testing.T) {
	s := newStore(t)
	r, err := s.Start(Metadata{Lab: "lab", Group: "group", Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	remote := t.TempDir()
	token := strings.Repeat("x", 32)
	handler, err := Handler(remote, token, true)
	if err != nil {
		t.Fatal(err)
	}
	var drop bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if drop {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, req)
	}))
	defer server.Close()
	u := &Uploader{Root: s.options.Dir, URL: server.URL, Token: token}
	if err := r.Add("output", []byte("first"), nil); err != nil {
		t.Fatal(err)
	}
	if err := u.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMetadata(remote, r.ID())
	if err != nil || m.Status != "recording" {
		t.Fatalf("active recording not uploaded: %v", err)
	}
	drop = true
	if err := r.Add("output", []byte("second"), nil); err != nil {
		t.Fatal(err)
	}
	if err := u.Sync(context.Background()); err == nil {
		t.Fatal("outage was hidden")
	}
	if err := r.Close("complete", "", 7); err != nil {
		t.Fatal(err)
	}
	drop = false
	if err := u.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.options.Dir, r.ID(), "uploaded.json")); err != nil {
		t.Fatal(err)
	}
	if err := u.Sync(context.Background()); err != nil {
		t.Fatal("lost acknowledgement retry:", err)
	}
	a, _ := os.ReadFile(filepath.Join(s.options.Dir, r.ID(), "events.jsonl"))
	b, _ := os.ReadFile(filepath.Join(remote, r.ID(), "events.jsonl"))
	if !bytes.Equal(a, b) {
		t.Fatal("uploaded bytes differ")
	}
	m, err = ReadMetadata(remote, r.ID())
	if err != nil || m.Status != "complete" || m.SHA256 == "" {
		t.Fatalf("final metadata: %+v %v", m, err)
	}
	resp, err := http.Get(server.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("unauthenticated recordings were exposed")
	}
}

func TestExportsHandleUTF8FragmentsAndCommandFields(t *testing.T) {
	s := newStore(t)
	r, err := s.Start(Metadata{Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Add("output", []byte{0xe2}, nil)
	_ = r.Add("output", []byte{0x82, 0xac}, nil)
	_ = r.Add("resize", nil, map[string]any{"cols": 100, "rows": 30})
	_ = r.Add("command_start", nil, map[string]any{"command": "echo €", "source": "bash_reported"})
	_ = r.Close("complete", "", 0)
	var out bytes.Buffer
	if err := Export(s.options.Dir, r.ID(), "cast", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "€") || !strings.Contains(out.String(), "100x30") || strings.Contains(out.String(), "�") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := Export(s.options.Dir, r.ID(), "commands", &out); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Fields["command"] != "echo €" {
		t.Fatal(event)
	}
}

func TestCollectorRejectsChangedOrUnverifiedCompletion(t *testing.T) {
	root := t.TempDir()
	token := strings.Repeat("t", 32)
	handler, _ := Handler(root, token, true)
	id, _ := NewID()
	m := Metadata{Schema: Schema, ID: id, Started: time.Now().UTC(), Status: "recording"}
	put := func(resource string, body []byte) int {
		req := httptest.NewRequest("PUT", "/api/sessions/"+id+"/"+resource, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out.Code
	}
	b, _ := json.Marshal(m)
	if got := put("session.json", b); got != 204 {
		t.Fatal(got)
	}
	if got := put("events.jsonl?offset=0", []byte("one\n")); got != 204 {
		t.Fatal(got)
	}
	if got := put("events.jsonl?offset=0", []byte("two\n")); got != 409 {
		t.Fatal(got)
	}
	m.Status = "complete"
	m.Bytes = 4
	m.SHA256 = "wrong"
	b, _ = json.Marshal(m)
	if got := put("session.json", b); got != 409 {
		t.Fatal("invalid checksum accepted", got)
	}
	if _, err := ReadMetadata(root, "../../etc/passwd"); err == nil {
		t.Fatal("invalid session id accepted")
	}
}
