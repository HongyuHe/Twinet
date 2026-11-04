package collection

import (
	"errors"
	"os"
	"testing"
)

type failingJournal struct {
	*os.File
	failed       bool
	failTruncate bool
}

func (f *failingJournal) Write(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		n, _ := f.File.Write(p[:len(p)/2])
		return n, errors.New("injected disk failure")
	}
	return f.File.Write(p)
}

func (f *failingJournal) Truncate(n int64) error {
	if f.failTruncate {
		return errors.New("injected truncate failure")
	}
	return f.File.Truncate(n)
}

func TestPartialWriteCannotCorruptFinalJournal(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "startup_recovery"}[failRollback], func(t *testing.T) {
			s := newStore(t)
			r, err := s.Start(Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			r.file = &failingJournal{File: r.file.(*os.File), failTruncate: failRollback}
			r.mu.Unlock()
			if err := r.Add("output", []byte("must not appear as a completed event"), nil); err == nil {
				t.Fatal("disk error was hidden")
			}
			if err := r.Close("complete", "", 0); err == nil {
				t.Fatal("session falsely reported success")
			}
			m, err := ReadMetadata(s.Directory(), r.ID())
			if err != nil {
				t.Fatal(err)
			}
			if failRollback && m.Status != "recording" {
				t.Fatal("unrepaired journal was finalized")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(s.options)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := Verify(s.Directory(), r.ID()); err != nil {
				t.Fatal(err)
			}
			m, _ = ReadMetadata(s.Directory(), r.ID())
			if m.Status != "incomplete" || m.Events != 2 {
				t.Fatalf("unexpected recovered recording: %+v", m)
			}
		})
	}
}
