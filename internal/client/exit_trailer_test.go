package client

import (
	"bytes"
	"fmt"
	"testing"
)

// An attached command used to report success whatever it did: the hijacked
// connection carries bytes and nothing else, so the exit status was simply
// never sent and the client returned zero.
//
// It made `twinet exec` say a failing command had worked, and it made the
// gateway's device list say every container was running, because the probe it
// used could not fail. A status display that cannot report a problem is worse
// than not having one.
func TestTheExitStatusSurvivesTheStream(t *testing.T) {
	for _, code := range []int{0, 1, 42, 255} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var out bytes.Buffer
			w := &exitTrailerWriter{w: &out}
			if _, err := w.Write([]byte("some output\nand more\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(w, "%s%d\n", attachExitTrailer, code); err != nil {
				t.Fatal(err)
			}
			if got := w.finish(); got != code {
				t.Errorf("the command exited %d and the caller was told %d", code, got)
			}
			if out.String() != "some output\nand more\n" {
				t.Errorf("the trailer leaked into the session output: %q", out.String())
			}
		})
	}
}

// The stream arrives in whatever pieces the network chose, so the trailer can
// be split across writes.
func TestATrailerSplitAcrossWritesIsStillRead(t *testing.T) {
	var out bytes.Buffer
	w := &exitTrailerWriter{w: &out}
	full := "hello\n" + attachExitTrailer + "7\n"
	for i := 0; i < len(full); i++ {
		if _, err := w.Write([]byte{full[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.finish(); got != 7 {
		t.Errorf("exit status 7 arrived a byte at a time and was read as %d", got)
	}
	if out.String() != "hello\n" {
		t.Errorf("session output was %q", out.String())
	}
}

// Nothing may be lost from a stream that carries no trailer, which is every
// interactive session that ends by the far side closing.
func TestOutputWithNoTrailerIsPassedThroughWhole(t *testing.T) {
	var out bytes.Buffer
	w := &exitTrailerWriter{w: &out}
	body := "line one\nline two\nline three\n"
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if got := w.finish(); got != 0 {
		t.Errorf("a stream with no trailer reported exit status %d", got)
	}
	if out.String() != body {
		t.Errorf("output was truncated: got %q, want %q", out.String(), body)
	}
}
