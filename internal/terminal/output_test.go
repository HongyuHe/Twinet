package terminal

import (
	"bytes"
	"testing"
)

func TestOutputFramesPreserveBinaryAndStatusSeparately(t *testing.T) {
	var wire bytes.Buffer
	f := &OutputFrames{FrameWriter: FrameWriter{Writer: &wire}}
	want := append(bytes.Repeat([]byte{0, 255, 1}, 20000), []byte("\x00twinet-exit:99\n")...)
	if _, err := f.Stdout().Write(want); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Stderr().Write([]byte("diagnostic\x00")); err != nil {
		t.Fatal(err)
	}
	if err := f.Exit(7); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code, err := ReadOutput(&wire, &out, &stderr)
	if err != nil || code != 7 || !bytes.Equal(out.Bytes(), want) || stderr.String() != "diagnostic\x00" {
		t.Fatalf("output changed: code=%d error=%v stdout=%d stderr=%q", code, err, out.Len(), stderr.String())
	}
}

func TestOutputFramesRequireFinalStatus(t *testing.T) {
	var wire bytes.Buffer
	f := &OutputFrames{FrameWriter: FrameWriter{Writer: &wire}}
	_, _ = f.Stdout().Write([]byte("partial"))
	var out bytes.Buffer
	if _, err := ReadOutput(&wire, &out, &out); err == nil {
		t.Fatal("interrupted stream appeared complete")
	}
}
