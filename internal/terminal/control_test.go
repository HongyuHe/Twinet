package terminal

import (
	"bytes"
	"io"
	"testing"
)

func TestFramedInputAndResizeRemainDistinct(t *testing.T) {
	var wire bytes.Buffer
	w := FrameWriter{Writer: &wire}
	if _, err := w.Write([]byte{'a', 0, 255}); err != nil {
		t.Fatal(err)
	}
	if err := w.Resize(Size{Rows: 40, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	if err := w.EOF(); err != nil {
		t.Fatal(err)
	}
	c := New(24, 80)
	changes, stop := c.Subscribe()
	defer stop()
	<-changes
	r, out := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Receive(&wire, c, out) }()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte{'a', 0, 255}) {
		t.Fatalf("stdin changed: %x", data)
	}
	if err := <-done; err != io.EOF {
		t.Fatal(err)
	}
	if size := <-changes; size.Rows != 40 || size.Cols != 120 {
		t.Fatal(size)
	}
}

func TestResizeSubscriptionKeepsLatestSize(t *testing.T) {
	c := New(24, 80)
	changes, stop := c.Subscribe()
	defer stop()
	for i := 1; i <= 100; i++ {
		c.Resize(uint32(i), uint32(i+20))
	}
	if got := <-changes; got.Rows != 100 || got.Cols != 120 {
		t.Fatal(got)
	}
}
