// Package terminal carries terminal resize requests alongside execution streams.
package terminal

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

type Size struct{ Rows, Cols uint32 }
type key struct{}
type Control struct {
	mu        sync.Mutex
	size      Size
	listeners map[chan Size]bool
}

func New(rows, cols uint32) *Control {
	return &Control{size: Size{rows, cols}, listeners: map[chan Size]bool{}}
}
func With(ctx context.Context, control *Control) context.Context {
	return context.WithValue(ctx, key{}, control)
}
func From(ctx context.Context) *Control { c, _ := ctx.Value(key{}).(*Control); return c }
func (c *Control) Resize(rows, cols uint32) {
	if rows == 0 || cols == 0 || rows > 65535 || cols > 65535 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.size = Size{rows, cols}
	for ch := range c.listeners {
		select {
		case ch <- c.size:
		default:
			select {
			case <-ch:
			default:
			}
			ch <- c.size
		}
	}
}
func (c *Control) Subscribe() (<-chan Size, func()) {
	ch := make(chan Size, 1)
	c.mu.Lock()
	c.listeners[ch] = true
	ch <- c.size
	c.mu.Unlock()
	return ch, func() { c.mu.Lock(); delete(c.listeners, ch); c.mu.Unlock() }
}

// FrameWriter serializes stdin and resize frames on the agent connection.
type FrameWriter struct {
	mu     sync.Mutex
	Writer io.Writer
}

func (w *FrameWriter) frame(kind byte, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	header := [5]byte{kind}
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	if _, err := w.Writer.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Writer.Write(data)
	return err
}
func (w *FrameWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		size := min(len(p), 32768)
		if err := w.frame('i', p[:size]); err != nil {
			return n, err
		}
		n += size
		p = p[size:]
	}
	return n, nil
}
func (w *FrameWriter) Resize(s Size) error {
	var data [8]byte
	binary.BigEndian.PutUint32(data[:4], s.Rows)
	binary.BigEndian.PutUint32(data[4:], s.Cols)
	return w.frame('r', data[:])
}
func (w *FrameWriter) EOF() error { return w.frame('e', nil) }

// Receive decodes stdin and resize frames. Stdin uses pipe backpressure, while
// resize frames update the control without entering the process's input stream.
func Receive(reader io.Reader, control *Control, out *io.PipeWriter) error {
	defer func() { _ = out.Close() }()
	for {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(header[1:])
		if n > 32768 {
			return errors.New("oversized terminal frame")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(reader, data); err != nil {
			return err
		}
		switch header[0] {
		case 'i':
			if _, err := out.Write(data); err != nil {
				return err
			}
		case 'r':
			if n != 8 {
				return errors.New("invalid resize frame")
			}
			control.Resize(binary.BigEndian.Uint32(data[:4]), binary.BigEndian.Uint32(data[4:]))
		case 'e':
			if n != 0 {
				return errors.New("invalid EOF frame")
			}
			_ = out.Close()
		default:
			return errors.New("unknown terminal frame")
		}
	}
}
