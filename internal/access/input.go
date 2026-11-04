package access

import (
	"context"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// sessionChannel gives every device execution a cancellable read without
// closing the SSH channel when the user returns to the device menu.
type sessionChannel struct {
	ssh.Channel
	ctx     context.Context
	mu      sync.Mutex
	chunks  chan []byte
	pending []byte
}

func newSessionChannel(ctx context.Context, ch ssh.Channel) *sessionChannel {
	s := &sessionChannel{Channel: ch, ctx: ctx, chunks: make(chan []byte, 4)}
	go func() {
		defer close(s.chunks)
		for {
			data := make([]byte, 16384)
			n, err := ch.Read(data)
			if n > 0 {
				select {
				case s.chunks <- data[:n]:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

func (s *sessionChannel) Read(p []byte) (int, error) { return s.ReadContext(s.ctx, p) }
func (s *sessionChannel) ReadContext(ctx context.Context, p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(s.pending) == 0 {
		select {
		case data, ok := <-s.chunks:
			if !ok {
				return 0, io.EOF
			}
			s.pending = data
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

type scopedInput struct {
	ctx     context.Context
	channel ssh.Channel
}

func (s scopedInput) Read(p []byte) (int, error) {
	if reader, ok := s.channel.(interface {
		ReadContext(context.Context, []byte) (int, error)
	}); ok {
		return reader.ReadContext(s.ctx, p)
	}
	return s.channel.Read(p)
}
