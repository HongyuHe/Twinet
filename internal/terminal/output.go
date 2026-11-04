package terminal

import (
	"encoding/binary"
	"errors"
	"io"
)

// OutputFrames separates arbitrary terminal bytes from exit status. Both output
// streams share a frame writer so concurrent writes cannot interleave frames.
type OutputFrames struct{ FrameWriter }

type outputWriter struct {
	frames *OutputFrames
	kind   byte
}

func (w outputWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		size := min(len(p), 32768)
		if err := w.frames.frame(w.kind, p[:size]); err != nil {
			return n, err
		}
		n += size
		p = p[size:]
	}
	return n, nil
}

func (f *OutputFrames) Stdout() io.Writer { return outputWriter{f, 'o'} }
func (f *OutputFrames) Stderr() io.Writer { return outputWriter{f, 's'} }
func (f *OutputFrames) Exit(code int) error {
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], uint32(code))
	return f.frame('x', data[:])
}

func ReadOutput(reader io.Reader, stdout, stderr io.Writer) (int, error) {
	for {
		var header [5]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return 1, errors.Join(errors.New("terminal stream ended without exit status"), err)
		}
		n := binary.BigEndian.Uint32(header[1:])
		if n > 32768 {
			return 1, errors.New("oversized terminal output frame")
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(reader, data); err != nil {
			return 1, err
		}
		var err error
		switch header[0] {
		case 'o':
			_, err = stdout.Write(data)
		case 's':
			_, err = stderr.Write(data)
		case 'x':
			if n != 4 {
				return 1, errors.New("invalid exit status frame")
			}
			return int(binary.BigEndian.Uint32(data)), nil
		default:
			return 1, errors.New("unknown terminal output frame")
		}
		if err != nil {
			return 1, err
		}
	}
}
