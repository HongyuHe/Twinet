package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/terminal"
)

type streamingRuntime struct {
	rt.Runtime
	stream func(context.Context, string, rt.ExecCmd, uint32, uint32, io.Writer, io.Writer) (int, error)
}

func (r *streamingRuntime) StreamExec(ctx context.Context, name string, cmd rt.ExecCmd, rows, cols uint32, out, stderr io.Writer) (int, error) {
	return r.stream(ctx, name, cmd, rows, cols, out, stderr)
}

func TestObservedRuntimePreservesInteractiveStream(t *testing.T) {
	control := terminal.New(24, 80)
	ctx := terminal.With(context.Background(), control)
	expectedErr := errors.New("stream interrupted")
	backend := &streamingRuntime{stream: func(ctx context.Context, name string, cmd rt.ExecCmd, rows, cols uint32, out, stderr io.Writer) (int, error) {
		if terminal.From(ctx) != control || name != "router" || !cmd.TTY || rows != 24 || cols != 80 {
			t.Fatal("stream context or terminal settings were lost")
		}
		_, _ = io.Copy(out, cmd.Stdin)
		_, _ = io.WriteString(stderr, "diagnostic")
		return 23, expectedErr
	}}
	observed := &observedRuntime{runtime: backend, metrics: newAgentMetrics()}
	var out, stderr bytes.Buffer
	code, err := observed.StreamExec(ctx, "router", rt.ExecCmd{TTY: true, Stdin: bytes.NewBufferString("live bytes")}, 24, 80, &out, &stderr)
	if code != 23 || !errors.Is(err, expectedErr) || out.String() != "live bytes" || stderr.String() != "diagnostic" {
		t.Fatalf("stream result: %d %v %q %q", code, err, out.String(), stderr.String())
	}
}
