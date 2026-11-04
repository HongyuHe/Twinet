package runtime

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/HongyuHe/twinet/internal/terminal"
	"github.com/moby/moby/api/pkg/stdcopy"
	mobyclient "github.com/moby/moby/client"
)

type streamBackend interface {
	StreamExec(context.Context, string, ExecCmd, uint32, uint32, io.Writer, io.Writer) (int, error)
}

func (d *Docker) StreamExec(ctx context.Context, name string, cmd ExecCmd, rows, cols uint32, out, stderr io.Writer) (int, error) {
	b, err := d.backendFor()
	if err != nil {
		return 1, err
	}
	if stream, ok := b.(streamBackend); ok {
		return stream.StreamExec(ctx, name, cmd, rows, cols, out, stderr)
	}
	return 1, fmt.Errorf("%w: interactive streaming requires the Docker API backend", ErrUnsupported)
}

func (p *Podman) StreamExec(ctx context.Context, name string, cmd ExecCmd, rows, cols uint32, out, stderr io.Writer) (int, error) {
	b, err := p.backendFor()
	if err != nil {
		return 1, err
	}
	if stream, ok := b.(streamBackend); ok {
		return stream.StreamExec(ctx, name, cmd, rows, cols, out, stderr)
	}
	return 1, fmt.Errorf("%w: runtime has no streaming API", ErrUnsupported)
}

func (d *dockerAPI) StreamExec(ctx context.Context, name string, cmd ExecCmd, rows, cols uint32, out, stderr io.Writer) (int, error) {
	id, err := terminal.ExecutionID(ctx)
	if err != nil {
		return 1, err
	}
	env := map[string]string{}
	for k, v := range cmd.Env {
		env[k] = v
	}
	env[terminal.ExecutionEnv] = id
	cmd.Env = env
	defer func() {
		if ctx.Err() != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command, _ := terminal.CleanupCommand(id)
			_, _ = d.Exec(cleanup, name, ExecCmd{Cmd: command})
		}
	}()
	created, err := d.client.ExecCreate(ctx, name, mobyclient.ExecCreateOptions{User: cmd.User, TTY: cmd.TTY, AttachStdin: cmd.Stdin != nil, AttachStdout: true, AttachStderr: true, Env: sortedEnv(cmd.Env), WorkingDir: cmd.WorkDir, Cmd: cmd.Cmd})
	if err != nil {
		return 1, err
	}
	attached, err := d.client.ExecAttach(ctx, created.ID, mobyclient.ExecAttachOptions{TTY: cmd.TTY})
	if err != nil {
		return 1, err
	}
	defer attached.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			attached.Close()
		case <-finished:
		}
	}()
	resize := func(s terminal.Size) {
		_, _ = d.client.ExecResize(ctx, created.ID, mobyclient.ExecResizeOptions{Height: uint(s.Rows), Width: uint(s.Cols)})
	}
	if cmd.TTY {
		resize(terminal.Size{Rows: rows, Cols: cols})
		if control := terminal.From(ctx); control != nil {
			changes, unsubscribe := control.Subscribe()
			defer unsubscribe()
			go func() {
				for {
					select {
					case size := <-changes:
						resize(size)
					case <-finished:
						return
					case <-ctx.Done():
						return
					}
				}
			}()
		}
	}
	if cmd.Stdin != nil {
		go func() { _, _ = io.Copy(attached.Conn, cmd.Stdin); _ = attached.CloseWrite() }()
	}
	if cmd.TTY {
		_, err = io.Copy(out, attached.Reader)
	} else {
		_, err = stdcopy.StdCopy(out, stderr, attached.Reader)
	}
	if ctx.Err() != nil {
		return 1, ctx.Err()
	}
	if err != nil {
		return 1, err
	}
	for {
		result, err := d.client.ExecInspect(ctx, created.ID, mobyclient.ExecInspectOptions{})
		if err != nil {
			return 1, err
		}
		if !result.Running {
			return result.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return 1, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
