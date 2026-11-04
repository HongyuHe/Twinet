package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"

	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/terminal"
)

// handleAttach gives the caller a bidirectional stream into a container.
//
// The gateway needs this because an interactive session is a stream in both
// directions for as long as a student wants it, which the request/response Exec
// API cannot express. Doing it through the agent rather than by SSH-ing between
// nodes matters: the agent already runs with the privilege required, it already
// authenticates and authorises, and the alternative would make the gateway
// depend on root-to-root SSH trust across the cluster -- a second, broader
// credential existing only so a student can see a routing table.
//
// The connection is hijacked rather than streamed as chunked HTTP because a
// terminal needs bytes to arrive as they are typed, and Go's response writer
// buffers until it decides otherwise.
func (s *Server) handleAttach(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	container := q.Get("container")
	if container == "" {
		httpError(w, http.StatusBadRequest, errors.New("container is required"))
		return
	}
	var cmd []string
	if raw := q.Get("cmd"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cmd); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("cmd must be a JSON array: %w", err))
			return
		}
	}
	if len(cmd) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("cmd is required"))
		return
	}
	// An interactive session on a lab somebody is grading would land in
	// somebody's marks.
	if why := s.refuseIfHeldByAnother(container, q.Get("hold")); why != "" {
		httpError(w, http.StatusConflict, errors.New(why))
		return
	}

	c, err := s.rt.Inspect(r.Context(), container)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if c.State == rt.StateAbsent {
		httpError(w, http.StatusNotFound, fmt.Errorf("no container %q on %s", container, s.cfg.Node))
		return
	}
	// The same authorisation as exec: an interactive shell is at least as
	// powerful as a single command, so it cannot be the weaker door.
	if c.Labels[deploy.LabelManaged] != "true" {
		httpError(w, http.StatusForbidden, errors.New("that container is not managed by twinet"))
		return
	}
	if isInternalControlContainer(c) {
		httpError(w, http.StatusForbidden, errors.New("that container is an internal control sidecar"))
		return
	}
	if owner := q.Get("owner"); owner != "" && c.Labels[deploy.LabelOwner] != owner {
		httpError(w, http.StatusForbidden,
			fmt.Errorf("%s belongs to %q, not %q", container, c.Labels[deploy.LabelOwner], owner))
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		httpError(w, http.StatusInternalServerError, errors.New("this server cannot stream"))
		return
	}

	tty := q.Get("tty") == "1"
	rows, _ := strconv.Atoi(q.Get("rows"))
	cols, _ := strconv.Atoi(q.Get("cols"))
	if rows <= 0 {
		rows = 24
	}
	if cols <= 0 {
		cols = 80
	}
	args := []string{"exec", "--interactive"}
	if tty {
		args = append(args, "--tty",
			"--env", fmt.Sprintf("LINES=%d", rows),
			"--env", fmt.Sprintf("COLUMNS=%d", cols),
			"--env", "TERM=xterm-256color")
	}
	args = append(args, container)
	args = append(args, cmd...)
	stream, nativeStream := s.rt.(rt.StreamExecRuntime)
	var cli string
	var cliArgs, cliEnv []string
	if !nativeStream {
		cli, cliArgs, cliEnv, err = s.attachCLI(args)
		if err != nil {
			httpError(w, http.StatusNotImplemented, err)
			return
		}
	}

	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	headers := "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
	frames := q.Get("frames")
	if frames == "1" || frames == "2" {
		headers += "X-Twinet-Frames: " + frames + "\r\n"
	}
	if _, err := buf.WriteString(headers + "\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	ctx = terminal.WithExecutionID(ctx, q.Get("execution"))
	defer cancel()
	input := io.Reader(buf.Reader)
	if frames == "1" || frames == "2" {
		control := terminal.New(uint32(rows), uint32(cols))
		ctx = terminal.With(ctx, control)
		reader, writer := io.Pipe()
		defer func() { _ = reader.Close() }()
		input = reader
		go func() { err := terminal.Receive(buf.Reader, control, writer); _ = writer.CloseWithError(err); cancel() }()
	}
	var stdout, stderr io.Writer = conn, conn
	status := func(code int) {
		if q.Get("status") == "1" {
			fmt.Fprintf(conn, "%s%d\n", attachExitTrailer, code)
		}
	}
	if frames == "2" {
		output := &terminal.OutputFrames{FrameWriter: terminal.FrameWriter{Writer: conn}}
		stdout, stderr = output.Stdout(), output.Stderr()
		status = func(code int) { _ = output.Exit(code) }
	}

	if nativeStream {
		env := map[string]string(nil)
		if tty {
			env = map[string]string{
				"LINES": strconv.Itoa(rows), "COLUMNS": strconv.Itoa(cols),
				"TERM": "xterm-256color",
			}
		}
		code, streamErr := stream.StreamExec(ctx, container, rt.ExecCmd{
			Cmd: cmd, Env: env, Stdin: input, TTY: tty,
		}, uint32(rows), uint32(cols), stdout, stderr)
		if streamErr != nil {
			fmt.Fprintf(stderr, "twinet: %v\r\n", streamErr)
			code = 1
		}
		status(code)
		return
	}

	proc := exec.CommandContext(ctx, cli, cliArgs...)
	if len(cliEnv) > 0 {
		proc.Env = append(os.Environ(), cliEnv...)
	}
	stdin, err := proc.StdinPipe()
	if err != nil {
		return
	}
	proc.Stdout, proc.Stderr = stdout, stderr
	if err := proc.Start(); err != nil {
		fmt.Fprintf(stderr, "twinet: %v\r\n", err)
		status(1)
		return
	}
	go func() { _, _ = io.Copy(stdin, input); _ = stdin.Close() }()

	// The exit status is sent back as a trailer, because a hijacked connection
	// carries bytes and nothing else: there is no header left to put it in.
	//
	// Without it every attached command reported success. `twinet exec` said 0
	// for a command that failed, and the gateway's device list said every
	// container was running because the probe it ran could not fail. A status
	// display that cannot report a problem is worse than none, because it is
	// believed.
	//
	// Only sent when asked for, so a client that does not know about it does
	// not find a stray line at the end of an interactive session.
	code := 0
	if err := proc.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	status(code)
}

func (s *Server) attachCLI(args []string) (string, []string, []string, error) {
	switch s.rt.Name() {
	case "docker":
		env := []string(nil)
		if endpoint := rt.Endpoint(s.rt); endpoint != "" {
			env = append(env, "DOCKER_HOST="+endpoint)
		}
		return "docker", args, env, nil
	case "podman":
		endpoint := rt.Endpoint(s.rt)
		if endpoint == "" {
			return "", nil, nil, errors.New("podman attach needs a runtime socket")
		}
		podmanArgs := append([]string{"--remote", "--url", endpoint}, args...)
		return "podman", podmanArgs, nil, nil
	default:
		return "", nil, nil, fmt.Errorf("runtime %q does not provide an interactive attach command", s.rt.Name())
	}
}

// attachExitTrailer introduces the exit status at the very end of an attach
// stream. It begins with a NUL so it cannot be confused with a line a program
// printed: a NUL is not something a terminal session emits.
const attachExitTrailer = "\x00twinet-exit:"
