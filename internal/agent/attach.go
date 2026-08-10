package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"

	"github.com/HongyuHe/twinet/internal/deploy"
	rt "github.com/HongyuHe/twinet/internal/runtime"
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

	args := []string{"exec", "--interactive"}
	if q.Get("tty") == "1" {
		rows, _ := strconv.Atoi(q.Get("rows"))
		cols, _ := strconv.Atoi(q.Get("cols"))
		if rows <= 0 {
			rows = 24
		}
		if cols <= 0 {
			cols = 80
		}
		args = append(args, "--tty",
			"--env", fmt.Sprintf("LINES=%d", rows),
			"--env", fmt.Sprintf("COLUMNS=%d", cols),
			"--env", "TERM=xterm-256color")
	}
	args = append(args, container)
	args = append(args, cmd...)

	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	if _, err := buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}

	proc := exec.CommandContext(r.Context(), "docker", args...)
	stdin, err := proc.StdinPipe()
	if err != nil {
		return
	}
	proc.Stdout, proc.Stderr = conn, conn
	if err := proc.Start(); err != nil {
		fmt.Fprintf(conn, "twinet: %v\r\n", err)
		return
	}
	go func() {
		// Anything the client buffered during the handshake belongs to the
		// session, not to the HTTP request, so it is forwarded before the raw
		// connection: dropping it loses the first keystrokes of every login.
		if n := buf.Reader.Buffered(); n > 0 {
			if b, err := buf.Reader.Peek(n); err == nil {
				_, _ = stdin.Write(b)
				_, _ = buf.Reader.Discard(n)
			}
		}
		_, _ = io.Copy(stdin, conn)
		_ = stdin.Close()
	}()
	_ = proc.Wait()
}
