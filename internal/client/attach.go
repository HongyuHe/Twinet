package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// dialStream opens the transport an attach runs over, matching whatever the
// node's HTTP client uses so the two cannot disagree about security.
func (n *Node) dialStream(ctx context.Context, host string) (net.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if n.tls == nil {
		return raw, nil
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	cfg := n.tls.Clone()
	cfg.ServerName = name
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c, nil
}

// Attach opens a bidirectional stream into a container on this node.
//
// The HTTP request is upgraded to a raw connection because a terminal needs
// bytes to arrive as they are typed, and any buffering layer between the two
// makes an interactive session feel broken in a way that is very hard to
// attribute later.
func (n *Node) Attach(ctx context.Context, container string, cmd []string,
	tty bool, rows, cols int, stdin io.Reader, stdout io.Writer) (int, error) {

	raw, err := json.Marshal(cmd)
	if err != nil {
		return 1, err
	}
	q := url.Values{}
	q.Set("container", container)
	q.Set("cmd", string(raw))
	// Ask for the exit status. Without it this function returned 0 whatever
	// the command did.
	q.Set("status", "1")
	if tty {
		q.Set("tty", "1")
		q.Set("rows", fmt.Sprint(rows))
		q.Set("cols", fmt.Sprint(cols))
	}

	host := strings.TrimPrefix(strings.TrimPrefix(n.Addr, "http://"), "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}

	// The stream is raw, so it has to establish its own transport rather than
	// borrowing the HTTP client's. Without this the attach path would be the
	// one plaintext hole left in a cluster that had otherwise moved to mutual
	// TLS -- and it is the path carrying an interactive root shell.
	conn, err := n.dialStream(ctx, host)
	if err != nil {
		return 1, fmt.Errorf("reach node %s: %w", n.Name, err)
	}
	defer func() { _ = conn.Close() }()

	req := fmt.Sprintf("GET /v1/attach?%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: upgrade\r\n\r\n",
		q.Encode(), host, n.Token)
	if _, err := io.WriteString(conn, req); err != nil {
		return 1, err
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return 1, err
	}
	if !strings.Contains(status, " 200 ") {
		return 1, fmt.Errorf("attach refused: %s", strings.TrimSpace(status))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 1, err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	go func() {
		_, _ = io.Copy(conn, stdin)
		// Half-close so the far side sees EOF on stdin and a piped command can
		// finish, rather than waiting forever for input that never comes.
		type halfCloser interface{ CloseWrite() error }
		if hc, ok := conn.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}()
	tw := &exitTrailerWriter{w: stdout}
	_, _ = io.Copy(tw, br)
	return tw.finish(), nil
}

// exitTrailerWriter passes a stream through while holding back just enough of
// the tail to recognise the exit-status trailer the agent appends.
//
// Holding back a few bytes is safe for an interactive session because the
// trailer is only ever the last thing on the stream, and the amount retained is
// smaller than a single line: a terminal cannot notice.
type exitTrailerWriter struct {
	w    io.Writer
	tail []byte
}

// keep is the most that can ever be part of a trailer: its introducer plus the
// digits of any exit status and the newline.
const keep = len(attachExitTrailer) + 8

func (e *exitTrailerWriter) Write(p []byte) (int, error) {
	n := len(p)
	e.tail = append(e.tail, p...)
	if len(e.tail) > keep {
		flush := e.tail[:len(e.tail)-keep]
		if _, err := e.w.Write(flush); err != nil {
			return 0, err
		}
		e.tail = append([]byte{}, e.tail[len(e.tail)-keep:]...)
	}
	return n, nil
}

// finish writes what is left and returns the exit status the trailer carried,
// or zero when there was none -- which is what an agent too old to send one
// produces, and is why the cluster refuses to run against mixed builds.
func (e *exitTrailerWriter) finish() int {
	body, code := e.tail, 0
	if i := bytes.LastIndex(body, []byte(attachExitTrailer)); i >= 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(
			string(body[i+len(attachExitTrailer):]))); err == nil {
			body, code = body[:i], n
		}
	}
	_, _ = e.w.Write(body)
	return code
}

// attachExitTrailer must match the agent's.
const attachExitTrailer = "\x00twinet-exit:"
