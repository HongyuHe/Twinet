package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

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
	if tty {
		q.Set("tty", "1")
		q.Set("rows", fmt.Sprint(rows))
		q.Set("cols", fmt.Sprint(cols))
	}

	host := strings.TrimPrefix(strings.TrimPrefix(n.Addr, "http://"), "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
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
		// finish, rather than waiting forever for input that will never come.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(stdout, br)
	return 0, nil
}
