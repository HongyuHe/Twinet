package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/collection"
	"github.com/HongyuHe/twinet/internal/terminal"
	"golang.org/x/crypto/ssh"
)

func TestRecoveredExecutionCleanupIsAcknowledged(t *testing.T) {
	dir := t.TempDir()
	store, err := collection.Open(collection.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	topo := twoASTopology()
	r, err := store.Start(collection.Metadata{Lab: topo.Name})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := collection.NewID()
	r.Select("as3/MSP", id)
	if err := r.Add("device_start", nil, map[string]any{"execution_id": id}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close("incomplete", "gateway stopped before session was finalized", -1); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := &Server{cfg: Config{Topology: topo, Logger: slog.Default(), Exec: collectionExec(func(_ context.Context, d string, cmd []string, _ io.Reader, _, _ io.Writer, _ bool, _, _ int) (int, error) {
		calls++
		if d != "as3/MSP" || !strings.Contains(strings.Join(cmd, " "), id) {
			t.Fatal("cleanup did not target the interrupted execution")
		}
		return 0, nil
	})}}
	for range 2 {
		if err := server.RecoverExecutions(dir); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("cleanup repeated after acknowledgement: %d calls", calls)
	}
}

type collectionExec func(context.Context, string, []string, io.Reader, io.Writer, io.Writer, bool, int, int) (int, error)

func (f collectionExec) Shell(ctx context.Context, d string, c []string, in io.Reader, out, errOut io.Writer, tty bool, rows, cols int) (int, error) {
	return f(ctx, d, c, in, out, errOut, tty, rows, cols)
}

func recordingSSH(t *testing.T, enabled, input bool, exec Execer) (*ssh.Client, string) {
	t.Helper()
	dir := t.TempDir()
	var store *collection.Store
	if enabled {
		var err error
		store, err = collection.Open(collection.Options{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	server, err := New(Config{Topology: twoASTopology(), Roster: &Roster{Groups: map[string]*Group{"group3": {AS: 3, AuthorizedKeys: []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}, KeyActors: map[string]string{fingerprint: "alice"}}}}, Exec: exec, HostKey: signer, Collection: store, CaptureInput: input})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			server.handleConn(ctx, conn)
		}
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "group3", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway did not stop")
		}
		if store != nil {
			_ = store.Close()
		}
	})
	return client, dir
}

func TestSSHCollectionCapturesCommandIdentityStreamsAndStatus(t *testing.T) {
	client, dir := recordingSSH(t, true, true, collectionExec(func(ctx context.Context, d string, cmd []string, in io.Reader, out, errOut io.Writer, _ bool, _, _ int) (int, error) {
		input, err := io.ReadAll(in)
		if err != nil {
			return 1, err
		}
		_, _ = out.Write(append([]byte("echo:"), input...))
		_, _ = errOut.Write([]byte("warning"))
		return 7, nil
	}))
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	session.Stdin = strings.NewReader("input\x00bytes")
	var out, stderr bytes.Buffer
	session.Stdout = &out
	session.Stderr = &stderr
	err = session.Run("MSP echo test")
	if exit, ok := err.(*ssh.ExitError); !ok || exit.ExitStatus() != 7 {
		t.Fatalf("exit: %v", err)
	}
	if out.String() != "echo:input\x00bytes" || stderr.String() != "warning" {
		t.Fatalf("streams: %q %q", out.String(), stderr.String())
	}
	metas, err := collection.List(dir)
	if err != nil || len(metas) != 1 {
		t.Fatalf("sessions: %+v %v", metas, err)
	}
	m := metas[0]
	if m.Actor != "alice" || m.Group != "group3" || m.AS != 3 || m.KeyFingerprint == "" || m.Status != "complete" {
		t.Fatalf("metadata: %+v", m)
	}
	var input, output []byte
	found := false
	err = collection.ReadEvents(dir, m.ID, func(e collection.Event) error {
		if e.Type == "input" {
			input = append(input, e.Data...)
		}
		if e.Type == "output" {
			output = append(output, e.Data...)
		}
		if e.Type == "command_start" {
			found = e.Device == "as3/MSP" && e.Fields["source"] == "gateway"
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(input) != "input\x00bytes" || string(output) != out.String() || !found {
		t.Fatalf("events missing: %q %q %v", input, output, found)
	}
}

func TestSSHRecordingDisabledAndInputOptOut(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "no_input"}[enabled], func(t *testing.T) {
			client, dir := recordingSSH(t, enabled, false, collectionExec(func(_ context.Context, _ string, _ []string, in io.Reader, out, _ io.Writer, _ bool, _, _ int) (int, error) {
				_, err := io.Copy(io.Discard, in)
				_, _ = io.WriteString(out, "done")
				return 0, err
			}))
			s, _ := client.NewSession()
			defer s.Close()
			s.Stdin = strings.NewReader("sensitive input")
			if err := s.Run("MSP true"); err != nil {
				t.Fatal(err)
			}
			metas, err := collection.List(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !enabled {
				if len(metas) != 0 {
					t.Fatal("disabled collection wrote a session")
				}
				return
			}
			if err := collection.ReadEvents(dir, metas[0].ID, func(e collection.Event) error {
				if e.Type == "input" {
					t.Error("input captured despite opt-out")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResizeDuringRunningSSHCommand(t *testing.T) {
	ready := make(chan struct{})
	got := make(chan terminal.Size, 1)
	client, dir := recordingSSH(t, true, true, collectionExec(func(ctx context.Context, _ string, _ []string, _ io.Reader, out, _ io.Writer, _ bool, _, _ int) (int, error) {
		changes, stop := terminal.From(ctx).Subscribe()
		defer stop()
		close(ready)
		for {
			select {
			case size := <-changes:
				if size.Cols == 123 {
					got <- size
					_, _ = io.WriteString(out, "resized")
					return 0, nil
				}
			case <-ctx.Done():
				return 1, ctx.Err()
			}
		}
	}))
	s, _ := client.NewSession()
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Start("MSP true"); err != nil {
		t.Fatal(err)
	}
	<-ready
	if err := s.WindowChange(41, 123); err != nil {
		t.Fatal(err)
	}
	select {
	case size := <-got:
		if size.Rows != 41 {
			t.Fatal(size)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resize blocked behind command")
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	metas, _ := collection.List(dir)
	found := false
	_ = collection.ReadEvents(dir, metas[0].ID, func(e collection.Event) error {
		if e.Type == "resize" {
			found = true
		}
		return nil
	})
	if !found {
		t.Fatal("resize was not recorded")
	}
}

func TestDevicePrefixPreservesCommandWhitespace(t *testing.T) {
	const command = "printf '%s' 'a  b'\n printf next"
	_, rest, ok := splitDevicePrefix([]string{"sh", "-c", "MSP " + command})
	if !ok || rest[2] != command {
		t.Fatalf("command changed: %#v", rest)
	}
}
