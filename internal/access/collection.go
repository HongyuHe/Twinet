package access

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/collection"
	"github.com/HongyuHe/twinet/internal/terminal"
	"golang.org/x/crypto/ssh"
)

// recordedChannel records before forwarding. A storage error closes the
// channel and cancels execution instead of continuing an unrecorded session.
type recordedChannel struct {
	streamMu sync.Mutex
	ssh.Channel
	recording    *collection.Recording
	captureInput bool
	cancel       context.CancelFunc
	out, errOut  *recordedOutput
}

func wrapChannel(ch ssh.Channel, r *collection.Recording, input bool, cancel context.CancelFunc) *recordedChannel {
	c := &recordedChannel{Channel: ch, recording: r, captureInput: input, cancel: cancel}
	c.out = &recordedOutput{channel: c, writer: ch, kind: "output"}
	c.errOut = &recordedOutput{channel: c, writer: ch.Stderr(), kind: "stderr"}
	return c
}

func (c *recordedChannel) fail(err error) error {
	if err != nil {
		c.cancel()
		_ = c.Close()
	}
	return err
}

func (c *recordedChannel) Read(p []byte) (int, error) {
	if len(p) > 16384 {
		p = p[:16384]
	}
	return c.ReadContext(context.Background(), p)
}

func (c *recordedChannel) ReadContext(ctx context.Context, p []byte) (int, error) {
	n, err := (scopedInput{ctx: ctx, channel: c.Channel}).Read(p)
	if n > 0 && c.captureInput {
		if recordErr := c.recording.Add("input", p[:n], nil); recordErr != nil {
			return 0, c.fail(recordErr)
		}
	}
	return n, err
}
func (c *recordedChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *recordedChannel) Stderr() io.ReadWriter {
	return &stderrChannel{Reader: c.Channel.Stderr(), Writer: c.errOut}
}

type stderrChannel struct {
	io.Reader
	io.Writer
}

type recordedOutput struct {
	mu        sync.Mutex
	channel   *recordedChannel
	writer    io.Writer
	kind      string
	prefix    []byte
	pending   []byte
	commandID string
}

func (o *recordedOutput) writeRaw(p []byte) error {
	o.channel.streamMu.Lock()
	defer o.channel.streamMu.Unlock()
	for len(p) > 0 {
		n := min(len(p), 16384)
		if err := o.channel.recording.Add(o.kind, p[:n], nil); err != nil {
			return o.channel.fail(err)
		}
		if _, err := o.writer.Write(p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (o *recordedOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.prefix) == 0 {
		return len(p), o.writeRaw(p)
	}
	o.pending = append(o.pending, p...)
	for len(o.pending) > 0 {
		i := bytes.Index(o.pending, o.prefix)
		if i < 0 {
			n := len(o.pending)
			for k := min(n, len(o.prefix)-1); k > 0; k-- {
				if bytes.Equal(o.pending[n-k:], o.prefix[:k]) {
					n -= k
					break
				}
			}
			if err := o.writeRaw(o.pending[:n]); err != nil {
				return 0, err
			}
			o.pending = append([]byte(nil), o.pending[n:]...)
			break
		}
		if err := o.writeRaw(o.pending[:i]); err != nil {
			return 0, err
		}
		o.pending = o.pending[i:]
		end := bytes.IndexByte(o.pending, 7)
		if end < 0 {
			if len(o.pending) > 65536 {
				if err := o.writeRaw(o.pending); err != nil {
					return 0, err
				}
				o.pending = nil
			}
			break
		}
		message := string(o.pending[len(o.prefix):end])
		if !o.shellEvent(message) {
			if err := o.writeRaw(o.pending[:end+1]); err != nil {
				return 0, err
			}
		}
		o.pending = o.pending[end+1:]
	}
	return len(p), nil
}

var historyPrefix = regexp.MustCompile(`^\s*[0-9]+\s{2}`)

func (o *recordedOutput) shellEvent(message string) bool {
	fields := strings.Split(message, ";")
	if len(fields) != 4 {
		return false
	}
	command, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	cwd, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return false
	}
	data := map[string]any{"source": "bash_reported", "cwd": string(cwd)}
	kind := ""
	switch fields[0] {
	case "ready":
		kind = "shell_ready"
	case "start":
		o.commandID, _ = collection.NewID()
		data["command"] = historyPrefix.ReplaceAllString(string(command), "")
		kind = "command_start"
	case "end":
		if o.commandID == "" {
			return true
		}
		status, err := strconv.Atoi(fields[3])
		if err != nil {
			return false
		}
		data["exit_code"] = status
		kind = "command_end"
	default:
		return false
	}
	data["command_id"] = o.commandID
	if kind == "command_end" {
		o.commandID = ""
	}
	_ = o.channel.fail(o.channel.recording.Add(kind, nil, data))
	return true
}

func (o *recordedOutput) finish() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	err := o.writeRaw(o.pending)
	if o.commandID != "" {
		if recordErr := o.channel.recording.Add("command_incomplete", nil, map[string]any{"source": "bash_reported", "command_id": o.commandID, "reason": "shell ended before another prompt"}); err == nil {
			err = recordErr
		}
	}
	o.pending = nil
	o.prefix = nil
	o.commandID = ""
	return err
}

// instrumentedShell uses a temporary rcfile only for this shell. The outer
// gateway recording remains active if the student replaces or changes Bash.
func instrumentedShell(ch *recordedChannel) []string {
	nonce, _ := collection.NewID()
	prefix := []byte("\x1b]777;twinet=" + nonce + ";")
	ch.out.mu.Lock()
	ch.out.prefix = prefix
	ch.out.mu.Unlock()
	ch.errOut.mu.Lock()
	ch.errOut.prefix = prefix
	ch.errOut.mu.Unlock()
	script := `rm -f -- "${BASH_SOURCE[0]}"
[[ -f /etc/bash.bashrc ]] && source /etc/bash.bashrc
[[ -f ~/.bashrc ]] && source ~/.bashrc
HISTCONTROL=
HISTIGNORE=
set -o history
__twinet_emit() {
  local kind="$1" command="$2" code="$3" c w
  c=$(printf '%s' "$command" | base64 | tr -d '\n')
  w=$(printf '%s' "$PWD" | base64 | tr -d '\n')
  printf '\033]777;twinet=NONCE;%s;%s;%s;%s\007' "$kind" "$c" "$w" "$code" >&2
}
__twinet_start() { __twinet_emit start "$(HISTTIMEFORMAT= builtin history 1)" ''; }
__twinet_end() { __twinet_emit end '' "$1"; }
PS0='$(__twinet_start)'
PROMPT_COMMAND='__twinet_end "$?"'
__twinet_emit ready '' ''
`
	script = strings.ReplaceAll(script, "NONCE", nonce)
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	command := `if command -v bash >/dev/null 2>&1; then f=$(mktemp /tmp/twinet-shell.XXXXXXXX) || exit 1; printf '%s' '` + encoded + `' | base64 -d > "$f" || exit 1; exec bash --rcfile "$f" -i; else exec /bin/sh; fi`
	return []string{"/bin/sh", "-c", command}
}

func (s *Server) executeSession(ctx context.Context, ch ssh.Channel, sess Session, device string, cmd []string, tty bool, rows, cols int, interactive bool) (int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdin := scopedInput{ctx: ctx, channel: ch}
	c, recording := ch.(*recordedChannel)
	if !recording {
		return s.cfg.Exec.Shell(ctx, device, cmd, stdin, ch, ch.Stderr(), tty, rows, cols)
	}
	segment, err := collection.NewID()
	if err != nil {
		return 1, err
	}
	ctx = terminal.WithExecutionID(ctx, segment)
	c.recording.Select(device, segment)
	fields := map[string]any{"source": "gateway", "interactive": interactive, "execution_id": segment}
	if d, ok := s.cfg.Topology.Device(device); ok {
		fields["container"] = d.Container
		fields["node"] = d.Node
	}
	if err := c.recording.Add("device_start", nil, fields); err != nil {
		return 1, c.fail(err)
	}
	if interactive && s.cfg.ShellEvents && tty {
		cmd = instrumentedShell(c)
	}
	if !interactive {
		if err := c.recording.Add("command_start", nil, map[string]any{"source": "gateway", "argv": cmd, "command_id": segment}); err != nil {
			return 1, c.fail(err)
		}
	}
	code, runErr := s.cfg.Exec.Shell(ctx, device, cmd, stdin, ch, ch.Stderr(), tty, rows, cols)
	if err := c.out.finish(); err != nil && runErr == nil {
		runErr = err
	}
	if err := c.errOut.finish(); err != nil && runErr == nil {
		runErr = err
	}
	if !interactive {
		_ = c.fail(c.recording.Add("command_end", nil, map[string]any{"source": "gateway", "command_id": segment, "exit_code": code}))
	}
	end := map[string]any{"exit_code": code}
	if runErr != nil {
		end["error"] = runErr.Error()
	}
	if err := c.recording.Add("device_end", nil, end); err != nil && runErr == nil {
		runErr = c.fail(err)
	}
	c.recording.Select("", "")
	return code, runErr
}

func (s *Server) startRecording(ch ssh.Channel, sess Session, tty bool, rows, cols int, cancel context.CancelFunc) (ssh.Channel, *collection.Recording, error) {
	if s.cfg.Collection == nil {
		return ch, nil, nil
	}
	host, _ := os.Hostname()
	m := collection.Metadata{Lab: s.cfg.Topology.Name, Group: sess.Group, AS: sess.AS, Actor: sess.Actor, AuthMethod: sess.AuthMethod, KeyFingerprint: sess.KeyFingerprint, RemoteAddress: sess.RemoteAddress, Gateway: host, CaptureInput: s.cfg.CaptureInput, ShellEvents: s.cfg.ShellEvents, TTY: tty, Rows: rows, Cols: cols}
	r, err := s.cfg.Collection.Start(m)
	if err != nil {
		return ch, nil, fmt.Errorf("cannot start collection: %w", err)
	}
	return wrapChannel(ch, r, s.cfg.CaptureInput, cancel), r, nil
}

// RecoverExecutions closes device processes whose recorded gateway died.
// Running this before listening prevents an old shell from outliving a session.
func (s *Server) RecoverExecutions(root string) error {
	metas, err := collection.List(root)
	if err != nil {
		return err
	}
	for _, m := range metas {
		if m.Lab != s.cfg.Topology.Name || m.Status != "incomplete" || m.Reason != "gateway stopped before session was finalized" {
			continue
		}
		ack := filepath.Join(root, m.ID, "executions-cleaned")
		if _, err := os.Stat(ack); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		active := map[string]string{}
		if err := collection.ReadEvents(root, m.ID, func(e collection.Event) error {
			if e.Type == "device_start" {
				if id, ok := e.Fields["execution_id"].(string); ok {
					active[id] = e.Device
				}
			}
			if e.Type == "device_end" {
				delete(active, e.Segment)
			}
			return nil
		}); err != nil {
			return err
		}
		for id, device := range active {
			command, err := terminal.CleanupCommand(id)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			code, err := s.cfg.Exec.Shell(ctx, device, command, strings.NewReader(""), io.Discard, io.Discard, false, 0, 0)
			cancel()
			if err != nil || code != 0 {
				return fmt.Errorf("cleaning interrupted session %s on %s: exit %d: %v", m.ID, device, code, err)
			}
			s.cfg.Logger.Info("cleaned interrupted recording execution", "session", m.ID, "device", device)
		}
		if err := os.WriteFile(ack, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}
