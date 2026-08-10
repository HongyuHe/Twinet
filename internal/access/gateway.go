// Package access is the front door: the SSH gateway students reach their
// devices through.
//
// The platform this replaces put an sshd inside every container, which is a
// login daemon in each of a thousand routers, a thousand copies of a password
// file to keep in step, and a process budget spent on waiting. Worse, it puts
// authorisation in the wrong place: once a student is inside a container, the
// only thing between them and another group's router is that they were given
// the right port number.
//
// Twinet authenticates once, at the edge, and then execs into the container
// through the node agent. Authorisation is a property of the connection, so a
// student who guesses another group's device name is refused by the same code
// that let them in, rather than by an accident of routing. There is exactly one
// place to rotate a credential, and no daemon inside the lab at all.
package access

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/HongyuHe/twinet/internal/model"
)

// Session is one student's connection, after authentication.
type Session struct {
	Group  string
	AS     int
	Device string
}

// Execer runs a command inside a device, wherever it lives in the cluster.
type Execer interface {
	Shell(ctx context.Context, deviceID string, cmd []string, stdin io.Reader,
		stdout, stderr io.Writer, tty bool, rows, cols int) (int, error)
}

// Roster maps a credential to the AS it may reach.
type Roster struct {
	// Groups is keyed by the login name a student uses.
	Groups map[string]*Group `json:"groups"`
}

// Group is one student group's entry.
type Group struct {
	AS int `json:"as"`
	// PasswordHash is the salted hash of the group's password. The password
	// itself is never stored: a roster that leaks should not hand an attacker
	// working credentials for a class.
	PasswordHash string `json:"password_hash,omitempty"`
	Salt         string `json:"salt,omitempty"`
	// AuthorizedKeys are SSH public keys in authorized_keys format.
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
}

// Config configures the gateway.
type Config struct {
	Topology *model.Topology
	Roster   *Roster
	Exec     Execer
	// HostKey is the server's identity. Regenerating it on every start would
	// train a class to ignore host-key warnings, which is the one habit a
	// networking course should not teach.
	HostKey ssh.Signer
	Listen  string
	// LegacyBase, when non-zero, additionally listens on base+ASN for each AS,
	// reproducing the "ssh -p 2003" entry point students may already know.
	LegacyBase int
	Logger     *slog.Logger
}

// Server is the SSH gateway.
type Server struct {
	cfg    Config
	cfgSSH *ssh.ServerConfig

	mu       sync.Mutex
	sessions int

	listeners []net.Listener
}

// New builds a gateway.
func New(cfg Config) (*Server, error) {
	if cfg.Topology == nil {
		return nil, fmt.Errorf("the gateway needs a topology")
	}
	if cfg.Exec == nil {
		return nil, fmt.Errorf("the gateway needs a way to reach devices")
	}
	if cfg.HostKey == nil {
		return nil, fmt.Errorf("the gateway needs a host key")
	}
	if cfg.Roster == nil {
		cfg.Roster = &Roster{Groups: map[string]*Group{}}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &Server{cfg: cfg}
	s.cfgSSH = &ssh.ServerConfig{
		PasswordCallback:  s.authPassword,
		PublicKeyCallback: s.authPublicKey,
		// A failed login is cheap for an attacker and expensive for us, so the
		// number of tries is bounded rather than left to the default.
		MaxAuthTries:  3,
		ServerVersion: "SSH-2.0-Twinet",
	}
	s.cfgSSH.AddHostKey(cfg.HostKey)
	return s, nil
}

// authPassword authenticates a group by password.
func (s *Server) authPassword(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	g, ok := s.cfg.Roster.Groups[c.User()]
	if !ok || g.PasswordHash == "" {
		// The same error and the same amount of work whether the group exists
		// or not, so a stranger cannot enumerate the class roster by timing.
		_ = hashPassword(string(pass), "decoy")
		return nil, fmt.Errorf("authentication failed")
	}
	want, err := base64.StdEncoding.DecodeString(g.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	got := hashPassword(string(pass), g.Salt)
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return nil, fmt.Errorf("authentication failed")
	}
	return permissionsFor(c.User(), g.AS), nil
}

func (s *Server) authPublicKey(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	g, ok := s.cfg.Roster.Groups[c.User()]
	if !ok {
		return nil, fmt.Errorf("authentication failed")
	}
	offered := key.Marshal()
	for _, line := range g.AuthorizedKeys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(pk.Marshal(), offered) == 1 {
			return permissionsFor(c.User(), g.AS), nil
		}
	}
	return nil, fmt.Errorf("authentication failed")
}

func permissionsFor(group string, asn int) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{
		"group": group,
		"as":    fmt.Sprint(asn),
	}}
}

// Serve listens until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.cfg.Listen
	if addr == "" {
		addr = ":2022"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.listeners = append(s.listeners, ln)
	s.cfg.Logger.Info("gateway listening", "addr", addr)

	// The legacy per-AS ports exist so a class that already knows
	// "ssh -p 2003 root@host" is not retrained for no reason. The port implies
	// the AS, but it does not authorise it: the credential still decides, so a
	// student connecting to another group's port reaches their own devices.
	if s.cfg.LegacyBase > 0 {
		for _, asn := range s.cfg.Topology.SortedASNs() {
			if s.cfg.Topology.ASes[asn].Role != model.RoleStudent {
				continue
			}
			p := fmt.Sprintf(":%d", s.cfg.LegacyBase+asn)
			l, err := net.Listen("tcp", p)
			if err != nil {
				s.cfg.Logger.Warn("legacy port unavailable", "port", p, "err", err)
				continue
			}
			s.listeners = append(s.listeners, l)
			go s.accept(ctx, l)
		}
	}

	go func() {
		<-ctx.Done()
		for _, l := range s.listeners {
			_ = l.Close()
		}
	}()

	s.accept(ctx, ln)
	return nil
}

func (s *Server) accept(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.cfg.Logger.Warn("accept", "err", err)
			continue
		}
		go s.handleConn(ctx, c)
	}
}

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	defer func() { _ = nc.Close() }()
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))

	conn, chans, reqs, err := ssh.NewServerConn(nc, s.cfgSSH)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	// The handshake is bounded; the session that follows is not, because a
	// student debugging a routing table legitimately sits idle for a long time.
	_ = nc.SetDeadline(time.Time{})

	go ssh.DiscardRequests(reqs)

	group := conn.Permissions.Extensions["group"]
	var asn int
	_, _ = fmt.Sscanf(conn.Permissions.Extensions["as"], "%d", &asn)

	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.sessions--
		s.mu.Unlock()
	}()

	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		c, chReqs, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ctx, c, chReqs, Session{Group: group, AS: asn})
	}
}

func (s *Server) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, sess Session) {
	defer func() { _ = ch.Close() }()

	var (
		rows, cols = 24, 80
		wantTTY    bool
	)
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			wantTTY = true
			if w, h, ok := parsePTY(req.Payload); ok {
				cols, rows = w, h
			}
			_ = req.Reply(true, nil)

		case "shell", "exec":
			var cmd []string
			if req.Type == "exec" {
				cmd = []string{"sh", "-c", parseExec(req.Payload)}
			}
			_ = req.Reply(true, nil)
			code := s.run(ctx, ch, sess, cmd, wantTTY, rows, cols)
			_, _ = ch.SendRequest("exit-status", false, exitStatus(code))
			return

		case "window-change":
			if w, h, ok := parsePTY(append(make([]byte, 0, len(req.Payload)+4), req.Payload...)); ok {
				cols, rows = w, h
			}

		default:
			_ = req.Reply(false, nil)
		}
	}
}

// run resolves which device the student asked for and execs into it.
func (s *Server) run(ctx context.Context, ch ssh.Channel, sess Session, cmd []string, tty bool, rows, cols int) int {
	device := s.defaultDevice(sess.AS)
	if device == "" {
		fmt.Fprintf(ch, "AS %d has no devices you can reach.\r\n", sess.AS)
		return 1
	}
	if len(cmd) == 0 {
		// An interactive login lands in a menu rather than on a fixed router,
		// because a group has eight of them and guessing which one is wanted
		// is worse than asking.
		chosen, err := s.chooseDevice(ch, sess)
		if err != nil {
			return 1
		}
		device = chosen
		cmd = []string{"/bin/sh", "-lc", "exec /bin/bash 2>/dev/null || exec /bin/sh"}
	} else if d, rest, ok := splitDevicePrefix(cmd); ok {
		// "ssh group3@gw MSP show ip route" targets one device directly, which
		// is what a script wants.
		full, err := s.resolve(sess, d)
		if err != nil {
			fmt.Fprintf(ch, "%v\r\n", err)
			return 1
		}
		device, cmd = full, rest
	}

	code, err := s.cfg.Exec.Shell(ctx, device, cmd, ch, ch, ch.Stderr(), tty, rows, cols)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "twinet: %v\r\n", err)
		return 1
	}
	return code
}

// resolve maps a short device name to a device the session is allowed to touch.
//
// This is the authorisation boundary, and it is deliberately a lookup within
// the session's own AS rather than a check applied to a global name. A student
// cannot name another group's router at all, so there is no rule to get wrong.
func (s *Server) resolve(sess Session, name string) (string, error) {
	if sess.AS == 0 {
		return "", fmt.Errorf("this session is not bound to an AS")
	}
	as, ok := s.cfg.Topology.ASes[sess.AS]
	if !ok {
		return "", fmt.Errorf("AS %d is not in this lab", sess.AS)
	}
	for _, d := range as.Devices {
		if strings.EqualFold(d.Name, name) {
			return d.ID, nil
		}
	}
	return "", fmt.Errorf("AS %d has no device called %q", sess.AS, name)
}

func (s *Server) devices(asn int) []*model.Device {
	as, ok := s.cfg.Topology.ASes[asn]
	if !ok {
		return nil
	}
	out := append([]*model.Device(nil), as.Devices...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == model.KindRouter
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Server) defaultDevice(asn int) string {
	for _, d := range s.devices(asn) {
		if d.Kind == model.KindRouter {
			return d.ID
		}
	}
	return ""
}

// chooseDevice presents the session's own devices and reads a choice.
func (s *Server) chooseDevice(ch ssh.Channel, sess Session) (string, error) {
	devs := s.devices(sess.AS)
	fmt.Fprintf(ch, "\r\nTwinet: AS %d (%s)\r\n\r\n", sess.AS, sess.Group)
	for i, d := range devs {
		fmt.Fprintf(ch, "  %2d) %-12s %s\r\n", i+1, d.Name, d.Kind)
	}
	fmt.Fprintf(ch, "\r\nDevice number or name: ")

	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if err != nil || n == 0 {
			return "", fmt.Errorf("no choice made")
		}
		switch buf[0] {
		case '\r', '\n':
			fmt.Fprint(ch, "\r\n")
			choice := strings.TrimSpace(string(line))
			var idx int
			if _, err := fmt.Sscanf(choice, "%d", &idx); err == nil && idx >= 1 && idx <= len(devs) {
				return devs[idx-1].ID, nil
			}
			if id, err := s.resolve(sess, choice); err == nil {
				return id, nil
			}
			fmt.Fprintf(ch, "No such device. Device number or name: ")
			line = nil
		case 0x7f, 0x08:
			if len(line) > 0 {
				line = line[:len(line)-1]
				fmt.Fprint(ch, "\b \b")
			}
		case 0x03, 0x04:
			return "", fmt.Errorf("cancelled")
		default:
			line = append(line, buf[0])
			_, _ = ch.Write(buf[:1])
		}
	}
}

// splitDevicePrefix recognises "DEVICE rest of command".
func splitDevicePrefix(cmd []string) (string, []string, bool) {
	if len(cmd) != 3 || cmd[0] != "sh" {
		return "", nil, false
	}
	fields := strings.Fields(cmd[2])
	if len(fields) < 2 {
		return "", nil, false
	}
	// A device name is a bare word; anything with a slash or a dot is a path.
	if strings.ContainsAny(fields[0], "/.=|&;$") {
		return "", nil, false
	}
	return fields[0], []string{"sh", "-c", strings.Join(fields[1:], " ")}, true
}

func parsePTY(payload []byte) (cols, rows int, ok bool) {
	if len(payload) < 4 {
		return 0, 0, false
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+n+8 {
		return 0, 0, false
	}
	p := payload[4+n:]
	cols = int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	rows = int(p[4])<<24 | int(p[5])<<16 | int(p[6])<<8 | int(p[7])
	return cols, rows, true
}

func parseExec(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+n {
		return ""
	}
	return string(payload[4 : 4+n])
}

func exitStatus(code int) []byte {
	return []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code)}
}

// hashPassword derives a verifier from a password and a salt.
//
// The password itself is never stored: a roster that leaks must not hand an
// attacker working credentials for a whole class.
func hashPassword(pass, salt string) []byte {
	return argonish([]byte(salt + "\x00" + pass))
}

// LoadHostKey reads the gateway's identity, creating it once if absent.
//
// It is persisted rather than generated per start because a host key that
// changes on every restart trains a class to click through host-key warnings,
// which is the one habit a networking course should not teach.
func LoadHostKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(raw)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := marshalED25519(priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(der), 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pem.EncodeToMemory(der))
}

// LoadRoster reads a roster from disk.
func LoadRoster(path string) (*Roster, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Roster
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("roster %s: %w", path, err)
	}
	if r.Groups == nil {
		r.Groups = map[string]*Group{}
	}
	return &r, nil
}

// Save writes a roster.
func (r *Roster) Save(path string) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// SetPassword stores a verifier for a group, never the password.
func (g *Group) SetPassword(pass string) error {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	g.Salt = base64.StdEncoding.EncodeToString(salt[:])
	g.PasswordHash = base64.StdEncoding.EncodeToString(hashPassword(pass, g.Salt))
	return nil
}

// GeneratePassword returns a memorable but unguessable credential.
func GeneratePassword() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return strings.ToLower(base64.RawURLEncoding.EncodeToString(b[:])), nil
}
