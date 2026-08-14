package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// A diagnostic credential is a read-only, single-lab derivative of the cluster
// token.
//
// It exists for one reason: something under evaluation has to be allowed to
// look at the network without being handed the keys to it. An RCA agent given
// TWINET_TOKEN can read every lab on the cluster, ask an agent to run anything
// in any container, take a hold, apply a plan, or simply destroy the evidence
// -- and the benchmark that results measures none of what it claims to.
//
// The credential carries its own scope. The server does not keep a list of
// issued tokens; it recomputes the MAC from the cluster secret and the lab name
// the token names, so an agent cannot widen its own scope without the secret,
// and a token stays valid exactly as long as the secret does.
const diagPrefix = "twdiag."

// DiagnosticToken derives the read-only credential for one lab.
func DiagnosticToken(secret, lab string) string {
	m := hmac.New(sha256.New, []byte(secret))
	// The lab is part of the signed message, so the scope cannot be edited.
	m.Write([]byte("twinet-diagnostic-v1\x00" + lab))
	return diagPrefix + hex.EncodeToString([]byte(lab)) + "." + hex.EncodeToString(m.Sum(nil))
}

// diagnosticScope returns the lab a diagnostic token is good for.
func diagnosticScope(secret, tok string) (string, bool) {
	if !strings.HasPrefix(tok, diagPrefix) {
		return "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(tok, diagPrefix), ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	lab := string(raw)
	want := DiagnosticToken(secret, lab)
	if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		return "", false
	}
	return lab, true
}

// scopeHeader is how a verified diagnostic scope reaches the handler. It is set
// by the authenticator on the way in and never read from the client: any value
// the client supplied is removed first.
const scopeHeader = "X-Twinet-Diagnostic-Lab"

// authDiag admits either the cluster token or a diagnostic token. Handlers
// wrapped with it must check diagScopeOf and restrict themselves accordingly.
func (s *Server) authDiag(h http.HandlerFunc) http.HandlerFunc {
	full := []byte("Bearer " + s.cfg.Token)
	return func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del(scopeHeader)
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), full) == 1 {
			h(w, r)
			return
		}
		if lab, ok := diagnosticScope(s.cfg.Token, strings.TrimPrefix(got, "Bearer ")); ok {
			r.Header.Set(scopeHeader, lab)
			h(w, r)
			return
		}
		http.Error(w, "unauthorised", http.StatusUnauthorized)
	}
}

// diagScopeOf reports the lab a diagnostic caller is confined to, and whether
// the caller is a diagnostic one at all.
func diagScopeOf(r *http.Request) (string, bool) {
	lab := r.Header.Get(scopeHeader)
	return lab, lab != ""
}

// readOnlyCommands are the programs a diagnostic caller may run. The rule is
// not "commands that look harmless" but "commands with no way to change the
// device": anything that configures, restarts, writes a file, or opens a shell
// is absent, because a fault an agent introduced itself is indistinguishable
// from the one it was asked to find.
var readOnlyCommands = map[string]bool{
	"ping": true, "ping6": true, "traceroute": true, "traceroute6": true,
	"tracepath": true, "mtr": true, "dig": true, "host": true, "nslookup": true,
	"ip": true, "ss": true, "netstat": true, "arp": true, "bridge": true,
	"cat": true, "ls": true, "head": true, "tail": true, "grep": true, "wc": true,
	"date": true, "uptime": true, "hostname": true, "ethtool": true,
	"vtysh": true, "birdc": true, "tcpdump": true,
	"ip6tables-save": true, "iptables-save": true, "sysctl": true, "nc": true,
	"ps": true, "free": true, "df": true, "sh": false, "bash": false,
}

// writeSubcommands marks the programs whose arguments have to be inspected
// before they are allowed: iproute2 tools observe and change with the same
// binary, and the difference is a word somewhere in the middle.
var writeSubcommands = map[string]map[string]bool{
	"ip":     {},
	"bridge": {},
	"sysctl": {},
}

// writeVerbs change something, wherever they appear in an iproute2 command
// line.
//
// Matching by position was the mistake. The parser took the first argument that
// did not begin with a dash as the object and the next as the verb, so
// `ip -family inet link set dev lo down` -- where "inet" is the *argument to*
// -family -- made "inet" the object, "link" the verb, and "set" invisible. A
// diagnostic session took an interface down on a host it was being scored on.
// A word that changes the device is refused wherever it occurs; a device called
// "set" would be refused too, which is the right way round.
var writeVerbs = map[string]bool{
	"set": true, "add": true, "del": true, "delete": true, "change": true,
	"replace": true, "append": true, "flush": true, "restore": true,
	"exec": true, "attach": true, "detach": true, "chain": true,
}

// writeOptions do something other than print, whatever else is on the line:
// -batch runs a file of commands, -force presses on past errors, and -netns
// moves the whole operation into another network namespace.
var writeOptions = map[string]bool{
	"-batch": true, "-force": true, "-n": true, "-netns": true,
	"-w": true, "--write": true, "-a": true, "-all": true,
}

// refuseIfWriting rejects an iproute2-style command that changes anything.
func refuseIfWriting(prog string, cmd []string) error {
	for _, a := range cmd[1:] {
		low := strings.ToLower(a)
		if writeVerbs[low] {
			return fmt.Errorf("a diagnostic session may not run %q: %q changes the device",
				strings.Join(cmd, " "), a)
		}
		// An option and its value may be written together.
		name := low
		if i := strings.IndexByte(name, '='); i > 0 {
			name = name[:i]
		}
		if writeOptions[name] {
			return fmt.Errorf("a diagnostic session may not run %q: %q is not an option that "+
				"only prints", strings.Join(cmd, " "), a)
		}
	}
	return nil
}

// ReadOnlyCommand reports whether a command can be run by a diagnostic caller.
//
// The check is deliberately conservative and deliberately dumb. It refuses
// anything it cannot reason about rather than trying to parse a shell, because
// the failure mode of being too clever here is an evaluated agent quietly
// repairing or worsening the network it is being scored on.
func ReadOnlyCommand(cmd []string) error {
	if len(cmd) == 0 {
		return errors.New("no command")
	}
	prog := cmd[0]
	if i := strings.LastIndex(prog, "/"); i >= 0 {
		prog = prog[i+1:]
	}
	allowed, known := readOnlyCommands[prog]
	if !known || !allowed {
		return fmt.Errorf("a diagnostic session may not run %q: it may only observe. "+
			"Allowed programs are read-only ones such as ping, traceroute, ip show, ss and "+
			"vtysh -c 'show ...'", prog)
	}
	for _, a := range cmd[1:] {
		// A newline is a command separator everywhere, and vtysh is no
		// exception: it reads what follows one as the next line of input. The
		// exemption below let a diagnostic session send
		// "show version\nconfigure terminal\ninterface lo\ndescription ..."
		// as a single -c body, whose first word is "show", and change the
		// router -- while a plain "configure terminal" was refused with 403.
		// An agent that can edit the device it is being scored on is not being
		// scored on anything.
		if strings.ContainsAny(a, "\n\r\x00") {
			return fmt.Errorf("a diagnostic session may not send more than one command in "+
				"an argument (%q contains a line break)", a)
		}
		// No shell metacharacters anywhere else. Every allowed program takes
		// its arguments directly, so a semicolon or a backtick is somebody
		// trying to reach a shell through one of them.
		if strings.ContainsAny(a, ";&`$><") {
			return fmt.Errorf("a diagnostic session may not use shell syntax (%q)", a)
		}
		if strings.Contains(a, "|") && prog != "vtysh" && prog != "grep" {
			return fmt.Errorf("a diagnostic session may not use shell syntax (%q)", a)
		}
	}
	switch prog {
	case "tcpdump":
		// -z runs a command, -w writes a file, and both are on a device this
		// session is only meant to watch.
		for _, a := range cmd[1:] {
			switch strings.ToLower(a) {
			case "-z", "-w", "-w-", "--postrotate-command":
				return fmt.Errorf("a diagnostic session may not run tcpdump %s: it writes to "+
					"the device or runs a command on it", a)
			}
		}
	case "vtysh":
		// Only "show" and "ping"/"traceroute" style commands. A vtysh that can
		// enter configuration mode can do anything the router can.
		for i, a := range cmd[1:] {
			if a != "-c" {
				continue
			}
			if i+2 > len(cmd)-1 {
				return errors.New("vtysh -c needs a command")
			}
			body := strings.TrimSpace(cmd[i+2])
			first := strings.Fields(body)
			if len(first) == 0 {
				return errors.New("vtysh -c needs a command")
			}
			// One command, checked as a whole. Validating the first word of a
			// body that may contain several is validating the wrong thing.
			if strings.ContainsAny(body, "\n\r;") {
				return fmt.Errorf("a diagnostic session may send only one vtysh command per "+
					"-c argument (%q)", body)
			}
			switch first[0] {
			case "show", "ping", "traceroute", "terminal":
			default:
				return fmt.Errorf("a diagnostic session may only run vtysh show commands, not %q", body)
			}
			// "show ... | ..." is fine, but redirection is not: it writes.
			if strings.ContainsAny(body, ">`") || strings.Contains(body, "$(") {
				return fmt.Errorf("a diagnostic session may not redirect (%q)", body)
			}
		}
	case "cat", "head", "tail", "grep", "ls", "wc":
		// Reading files is allowed, writing through them is not; none of these
		// write, and redirection was refused above.
	default:
		if writeSubcommands[prog] != nil {
			if err := refuseIfWriting(prog, cmd); err != nil {
				return err
			}
		}
	}
	return nil
}
