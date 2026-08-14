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

// What a diagnostic caller may run, program by program, with the arguments each
// one is allowed.
//
// This was a list of programs plus a scan for words that write, and it was
// walked past twice: once with a newline hiding "configure terminal" inside a
// vtysh body, once with `ip -family inet link set`, where the argument of an
// option was mistaken for the object. A denylist has to think of everything; a
// grammar has to be given permission. Every program here has a validator, the
// default is refusal, and a program whose read-only subset is not worth
// spelling out is simply absent.
//
// Absent on purpose, having been present: ethtool, whose -K and -s change the
// device; nc, whose -e runs a command; curl and wget, which write files; birdc,
// which configures a routing daemon these images do not even run.
var readOnlyPrograms = map[string]func(cmd []string) error{
	// Pure observation, whatever the arguments.
	"ping": nil, "ping6": nil, "traceroute": nil, "traceroute6": nil,
	"tracepath": nil, "mtr": nil, "dig": nil, "host": nil, "nslookup": nil,
	"cat": nil, "head": nil, "tail": nil, "grep": nil, "wc": nil, "ls": nil,
	"date": nil, "uptime": nil, "ps": nil, "free": nil, "df": nil,
	"netstat": nil,

	// iptables-save -f writes the ruleset to a file, as root, anywhere.
	"iptables-save":  savesReadOnly,
	"ip6tables-save": savesReadOnly,

	// Observation with a way to write, spelled out.
	"ip":       refuseWrites,
	"bridge":   refuseWrites,
	"sysctl":   sysctlReadOnly,
	"ss":       ssReadOnly,
	"arp":      arpReadOnly,
	"hostname": hostnameReadOnly,
	"tcpdump":  tcpdumpReadOnly,
	"vtysh":    vtyshReadOnly,
}

// writeVerbs change something, wherever they appear in an iproute2 command
// line.
//
// Matching by position was the mistake. The parser took the first argument that
// did not begin with a dash as the object and the next as the verb, so
// `ip -family inet link set dev lo down` -- where "inet" is the *argument to*
// -family -- made "inet" the object, "link" the verb, and "set" invisible. A
// diagnostic session took an interface down on a host it was being scored on.
var writeVerbs = map[string]bool{
	"set": true, "add": true, "del": true, "delete": true, "change": true,
	"replace": true, "append": true, "flush": true, "restore": true,
	"exec": true, "attach": true, "detach": true, "chain": true,
}

// writeOptions do something other than print, whatever else is on the line:
// -batch runs a file of commands, -force presses on past errors, and -netns
// moves the whole operation into another network namespace.
var writeOptionNames = map[string]bool{
	"batch": true, "force": true, "netns": true, "all": true, "write": true,
}

// refuseWrites rejects an iproute2-style command that changes anything.
//
// Abbreviations count. iproute2 accepts any unambiguous prefix of a keyword, so
// `ip link se dev lo up` is `ip link set dev lo up` -- and a validator matching
// the exact spellings saw an argument called "se" and let it through. A
// diagnostic session brought an interface up on a device it was being scored
// on, and could as easily have brought one down. Anything that could be short
// for a word that writes is refused; a device really called "se" would be
// refused too, which is the right way round.
func refuseWrites(cmd []string) error {
	for _, a := range cmd[1:] {
		low := strings.ToLower(a)
		if strings.HasPrefix(low, "-") {
			name := strings.TrimLeft(low, "-")
			if i := strings.IndexByte(name, '='); i > 0 {
				name = name[:i]
			}
			for w := range writeOptionNames {
				if name != "" && strings.HasPrefix(w, name) {
					return fmt.Errorf("a diagnostic session may not run %q: %q can be short "+
						"for -%s, which does more than print",
						strings.Join(cmd, " "), a, w)
				}
			}
			continue
		}
		for w := range writeVerbs {
			// Two characters is where iproute2 stops being ambiguous; a single
			// letter it rejects itself.
			if len(low) >= 2 && strings.HasPrefix(w, low) {
				return fmt.Errorf("a diagnostic session may not run %q: %q is, or can be "+
					"short for, %q, which changes the device",
					strings.Join(cmd, " "), a, w)
			}
		}
	}
	return nil
}

// savesReadOnly allows the ruleset dumps to print and nothing else.
//
// `iptables-save -f <path>` creates or truncates a file, as root, anywhere on
// the device -- including a routing configuration. It was allowed because its
// name says "save" and its validator was nil.
func savesReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		switch a {
		case "-c", "--counters", "-t", "--table", "-M", "--modprobe":
			continue
		}
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("a diagnostic session may run %s only to print (%q)", cmd[0], a)
		}
	}
	return nil
}

func sysctlReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		if hasShortOption(a, 'w') || hasShortOption(a, 'p') ||
			a == "--write" || a == "--load" || strings.Contains(a, "=") {
			return fmt.Errorf("a diagnostic session may not set a kernel parameter (%q)", a)
		}
	}
	return nil
}

func ssReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		// ss -K closes sockets, which on a router is a session reset -- an
		// evaluated agent used `ss -Ktn` to drop a BGP session on a device it
		// was being scored on. Short options cluster, so matching "-K" exactly
		// was matching one spelling of several.
		if hasShortOption(a, 'K') || a == "--kill" {
			return errors.New("a diagnostic session may not close sockets (ss -K)")
		}
	}
	return nil
}

// hasShortOption reports whether a clustered short-option argument contains a
// letter: -K, -Ktn and -tnK are the same option three ways.
//
// Every validator that matched an option by exact string was matching one
// spelling of several. A long option (--kill) and anything after "=" are not
// clusters and are compared whole.
func hasShortOption(arg string, opt byte) bool {
	if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
		return false
	}
	body := arg[1:]
	if i := strings.IndexByte(body, '='); i >= 0 {
		body = body[:i]
	}
	return strings.IndexByte(body, opt) >= 0
}

func arpReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		for _, o := range []byte{'d', 's', 'f'} {
			if hasShortOption(a, o) {
				return fmt.Errorf("a diagnostic session may not change the ARP table (%q)", a)
			}
		}
		switch a {
		case "--delete", "--set", "--file":
			return fmt.Errorf("a diagnostic session may not change the ARP table (%q)", a)
		}
	}
	return nil
}

func hostnameReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		if !strings.HasPrefix(a, "-") {
			return errors.New("a diagnostic session may not set the hostname")
		}
		if hasShortOption(a, 'F') || hasShortOption(a, 'b') ||
			a == "--file" || a == "--boot" {
			return fmt.Errorf("a diagnostic session may not set the hostname (%q)", a)
		}
	}
	return nil
}

func tcpdumpReadOnly(cmd []string) error {
	for _, a := range cmd[1:] {
		for _, o := range []byte{'z', 'w', 'W'} {
			if hasShortOption(a, o) {
				return fmt.Errorf("a diagnostic session may not run tcpdump %s: it writes to "+
					"the device or runs a command on it", a)
			}
		}
		if a == "--postrotate-command" {
			return fmt.Errorf("a diagnostic session may not run tcpdump %s", a)
		}
	}
	return nil
}

// vtyshReadOnly accepts only show-style commands, in any spelling of the option
// that carries them.
//
// The previous version matched the literal "-c" and nothing else, so
// `vtysh --command 'configure terminal' --command 'interface lo' ...` went
// through untouched and a diagnostic session edited a router. Every option is
// now either one of the two spellings that carry a command, or refused.
func vtyshReadOnly(cmd []string) error {
	for i := 1; i < len(cmd); i++ {
		a := cmd[i]
		var body string
		switch {
		case a == "-c" || a == "--command":
			if i+1 >= len(cmd) {
				return errors.New("vtysh -c needs a command")
			}
			i++
			body = cmd[i]
		case strings.HasPrefix(a, "-c="):
			body = strings.TrimPrefix(a, "-c=")
		case strings.HasPrefix(a, "--command="):
			body = strings.TrimPrefix(a, "--command=")
		default:
			return fmt.Errorf("a diagnostic session may run vtysh only as `vtysh -c \"show "+
				"...\"`; %q is not that", a)
		}
		body = strings.TrimSpace(body)
		if body == "" {
			return errors.New("vtysh -c needs a command")
		}
		// One command, checked as a whole. Validating the first word of a body
		// that may contain several is validating the wrong thing.
		if strings.ContainsAny(body, "\n\r;") {
			return fmt.Errorf("a diagnostic session may send only one vtysh command per "+
				"argument (%q)", body)
		}
		switch strings.Fields(body)[0] {
		case "show", "ping", "traceroute", "terminal":
		default:
			return fmt.Errorf("a diagnostic session may only run vtysh show commands, not %q",
				body)
		}
		// "show ... | ..." is fine, but redirection is not: it writes.
		if strings.ContainsAny(body, ">`") || strings.Contains(body, "$(") {
			return fmt.Errorf("a diagnostic session may not redirect (%q)", body)
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
	validate, known := readOnlyPrograms[prog]
	if !known {
		return fmt.Errorf("a diagnostic session may not run %q: it may only observe. "+
			"Allowed programs are read-only ones such as ping, traceroute, ip show, ss and "+
			"vtysh -c 'show ...'", prog)
	}
	for _, a := range cmd[1:] {
		// A newline is a command separator everywhere, and vtysh is no
		// exception: it reads what follows one as the next line of input. The
		// exemption that used to be here let a diagnostic session send
		// "show version\nconfigure terminal\ninterface lo\ndescription ..."
		// as a single body whose first word is "show", and change the router --
		// while a plain "configure terminal" was refused with 403.
		if strings.ContainsAny(a, "\n\r\x00") {
			return fmt.Errorf("a diagnostic session may not send more than one command in "+
				"an argument (%q contains a line break)", a)
		}
		// No shell metacharacters. Every allowed program takes its arguments
		// directly, so a semicolon or a backtick is somebody trying to reach a
		// shell through one of them.
		if strings.ContainsAny(a, ";&`$><") {
			return fmt.Errorf("a diagnostic session may not use shell syntax (%q)", a)
		}
		if strings.Contains(a, "|") && prog != "vtysh" && prog != "grep" {
			return fmt.Errorf("a diagnostic session may not use shell syntax (%q)", a)
		}
	}
	if validate == nil {
		return nil
	}
	return validate(cmd)
}
