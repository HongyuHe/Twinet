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
