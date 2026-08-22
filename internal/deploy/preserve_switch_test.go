package deploy

import (
	"strings"
	"testing"
)

// ovs-vsctl prints a trunk list as "[10, 20]". Stripping only the brackets
// leaves "trunks=10, 20", which the shell splits on the space: the port is set
// to carry VLAN 10 and the second VLAN is dropped without a word. Restoring
// such a capture quietly halves a datacentre, and the symptom -- two hosts that
// cannot reach each other -- is several steps removed from the cause.
//
// This was found and fixed in the submission archive, then left in place here:
// the same corruption, in the path that runs automatically every time a
// container is replaced.
func TestCapturedTrunkListsHaveNoSpaces(t *testing.T) {
	if !strings.Contains(switchCapture, `tr -d '[] '`) {
		t.Error("the capture script does not strip spaces from ovs-vsctl list output, " +
			"so a multi-VLAN trunk is truncated on restore")
	}
	if strings.Contains(switchCapture, `tr -d '[]'`) {
		t.Error("the capture script still strips only brackets, leaving the space that breaks the restore")
	}
	if strings.Contains(switchCapture, "2>/dev/null") || !strings.Contains(switchCapture, "|| exit $?") {
		t.Error("switch capture hides ovs-vsctl failures instead of refusing a destructive restore")
	}
}

func TestATwoVLANTrunkSurvivesTheRoundTrip(t *testing.T) {
	cmds := ovsReplay("port trunk_S2 tag= trunks=10,20 mode=trunk\n")
	joined := strings.Join(cmds, " ; ")
	if !strings.Contains(joined, "trunks=10,20") {
		t.Errorf("a two-VLAN trunk did not survive the round trip: %q", joined)
	}
}

// Every replayed command must be able to report failure. Appending `|| true`
// makes the restore unconditionally succeed, so a device that came back with
// none of its addresses is indistinguishable from one that came back intact.
func TestReplayCommandsDoNotSuppressFailure(t *testing.T) {
	sets := map[string][]string{
		"addr":   addrReplay("1: eth0    inet 3.101.0.1/24 scope global eth0\n---\ndefault via 3.101.0.2 dev eth0\n---\n"),
		"tunnel": tunnelReplay("tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64\n"),
		"ovs":    ovsReplay("port trunk_S2 tag=10 trunks= mode=access\n"),
	}
	for name, cmds := range sets {
		if len(cmds) == 0 {
			t.Errorf("%s: produced no commands, so the restore is a no-op", name)
		}
		for _, c := range cmds {
			if strings.Contains(c, "|| true") || strings.Contains(c, "2>/dev/null") {
				t.Errorf("%s: %q cannot fail, so a broken restore reports success", name, c)
			}
		}
	}
}

// The tunnel capture parses `ip -d tunnel show`. This is that command's real
// output, copied from a running router, so the parser is tested against the
// format it will actually meet rather than the one it was written against.
func TestTunnelCaptureParsesRealDeviceOutput(t *testing.T) {
	const real = `sit0: ipv6/ip remote any local any ttl 64 nopmtudisc 6rd-prefix 2002::/16
tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64 6rd-prefix 2002::/16
`
	cmds := tunnelReplay(real)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip tunnel add tun6 mode sit remote 3.153.0.1 local 3.156.0.1") {
		t.Errorf("the student's tunnel was not recovered from real `ip -d tunnel show` output:\n%s", joined)
	}
	if strings.Contains(joined, "sit0") {
		t.Error("the kernel's own sit0 device was replayed; it exists already and re-adding it fails")
	}
}
