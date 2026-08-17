package grade

import (
	"strings"
	"testing"
)

// The processes of a core router as the exercise wants it.
//
// FRR starts bgpd and nothing configures it, which is the state being asked
// for: no instance, no table, no port. A reader that called this a second BGP
// daemon would fail every correct answer, which is the more expensive mistake
// of the two.
const referenceCore = `COMMAND
/sbin/docker-init -- /usr/local/bin/twinet-entrypoint sleep infinity
sleep infinity
/usr/lib/frr/watchfrr -d -F traditional zebra mgmtd bgpd ospfd ospf6d ldpd staticd
/usr/lib/frr/zebra -d -F traditional -A 127.0.0.1 -s 90000000
/usr/lib/frr/bgpd -d -F traditional -A 127.0.0.1 -M rpki
/usr/lib/frr/ldpd -d -F traditional -A 127.0.0.1
/usr/lib/frr/staticd -d -F traditional -A 127.0.0.1
`

func TestAnUnconfiguredBGPDaemonIsNotAFinding(t *testing.T) {
	spaces, findings := bgpDaemons("R5", referenceCore)
	if len(spaces) != 0 || len(findings) != 0 {
		t.Fatalf("the reference core router was reported as running hidden BGP: %v %v",
			spaces, findings)
	}
}

func TestWatchfrrListingBGPDIsNotABGPDaemon(t *testing.T) {
	// The supervisor's command line names every daemon it manages, bgpd
	// included. Matching the word rather than the program would find one on
	// every FRR router in the lab.
	const only = "/usr/lib/frr/watchfrr -d -F traditional zebra mgmtd bgpd ospfd\n"
	_, findings := bgpDaemons("R5", only)
	if len(findings) != 0 {
		t.Fatalf("watchfrr was mistaken for a BGP daemon: %v", findings)
	}
}

func TestASecondBGPDaemonInAPathspaceIsFound(t *testing.T) {
	ps := referenceCore + "/usr/lib/frr/bgpd -N x -d -A 127.0.0.1\n"
	spaces, findings := bgpDaemons("R5", ps)
	if len(spaces) != 1 || spaces[0] != "x" {
		t.Fatalf("the pathspace was not read: %v", spaces)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], `pathspace "x"`) {
		t.Fatalf("the hidden daemon was not reported: %v", findings)
	}
}

func TestEverySpellingOfAPathspaceIsRead(t *testing.T) {
	for _, tc := range []struct{ args, want string }{
		{"/usr/lib/frr/bgpd -N x -d", "x"},
		{"/usr/lib/frr/bgpd --pathspace hidden -d", "hidden"},
		{"/usr/lib/frr/bgpd --pathspace=hidden -d", "hidden"},
		{"/usr/lib/frr/bgpd --vty_socket /var/run/frr/other/ -d", "other"},
		{"/usr/lib/frr/bgpd --vty_socket=/var/run/frr/other -d", "other"},
		{"/usr/lib/frr/bgpd -d -F traditional -A 127.0.0.1 -M rpki", ""},
	} {
		if got := pathspaceOf(strings.Fields(tc.args)); got != tc.want {
			t.Errorf("%s: read pathspace %q, wanted %q", tc.args, got, tc.want)
		}
	}
}

func TestASecondCopyOfTheDefaultDaemonIsFound(t *testing.T) {
	// Started by hand with no pathspace at all. It cannot own the default
	// socket, which is taken, so vtysh still answers for the idle one.
	ps := referenceCore + "/usr/lib/frr/bgpd -d -A 127.0.0.1\n"
	_, findings := bgpDaemons("R5", ps)
	if len(findings) != 1 || !strings.Contains(findings[0], "runs 2 BGP daemons") {
		t.Fatalf("a second copy of bgpd was not reported: %v", findings)
	}
}

func TestADaemonThatIsNotFRRIsFound(t *testing.T) {
	for _, prog := range []string{"/usr/sbin/bird", "/usr/bin/gobgpd", "/usr/local/bin/exabgp"} {
		_, findings := bgpDaemons("R5", referenceCore+prog+" -c /etc/x.conf\n")
		if len(findings) != 1 {
			t.Fatalf("%s was not reported as a BGP daemon: %v", prog, findings)
		}
	}
}

func TestACoreRouterWithNoBGPPortIsNotAFinding(t *testing.T) {
	// LDP on 646 and the vty ports are what a core router legitimately holds.
	const ss = `LISTEN 0      128        1.155.0.1:646        0.0.0.0:*
LISTEN 0      3          127.0.0.1:2605       0.0.0.0:*
ESTAB  0      0          1.155.0.1:59921    1.154.0.1:646
`
	if got := bgpSockets("R5", ss); len(got) != 0 {
		t.Fatalf("a core router holding only LDP was reported as speaking BGP: %v", got)
	}
}

func TestAListenerOnTheBGPPortIsFound(t *testing.T) {
	const ss = `LISTEN 0      128          0.0.0.0:179        0.0.0.0:*
LISTEN 0      128             [::]:179           [::]:*
`
	got := bgpSockets("R5", ss)
	if len(got) != 2 {
		t.Fatalf("wanted both listeners reported, got %v", got)
	}
	for _, g := range got {
		if !strings.Contains(g, "listening for BGP") {
			t.Errorf("unclear evidence: %q", g)
		}
	}
}

func TestASessionToTheBGPPortIsFound(t *testing.T) {
	// The connecting end holds no listener at all: its local port is ephemeral
	// and only the peer's says what it is speaking.
	const ss = "ESTAB  0      0          1.155.0.1:41234    1.154.0.1:179\n"
	got := bgpSockets("R5", ss)
	if len(got) != 1 || !strings.Contains(got[0], "holds a BGP connection") {
		t.Fatalf("an outgoing BGP session was not reported: %v", got)
	}
}

func TestAPortEndingIn179IsNotTheBGPPort(t *testing.T) {
	// 1179 ends in 179 and is not it. Substring matching here would fail a
	// correct answer for a port it chose at random.
	const ss = `LISTEN 0      128        1.155.0.1:1179       0.0.0.0:*
ESTAB  0      0          1.155.0.1:51179    1.154.0.1:646
`
	if got := bgpSockets("R5", ss); len(got) != 0 {
		t.Fatalf("a port that merely ends in 179 was read as BGP: %v", got)
	}
}

func TestTheNumberOfHiddenNeighboursIsRead(t *testing.T) {
	const summary = `
IPv4 Unicast Summary:
BGP router identifier 1.155.0.1, local AS number 1 VRF default vrf-id 0
BGP table version 0
RIB entries 0, using 0 bytes of memory
Peers 1, using 13 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd
1.154.0.1       4          1         0         0        0    0    0    never         Idle

Total number of neighbors 1
`
	if got := bgpPeerCount(summary); got != 1 {
		t.Fatalf("read %d neighbours, wanted 1", got)
	}
	if got := bgpPeerCount("% BGP instance not found\n"); got != 0 {
		t.Fatalf("read %d neighbours from an absent instance", got)
	}
}
