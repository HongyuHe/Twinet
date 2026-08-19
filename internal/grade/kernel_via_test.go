package grade

import "testing"

func TestProbeAddrPicksAHostAddress(t *testing.T) {
	cases := map[string]string{
		"2.0.0.0/8":      "2.0.0.1",
		"10.1.2.0/24":    "10.1.2.1",
		"192.0.2.7/32":   "192.0.2.7",
		"198.51.100.0/8": "198.0.0.1",
		"::/0":           "",
		"nonsense":       "",
	}
	for prefix, want := range cases {
		if got := probeAddr(prefix); got != want {
			t.Errorf("probeAddr(%q) = %q, want %q", prefix, got, want)
		}
	}
}

// A policy rule sends the lookup to another table, and the kernel says so in
// the same shape as any other answer. This is the case the check used to miss
// entirely: the daemon's table still showed the fast path.
func TestParseKernelHopsReadsAPolicyRoutedAnswer(t *testing.T) {
	out := `@ 2.0.0.1
2.0.0.1 via 179.1.3.1 dev ext_1_ALL table 100 src 179.1.3.2 uid 0
@ 3.0.0.1
3.0.0.1 via 3.0.2.2 dev port_CHI src 3.0.2.1 uid 0
`
	hops := parseKernelHops(out)
	if len(hops) != 2 {
		t.Fatalf("got %d hops, want 2: %+v", len(hops), hops)
	}
	if h := hops["2.0.0.1"]; h.via != "179.1.3.1" || h.dev != "ext_1_ALL" {
		t.Errorf("policy-routed answer read as %+v", h)
	}
	if h := hops["3.0.0.1"]; h.via != "3.0.2.2" || h.dev != "port_CHI" {
		t.Errorf("ordinary answer read as %+v", h)
	}
}

// A destination on a connected subnet has no next hop. The interface alone is
// still a usable answer, because a slow link can be named by its interface.
func TestParseKernelHopsReadsAConnectedAnswer(t *testing.T) {
	hops := parseKernelHops("@ 3.0.2.2\n3.0.2.2 dev port_CHI src 3.0.2.1 uid 0\n")
	h, ok := hops["3.0.2.2"]
	if !ok {
		t.Fatal("connected answer was dropped")
	}
	if h.via != "" || h.dev != "port_CHI" {
		t.Errorf("read as %+v, want dev only", h)
	}
}

// An address the kernel cannot route carries neither field. Recording it as a
// hop would invent a forwarding decision that was never made.
func TestParseKernelHopsDropsUnroutableAnswers(t *testing.T) {
	out := `@ 9.0.0.1
RTNETLINK answers: Network is unreachable
@ 2.0.0.1
2.0.0.1 via 179.1.3.1 dev ext_1_ALL table 100 src 179.1.3.2 uid 0
`
	hops := parseKernelHops(out)
	if _, ok := hops["9.0.0.1"]; ok {
		t.Error("an unreachable destination was recorded as a hop")
	}
	if _, ok := hops["2.0.0.1"]; !ok {
		t.Error("a later answer was lost after an unreachable one")
	}
}

// The echo marker is what pairs an answer with its question. A missing answer
// must not shift every following answer onto the wrong address.
func TestParseKernelHopsDoesNotShiftOnMissingAnswer(t *testing.T) {
	out := `@ 9.0.0.1
@ 2.0.0.1
2.0.0.1 via 179.1.3.1 dev ext_1_ALL
`
	hops := parseKernelHops(out)
	if len(hops) != 1 {
		t.Fatalf("got %d hops, want 1: %+v", len(hops), hops)
	}
	if h := hops["2.0.0.1"]; h.via != "179.1.3.1" {
		t.Errorf("answer landed on the wrong address: %+v", hops)
	}
}
