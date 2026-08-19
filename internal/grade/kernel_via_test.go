package grade

import (
	"strings"
	"testing"
)

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

// The three rules the kernel installs itself are not the submission's doing
// and need no probing.
func TestParseIPRulesIgnoresTheKernelsOwnRules(t *testing.T) {
	out := "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n"
	rules, unsupported := parseIPRules(out)
	if len(rules) != 0 || len(unsupported) != 0 {
		t.Fatalf("got %+v / %v, want nothing", rules, unsupported)
	}
}

// A rule keyed on the source is how transit traffic is singled out, and it is
// the case a plain lookup cannot see.
func TestParseIPRulesReadsASourceRule(t *testing.T) {
	out := "0:\tfrom all lookup local\n100:\tfrom 4.0.0.0/8 lookup 100\n32766:\tfrom all lookup main\n"
	rules, unsupported := parseIPRules(out)
	if len(unsupported) != 0 {
		t.Fatalf("unsupported: %v", unsupported)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.from != "4.0.0.0/8" || r.table != "100" || r.prio != "100" {
		t.Errorf("read as %+v", r)
	}
	if got := r.selectors(); got != "from 4.0.0.0/8" {
		t.Errorf("selectors = %q", got)
	}
}

// A rule on a port or a uid cannot be simulated by a route lookup. Saying
// nothing goes the slow way would be a guess, so it is refused instead.
func TestParseIPRulesRefusesWhatItCannotSimulate(t *testing.T) {
	for _, line := range []string{
		"100:\tfrom all ipproto tcp dport 179 lookup 100",
		"100:\tfrom all uidrange 0-0 lookup 100",
		"100:\tnot from 4.0.0.0/8 lookup 100",
		"100:\tfrom all oif eth0 lookup 100",
	} {
		rules, unsupported := parseIPRules(line)
		if len(unsupported) != 1 || len(rules) != 0 {
			t.Errorf("%q: got %+v / %v, want it refused", line, rules, unsupported)
		}
	}
}

// A source rule must be probed as a packet that rule matches, on an interface
// the packet could have arrived on -- the kernel refuses the lookup otherwise.
func TestRouteProbesPresentsAPacketTheRuleMatches(t *testing.T) {
	addrs := []string{"1.0.0.1", "2.0.0.1"}
	rules := []ipRule{{prio: "100", from: "4.0.0.0/8", table: "100", text: "from 4.0.0.0/8"}}
	probes, err := routeProbes(addrs, rules, "port_CHI")
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 4 {
		t.Fatalf("got %d probes, want 4: %+v", len(probes), probes)
	}
	for _, p := range probes[:2] {
		if p.args != "" || p.ctx != "" {
			t.Errorf("plain probe carries context: %+v", p)
		}
	}
	for _, p := range probes[2:] {
		if p.args != "from 4.0.0.1 iif port_CHI" {
			t.Errorf("rule probe args = %q", p.args)
		}
		if p.ctx != "from 4.0.0.0/8" {
			t.Errorf("rule probe ctx = %q", p.ctx)
		}
	}
}

// With no rules of the submission's own, nothing beyond the plain lookups is
// asked -- so a correct submission costs exactly what it did before.
func TestRouteProbesAddsNothingWithoutRules(t *testing.T) {
	probes, err := routeProbes([]string{"1.0.0.1", "2.0.0.1"}, nil, "port_CHI")
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 2 {
		t.Fatalf("got %d probes, want 2", len(probes))
	}
}

// A rule that matches any source still needs one to be named, and it must not
// be the destination being asked about.
func TestRouteProbesUsesAStandInSourceForMatchAllRules(t *testing.T) {
	addrs := []string{"1.0.0.1", "2.0.0.1"}
	rules := []ipRule{{prio: "100", from: "all", iif: "port_NYC", table: "100", text: "from all iif port_NYC"}}
	probes, err := routeProbes(addrs, rules, "port_CHI")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probes[2:] {
		if !strings.Contains(p.args, "iif port_NYC") {
			t.Errorf("rule's own interface not used: %q", p.args)
		}
		if strings.Contains(p.args, "from "+p.addr+" ") {
			t.Errorf("probe sourced from its own destination: %+v", p)
		}
	}
}

// A rule keyed only on a firewall mark needs no arrival interface: the kernel
// answers for a marked packet the router originates.
func TestRouteProbesAsksAboutAMarkDirectly(t *testing.T) {
	rules := []ipRule{{prio: "100", from: "all", mark: "0x7/0xff", table: "100", text: "from all fwmark 0x7/0xff"}}
	probes, err := routeProbes([]string{"1.0.0.1"}, rules, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 2 {
		t.Fatalf("got %d probes, want 2: %+v", len(probes), probes)
	}
	if probes[1].args != "mark 0x7" {
		t.Errorf("args = %q, want the mask stripped", probes[1].args)
	}
}

func TestPickIifSkipsLoopbackAndDownLinks(t *testing.T) {
	out := `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
5: port_NYC@if4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN
3: port_CHI@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
`
	if got := pickIif(out); got != "port_CHI" {
		t.Errorf("pickIif = %q, want port_CHI", got)
	}
	if got := pickIif("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"); got != "" {
		t.Errorf("pickIif on loopback only = %q, want empty", got)
	}
}
