package fault

import "testing"

// Verbatim ovs-ofctl dump-flows output, including the leading space and the
// cookie/duration preamble that the parser has to step over.
const (
	flowDropPort1 = ` cookie=0x0, duration=0.208s, table=0, n_packets=0, n_bytes=0, idle_age=0, priority=100,in_port=1 actions=drop`
	flowDropPort2 = ` cookie=0x0, duration=0.002s, table=0, n_packets=0, n_bytes=0, idle_age=0, priority=100,in_port=2 actions=drop`
	flowLoopPort1 = ` cookie=0x0, duration=1.100s, table=0, n_packets=0, n_bytes=0, idle_age=0, priority=200,in_port=1 actions=IN_PORT`
	flowNormal    = ` cookie=0x0, duration=149962.079s, table=0, n_packets=88386, n_bytes=7571661, idle_age=0, hard_age=65534, priority=0 actions=NORMAL`
	flowBanner    = "NXST_FLOW reply (xid=0x4):"
)

func table(lines ...string) string {
	out := flowBanner
	for _, l := range lines {
		out += "\n" + l
	}
	return out + "\n"
}

func TestOVSFlowEvidenceFindsTheRecordedPort(t *testing.T) {
	ev := ovsFlowEvidence(table(flowDropPort1, flowNormal), 100, "1", "drop", "a drop rule on port 1")
	if !ev.Verified {
		t.Fatalf("a drop rule on the recorded port should verify, got %+v", ev)
	}
	if ev.Observed != "cookie=0x0, duration=0.208s, table=0, n_packets=0, n_bytes=0, idle_age=0, priority=100,in_port=1 actions=drop" {
		t.Fatalf("evidence should quote the rule it found, got %q", ev.Observed)
	}
}

// The finding: the rule was moved to another port, so the host the fault names
// is reachable again. The old predicate answered "still in effect" using the
// other port's rule as its evidence.
func TestOVSFlowEvidenceRejectsAnotherPortsRule(t *testing.T) {
	ev := ovsFlowEvidence(table(flowDropPort2, flowNormal), 100, "1", "drop", "a drop rule on port 1")
	if ev.Verified {
		t.Fatalf("a drop rule on port 2 must not verify a fault recorded on port 1, got %+v", ev)
	}
	if !contains(ev.Observed, "in_port=2") || !contains(ev.Observed, "elsewhere") {
		t.Fatalf("evidence should say the rule sits elsewhere and name it, got %q", ev.Observed)
	}
}

// "priority=100" and "actions=drop" from two unrelated rules satisfied both
// halves of the old two-substring test while nothing on the port was dropped.
func TestOVSFlowEvidenceRejectsPriorityAndDropFromDifferentRules(t *testing.T) {
	split := table(
		` cookie=0x0, duration=1.0s, table=0, priority=100,in_port=1 actions=NORMAL`,
		` cookie=0x0, duration=1.0s, table=0, priority=50,in_port=3 actions=drop`,
		flowNormal)
	ev := ovsFlowEvidence(split, 100, "1", "drop", "a drop rule on port 1")
	if ev.Verified {
		t.Fatalf("a forward at the priority plus an unrelated drop is not a drop on the port, got %+v", ev)
	}
	if !contains(ev.Observed, "does not drop") {
		t.Fatalf("evidence should say the rule found does not drop, got %q", ev.Observed)
	}
}

// in_port=1 is a prefix of in_port=10.
func TestOVSFlowOnDoesNotMatchAPortPrefix(t *testing.T) {
	ten := ` cookie=0x0, duration=1.0s, table=0, priority=100,in_port=10 actions=drop`
	if _, _, ok := ovsFlowOn(table(ten, flowNormal), 100, "1"); ok {
		t.Fatal("a rule on port 10 must not answer for port 1")
	}
	if _, _, ok := ovsFlowOn(table(ten, flowNormal), 100, "10"); !ok {
		t.Fatal("a rule on port 10 should still answer for port 10")
	}
}

// ovs-ofctl does not promise a field order, so the parser must not depend on
// priority being printed before in_port.
func TestOVSFlowOnIgnoresFieldOrder(t *testing.T) {
	reordered := ` cookie=0x0, duration=1.0s, table=0, in_port=1,priority=100 actions=drop`
	line, actions, ok := ovsFlowOn(table(reordered), 100, "1")
	if !ok || actions != "drop" {
		t.Fatalf("field order should not matter, got ok=%v actions=%q line=%q", ok, actions, line)
	}
}

func TestOVSFlowEvidenceSaysNothingIsThere(t *testing.T) {
	ev := ovsFlowEvidence(table(flowNormal), 100, "1", "drop", "a drop rule on port 1")
	if ev.Verified {
		t.Fatalf("an empty table must not verify, got %+v", ev)
	}
	if ev.Observed != "no rule at priority=100 on port 1" {
		t.Fatalf("evidence should report the absence plainly, got %q", ev.Observed)
	}
}

// A fault whose port was never recorded cannot be checked against one.
func TestOVSFlowOnRefusesAnEmptyPort(t *testing.T) {
	if _, _, ok := ovsFlowOn(table(flowDropPort1), 100, ""); ok {
		t.Fatal("an unrecorded port must not match whatever rule comes first")
	}
}

func TestOVSFlowEvidenceLoopAction(t *testing.T) {
	ev := ovsFlowEvidence(table(flowLoopPort1, flowNormal), 200, "1", "IN_PORT", "a loop on port 1")
	if !ev.Verified {
		t.Fatalf("IN_PORT on the recorded port should verify, got %+v", ev)
	}
	moved := ovsFlowEvidence(table(flowNormal), 200, "1", "IN_PORT", "a loop on port 1")
	if moved.Verified {
		t.Fatalf("a removed loop rule must not verify, got %+v", moved)
	}
}

func TestHasActionWholeTermOnly(t *testing.T) {
	if hasAction("drop_all", "drop") {
		t.Fatal("drop must not be found inside a longer action name")
	}
	if !hasAction("in_port", "IN_PORT") {
		t.Fatal("the action name is compared without regard to case")
	}
	if !hasAction("mod_vlan_vid:10,drop", "drop") {
		t.Fatal("drop should be found among several actions")
	}
}

func TestObservedRouteDistinguishesAbsence(t *testing.T) {
	if got := observedRoute("", "0.0.0.0/1"); got != "no route for 0.0.0.0/1" {
		t.Fatalf("an empty table should read as an absence, got %q", got)
	}
	if got := observedRoute("blackhole 0.0.0.0/1 \n", "0.0.0.0/1"); got != "blackhole 0.0.0.0/1" {
		t.Fatalf("a present route should be quoted, got %q", got)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
