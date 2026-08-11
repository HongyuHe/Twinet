package fault

import (
	"strings"
	"testing"
)

// A resolve is not finished when the fault's predicate goes false. It is
// finished when the device is as the injection found it.
//
// The difference is not academic. A fault that pointed a host's default route
// at a dead neighbour resolved by deleting the default route; where no baseline
// had been recorded it put nothing back. Its verifier asked "is the route via
// the wrong gateway?", the answer was no, and the resolve reported success --
// while the host was left with no default route at all. That damage surfaced
// days later as a single unreachable host in a grading run, with nothing left
// to connect it to the fault that caused it.
func TestARemovedBaselineLineIsReportedAsNotPutBack(t *testing.T) {
	before := "default via 5.105.0.2 dev CHIrouter\n5.105.0.0/24 dev CHIrouter scope link"
	after := "default via 5.105.0.9 dev CHIrouter\n5.105.0.0/24 dev CHIrouter scope link"
	added, removed := delta(before, after)

	// The demolition: the wrong route is gone and nothing replaced it.
	demolished := "5.105.0.0/24 dev CHIrouter scope link"
	r := residue(added, removed, demolished)
	if r == "" {
		t.Fatal("a resolve that deleted the host's default route and put nothing back " +
			"was reported as clean")
	}
	if !strings.Contains(r, "not put back") || !strings.Contains(r, "5.105.0.2") {
		t.Errorf("the report does not say what was lost: %q", r)
	}

	// The correct undo.
	if r := residue(added, removed, before); r != "" {
		t.Errorf("a correct undo was reported as leaving residue: %q", r)
	}
}

// Injecting two faults on one device must not make either look contaminated by
// the other. Each injection is answerable for its own delta and nothing else.
func TestConcurrentFaultsDoNotAccuseEachOther(t *testing.T) {
	clean := "-A INPUT -p icmp -j DROP"
	// The first fault adds an ICMP rule.
	a1, r1 := delta("", clean)
	// The second is injected while the first is still active, and adds OSPF.
	both := clean + "\n-A INPUT -p ospf -j DROP"
	a2, r2 := delta(clean, both)

	// Resolving the second leaves the first in place. That is not its residue.
	if got := residue(a2, r2, clean); got != "" {
		t.Errorf("resolving the second fault blamed itself for the first: %q", got)
	}
	// Resolving the first afterwards leaves nothing.
	if got := residue(a1, r1, ""); got != "" {
		t.Errorf("a fully undone fault was reported as leaving residue: %q", got)
	}
	// But a resolve that did nothing is still caught.
	if got := residue(a1, r1, clean); got == "" {
		t.Error("a resolve that left its own rule in place was reported as clean")
	}
}

// iptables-save prints the table header, chain policies and COMMIT the moment
// any rule exists. Counting those as state a fault left behind would make every
// packet-filter fault permanently unresolvable after the first use.
func TestFingerprintIgnoresPacketFilterScaffolding(t *testing.T) {
	if strings.Contains(fingerprintScript(), "grep -v '^#'") {
		t.Error("the fingerprint still keeps iptables-save's structural lines")
	}
	if !strings.Contains(fingerprintScript(), `grep '^-A'`) {
		t.Error("the fingerprint does not restrict itself to actual filter rules")
	}
}
