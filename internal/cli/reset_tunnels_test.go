package cli

import (
	"regexp"
	"strings"
	"testing"
)

// The kernel creates one tunnel device per encapsulation module and refuses to
// delete it: `ip tunnel del gre0` answers "Operation not permitted". Only sit0
// was excluded, so on any router where the gre module had been loaded -- every
// router in a course that teaches tunnelling -- the reset could not remove
// gre0, the read-back counted it as the previous submission's work, and every
// submission in the class run was quarantined. A whole class receives no marks.
func TestKernelFallbackTunnelsAreNotStudentWork(t *testing.T) {
	re := regexp.MustCompile(fallbackTunnelPattern())

	for _, name := range []string{"sit0", "gre0", "gretap0", "erspan0", "tunl0", "ip6tnl0"} {
		line := name + ": gre/ip remote any local any ttl inherit"
		if !re.MatchString(line) {
			t.Errorf("%s would be reported as a student's leftover tunnel, and it cannot be deleted", name)
		}
		if !strings.Contains(fallbackTunnelCases(), name+":*") {
			t.Errorf("the reset would try to delete %s, which always fails", name)
		}
	}
}

// The exclusion must not become a hiding place: a tunnel somebody created is
// still the previous submission's work, and grading the next student on it is
// what the read-back exists to prevent.
func TestARealTunnelIsStillReportedAsLeftover(t *testing.T) {
	re := regexp.MustCompile(fallbackTunnelPattern())

	for _, line := range []string{
		"tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64",
		"gre1: gre/ip remote 3.0.0.2 local 3.0.0.1 ttl inherit",
		"gre10: gre/ip remote 4.0.0.2 local 4.0.0.1 ttl inherit",
		"sit01: ipv6/ip remote 5.0.0.2 local 5.0.0.1 ttl 64",
	} {
		if re.MatchString(line) {
			t.Errorf("a tunnel somebody created would be ignored by the reset check: %s", line)
		}
	}
}
