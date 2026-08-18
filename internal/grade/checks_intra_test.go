package grade

import (
	"net/netip"
	"testing"
)

// A rule left behind by a student testing whether traffic moves between two
// ports, aimed at an address nothing in the lab has, carries no frame across.
func TestARuleNoFrameCanSatisfyIsNotACrossing(t *testing.T) {
	inv := []netip.Prefix{
		netip.MustParsePrefix("3.200.0.0/24"),
		netip.MustParsePrefix("3.200.1.0/24"),
	}
	got := flowDeliversNothing(
		" cookie=0x0, n_packets=0, priority=200,ip,nw_dst=192.168.99.99,in_port=1", inv)
	if got == "" {
		t.Fatal("a rule aimed at an address nothing has was counted as a way across")
	}
}

// But a rule aimed at a real host is a way across, however few packets it has
// carried so far. Excusing rules by their counter would pass VLANs left wide
// open just because nobody sent anything while the grader watched.
func TestARuleAimedAtARealHostIsACrossing(t *testing.T) {
	inv := []netip.Prefix{netip.MustParsePrefix("3.200.1.0/24")}
	for _, m := range []string{
		" n_packets=0, priority=200,ip,nw_dst=3.200.1.5,in_port=1",
		" n_packets=0, priority=200,ip,nw_dst=3.200.0.0/16,in_port=1",
		" n_packets=0, priority=200,in_port=1",
		" n_packets=0, priority=200,ip,nw_dst=224.0.0.1,in_port=1",
		" n_packets=0, priority=200,ip,nw_dst=nonsense,in_port=1",
	} {
		if why := flowDeliversNothing(m, inv); why != "" {
			t.Fatalf("a real way across was excused: %q -> %s", m, why)
		}
	}
}

// And nothing is excused on a bridge that can manufacture such a frame.
func TestARewritingBridgeExcusesNothing(t *testing.T) {
	if bridgeOnlyForwards([]string{" priority=1 actions=mod_nw_dst:192.168.99.99,resubmit(,0)"}) {
		t.Fatal("a bridge that rewrites destinations was treated as merely forwarding")
	}
	if !bridgeOnlyForwards([]string{" priority=0 actions=NORMAL", " priority=200 actions=output:2"}) {
		t.Fatal("a bridge that only chooses ports was treated as rewriting")
	}
}
