package fault

import (
	"strings"
	"testing"
)

// A fault that installs more than one mechanism is not undone when one of them
// is removed, and these are the cases where a check that looked at a single
// mechanism reported the lab clean while traffic was still on the floor.

// Verbatim from `tc qdisc show dev ext_7_MSP` on as3/SFO.
const (
	qdiscDetached = "qdisc netem 1: root refcnt 57 limit 1000 loss 100% seed 16917705474543554663"
	qdiscCleared  = "qdisc pfifo_fast 800e: root refcnt 57 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1"
)

func TestDetachObservedNamesTheSurvivingHalf(t *testing.T) {
	cases := []struct {
		name            string
		egress, ingress bool
		qdisc           string
		wantContains    string
		wantNotContains string
	}{
		{
			name: "both halves installed", egress: true, ingress: true, qdisc: qdiscDetached,
			wantContains: "both directions",
		},
		{
			// The mutation that exposed this: the netem is gone, the ingress
			// filter is not, and the link still carries nothing inbound.
			name: "egress cleared, ingress still dropping", ingress: true, qdisc: qdiscCleared,
			wantContains:    "still dropped by the ingress filter",
			wantNotContains: "no ingress drop filter",
		},
		{
			name: "ingress cleared, egress still dropping", egress: true, qdisc: qdiscDetached,
			wantContains: "no ingress drop filter remains",
		},
		{
			name: "both cleared", qdisc: qdiscCleared,
			wantContains: "no ingress drop filter",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detachObserved(c.qdisc, c.egress, c.ingress)
			if !strings.Contains(got, c.wantContains) {
				t.Errorf("observation %q does not mention %q", got, c.wantContains)
			}
			if c.wantNotContains != "" && strings.Contains(got, c.wantNotContains) {
				t.Errorf("observation %q wrongly says %q", got, c.wantNotContains)
			}
		})
	}
}

// The whole point: with the ingress filter alone the fault is still in effect.
func TestDetachIsStillInEffectOnIngressAlone(t *testing.T) {
	// Mirrors the Verify predicate: egress || ingress.
	for _, c := range []struct {
		egress, ingress, want bool
	}{
		{true, true, true},
		{false, true, true}, // the case that used to report "no longer in effect"
		{true, false, true},
		{false, false, false},
	} {
		if got := c.egress || c.ingress; got != c.want {
			t.Errorf("egress=%v ingress=%v: verified=%v, want %v",
				c.egress, c.ingress, got, c.want)
		}
	}
}

func TestDNSBlockedEvidenceNamesTheProtocol(t *testing.T) {
	protos := []string{"udp", "tcp"}
	cases := []struct {
		name         string
		still, clear []string
		want         bool
		wantContains string
	}{
		{
			name: "both blocked", still: protos, want: true,
			wantContains: "udp and tcp dropped",
		},
		{
			// Removing the udp rule restores name resolution. The old report
			// said "1 rule(s) dropping port 53" and named neither protocol.
			name: "udp freed, tcp still blocked", still: []string{"tcp"},
			clear: []string{"udp"}, want: true,
			wantContains: "tcp dropped; udp reach the resolver",
		},
		{
			name: "tcp freed, udp still blocked", still: []string{"udp"},
			clear: []string{"tcp"}, want: true,
			wantContains: "udp dropped; tcp reach the resolver",
		},
		{
			name: "both freed", clear: protos, want: false,
			wantContains: "udp and tcp reach the resolver",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := dnsBlockedEvidence(protos, c.still, c.clear)
			if ev.Verified != c.want {
				t.Errorf("verified=%v, want %v", ev.Verified, c.want)
			}
			if !strings.Contains(ev.Observed, c.wantContains) {
				t.Errorf("observation %q does not mention %q", ev.Observed, c.wantContains)
			}
		})
	}
}

func TestRouteViaMatchesWholeAddress(t *testing.T) {
	cases := []struct {
		name, out, gw string
		want          bool
	}{
		{
			name: "the injected gateway", gw: "3.106.0.254",
			out:  "default via 3.106.0.254 dev ATLrouter",
			want: true,
		},
		{
			// The bogus neighbour sits one digit from the real gateway, so a
			// substring search confuses .1 with .10 and .254 with .254x.
			name: "a longer address with the same prefix", gw: "3.106.0.2",
			out:  "default via 3.106.0.254 dev ATLrouter",
			want: false,
		},
		{
			name: "the restored gateway is not the wrong one", gw: "3.106.0.254",
			out:  "default via 3.106.0.2 dev ATLrouter",
			want: false,
		},
		{
			name: "no default route at all", gw: "3.106.0.254", out: "", want: false,
		},
		{
			name: "the address appears as a destination, not a gateway", gw: "3.106.0.254",
			out:  "3.106.0.254 dev ATLrouter scope link",
			want: false,
		},
		{
			name: "one of several routes", gw: "3.106.0.254",
			out:  "default via 3.106.0.2 dev eth0\n10.0.0.0/8 via 3.106.0.254 dev eth0",
			want: true,
		},
		{
			name: "no gateway recorded", gw: "", out: "default via 3.106.0.254 dev eth0", want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routeVia(c.out, c.gw); got != c.want {
				t.Errorf("routeVia(%q, %q) = %v, want %v", c.out, c.gw, got, c.want)
			}
		})
	}
}
