package ipam

import (
	"net/netip"
	"testing"
)

func TestCompileAndEval(t *testing.T) {
	p, err := Compile(map[string]string{
		FieldASBlock:        `{{ .AS }}.0.0.0/8`,
		FieldRouterLoopback: `{{ .AS }}.{{ add 150 .RouterID }}.0.1/24`,
		FieldRouterRouter:   `{{ .AS }}.0.{{ add 1 .LinkIndex }}.0/24`,
		FieldRouterHost:     `{{ .AS }}.{{ add 100 .RouterID }}.0.0/24`,
		FieldInterAS:        `{{ cidrSubnet "179.0.0.0/8" .LinkIndex 24 }}`,
		FieldIXPPeering:     `180.{{ .IXP }}.0.0/24`,
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	tests := []struct {
		field string
		ctx   Ctx
		want  string
	}{
		{FieldASBlock, Ctx{AS: 12}, "12.0.0.0/8"},
		{FieldRouterLoopback, Ctx{AS: 12, RouterID: 6}, "12.156.0.1/24"},
		{FieldRouterRouter, Ctx{AS: 3, LinkIndex: 2}, "3.0.3.0/24"},
		{FieldRouterHost, Ctx{AS: 85, RouterID: 5}, "85.105.0.0/24"},
		{FieldInterAS, Ctx{LinkIndex: 42}, "179.0.42.0/24"},
		{FieldInterAS, Ctx{LinkIndex: 300}, "179.1.44.0/24"},
		{FieldIXPPeering, Ctx{IXP: 142}, "180.142.0.0/24"},
	}
	for _, tc := range tests {
		got, err := p.Eval(tc.field, tc.ctx)
		if err != nil {
			t.Errorf("%s: %v", tc.field, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s%+v = %q, want %q", tc.field, tc.ctx, got, tc.want)
		}
	}
}

// The addressing plan must reproduce the values the COS-461 assignment text
// tells students to configure. If this test ever fails, the platform and the
// assignment have diverged, which is exactly the failure the legacy platform
// suffered by restating the plan in four places.
func TestMatchesCOS461AssignmentText(t *testing.T) {
	p, err := Compile(map[string]string{
		FieldRouterLoopback: `{{ .AS }}.{{ add 150 .RouterID }}.0.1/24`,
		FieldRouterHost:     `{{ .AS }}.{{ add 100 .RouterID }}.0.0/24`,
	})
	if err != nil {
		t.Fatal(err)
	}
	// "the loopback address of the router MSP for group 10 is 10.151.0.1/24"
	// MSP has router ID 1.
	if got, _ := p.Eval(FieldRouterLoopback, Ctx{AS: 10, RouterID: 1}); got != "10.151.0.1/24" {
		t.Errorf("MSP loopback for group 10 = %q, want 10.151.0.1/24", got)
	}
	// "the subnet used for group 85 between the CHI router and the
	// corresponding host is 85.105.0.0/24" - CHI has router ID 5.
	if got, _ := p.Eval(FieldRouterHost, Ctx{AS: 85, RouterID: 5}); got != "85.105.0.0/24" {
		t.Errorf("CHI host subnet for group 85 = %q, want 85.105.0.0/24", got)
	}
}

func TestEvalErrors(t *testing.T) {
	if _, err := Compile(map[string]string{"bad": `{{ nosuchfunc }}`}); err == nil {
		t.Fatal("expected compile error for unknown function")
	}
	p, err := Compile(map[string]string{"x": `{{ cidrSubnet "not-a-prefix" 1 24 }}`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Eval("x", Ctx{}); err == nil {
		t.Fatal("expected eval error for malformed base prefix")
	}
	if _, err := p.Eval("missing", Ctx{}); err == nil {
		t.Fatal("expected error for undefined field")
	}
}

func TestCidrHelpers(t *testing.T) {
	if got, err := cidrSubnet("179.0.0.0/8", 0, 24); err != nil || got != "179.0.0.0/24" {
		t.Errorf("cidrSubnet 0 = %q, %v", got, err)
	}
	if _, err := cidrSubnet("179.0.0.0/8", 1<<16, 24); err == nil {
		t.Error("expected out-of-range error")
	}
	if got, err := cidrHost("10.0.1.0/24", 1); err != nil || got != "10.0.1.1/24" {
		t.Errorf("cidrHost = %q, %v", got, err)
	}
	if _, err := cidrHost("10.0.1.0/24", 256); err == nil {
		t.Error("expected does-not-fit error")
	}
	if got, err := cidrNetwork("10.0.1.7/24"); err != nil || got != "10.0.1.0/24" {
		t.Errorf("cidrNetwork = %q, %v", got, err)
	}
}

func TestRegistryConflicts(t *testing.T) {
	r := NewRegistry()
	agg := netip.MustParsePrefix("12.0.0.0/8")
	r.Exempt(agg)
	r.Claim(agg, "as12 aggregate", FieldASBlock)
	r.Claim(netip.MustParsePrefix("12.0.1.0/24"), "as12 link a", FieldRouterRouter)
	r.Claim(netip.MustParsePrefix("12.0.2.0/24"), "as12 link b", FieldRouterRouter)
	if c := r.Conflicts(); len(c) != 0 {
		t.Fatalf("unexpected conflicts under an exempt aggregate: %v", c)
	}

	r2 := NewRegistry()
	r2.Claim(netip.MustParsePrefix("10.0.1.0/24"), "link a", FieldRouterRouter)
	r2.Claim(netip.MustParsePrefix("10.0.1.128/25"), "link b", FieldRouterRouter)
	c := r2.Conflicts()
	if len(c) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(c), c)
	}
	if c[0].String() == "" {
		t.Error("conflict should render")
	}
}

func TestRegistryNoFalsePositives(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 500; i++ {
		p, err := cidrSubnet("179.0.0.0/8", i, 24)
		if err != nil {
			t.Fatal(err)
		}
		r.Claim(netip.MustParsePrefix(p), "link", FieldInterAS)
	}
	if c := r.Conflicts(); len(c) != 0 {
		t.Fatalf("disjoint subnets reported as conflicting: %v", c[:min(3, len(c))])
	}
}

func TestLastAddr(t *testing.T) {
	cases := map[string]string{
		"10.0.1.0/24":   "10.0.1.255",
		"10.0.0.0/8":    "10.255.255.255",
		"10.0.1.5/32":   "10.0.1.5",
		"2001:db8::/32": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for in, want := range cases {
		got := lastAddr(netip.MustParsePrefix(in))
		if got.String() != want {
			t.Errorf("lastAddr(%s) = %s, want %s", in, got, want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
