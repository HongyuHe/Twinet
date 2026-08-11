package cli

import (
	"os"
	"strings"
	"testing"
)

// A version warning was the wrong shape for this failure.
//
// The node agent renders the device configuration, so a node on an older build
// produces different configuration from the same manifest -- and reports
// success while doing it. The deploy converges, the manifest is right, the
// controller's tests pass, and the routers are configured differently from what
// anybody asked for. That happened during the MPLS work: the controller emitted
// a route distinguisher and every router came up without one, because the
// agents were four commits behind.
//
// A warning scrolls past in ordinary output and nothing downstream changes
// behaviour, so the person reading it has no reason to believe the result is
// invalid. Refusing is the only response that cannot be missed.
func TestAVersionMismatchRefusesRatherThanWarns(t *testing.T) {
	// The behaviour is tested where it lives, in
	// client.TestApplyRefusesAClusterOfMixedBuilds: a node reporting a
	// different build causes Apply to refuse rather than warn.
	//
	// What is checked here is that the deploy path still asks before doing any
	// other work, so the operator is told at the start rather than after the
	// underlay has been built.
	src, err := os.ReadFile("node.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, "checkVersionSkew(ctx, c)") {
		t.Error("the deploy path no longer checks for mixed builds before it starts; " +
			"Apply will still refuse, but only after the underlay has been built")
	}
	if strings.Contains(body, "func warnVersionSkew") {
		t.Error("version skew is reported as a warning again")
	}
}
