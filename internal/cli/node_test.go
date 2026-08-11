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
	if _, err := os.Stat("../../internal/cli/node.go"); err != nil {
		t.Skip("source not available")
	}
	src, err := os.ReadFile("node.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if strings.Contains(body, "func warnVersionSkew") {
		t.Error("version skew is still reported as a warning; a node rendering " +
			"different configuration from the same manifest must stop the deploy")
	}
	if !strings.Contains(body, "func checkVersionSkew") {
		t.Error("no version check refuses the deploy")
	}
	if !strings.Contains(body, "TWINET_ALLOW_VERSION_SKEW") {
		t.Error("no documented way to proceed deliberately; people will patch the " +
			"check out instead, which is worse")
	}
}
