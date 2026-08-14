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

// Rebalancing moves autonomous systems between machines, and pruning is what
// removes them from the machine they left. A scope switches pruning off, so
// asking for both is asking for a move whose old copy keeps running and keeps
// announcing the same prefix -- and both halves look correct, which is why
// nobody would think to look.
func TestRebalanceAndOnlyAreRefusedTogether(t *testing.T) {
	root := Root()
	root.SetArgs([]string{"deploy", "-m", "../../examples/cos461", "--rebalance", "--only", "as=3"})
	var out strings.Builder
	root.SetOut(&out)
	root.SetErr(&out)
	err := root.Execute()
	if err == nil {
		t.Fatal("a rebalance scoped to one system was accepted, so the moved system runs " +
			"on two machines at once and announces its prefix from both")
	}
	if !strings.Contains(err.Error(), "both places") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// Destroying a grading harness by name uses the class manifest to say which
// machines to reach. Deleting the placement record then deletes the *class's*
// record: the next deployment places a running lab again from scratch,
// `inspect --placement` disagrees with what is actually running, and exec
// answers 404 from the wrong nodes. Observed on this cluster.
func TestDestroyingAHarnessKeepsTheClassPlacementRecord(t *testing.T) {
	src, err := os.ReadFile("deploy.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "os.Remove(filepath.Join(labPrivateDir(top), place.RecordName))")
	if i < 0 {
		t.Fatal("the placement record is never removed, so a destroyed lab stays pinned")
	}
	before := body[:i]
	if !strings.Contains(before[strings.LastIndex(before, "RunE:"):], "name != top.Name") {
		t.Error("the placement record is removed whatever lab was destroyed, so cleaning up " +
			"a grading harness deletes the class's own record")
	}
}
