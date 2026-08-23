package render

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestPlatformLoopbackIsAppliedAfterFRRCommands(t *testing.T) {
	loaded, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	var router *model.Device
	for _, candidate := range result.Topology.ASes[3].Routers {
		if lo, ok := candidate.IfaceByName("lo"); ok && lo.Addr4 != "" {
			router = candidate
			break
		}
	}
	if router == nil {
		t.Fatal("COS fixture has no declared router loopback")
	}
	commands, err := New(result.Topology, ModeSolve).Commands(router)
	if err != nil {
		t.Fatal(err)
	}
	loopback, lastFRR := -1, -1
	for i, command := range commands {
		if command.FRRControl {
			lastFRR = i
		}
		if command.Describe == "configure loopback" {
			loopback = i
		}
	}
	if loopback < 0 || lastFRR < 0 || loopback <= lastFRR {
		t.Fatalf("loopback command index %d, last FRR command index %d", loopback, lastFRR)
	}
}
