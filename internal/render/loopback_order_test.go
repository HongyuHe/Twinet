package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func loadCOSRenderTopology(t *testing.T) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology
}

func TestPlatformLoopbackIsAppliedAfterFRRCommands(t *testing.T) {
	top := loadCOSRenderTopology(t)
	var router *model.Device
	for _, candidate := range top.ASes[3].Routers {
		if lo, ok := candidate.IfaceByName("lo"); ok && lo.Addr4 != "" {
			router = candidate
			break
		}
	}
	if router == nil {
		t.Fatal("COS fixture has no declared router loopback")
	}
	commands, err := New(top, ModeSolve).Commands(router)
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

func TestSolveConfiguresStudentInterfaceAddressesAfterFRR(t *testing.T) {
	top := loadCOSRenderTopology(t)
	router := top.Devices["as3/ATL"]
	if router == nil {
		t.Fatal("COS fixture has no AS3/ATL router")
	}
	solved, err := New(top, ModeSolve).Commands(router)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range solved {
		if command.Describe != "configure solved interface addresses" {
			continue
		}
		body := command.Args[len(command.Args)-1]
		if !strings.Contains(body, "ATL-L2.10") ||
			!strings.Contains(body, "ip addr replace") ||
			!strings.Contains(body, "ip -6 addr replace") {
			t.Fatalf("solved address command is incomplete:\n%s", body)
		}
		found = true
	}
	if !found {
		t.Fatal("solve mode has no explicit router interface address reconciliation")
	}
	platform, err := New(top, ModePlatform).Commands(router)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range platform {
		if command.Describe == "configure solved interface addresses" {
			t.Fatal("teaching mode overwrites student interface addresses")
		}
	}
}
