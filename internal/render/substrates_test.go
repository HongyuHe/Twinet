package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestOpenFlowRenderingDoesNotChangeStandaloneOVS(t *testing.T) {
	legacy := loadRenderedTopology(t, "../../examples/demo")
	var standalone bool
	for _, d := range legacy.Devices {
		if d.OpenFlowController != "" || !strings.Contains(d.ID, "_S") {
			continue
		}
		cmds, err := New(legacy, ModePlatform).Commands(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, cmd := range cmds {
			if strings.Contains(strings.Join(cmd.Args, " "), "set-controller") {
				t.Fatalf("standalone OVS %s gained an OpenFlow controller command", d.ID)
			}
		}
		standalone = true
		break
	}
	if !standalone {
		t.Fatal("demo has no standalone OVS switch to test")
	}

	mixed := loadRenderedTopology(t, "../../examples/mixed-substrate")
	controllerBound := false
	for _, d := range mixed.Devices {
		if d.OpenFlowController == "" {
			continue
		}
		cmds, err := New(mixed, ModePlatform).Commands(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, cmd := range cmds {
			if strings.Contains(strings.Join(cmd.Args, " "), "set-controller") {
				controllerBound = true
			}
		}
	}
	if !controllerBound {
		t.Fatal("declared OpenFlow OVS switch did not receive a controller command")
	}
}

func loadRenderedTopology(t *testing.T, path string) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.Validate().Err(); err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology
}
