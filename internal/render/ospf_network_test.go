package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
)

func TestGeneratedClosUsesPointToPointOSPFOnRouterLinks(t *testing.T) {
	loaded, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range result.Topology.ASes[42].Routers {
		config, err := Router(result.Topology, device)
		if err != nil {
			t.Fatal(err)
		}
		want := 2
		if strings.HasPrefix(device.Name, "spine") {
			want = 3
		}
		got := strings.Count(config.Platform+config.Expected,
			" ip ospf network point-to-point\n")
		if got != want {
			t.Errorf("%s has %d point-to-point OSPF interfaces, want %d",
				device.ID, got, want)
		}
	}
}
