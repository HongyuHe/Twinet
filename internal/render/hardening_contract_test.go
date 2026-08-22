package render

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
)

// Every generated file and every renderer command write target must have a
// declared writable mount. This catches a new DNS zone, RTR state file, OVS
// database, or provider path before a no-change redeploy discovers Docker's
// read-only-rootfs rule in a live course.
func TestBundledRendererWritesHaveHardenedTargets(t *testing.T) {
	manifests, err := filepath.Glob("../../examples/*")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("no bundled manifests found")
	}
	for _, path := range manifests {
		loaded, err := manifest.Load(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := loaded.Validate().Err(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		result, err := expand.Expand(loaded.Lab)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		renderer := New(result.Topology, ModeSolve)
		for _, device := range result.Topology.SortedDevices() {
			targets, err := renderer.MutablePaths(device)
			if err != nil {
				t.Fatalf("%s: mutable paths for %s: %v", path, device.ID, err)
			}
			for _, target := range targets {
				if strings.HasPrefix(target.Path, "/proc/") ||
					strings.HasPrefix(target.Path, "/sys/") ||
					strings.HasPrefix(target.Path, "/dev/") {
					t.Errorf("%s: renderer writes sensitive path %s for %s", path, target.Path, device.ID)
				}
				if !HardenedWritableContract(device, target) {
					t.Errorf("%s: %s renderer write target %s lacks an explicit writable contract",
						path, device.ID, target.Path)
				}
			}
		}
	}
}
