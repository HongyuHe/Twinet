package fault

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A benchmark that measures how well an agent diagnoses a fault must not leave
// the answer inside the container it is diagnosing. A file called
// /run/twinet_flap_eth0.pid names the framework, the fault and the interface;
// anything with a shell can read the solution off the disk, and every score
// collected that way is meaningless.
//
// Bookkeeping therefore lives in the injection record the controller keeps.
// This test reads the fault sources and fails if any of them writes a
// self-identifying marker into a device.
func TestFaultsLeaveNoMarkersInsideTheContainer(t *testing.T) {
	files, err := filepath.Glob("faults*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no fault sources were found, so this test proves nothing")
	}
	// Any literal path that names the framework is a giveaway regardless of
	// which directory it lands in.
	marker := regexp.MustCompile(`"[^"]*/(?:run|tmp|var)/[^"]*twinet[^"]*"`)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if m := marker.FindString(line); m != "" {
				t.Errorf("%s:%d writes %s into the device under test, "+
					"which tells the agent both that a fault was injected and which one", f, i+1, m)
			}
		}
	}
}

// A fault must not be identifiable by a constant that appears in this
// repository. An agent being benchmarked can reasonably be assumed to have read
// the source; if the marker is the same on every injection, it can list the
// switch's flows, find the one carrying the known value, and read the answer off
// it without diagnosing anything.
func TestFaultMarkersAreNotConstant(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		c, err := randomCookie()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c] {
			t.Fatalf("randomCookie repeated %s within %d draws; the same marker on two "+
				"injections is a tell across episodes", c, i+1)
		}
		seen[c] = true
		if len(c) < 10 {
			t.Errorf("marker %q is short enough to stand out among real cookies", c)
		}
	}
	// And the constant it replaced must be gone.
	files, _ := filepath.Glob("faults*.go")
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "0x7714e7") {
			t.Errorf("%s still carries the fixed cookie that gave the fault away", f)
		}
	}
}
