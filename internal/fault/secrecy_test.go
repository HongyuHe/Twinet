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
	// Every source in the package, not only the ones named faults*.go.
	//
	// This used to glob faults*.go, and the leak it was written to prevent was
	// then added in a file called injected_marker.go: a path under /etc holding
	// the name of the injected fault, written into the device under test. An
	// agent being evaluated on root-cause analysis could read the answer with
	// `cat`. Both halves of the test were too narrow -- the file list and the
	// pattern, which did not cover /etc.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no fault sources were found, so this test proves nothing")
	}
	var sources []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			sources = append(sources, f)
		}
	}
	files = sources
	if len(files) < 3 {
		t.Fatalf("only %d source file(s) were scanned, which is too few to be the "+
			"whole package; this test would miss a leak in the rest", len(files))
	}
	// Any literal path that names the framework is a giveaway regardless of
	// which directory it lands in.
	marker := regexp.MustCompile(`"[^"]*/(?:run|tmp|var|etc|opt|srv|usr)/[^"]*twinet[^"]*"`)
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

// A fault must not be identifiable by anything it writes into the device.
//
// An agent being benchmarked can reasonably be assumed to have read this source.
// The switches in this lab carry exactly one flow -- "cookie=0x0, priority=0,
// actions=NORMAL" -- so a rule with a non-zero cookie, or a priority in the
// tens of thousands, can be picked out of a flow dump instantly and the fault
// read off it without diagnosing anything.
//
// A fault should look like the misconfiguration it is imitating.
func TestFlowRulesDoNotAdvertiseThemselves(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	tells := []struct {
		pattern *regexp.Regexp
		why     string
	}{
		{regexp.MustCompile(`cookie=(?:0x)?[1-9a-fA-F]`),
			"a non-zero flow cookie, which nothing else in these labs sets"},
		{regexp.MustCompile(`priority=[1-9][0-9]{4,}`),
			"a priority far outside anything a person would write by hand"},
		{regexp.MustCompile(`--comment\s`),
			"a firewall rule comment, which marks the injected rule as not the student's"},
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, tell := range tells {
				if m := tell.pattern.FindString(line); m != "" {
					t.Errorf("%s:%d writes %q into the device under test: %s",
						f, i+1, m, tell.why)
				}
			}
		}
	}

	// And the constant that started all this must still be gone. Assembled
	// rather than written out, so this test does not trip over itself.
	gone := "0x" + "7714e7"
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), gone) {
			t.Errorf("%s still carries the fixed cookie that gave the fault away", f)
		}
	}
}
