package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func courseTopology(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	return r.Topology
}

// A grading harness has to do two contradictory-looking things at once: build a
// correct internet around the submission, and leave the submission's own AS
// untouched. Getting this wrong is silent and expensive in both directions. If
// the neighbours are left unconfigured, a correct student is marked against
// sessions that were never going to come up. If the graded AS is solved, every
// student scores full marks for work the platform did.
func TestHarnessSolvesEveryoneExceptTheGradedAS(t *testing.T) {
	top := courseTopology(t)
	const graded = 3
	r := NewHarness(top, graded)

	var checkedGraded, checkedOther bool
	for _, d := range top.SortedDevices() {
		if d.Kind != model.KindRouter {
			continue
		}
		files, err := r.Files(d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		spec, ok := files["/etc/frr/frr.conf"]
		if !ok {
			continue
		}
		body := string(spec.Content)
		cfg, err := Router(top, d)
		if err != nil {
			t.Fatalf("%s: %v", d.ID, err)
		}
		expected := strings.TrimSpace(cfg.Expected)

		switch {
		case d.ASN == graded:
			if expected != "" && strings.Contains(body, expected) {
				t.Errorf("%s is the graded AS but was handed the reference solution", d.ID)
			}
			checkedGraded = true
		case d.ASN != 0 && expected != "":
			if !strings.Contains(body, expected) {
				t.Errorf("%s is a neighbour and should have been solved, but was left unconfigured", d.ID)
			}
			checkedOther = true
		}
	}
	if !checkedGraded || !checkedOther {
		t.Fatalf("test did not exercise both cases (graded=%v, other=%v)", checkedGraded, checkedOther)
	}
}

func TestPlainModesAreUnaffected(t *testing.T) {
	top := courseTopology(t)
	for _, mode := range []Mode{ModePlatform, ModeSolve} {
		r := New(top, mode)
		for _, d := range top.SortedDevices() {
			if got := r.modeFor(d); got != mode {
				t.Fatalf("mode %s leaked into %s as %s", mode, d.ID, got)
			}
		}
	}
}
