package fault

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The coverage figures in the documentation are checked against the registry.
//
// They have been wrong three times. Once by counting types the plan intended to
// add rather than the ones that existed; once by leaving a paragraph saying 42
// and 40 above a table saying 47 and 45; and once by describing "the 20 gaps"
// when there were fifteen. Each survived at least one review, because a number
// in prose is exactly the kind of claim a reader takes on trust.
//
// So the document is now read by a test. A figure that drifts fails the build.
func TestTheCoverageTableMatchesTheRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../docs/10_fault_injection.md")
	if err != nil {
		t.Skipf("the fault-injection document is not here: %v", err)
	}
	doc := string(raw)

	nikaRaw, err := os.ReadFile("nika_types.json")
	if err != nil {
		t.Fatal(err)
	}
	var nika map[string]string
	if err := json.Unmarshal(nikaRaw, &nika); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for n := range nika {
		want[n] = true
	}
	have := map[string]bool{}
	for _, f := range All() {
		have[f.Name] = true
	}
	implemented, only := 0, 0
	for n := range want {
		if have[n] {
			implemented++
		}
	}
	for n := range have {
		if !want[n] {
			only++
		}
	}
	figures := map[string]int{
		"NIKA types":            len(want),
		"Implemented in Twinet": implemented,
		"Not implemented":       len(want) - implemented,
		"Twinet-only types":     only,
		"Total Twinet types":    len(have),
	}
	for label, n := range figures {
		row := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(label) +
			` \|\s*\**(\d+)\**\s*\|`)
		m := row.FindStringSubmatch(doc)
		if m == nil {
			t.Errorf("the coverage table has no row for %q", label)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Errorf("%q: %v", label, err)
			continue
		}
		if got != n {
			t.Errorf("the document says %s is %d; the registry says %d", label, got, n)
		}
	}

	// And the prose, which is where two of the three mistakes were.
	for _, claim := range []struct {
		pattern string
		want    int
	}{
		{`Twinet registers \*\*(\d+)\*\* fault types`, len(have)},
		{`\*\*(\d+) are NIKA types\*\*`, implemented},
		{`The (\d+) gaps are not scattered`, len(want) - implemented},
	} {
		m := regexp.MustCompile(claim.pattern).FindStringSubmatch(doc)
		if m == nil {
			t.Errorf("the document no longer makes the claim %q, so it cannot be checked",
				claim.pattern)
			continue
		}
		got, _ := strconv.Atoi(m[1])
		if got != claim.want {
			t.Errorf("the document says %s (%d); the registry says %d",
				strings.TrimSpace(m[0]), got, claim.want)
		}
	}
}
