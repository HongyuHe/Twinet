package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/place"
)

func TestPlacementReportIncludesGeneratedLinkClasses(t *testing.T) {
	l, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	res, err := expand.Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(res.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writePlacement(&out, res.Topology); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"locality by link class:", "spine-leaf", "leaf-host"} {
		if !strings.Contains(text, want) {
			t.Errorf("placement report lacks %q:\n%s", want, text)
		}
	}
}
