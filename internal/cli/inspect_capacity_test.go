package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/place"
)

func TestInspectCapacityReportsSidecarsAndPressure(t *testing.T) {
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics := loaded.Validate(); diagnostics.HasErrors() {
		t.Fatal(diagnostics.Err())
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(result.Topology, place.Options{Strict: true}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeCapacity(&out, result.Topology); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"frr-control sidecars", "PRESSURE", "110.60CPU"} {
		if !strings.Contains(text, want) {
			t.Errorf("capacity output omitted %q:\n%s", want, text)
		}
	}
}
