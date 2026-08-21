package manifest

import (
	"strings"
	"testing"
)

func TestUnsupportedNOSFeatureIsRefusedBeforeDeploy(t *testing.T) {
	body := strings.Replace(minimal, "A: {id: 1}", "A: {id: 1, nos: bird}", 1)
	body = strings.Replace(body, "    internal_links:", "    mpls: {enabled: true}\n    internal_links:", 1)
	loaded, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := loaded.Validate()
	if !diagnostics.HasErrors() {
		t.Fatal("BIRD MPLS request was accepted")
	}
	message := diagnostics.String()
	for _, want := range []string{"router \"A\"", "bird", "mpls"} {
		if !strings.Contains(message, want) {
			t.Fatalf("%q does not name %q", message, want)
		}
	}
}
