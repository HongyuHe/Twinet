package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRefreshingAReleaseLockUsesAuthoredImageReferences(t *testing.T) {
	manifest := filepath.Join(documentationRepoRoot(t), "examples", "mixed-substrate")
	authored, err := loadExpanded(&Options{Manifest: manifest}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range topologyImageRefs(authored) {
		if strings.Contains(ref, "@sha256:") {
			t.Fatalf("unlocked topology already contains the previous lock value %q", ref)
		}
	}

	applied, err := loadExpanded(&Options{Manifest: manifest}, true)
	if err != nil {
		t.Fatal(err)
	}
	foundDigest := false
	for _, ref := range topologyImageRefs(applied) {
		foundDigest = foundDigest || strings.Contains(ref, "@sha256:")
	}
	if !foundDigest {
		t.Fatal("test fixture did not apply its existing release lock")
	}
}
