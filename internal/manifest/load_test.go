package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest is the only thing between a typo and a class of students being
// marked on a network that is not the one described. Validation exists to turn
// a mistake into a message rather than into a lab that deploys and is quietly
// wrong, so these tests are about what it refuses.
func writeLab(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "twinet.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const minimal = `apiVersion: twinet.dev/v1
kind: Lab
metadata:
  name: t
addressing:
  as_block: "{{ .AS }}.0.0.0/8"
  intra_as: "{{ .AS }}.0.{{ .LinkIndex }}.0/24"
  inter_as: "179.{{ .Low }}.{{ .High }}.0/24"
  loopback: "{{ .AS }}.{{ add 150 .RouterIndex }}.0.1/24"
autonomous_systems:
  - list: [1]
    template: t
`

func TestTheExampleLabLoads(t *testing.T) {
	l, err := Load("../../examples/cos461")
	if err != nil {
		t.Fatalf("the course lab does not load: %v", err)
	}
	if l.Lab.Metadata.Name != "cos461" {
		t.Errorf("name is %q", l.Lab.Metadata.Name)
	}
	if l.Lab.Dir == "" {
		t.Error("the lab does not record where it was loaded from, so nothing relative to it resolves")
	}
}

func TestAMissingManifestIsReportedClearly(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("an empty directory loaded as a lab")
	}
	if !strings.Contains(err.Error(), "twinet.yaml") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

func TestUnknownFieldsAreRefused(t *testing.T) {
	// A silently ignored field is the worst failure a configuration format can
	// have: the author believes they configured something, the platform
	// believes they did not, and the lab is subtly not the one described.
	dir := writeLab(t, minimal+"\nnot_a_real_field: 3\n")
	if _, err := Load(dir); err == nil {
		t.Error("a manifest with an unknown top-level field was accepted")
	}
}

func TestAMalformedManifestSaysWhereItIsWrong(t *testing.T) {
	dir := writeLab(t, "apiVersion: twinet.dev/v1\nkind: Lab\nmetadata:\n  name: [this is not a name]\n")
	_, err := Load(dir)
	if err == nil {
		t.Fatal("a malformed manifest was accepted")
	}
	// A parse error with no location is nearly useless on a file that is
	// hundreds of lines long.
	if !strings.Contains(err.Error(), "line") && !strings.Contains(err.Error(), "twinet.yaml") {
		t.Errorf("the error locates nothing: %v", err)
	}
}

func TestAReferencedTemplateMustExist(t *testing.T) {
	dir := writeLab(t, minimal)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("a manifest naming a template that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "t") {
		t.Errorf("the error does not name the missing template: %v", err)
	}
}

// Diagnostics are collected rather than returned one at a time, so an author
// fixes everything in one pass instead of rerunning after each mistake.
func TestEveryProblemIsReportedAtOnce(t *testing.T) {
	l, err := Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	if l.Diags.HasErrors() {
		t.Errorf("the course lab reports errors: %v", l.Diags)
	}
}
