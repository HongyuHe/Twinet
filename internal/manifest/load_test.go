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

// A manifest that is genuinely valid.
//
// The previous one was not: it named addressing fields and template shapes that
// do not exist, so every test that used it failed at the schema and never
// reached the thing it claimed to be checking. "A referenced template must
// exist" passed because the error text happened to contain the letter it
// searched for. A fixture that does not parse turns every test built on it into
// one that cannot fail for the right reason.
const minimal = `apiVersion: twinet.dev/v1
kind: Lab
metadata:
  name: t
addressing:
  as_block: "{{ .AS }}.0.0.0/8"
  router_router: "{{ .AS }}.0.{{ .LinkIndex }}.0/24"
  router_host: "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24"
  router_loopback: "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24"
  inter_as: "179.{{ .Low }}.{{ .High }}.0/24"
templates:
  small:
    routers:
      A: {id: 1}
      B: {id: 2}
    internal_links:
      - {a: A, b: B}
autonomous_systems:
  - list: [1]
    template: small
`

// The fixture has to actually load, or nothing built on it means anything.
func TestTheMinimalFixtureIsValid(t *testing.T) {
	l, err := Load(writeLab(t, minimal))
	if err != nil {
		t.Fatalf("the fixture every other test builds on does not load: %v", err)
	}
	// Load parses; Validate checks. A test that reads Diags without calling
	// Validate is reading a field nothing has written, and passes whatever the
	// manifest says.
	if d := l.Validate(); d.HasErrors() {
		t.Fatalf("the fixture reports errors: %v", d)
	}
}

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
	body := strings.Replace(minimal, "template: small", "template: no_such_template", 1)
	l, err := Load(writeLab(t, body))
	// The name is deliberately one that cannot appear by accident in an
	// unrelated message: the previous test searched for "t", which appears in
	// almost any Go type name, and would have passed on any error at all.
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if d := l.Validate(); d.HasErrors() {
		msg = d.String()
	} else {
		t.Fatal("a manifest naming a template that does not exist was accepted")
	}
	if !strings.Contains(msg, "no_such_template") {
		t.Errorf("the error does not name the missing template: %s", msg)
	}
}

// Diagnostics are collected rather than returned one at a time, so an author
// fixes everything in one pass instead of rerunning after each mistake.
func TestEveryProblemIsReportedAtOnce(t *testing.T) {
	l, err := Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}

	if d := l.Validate(); d.HasErrors() {
		t.Errorf("the course lab reports errors: %v", d)
	}

	// And a manifest with several independent mistakes reports all of them, so
	// an author fixes everything in one pass rather than rediscovering the next
	// one after each edit.
	body := strings.Replace(minimal, "template: small", "template: no_such_template", 1)
	body = strings.Replace(body, `inter_as: "179.{{ .Low }}.{{ .High }}.0/24"`,
		`inter_as: "this is not a prefix"`, 1)
	bad, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatalf("the manifest should load and then fail validation, not fail to parse: %v", err)
	}
	d := bad.Validate()
	if n := len(d.Errors()); n < 2 {
		t.Errorf("two independent mistakes produced %d diagnostic(s); an author would "+
			"have to rerun after each fix:\n%v", n, d)
	}
}

func TestStatePolicyDefaultsToSeparatedClusterCopies(t *testing.T) {
	body := minimal + `
placement:
  nodes:
    - {name: n0, failure_domain: rack-a, front: true}
    - {name: n1, failure_domain: rack-a}
`
	l, err := Load(writeLab(t, body))
	if err != nil {
		t.Fatal(err)
	}
	d := l.Validate()
	if !d.HasErrors() || !strings.Contains(d.String(), "failure domains") {
		t.Fatalf("cluster state policy accepted two copies in one failure domain:\n%s", d.String())
	}
	if l.Lab.State.ReplicationFactor != 2 || !l.Lab.State.FailClosedEnabled() {
		t.Fatalf("cluster durability defaults are not fail-closed two-copy state: %+v", l.Lab.State)
	}
}

func TestSingleNodeStatePolicyIsAnExplicitWarning(t *testing.T) {
	l, err := Load(writeLab(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	d := l.Validate()
	if d.HasErrors() {
		t.Fatal(d)
	}
	if l.Lab.State.ReplicationFactor != 1 {
		t.Fatalf("single node default replication factor is %d, want 1", l.Lab.State.ReplicationFactor)
	}
	if !strings.Contains(d.String(), "single-node durability") {
		t.Fatalf("single-node data-loss warning is absent:\n%s", d.String())
	}
}
