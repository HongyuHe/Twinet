package schema

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A schema nobody checks is worse than no schema, because the documentation
// then claims something that is not true. These tests check it describes the
// manifest the loader actually accepts.
func TestTheSchemaDescribesTheManifest(t *testing.T) {
	raw, err := JSON(model.Lab{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the generated schema is not valid JSON: %v", err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	if len(defs) < 10 {
		t.Fatalf("only %d types were emitted; the walk is not reaching the manifest",
			len(defs))
	}

	lab, ok := defs["Lab"].(map[string]any)
	if !ok {
		t.Fatal("no Lab definition")
	}
	props, _ := lab["properties"].(map[string]any)
	// The top-level keys every manifest has to have. Named individually so a
	// refactor that drops one fails here rather than producing a schema that
	// silently permits less.
	for _, key := range []string{"apiVersion", "kind", "metadata", "addressing"} {
		if _, ok := props[key]; !ok {
			t.Errorf("the schema has no %q at the top level, so an editor would "+
				"mark a correct manifest as wrong", key)
		}
	}
}

// The names in the schema must be the names the YAML decoder expects. Emitting
// Go field names would produce a schema that rejects every real manifest while
// looking entirely plausible.
func TestTheSchemaUsesTheNamesTheDecoderUses(t *testing.T) {
	raw, _ := JSON(model.Lab{})
	body := string(raw)
	for _, want := range []string{
		`"router_loopback"`, `"link_defaults"`, `"apiVersion"`, `"autonomous_systems"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the schema does not mention %s; it is emitting Go field names "+
				"rather than manifest keys, so it would reject every real lab", want)
		}
	}
	// And must not contain the Go spelling of a field that is renamed in YAML.
	if strings.Contains(body, `"RouterLoopback"`) {
		t.Error("the schema contains a Go field name")
	}
}

// Recursive types must not make the generator loop for ever.
func TestTheGeneratorTerminatesOnRecursiveTypes(t *testing.T) {
	type node struct {
		Name  string  `yaml:"name"`
		Child *node   `yaml:"child,omitempty"`
		More  []*node `yaml:"more,omitempty"`
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Of(node{})
	}()
	select {
	case <-done:
	default:
		// Give it a moment; a genuine infinite loop never returns.
		<-done
	}
}

// Required is driven by the struct tags, and must not be produced for a field
// the decoder treats as optional -- an editor marking valid manifests invalid
// is how people turn the schema off.
func TestOptionalFieldsAreNotRequired(t *testing.T) {
	type spec struct {
		Must string `yaml:"must" jsonschema:"required"`
		May  string `yaml:"may,omitempty" jsonschema:"required"`
		Also string `yaml:"also,omitempty"`
	}
	s := Of(spec{})
	def := s.Defs["spec"]
	if def == nil {
		t.Fatal("no definition emitted")
	}
	req := strings.Join(def.Required, ",")
	if !strings.Contains(req, "must") {
		t.Error("a required field is not marked required")
	}
	if strings.Contains(req, "may") {
		t.Error(`a field tagged omitempty was marked required; the decoder accepts ` +
			`a manifest without it, so an editor would report a correct lab as broken`)
	}
	if strings.Contains(req, "also") {
		t.Error("an untagged field was marked required")
	}
}
