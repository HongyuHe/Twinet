package schema

import (
	"encoding/json"
	"sort"
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

// A schema that accepts anything is a file that looks like a guarantee and is
// not one. Two things it must reject, because they are the mistakes people
// actually make:
//
//   - a misspelled key, which otherwise validates and then silently configures
//     nothing at all;
//   - a value outside the set the field allows, which is already written on the
//     field and was simply not emitted.
func TestTheSchemaRejectsWhatTheModelWouldNotAccept(t *testing.T) {
	s := Of(model.Lab{})
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	if len(defs) == 0 {
		t.Fatal("the schema defines nothing")
	}

	var open []string
	for name, d := range defs {
		m, _ := d.(map[string]any)
		if m["type"] != "object" {
			continue
		}
		if v, ok := m["additionalProperties"]; !ok || v != false {
			open = append(open, name)
		}
	}
	if len(open) > 0 {
		sort.Strings(open)
		t.Errorf("%d object(s) accept properties they do not define: %s.\n"+
			"A misspelled key in a manifest then validates cleanly and silently "+
			"configures nothing, which is the most common mistake a schema exists "+
			"to catch.", len(open), strings.Join(open, ", "))
	}

	// Every field carrying an enum tag must carry the enum in the schema, or
	// the constraint exists in the code and not in the file people validate
	// against.
	want := map[string][]string{
		"Placement": {"strategy"},
		"Access":    {"mode"},
		"Behaviour": {"kind"},
	}
	for def, fields := range want {
		d, ok := defs[def].(map[string]any)
		if !ok {
			t.Errorf("the schema has no definition for %s", def)
			continue
		}
		props, _ := d["properties"].(map[string]any)
		for _, f := range fields {
			p, ok := props[f].(map[string]any)
			if !ok {
				t.Errorf("%s.%s is missing from the schema", def, f)
				continue
			}
			if _, ok := p["enum"]; !ok {
				t.Errorf("%s.%s allows any string, though the model restricts it to a "+
					"fixed set; a manifest naming a strategy that does not exist would "+
					"validate and then be placed by whatever the default happens to be",
					def, f)
			}
		}
	}
}
