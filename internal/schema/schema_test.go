package schema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/HongyuHe/twinet/internal/manifest"
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

// A misspelled device kind is the mistake the reviewer led with: kinds.routr
// decodes into the map under that key, no code ever looks it up, and the lab
// silently drops those defaults. KnownFields on the decoder does not catch it,
// because it is a map key and not a struct field. The schema is the only thing
// that can.
func TestAMisspelledDeviceKindKeyIsRejected(t *testing.T) {
	root := Of(model.Lab{})
	base := `
apiVersion: twinet.dev/v1
kind: Lab
metadata: {name: t}
addressing: {as_block: x, router_loopback: x, router_router: x, router_host: x, inter_as: x}
autonomous_systems: [{list: [1]}]
`
	if errs := schemaErrors(decodeYAMLString(t, base), root, root.Defs, ""); len(errs) != 0 {
		t.Fatalf("the base manifest should validate; a later assertion is only "+
			"meaningful if the single change is what breaks it. Got: %v", errs)
	}
	bad := base + "kinds: {routr: {image: x}}\n"
	errs := schemaErrors(decodeYAMLString(t, bad), root, root.Defs, "")
	if len(errs) == 0 {
		t.Fatal("kinds.routr validated cleanly; a misspelled device kind decodes " +
			"into a map entry nothing reads and then configures nothing at all")
	}
	if !anyContains(errs, "routr") {
		t.Errorf("the rejection should name the offending key; got: %v", errs)
	}
}

// A wrong header is the other silent pass: the document decodes into a Lab even
// though it does not claim to be one, so nothing downstream objects. apiVersion
// and kind are fixed strings, and the schema has to say so.
func TestAWrongApiVersionOrKindIsRejected(t *testing.T) {
	root := Of(model.Lab{})
	doc := `
apiVersion: acme.example/v9
kind: NotALab
metadata: {name: t}
addressing: {as_block: x, router_loopback: x, router_router: x, router_host: x, inter_as: x}
autonomous_systems: [{list: [1]}]
`
	errs := schemaErrors(decodeYAMLString(t, doc), root, root.Defs, "")
	if !anyContains(errs, "acme.example/v9") {
		t.Errorf("a wrong apiVersion validated; got: %v", errs)
	}
	if !anyContains(errs, "NotALab") {
		t.Errorf("a wrong kind validated; got: %v", errs)
	}
}

// The loader accepts internal_links written as the compact [A, B] pair as well
// as the mapping form. A schema that rejects the documented compact form is one
// people learn to switch off, so it must accept exactly what the loader does.
func TestTheCompactLinkFormIsAccepted(t *testing.T) {
	root := Of(model.Lab{})
	inlined := `
apiVersion: twinet.dev/v1
kind: Lab
metadata: {name: t}
addressing: {as_block: x, router_loopback: x, router_router: x, router_host: x, inter_as: x}
autonomous_systems: [{list: [1]}]
templates:
  t:
    routers: {R1: {id: 1}, R2: {id: 2}}
    internal_links:
      - [R1, R2]
      - {a: R1, b: R2, delay: 25ms}
`
	if errs := schemaErrors(decodeYAMLString(t, inlined), root, root.Defs, ""); len(errs) != 0 {
		t.Fatalf("the documented compact link form was rejected: %v", errs)
	}
	// And the same form in a standalone template, validated the way CI does.
	tpl := `
apiVersion: twinet.dev/v1
kind: ASTemplate
metadata: {name: t}
routers: {S1: {id: 1}, S2: {id: 2}}
internal_links:
  - [S1, S2]
`
	if errs := schemaErrors(decodeYAMLString(t, tpl), root.Defs["ASTemplate"], root.Defs, ""); len(errs) != 0 {
		t.Fatalf("a template using the compact link form was rejected: %v", errs)
	}
}

// A named string type whose members are a closed set -- an ASRole, a
// Relationship, a DeviceKind used as a value rather than a map key -- is the
// same silent pass as a misspelled kind: the wrong value decodes and is then
// resolved against nothing. The set is written on the type; the schema has to
// emit it.
func TestAValueOutsideAClosedSetIsRejected(t *testing.T) {
	root := Of(model.Lab{})
	doc := `
apiVersion: twinet.dev/v1
kind: Lab
metadata: {name: t}
addressing: {as_block: x, router_loopback: x, router_router: x, router_host: x, inter_as: x}
autonomous_systems: [{list: [1], role: intern}]
`
	errs := schemaErrors(decodeYAMLString(t, doc), root, root.Defs, "")
	if !anyContains(errs, "intern") {
		t.Errorf("role: intern validated, though the model allows only "+
			"student, staff and ixp; got: %v", errs)
	}
}

// The property that matters most: anything the loader accepts, the schema must
// accept. It runs the real loader and the schema over every example manifest
// and every AS template the project ships, so a schema change that starts
// rejecting a real lab -- the compact link, a header const that is too narrow,
// a map wrongly closed -- fails here rather than in a course author's editor.
func TestEveryExampleTheLoaderAcceptsAlsoValidatesAgainstTheSchema(t *testing.T) {
	root := Of(model.Lab{})
	manifests, err := filepath.Glob("../../examples/*/twinet.yaml")
	if err != nil || len(manifests) == 0 {
		t.Fatalf("no example manifests found (glob err %v)", err)
	}
	for _, mpath := range manifests {
		dir := filepath.Dir(mpath)
		if _, err := manifest.Load(dir); err != nil {
			t.Errorf("%s: the loader rejected a shipped example: %v", dir, err)
			continue
		}
		if errs := schemaErrors(decodeYAMLFile(t, mpath), root, root.Defs, ""); len(errs) != 0 {
			t.Errorf("%s: the loader accepts it but the schema rejects it:\n  %s",
				mpath, strings.Join(errs, "\n  "))
		}
		tpls, _ := filepath.Glob(filepath.Join(dir, "templates", "*.yaml"))
		for _, tp := range tpls {
			if errs := schemaErrors(decodeYAMLFile(t, tp), root.Defs["ASTemplate"], root.Defs, ""); len(errs) != 0 {
				t.Errorf("%s: the loader accepts it but the schema rejects it:\n  %s",
					tp, strings.Join(errs, "\n  "))
			}
		}
	}
}

// schemaErrors validates a decoded YAML document against a schema this package
// produced. The module carries no JSON-Schema library by design, so this
// implements exactly the subset the generator emits -- $ref, type, enum, oneOf,
// properties/required/additionalProperties, items, propertyNames and the array
// bounds -- and nothing more. It is enough to answer "does the schema accept
// this?" for real manifests and for the mistakes the tests above construct.
func schemaErrors(doc any, s *Schema, defs map[string]*Schema, path string) []string {
	if s == nil || doc == nil {
		return nil
	}
	if s.Ref != "" {
		return schemaErrors(doc, defs[strings.TrimPrefix(s.Ref, "#/$defs/")], defs, path)
	}
	if len(s.OneOf) > 0 {
		matched := 0
		for _, sub := range s.OneOf {
			if len(schemaErrors(doc, sub, defs, path)) == 0 {
				matched++
			}
		}
		if matched != 1 {
			return []string{fmt.Sprintf("%s: matched %d of %d oneOf branches",
				at(path), matched, len(s.OneOf))}
		}
		return nil
	}
	if len(s.Enum) > 0 {
		sv, ok := doc.(string)
		if !ok || !enumHas(s.Enum, sv) {
			return []string{fmt.Sprintf("%s: %v is not one of %v", at(path), doc, s.Enum)}
		}
	}
	var errs []string
	switch s.Type {
	case "object":
		m, ok := doc.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: expected object, got %T", at(path), doc)}
		}
		if s.PropertyNames != nil {
			for k := range m {
				errs = append(errs, schemaErrors(k, s.PropertyNames, defs, path+"."+k)...)
			}
		}
		for _, r := range s.Required {
			if _, ok := m[r]; !ok {
				errs = append(errs, fmt.Sprintf("%s: missing required property %q", at(path), r))
			}
		}
		for k, v := range m {
			switch {
			case s.Properties[k] != nil:
				errs = append(errs, schemaErrors(v, s.Properties[k], defs, path+"."+k)...)
			case s.AddProps != nil:
				errs = append(errs, schemaErrors(v, s.AddProps, defs, path+"."+k)...)
			case s.Closed:
				errs = append(errs, fmt.Sprintf("%s: additional property %q is not allowed", at(path), k))
			}
		}
	case "array":
		arr, ok := doc.([]any)
		if !ok {
			return []string{fmt.Sprintf("%s: expected array, got %T", at(path), doc)}
		}
		if s.MinItems > 0 && len(arr) < s.MinItems {
			errs = append(errs, fmt.Sprintf("%s: has %d items, fewer than %d", at(path), len(arr), s.MinItems))
		}
		if s.MaxItems > 0 && len(arr) > s.MaxItems {
			errs = append(errs, fmt.Sprintf("%s: has %d items, more than %d", at(path), len(arr), s.MaxItems))
		}
		for i, e := range arr {
			errs = append(errs, schemaErrors(e, s.Items, defs, fmt.Sprintf("%s[%d]", path, i))...)
		}
	case "string":
		if _, ok := doc.(string); !ok {
			errs = append(errs, fmt.Sprintf("%s: expected string, got %T", at(path), doc))
		}
	case "integer":
		if !isInteger(doc) {
			errs = append(errs, fmt.Sprintf("%s: expected integer, got %T", at(path), doc))
		}
	case "number":
		if !isInteger(doc) && !isFloat(doc) {
			errs = append(errs, fmt.Sprintf("%s: expected number, got %T", at(path), doc))
		}
	case "boolean":
		if _, ok := doc.(bool); !ok {
			errs = append(errs, fmt.Sprintf("%s: expected boolean, got %T", at(path), doc))
		}
	}
	return errs
}

func at(path string) string {
	if path == "" {
		return "(root)"
	}
	return strings.TrimPrefix(path, ".")
}

func enumHas(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func anyContains(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func isInteger(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	}
	return false
}

func isFloat(v any) bool {
	switch v.(type) {
	case float32, float64:
		return true
	}
	return false
}

// normalizeYAML rewrites what yaml.v3 decodes into what a JSON document holds:
// map[string]any with string keys. The int-keyed maps in the model (VLAN and AS
// tables) decode as map[any]any, which the validator would otherwise not walk.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalizeYAML(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[fmt.Sprint(k)] = normalizeYAML(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeYAML(e)
		}
		return out
	default:
		return v
	}
}

func decodeYAMLString(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("test manifest is not valid YAML: %v", err)
	}
	return normalizeYAML(v)
}

func decodeYAMLFile(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return normalizeYAML(v)
}
