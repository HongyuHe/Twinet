// Package schema derives a JSON Schema from the manifest's Go types.
//
// The documentation has claimed since the design that the schema is generated
// from the Go structs, "so there is no dual source of truth". It was not
// generated from anything; there was no schema at all. The `jsonschema:` tags
// were written on the struct fields, read by nobody, and free to drift from the
// validation code that actually ran.
//
// That is a small lie with a real cost. A course author editing a manifest gets
// no completion and no inline errors, and learns what a field is called by
// running `twinet validate` and reading a complaint -- which is the experience
// the manifest design exists to avoid. And a claim in the documentation that
// nobody can check is how the rest of the documentation stops being trusted.
//
// It is reflected here rather than through a library because the dependency set
// is deliberately small: five direct dependencies, none of which are needed to
// walk a struct.
package schema

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
)

// Schema is a JSON Schema document, in the subset this generator emits.
type Schema struct {
	Schema      string             `json:"$schema,omitempty"`
	ID          string             `json:"$id,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	Defs        map[string]*Schema `json:"$defs,omitempty"`
	Type        string             `json:"type,omitempty"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	AddProps    *Schema            `json:"additionalProperties,omitempty"`
	Enum        []string           `json:"enum,omitempty"`

	// Closed marks an object that accepts only the properties it names.
	//
	// It is separate from AddProps because "additionalProperties": false and
	// "additionalProperties": {...} are the same JSON key with different
	// types, and a *Schema cannot express the false.
	Closed bool `json:"-"`
}

// MarshalJSON writes additionalProperties: false for a closed object.
//
// Without it the schema accepted any unknown top-level field, so a manifest
// with a misspelled key -- "servces:", "placment:" -- validated cleanly and
// then silently did not have the thing the author meant to configure. That is
// the failure a schema exists to prevent, and it is the most common one.
func (s Schema) MarshalJSON() ([]byte, error) {
	type plain Schema
	if !s.Closed {
		return json.Marshal(plain(s))
	}
	raw, err := json.Marshal(plain(s))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["additionalProperties"] = json.RawMessage("false")
	return json.Marshal(m)
}

type generator struct {
	defs map[string]*Schema
	seen map[reflect.Type]string
}

// Of returns the schema for a value's type, with every named struct it reaches
// emitted once under $defs and referenced.
func Of(v any) *Schema {
	g := &generator{defs: map[string]*Schema{}, seen: map[reflect.Type]string{}}
	root := g.walk(reflect.TypeOf(v))
	return &Schema{
		Schema: "https://json-schema.org/draft/2020-12/schema",
		ID:     "https://twinet.dev/schema/lab.json",
		Ref:    root.Ref,
		Defs:   g.defs,
		Title:  "Twinet lab manifest",
	}
}

func (g *generator) walk(t reflect.Type) *Schema {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return &Schema{Type: "string"}
	case reflect.Bool:
		return &Schema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &Schema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return &Schema{Type: "number"}
	case reflect.Slice, reflect.Array:
		return &Schema{Type: "array", Items: g.walk(t.Elem())}
	case reflect.Map:
		return &Schema{Type: "object", AddProps: g.walk(t.Elem())}
	case reflect.Interface:
		// Deliberately unconstrained: a field typed `any` holds whatever the
		// template engine produces, and pretending otherwise would reject
		// manifests that are correct.
		return &Schema{}
	case reflect.Struct:
		return g.structSchema(t)
	default:
		return &Schema{}
	}
}

func (g *generator) structSchema(t reflect.Type) *Schema {
	if name, ok := g.seen[t]; ok {
		return &Schema{Ref: "#/$defs/" + name}
	}
	name := t.Name()
	if name == "" {
		name = "anon"
	}
	// Two packages can both define a "Spec"; qualifying by package keeps them
	// apart rather than silently merging two unrelated shapes.
	if _, clash := g.defs[name]; clash {
		name = strings.TrimPrefix(t.PkgPath(), "github.com/HongyuHe/twinet/internal/") + "." + name
	}
	g.seen[t] = name
	// Closed: a struct names every field it has, so anything else in the YAML
	// is a mistake -- almost always a misspelling, which otherwise validates
	// and then silently configures nothing.
	s := &Schema{Type: "object", Properties: map[string]*Schema{}, Title: t.Name(), Closed: true}
	g.defs[name] = s

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		key, omit := yamlName(f)
		if key == "-" {
			continue
		}
		if key == "" && f.Anonymous {
			// Embedded and inlined: lift its fields into this object, which is
			// what the YAML decoder does.
			sub := g.walk(f.Type)
			if d := g.defs[strings.TrimPrefix(sub.Ref, "#/$defs/")]; d != nil {
				for k, v := range d.Properties {
					s.Properties[k] = v
				}
				s.Required = append(s.Required, d.Required...)
			}
			continue
		}
		if key == "" {
			key = strings.ToLower(f.Name)
		}
		fs := g.walk(f.Type)
		// An enum constrains the value, and the constraint is already written
		// on the field. Emitting it is what makes the schema able to reject
		// placement.strategy: "balanced-ish" rather than merely note that it
		// is a string.
		if vals := tagValues(f, "jsonschema", "enum"); len(vals) > 0 {
			cp := *fs
			cp.Enum = vals
			fs = &cp
		}
		if doc := tagValue(f, "jsonschema", "description"); doc != "" {
			// A copy, so a description on one use of a shared type does not
			// leak onto every other use of it.
			cp := *fs
			cp.Description = doc
			fs = &cp
		}
		s.Properties[key] = fs
		if !omit && hasTagFlag(f, "jsonschema", "required") {
			s.Required = append(s.Required, key)
		}
	}
	sort.Strings(s.Required)
	return &Schema{Ref: "#/$defs/" + name}
}

func yamlName(f reflect.StructField) (name string, omitempty bool) {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		tag = f.Tag.Get("json")
	}
	if tag == "" {
		return "", false
	}
	parts := strings.Split(tag, ",")
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
		if p == "inline" {
			return "", omitempty
		}
	}
	return parts[0], omitempty
}

func tagValue(f reflect.StructField, tag, key string) string {
	for _, p := range strings.Split(f.Tag.Get(tag), ",") {
		if v, ok := strings.CutPrefix(p, key+"="); ok {
			return v
		}
	}
	return ""
}

func hasTagFlag(f reflect.StructField, tag, flag string) bool {
	for _, p := range strings.Split(f.Tag.Get(tag), ",") {
		if p == flag {
			return true
		}
	}
	return false
}

// JSON renders the schema.
func JSON(v any) ([]byte, error) {
	return json.MarshalIndent(Of(v), "", "  ")
}

// tagValues collects every occurrence of a repeated key in a struct tag, which
// is how an enum with several members is written: enum=a,enum=b,enum=c.
func tagValues(f reflect.StructField, tag, key string) []string {
	var out []string
	for _, part := range strings.Split(f.Tag.Get(tag), ",") {
		if v, ok := strings.CutPrefix(part, key+"="); ok {
			out = append(out, v)
		}
	}
	return out
}
