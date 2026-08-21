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

	"github.com/HongyuHe/twinet/internal/model"
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

	// OneOf lets a value match exactly one of several shapes. It is how a
	// custom UnmarshalYAML that decodes more than one form is expressed: the
	// compact link [A, B] and the mapping form are both accepted by the loader,
	// so the schema has to accept both or it rejects manifests that work.
	OneOf []*Schema `json:"oneOf,omitempty"`

	// PropertyNames constrains an object's keys. It is emitted where the keys
	// are a closed set -- the device kinds -- so that kinds.routr, which the
	// decoder takes and then nothing ever looks up, is rejected rather than
	// silently configuring nothing.
	PropertyNames *Schema `json:"propertyNames,omitempty"`

	// MinItems and MaxItems bound an array's length. They pin the compact link
	// form to the two endpoints its UnmarshalYAML requires.
	MinItems int `json:"minItems,omitempty"`
	MaxItems int `json:"maxItems,omitempty"`

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

// The manifest types carry three kinds of fact that reflection cannot recover
// from the struct alone, and that a generated schema therefore has to be told:
//
//   - the fixed header strings apiVersion and kind, which identify which
//     document a file is and are checked nowhere in the struct shape;
//   - the closed sets whose members live in a Valid() switch rather than in a
//     `jsonschema:"enum=..."` tag (DeviceKind, ASRole, Relationship); and
//   - the extra YAML shapes a custom UnmarshalYAML accepts (the compact link,
//     the bare-string provisioning rule).
//
// They are expressed in terms of the model's own exported constants, so each
// literal still has a single definition in the model and these tables only
// record where in the schema it belongs. Keeping them here rather than as
// struct tags avoids a second edit to the model for what is schema metadata,
// at the cost of listing the closed types in one place; a new member added to
// one of those types without being added here is caught by the round-trip test
// that every example the loader accepts must also validate.
var (
	// constFields names the fields whose value is a fixed string, per type.
	constFields = map[reflect.Type]map[string]string{
		reflect.TypeOf(model.Lab{}): {
			"apiVersion": model.APIVersion,
			"kind":       model.KindLab,
		},
		reflect.TypeOf(model.ASTemplate{}): {
			"apiVersion": model.APIVersion,
			"kind":       model.KindASTemplate,
		},
	}

	// closedSets lists, per named type, the values the model treats as the
	// whole set. Used both for a field of that type (an enum on the value) and
	// for a map keyed by it (propertyNames on the object).
	closedSets = map[reflect.Type][]string{
		reflect.TypeOf(model.DeviceKind("")): {
			string(model.KindRouter), string(model.KindHost),
			string(model.KindSwitch), string(model.KindService),
			string(model.KindP4), string(model.KindController),
		},
		reflect.TypeOf(model.ASRole("")): {
			string(model.RoleStudent), string(model.RoleStaff), string(model.RoleIXP),
		},
		reflect.TypeOf(model.Relationship("")): {
			string(model.RelProvider), string(model.RelCustomer), string(model.RelPeer),
		},
	}

	// altForms lists the non-object shapes a type's UnmarshalYAML also decodes.
	// The object shape is appended by the generator, producing a oneOf that
	// matches exactly what the loader accepts.
	altForms = map[reflect.Type][]*Schema{
		reflect.TypeOf(model.InternalLink{}): {
			// The compact [A, B] endpoint pair.
			{Type: "array", Items: &Schema{Type: "string"}, MinItems: 2, MaxItems: 2},
		},
		reflect.TypeOf(model.ProvisionRule{}): {
			// A bare device kind or well-known scope name.
			{Type: "string"},
		},
	}
)

func (g *generator) walk(t reflect.Type) *Schema {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		if vals := closedSets[t]; len(vals) > 0 {
			// A named string whose members live in a Valid() switch rather than
			// in a tag -- a DeviceKind, ASRole or Relationship. Reflection sees
			// only "string", so the set is recorded below; emitting it is what
			// lets the schema reject a value the loader takes and later cannot
			// resolve.
			return &Schema{Type: "string", Enum: append([]string(nil), vals...)}
		}
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
		s := &Schema{Type: "object", AddProps: g.walk(t.Elem())}
		if vals := closedSets[t.Key()]; len(vals) > 0 {
			// The keys are a closed set, so a misspelling is a key the map
			// silently absorbs and no code reads back. propertyNames rejects
			// anything outside the set instead of validating it cleanly.
			s.PropertyNames = &Schema{Enum: append([]string(nil), vals...)}
		}
		return s
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
		if c, ok := constFields[t][key]; ok {
			// apiVersion and kind say which document a file is; a wrong header
			// decodes cleanly and then means the file is not the kind it
			// claims. A single-valued enum is JSON Schema's const, and rejects
			// it. It overrides any enum tag deliberately: this is the value.
			cp := *fs
			cp.Enum = []string{c}
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
	if alts := altForms[t]; len(alts) > 0 {
		// This type's UnmarshalYAML also decodes non-object forms, so the
		// object schema alone would reject input the loader takes. Replace the
		// definition with a oneOf of every shape the loader accepts, the object
		// form last. References to #/$defs/<name> then resolve to the oneOf, so
		// every use of the type accepts the same forms the decoder does.
		forms := make([]*Schema, 0, len(alts)+1)
		forms = append(forms, alts...)
		forms = append(forms, s)
		g.defs[name] = &Schema{OneOf: forms}
	}
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
