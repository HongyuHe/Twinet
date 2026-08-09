// Package manifest loads, merges and validates Twinet manifests.
//
// Two properties matter more than anything else here:
//
//  1. Errors are *aggregated*. A course author editing a 100-AS lab must see
//     every problem in one pass, not the first one. The legacy platform's
//     bash+regex parsing aborted on the first bad line, which meant a
//     find-one-fix-one loop over eight positional text files.
//
//  2. Errors are *positioned*. Every diagnostic carries file:line:column
//     recovered from the YAML node tree, plus the offending value.
package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/HongyuHe/twinet/internal/model"
)

// Diagnostic is a single validation problem.
type Diagnostic struct {
	File    string
	Line    int
	Column  int
	Path    string // dotted path within the document, e.g. "peerings.links[3].a"
	Message string
	Hint    string
	Sev     Severity
}

// Severity classifies a diagnostic.
type Severity string

const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

func (d Diagnostic) String() string {
	loc := d.File
	if d.Line > 0 {
		loc = fmt.Sprintf("%s:%d:%d", d.File, d.Line, d.Column)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s: %s", loc, d.Sev, d.Message)
	if d.Path != "" {
		fmt.Fprintf(&b, " (at %s)", d.Path)
	}
	if d.Hint != "" {
		fmt.Fprintf(&b, "\n    hint: %s", d.Hint)
	}
	return b.String()
}

// Diagnostics is an aggregated set of problems.
type Diagnostics struct {
	Items []Diagnostic
}

// Add appends an error diagnostic.
func (d *Diagnostics) Add(file, path, msg string, node *yaml.Node) {
	di := Diagnostic{File: file, Path: path, Message: msg, Sev: SevError}
	if node != nil {
		di.Line, di.Column = node.Line, node.Column
	}
	d.Items = append(d.Items, di)
}

// Addf appends a formatted error diagnostic.
func (d *Diagnostics) Addf(file, path string, node *yaml.Node, format string, args ...any) {
	d.Add(file, path, fmt.Sprintf(format, args...), node)
}

// AddHint appends an error diagnostic with a remediation hint.
func (d *Diagnostics) AddHint(file, path string, node *yaml.Node, msg, hint string) {
	di := Diagnostic{File: file, Path: path, Message: msg, Hint: hint, Sev: SevError}
	if node != nil {
		di.Line, di.Column = node.Line, node.Column
	}
	d.Items = append(d.Items, di)
}

// Warn appends a warning diagnostic.
func (d *Diagnostics) Warn(file, path, msg string, node *yaml.Node) {
	di := Diagnostic{File: file, Path: path, Message: msg, Sev: SevWarning}
	if node != nil {
		di.Line, di.Column = node.Line, node.Column
	}
	d.Items = append(d.Items, di)
}

// HasErrors reports whether any diagnostic is an error.
func (d *Diagnostics) HasErrors() bool {
	for _, i := range d.Items {
		if i.Sev == SevError {
			return true
		}
	}
	return false
}

// Errors returns only the error-severity diagnostics.
func (d *Diagnostics) Errors() []Diagnostic {
	var out []Diagnostic
	for _, i := range d.Items {
		if i.Sev == SevError {
			out = append(out, i)
		}
	}
	return out
}

// Sort orders diagnostics by file then position, for stable output.
func (d *Diagnostics) Sort() {
	sort.SliceStable(d.Items, func(a, b int) bool {
		x, y := d.Items[a], d.Items[b]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		return x.Column < y.Column
	})
}

// Err returns an error summarising the diagnostics, or nil if there are none.
func (d *Diagnostics) Err() error {
	if !d.HasErrors() {
		return nil
	}
	d.Sort()
	var b strings.Builder
	n := 0
	for _, i := range d.Items {
		if i.Sev != SevError {
			continue
		}
		n++
		b.WriteString(i.String())
		b.WriteString("\n")
	}
	return fmt.Errorf("%d validation error(s):\n%s", n, b.String())
}

// String renders all diagnostics, warnings included.
func (d *Diagnostics) String() string {
	d.Sort()
	var b strings.Builder
	for _, i := range d.Items {
		b.WriteString(i.String())
		b.WriteString("\n")
	}
	return b.String()
}

// Loaded is the result of loading a manifest: the lab plus the YAML node trees
// retained so validation can report exact positions.
type Loaded struct {
	Lab   *model.Lab
	Nodes map[string]*yaml.Node // file -> root node
	Files map[string]string     // logical name -> path
	Diags Diagnostics
}

// Load reads a lab manifest and every AS template it references.
//
// path may be a manifest file or a directory containing twinet.yaml.
func Load(path string) (*Loaded, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	dir := path
	if !info.IsDir() {
		dir = filepath.Dir(path)
	} else {
		for _, cand := range []string{"twinet.yaml", "twinet.yml"} {
			p := filepath.Join(dir, cand)
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
		if path == dir {
			return nil, fmt.Errorf("no twinet.yaml in %s", dir)
		}
	}

	l := &Loaded{
		Nodes: map[string]*yaml.Node{},
		Files: map[string]string{},
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, positionedYAMLError(path, err)
	}
	lab := &model.Lab{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(lab); err != nil {
		return nil, positionedYAMLError(path, err)
	}
	lab.Dir = dir
	l.Lab = lab
	l.Nodes[path] = &root
	l.Files["lab"] = path

	// Load AS templates from templates/ unless inlined.
	if lab.Templates == nil {
		lab.Templates = map[string]*model.ASTemplate{}
	}
	tdir := filepath.Join(dir, "templates")
	if st, err := os.Stat(tdir); err == nil && st.IsDir() {
		err := filepath.WalkDir(tdir, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			traw, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("read %s: %w", p, err)
			}
			var troot yaml.Node
			if err := yaml.Unmarshal(traw, &troot); err != nil {
				return positionedYAMLError(p, err)
			}
			tpl := &model.ASTemplate{}
			tdec := yaml.NewDecoder(strings.NewReader(string(traw)))
			tdec.KnownFields(true)
			if err := tdec.Decode(tpl); err != nil {
				return positionedYAMLError(p, err)
			}
			name := tpl.Metadata.Name
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
				tpl.Metadata.Name = name
			}
			if _, dup := lab.Templates[name]; dup {
				return fmt.Errorf("%s: duplicate template name %q", p, name)
			}
			lab.Templates[name] = tpl
			l.Nodes[p] = &troot
			l.Files["template:"+name] = p
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	lab.Normalize()
	return l, nil
}

// positionedYAMLError converts a yaml decode error into one that names the file.
func positionedYAMLError(path string, err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %d yaml error(s):\n", path, len(te.Errors))
		for _, e := range te.Errors {
			fmt.Fprintf(&b, "  %s\n", e)
		}
		return errors.New(b.String())
	}
	return fmt.Errorf("%s: %w", path, err)
}

// nodeAt walks a YAML document to the node addressed by a dotted/indexed path
// such as "peerings.links[3].a", returning nil when the path does not resolve.
// It is best-effort: diagnostics degrade to file-level when it fails.
func nodeAt(root *yaml.Node, path string) *yaml.Node {
	if root == nil {
		return nil
	}
	cur := root
	if cur.Kind == yaml.DocumentNode && len(cur.Content) > 0 {
		cur = cur.Content[0]
	}
	if path == "" {
		return cur
	}
	for _, seg := range splitPath(path) {
		if cur == nil {
			return nil
		}
		if seg.index >= 0 {
			if cur.Kind != yaml.SequenceNode || seg.index >= len(cur.Content) {
				return nil
			}
			cur = cur.Content[seg.index]
			continue
		}
		if cur.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(cur.Content); i += 2 {
			if cur.Content[i].Value == seg.key {
				next = cur.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

type pathSeg struct {
	key   string
	index int
}

func splitPath(path string) []pathSeg {
	var out []pathSeg
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		for {
			open := strings.IndexByte(part, '[')
			if open < 0 {
				if part != "" {
					out = append(out, pathSeg{key: part, index: -1})
				}
				break
			}
			if open > 0 {
				out = append(out, pathSeg{key: part[:open], index: -1})
			}
			closeIdx := strings.IndexByte(part[open:], ']')
			if closeIdx < 0 {
				break
			}
			var idx int
			if _, err := fmt.Sscanf(part[open+1:open+closeIdx], "%d", &idx); err == nil {
				out = append(out, pathSeg{index: idx})
			}
			part = part[open+closeIdx+1:]
			if part == "" {
				break
			}
		}
	}
	return out
}
