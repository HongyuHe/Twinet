package model

import (
	"fmt"
	"sort"
	"strings"
)

// InteriorKind identifies the generator used to build an AS's internal graph.
// Explicit is deliberately the zero-risk default: templates written before
// generated interiors existed keep their ordinary routers and internal_links.
type InteriorKind string

const (
	InteriorExplicit InteriorKind = "explicit"
	InteriorRing     InteriorKind = "ring"
	InteriorTwoTier  InteriorKind = "two-tier"
	InteriorClos     InteriorKind = "clos"
)

// GeneratorScope distinguishes the two graph levels that generators can
// produce. Keeping their names in one registry prevents manifest validation
// and expansion from growing separate, drifting lists of supported kinds.
type GeneratorScope string

const (
	GeneratorInterAS  GeneratorScope = "inter-as"
	GeneratorInterior GeneratorScope = "interior"
)

// GeneratorRegistry describes the built-in generator names. Generation itself
// lives in expand, where it can turn declarations into concrete devices and
// links; this registry is deliberately model-only so both expansion and
// manifest validation use the same vocabulary without an import cycle.
type GeneratorRegistry struct {
	kinds map[GeneratorScope]map[string]struct{}
}

// NewGeneratorRegistry creates the registry of generator kinds compiled into
// this version of Twinet.
func NewGeneratorRegistry() GeneratorRegistry {
	return GeneratorRegistry{kinds: map[GeneratorScope]map[string]struct{}{
		GeneratorInterAS: {
			"tiered-internet": {},
		},
		GeneratorInterior: {
			string(InteriorExplicit): {},
			string(InteriorRing):     {},
			string(InteriorTwoTier):  {},
			string(InteriorClos):     {},
		},
	}}
}

// Has reports whether kind is registered for scope.
func (r GeneratorRegistry) Has(scope GeneratorScope, kind string) bool {
	_, ok := r.kinds[scope][kind]
	return ok
}

// Kinds returns registered names in stable order.
func (r GeneratorRegistry) Kinds(scope GeneratorScope) []string {
	out := make([]string, 0, len(r.kinds[scope]))
	for k := range r.kinds[scope] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Generators is the one built-in registry shared by inter-AS and interior
// generation.
var Generators = NewGeneratorRegistry()

// InteriorKinds returns the interior kinds a manifest or rubric may name.
func InteriorKinds() []InteriorKind {
	names := Generators.Kinds(GeneratorInterior)
	out := make([]InteriorKind, len(names))
	for i, n := range names {
		out[i] = InteriorKind(n)
	}
	return out
}

// Valid reports whether k names a built-in interior generator.
func (k InteriorKind) Valid() bool {
	return Generators.Has(GeneratorInterior, string(k))
}

// RouterSet names routers explicitly or asks a generator to create a count of
// them. YAML accepts either compact form:
//
//	routers: [TOP, RIGHT, BOTTOM]
//	core: 2
//
// or the extended form {names: [...], count: 2, prefix: core}. Names and
// count are mutually exclusive because silently preferring one creates a
// topology different from the one an author believes they wrote.
type RouterSet struct {
	Names  []string `yaml:"names,omitempty" json:"names,omitempty"`
	Count  int      `yaml:"count,omitempty" json:"count,omitempty"`
	Prefix string   `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// HubName is a named optional ring hub. In YAML, hub: true is accepted as the
// convenient spelling for the deterministic default name "hub".
type HubName string

// InteriorSpec is the typed discriminated declaration for an AS interior.
// Fields relevant to the selected Kind are kept together rather than placed in
// an untyped parameter map, so schema generation and validation can catch
// impossible shapes before deployment.
type InteriorSpec struct {
	Kind InteriorKind `yaml:"kind" json:"kind" jsonschema:"required,enum=explicit,enum=ring,enum=two-tier,enum=clos"`

	// Explicit uses the template's routers and either these links or the
	// legacy top-level internal_links. It is a named form of the old model.
	Links []InternalLink `yaml:"links,omitempty" json:"links,omitempty"`

	// Ring accepts routers as names or a count. Count and Prefix are compact
	// aliases for routers.count and routers.prefix.
	Routers RouterSet `yaml:"routers,omitempty" json:"routers,omitempty"`
	Count   int       `yaml:"count,omitempty" json:"count,omitempty"`
	Prefix  string    `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Hub     HubName   `yaml:"hub,omitempty" json:"hub,omitempty"`

	// Two-tier creates a core/edge graph. An edge attaches to EdgeUplinks
	// distinct cores in a deterministic rotating order.
	Core        RouterSet `yaml:"core,omitempty" json:"core,omitempty"`
	Edge        RouterSet `yaml:"edge,omitempty" json:"edge,omitempty"`
	EdgeUplinks int       `yaml:"edge_uplinks,omitempty" json:"edge_uplinks,omitempty"`

	// Clos creates a full spine/leaf bipartite graph and directly attached
	// hosts for each leaf. Singular aliases are retained for hand-authored
	// manifests that read more naturally, while the documented plural names
	// remain canonical.
	Spines       int `yaml:"spines,omitempty" json:"spines,omitempty"`
	Leaves       int `yaml:"leaves,omitempty" json:"leaves,omitempty"`
	Spine        int `yaml:"spine,omitempty" json:"spine,omitempty"`
	Leaf         int `yaml:"leaf,omitempty" json:"leaf,omitempty"`
	HostsPerLeaf int `yaml:"hosts_per_leaf,omitempty" json:"hosts_per_leaf,omitempty"`

	// Distributable allows placement to retain each spine and each
	// leaf-with-hosts group locally while carrying spine/leaf links between
	// nodes when the fabric is large enough to need it.
	Distributable bool `yaml:"distributable,omitempty" json:"distributable,omitempty"`

	// LinkProps apply to every link emitted by a generated (non-explicit)
	// interior, before the lab defaults.
	LinkProps `yaml:",inline" json:",inline"`
}

// EffectiveInteriorKind returns explicit for legacy templates with no
// declaration. That is both the backward-compatible behavior and the kind
// rubrics use when they opt into shape compatibility.
func (t *ASTemplate) EffectiveInteriorKind() InteriorKind {
	if t == nil || t.Interior == nil {
		return InteriorExplicit
	}
	return t.Interior.Kind
}

// EffectiveInternalLinks returns the ordinary router/link declaration used by
// an explicit template. A nil Interior.Links means "use legacy
// internal_links"; an explicitly empty list means an intentionally linkless
// explicit interior.
func (t *ASTemplate) EffectiveInternalLinks() []InternalLink {
	if t != nil && t.Interior != nil && t.Interior.Kind == InteriorExplicit && t.Interior.Links != nil {
		return t.Interior.Links
	}
	if t == nil {
		return nil
	}
	return t.InternalLinks
}

// EffectiveRouterSpecs returns the routers an interior declaration produces.
// Generated specs carry stable IDs in generation order; their defaults are
// inherited from the template and lab exactly like explicitly declared routers.
func (t *ASTemplate) EffectiveRouterSpecs() (map[string]*RouterSpec, error) {
	if t == nil {
		return nil, fmt.Errorf("template is nil")
	}
	kind := t.EffectiveInteriorKind()
	if kind == InteriorExplicit {
		return t.Routers, nil
	}
	if t.Interior == nil {
		return nil, fmt.Errorf("interior is missing")
	}
	names, err := t.Interior.RouterNames()
	if err != nil {
		return nil, err
	}
	out := make(map[string]*RouterSpec, len(names))
	for i, n := range names {
		out[n] = &RouterSpec{ID: i + 1}
	}
	return out, nil
}

// RouterNames returns generated router names in topology order.
func (i *InteriorSpec) RouterNames() ([]string, error) {
	if i == nil {
		return nil, fmt.Errorf("interior is missing")
	}
	switch i.Kind {
	case InteriorRing:
		return i.Routers.Resolve("r", i.Count, i.Prefix)
	case InteriorTwoTier:
		core, edge, err := i.TwoTierRouterNames()
		if err != nil {
			return nil, err
		}
		return append(core, edge...), nil
	case InteriorClos:
		spines, leaves := i.ClosCounts()
		if spines <= 0 || leaves <= 0 {
			return nil, fmt.Errorf("spines and leaves must both be positive")
		}
		out := make([]string, 0, spines+leaves)
		for n := 1; n <= spines; n++ {
			out = append(out, fmt.Sprintf("spine%d", n))
		}
		for n := 1; n <= leaves; n++ {
			out = append(out, fmt.Sprintf("leaf%d", n))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("kind %q does not generate router names", i.Kind)
	}
}

// ClosCounts returns the canonical plural Clos counts, accepting singular
// aliases for authored readability.
func (i *InteriorSpec) ClosCounts() (int, int) {
	spines, leaves := i.Spines, i.Leaves
	if spines == 0 {
		spines = i.Spine
	}
	if leaves == 0 {
		leaves = i.Leaf
	}
	return spines, leaves
}

// Resolve returns the named routers or deterministically generated names.
func (r RouterSet) Resolve(defaultPrefix string, countAlias int, prefixAlias string) ([]string, error) {
	if len(r.Names) > 0 && (r.Count != 0 || countAlias != 0) {
		return nil, fmt.Errorf("names and count are both set")
	}
	if r.Count != 0 && countAlias != 0 {
		return nil, fmt.Errorf("count is set both under the router set and directly on interior")
	}
	if r.Prefix != "" && prefixAlias != "" {
		return nil, fmt.Errorf("prefix is set both under the router set and directly on interior")
	}
	if len(r.Names) > 0 {
		if err := uniqueNames(r.Names); err != nil {
			return nil, err
		}
		return append([]string(nil), r.Names...), nil
	}
	count := r.Count
	if count == 0 {
		count = countAlias
	}
	if count <= 0 {
		return nil, fmt.Errorf("declare router names or a positive count")
	}
	prefix := r.Prefix
	if prefix == "" {
		prefix = prefixAlias
	}
	if prefix == "" {
		prefix = defaultPrefix
	}
	out := make([]string, count)
	for n := range out {
		out[n] = fmt.Sprintf("%s%d", prefix, n+1)
	}
	return out, nil
}

// TwoTierRouterNames resolves the core and edge sets independently so callers
// can retain their roles while building links.
func (i *InteriorSpec) TwoTierRouterNames() ([]string, []string, error) {
	core, err := i.Core.Resolve("core", 0, "")
	if err != nil {
		return nil, nil, fmt.Errorf("core: %w", err)
	}
	edge, err := i.Edge.Resolve("edge", 0, "")
	if err != nil {
		return nil, nil, fmt.Errorf("edge: %w", err)
	}
	return core, edge, nil
}

func uniqueNames(names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			return fmt.Errorf("router name is empty")
		}
		if seen[n] {
			return fmt.Errorf("router name %q is declared twice", n)
		}
		seen[n] = true
	}
	return nil
}

// ValidateInterior checks that a typed declaration is internally coherent.
// It deliberately belongs to the model so expansion and manifest validation
// reject the same impossible parameters.
func (t *ASTemplate) ValidateInterior() error {
	if t == nil || t.Interior == nil {
		return nil
	}
	i := t.Interior
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if i.Kind == "" {
		add("interior.kind is required")
	} else if !i.Kind.Valid() {
		add("unknown interior kind %q (supported: %s)", i.Kind,
			strings.Join(interiorKindStrings(), ", "))
	}

	switch i.Kind {
	case InteriorExplicit:
		if len(t.Routers) == 0 {
			add("explicit interior declares no routers")
		}
		if i.Links != nil && len(t.InternalLinks) > 0 {
			add("links and legacy internal_links are both set; use one explicit link declaration")
		}
		if i.hasGeneratedParameters() {
			add("explicit interior cannot set generated-shape parameters")
		}
	case InteriorRing:
		if len(t.Routers) > 0 {
			add("ring generates routers; remove top-level routers")
		}
		if len(t.InternalLinks) > 0 || i.Links != nil {
			add("ring generates links; remove internal_links and interior.links")
		}
		names, err := i.RouterNames()
		if err != nil {
			add("ring routers: %v", err)
		} else {
			if len(names) < 3 {
				add("ring needs at least 3 routers, got %d", len(names))
			}
			if i.Hub != "" {
				for _, n := range names {
					if n == string(i.Hub) {
						add("ring hub %q duplicates a router", i.Hub)
					}
				}
			}
		}
		if !i.Core.empty() || !i.Edge.empty() || i.EdgeUplinks != 0 || i.Spines != 0 || i.Leaves != 0 ||
			i.Spine != 0 || i.Leaf != 0 || i.HostsPerLeaf != 0 || i.Distributable {
			add("ring cannot set two-tier or clos parameters")
		}
	case InteriorTwoTier:
		if len(t.Routers) > 0 {
			add("two-tier generates routers; remove top-level routers")
		}
		if len(t.InternalLinks) > 0 || i.Links != nil {
			add("two-tier generates links; remove internal_links and interior.links")
		}
		core, edge, terr := i.TwoTierRouterNames()
		if terr != nil {
			add("%v", terr)
		}
		if terr == nil {
			if err := uniqueNames(append(append([]string{}, core...), edge...)); err != nil {
				add("two-tier: %v", err)
			}
			if i.EdgeUplinks <= 0 {
				add("edge_uplinks must be positive")
			} else if i.EdgeUplinks > len(core) {
				add("edge_uplinks %d exceeds the %d declared core router(s)", i.EdgeUplinks, len(core))
			}
		}
		if !i.Routers.empty() || i.Count != 0 || i.Prefix != "" || i.Hub != "" ||
			i.Spines != 0 || i.Leaves != 0 || i.Spine != 0 || i.Leaf != 0 || i.HostsPerLeaf != 0 ||
			i.Distributable {
			add("two-tier cannot set ring or clos parameters")
		}
	case InteriorClos:
		if len(t.Routers) > 0 {
			add("clos generates routers; remove top-level routers")
		}
		if len(t.InternalLinks) > 0 || i.Links != nil {
			add("clos generates links; remove internal_links and interior.links")
		}
		if i.Spines != 0 && i.Spine != 0 {
			add("spines and spine are both set; use one")
		}
		if i.Leaves != 0 && i.Leaf != 0 {
			add("leaves and leaf are both set; use one")
		}
		spines, leaves := i.ClosCounts()
		if spines <= 0 {
			add("spines must be positive")
		}
		if leaves <= 0 {
			add("leaves must be positive")
		}
		if i.HostsPerLeaf < 0 {
			add("hosts_per_leaf cannot be negative")
		}
		if !i.Routers.empty() || i.Count != 0 || i.Prefix != "" || i.Hub != "" ||
			!i.Core.empty() || !i.Edge.empty() || i.EdgeUplinks != 0 {
			add("clos cannot set ring or two-tier parameters")
		}
	}

	sort.Strings(problems)
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	return nil
}

func (i *InteriorSpec) hasGeneratedParameters() bool {
	return !i.Routers.empty() || i.Count != 0 || i.Prefix != "" || i.Hub != "" ||
		!i.Core.empty() || !i.Edge.empty() || i.EdgeUplinks != 0 ||
		i.Spines != 0 || i.Leaves != 0 || i.Spine != 0 || i.Leaf != 0 ||
		i.HostsPerLeaf != 0 || i.Distributable || hasLinkProps(i.LinkProps)
}

func (r RouterSet) empty() bool {
	return len(r.Names) == 0 && r.Count == 0 && r.Prefix == ""
}

func hasLinkProps(p LinkProps) bool {
	return p.Bandwidth != "" || p.Delay != "" || p.Queue != "" || p.Loss != "" || p.MTU != nil
}

func interiorKindStrings() []string {
	kinds := InteriorKinds()
	out := make([]string, len(kinds))
	for n, k := range kinds {
		out[n] = string(k)
	}
	return out
}
