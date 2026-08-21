package expand

import (
	"fmt"
	"sort"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
)

// interiorShape is the ordinary router/link representation produced by one
// interior declaration. Nothing after expansion needs a special fabric graph:
// render, verification and grading still receive only devices and links.
type interiorShape struct {
	kind              model.InteriorKind
	routers           []interiorRouter
	links             []interiorLink
	hosts             []interiorHost
	generated         bool
	suppressAutoHosts bool
	distributable     bool
}

type interiorRouter struct {
	name      string
	spec      *model.RouterSpec
	role      model.InteriorRole
	roleIndex int
}

type interiorLink struct {
	a, b  string
	props model.LinkProps
	class model.LinkClass
}

type interiorHost struct {
	name      string
	leaf      string
	leafIndex int
	index     int
}

// compileInterior dispatches through the shared generator registry. Explicit
// intentionally retains the original map/list declarations, so the old syntax
// compiles to exactly the same ordinary representation it always did.
func compileInterior(tpl *model.ASTemplate) (*interiorShape, error) {
	if tpl == nil {
		return nil, fmt.Errorf("template is nil")
	}
	if err := tpl.ValidateInterior(); err != nil {
		return nil, err
	}
	kind := tpl.EffectiveInteriorKind()
	if !model.Generators.Has(model.GeneratorInterior, string(kind)) {
		return nil, fmt.Errorf("unknown generator kind %q (supported: %v)",
			kind, model.Generators.Kinds(model.GeneratorInterior))
	}

	switch kind {
	case model.InteriorExplicit:
		return compileExplicitInterior(tpl), nil
	case model.InteriorRing:
		return compileRingInterior(tpl)
	case model.InteriorTwoTier:
		return compileTwoTierInterior(tpl)
	case model.InteriorClos:
		return compileClosInterior(tpl)
	default:
		return nil, fmt.Errorf("generator kind %q is registered but has no compiler", kind)
	}
}

func compileExplicitInterior(tpl *model.ASTemplate) *interiorShape {
	names := sortedKeys(tpl.Routers)
	// Preserve the pre-generator ordering exactly: keys were sorted before
	// sorting by ID, and equal (invalid) IDs retained that stable source order
	// until the normal verifier reported them.
	sort.Slice(names, func(i, j int) bool {
		return tpl.Routers[names[i]].ID < tpl.Routers[names[j]].ID
	})
	out := &interiorShape{kind: model.InteriorExplicit}
	for _, n := range names {
		out.routers = append(out.routers, interiorRouter{name: n, spec: tpl.Routers[n]})
	}
	for _, l := range tpl.EffectiveInternalLinks() {
		out.links = append(out.links, interiorLink{a: l.A, b: l.B, props: l.LinkProps})
	}
	return out
}

func compileRingInterior(tpl *model.ASTemplate) (*interiorShape, error) {
	i := tpl.Interior
	names, err := i.RouterNames()
	if err != nil {
		return nil, err
	}
	out := &interiorShape{kind: model.InteriorRing, generated: true}
	for n, name := range names {
		out.routers = append(out.routers, interiorRouter{
			name: name, spec: &model.RouterSpec{ID: n + 1},
			role: model.InteriorRoleRing, roleIndex: n + 1,
		})
	}
	for n, name := range names {
		out.links = append(out.links, interiorLink{
			a: name, b: names[(n+1)%len(names)],
			props: i.LinkProps, class: model.LinkClassRing,
		})
	}
	if i.Hub != "" {
		hub := string(i.Hub)
		out.routers = append(out.routers, interiorRouter{
			name: hub, spec: &model.RouterSpec{ID: len(out.routers) + 1},
			role: model.InteriorRoleHub, roleIndex: 1,
		})
		for _, name := range names {
			out.links = append(out.links, interiorLink{
				a: hub, b: name, props: i.LinkProps, class: model.LinkClassRingHub,
			})
		}
	}
	return out, nil
}

func compileTwoTierInterior(tpl *model.ASTemplate) (*interiorShape, error) {
	i := tpl.Interior
	core, edge, err := i.TwoTierRouterNames()
	if err != nil {
		return nil, err
	}
	out := &interiorShape{kind: model.InteriorTwoTier, generated: true}
	for n, name := range core {
		out.routers = append(out.routers, interiorRouter{
			name: name, spec: &model.RouterSpec{ID: len(out.routers) + 1},
			role: model.InteriorRoleCore, roleIndex: n + 1,
		})
	}
	for n, name := range edge {
		out.routers = append(out.routers, interiorRouter{
			name: name, spec: &model.RouterSpec{ID: len(out.routers) + 1},
			role: model.InteriorRoleEdge, roleIndex: n + 1,
		})
		for uplink := 0; uplink < i.EdgeUplinks; uplink++ {
			// Rotate the first core by edge so an incomplete fanout remains
			// balanced and reproducible rather than concentrating on core1.
			out.links = append(out.links, interiorLink{
				a: name, b: core[(n+uplink)%len(core)],
				props: i.LinkProps, class: model.LinkClassCoreEdge,
			})
		}
	}
	return out, nil
}

func compileClosInterior(tpl *model.ASTemplate) (*interiorShape, error) {
	i := tpl.Interior
	spines, leaves := i.ClosCounts()
	out := &interiorShape{
		kind:              model.InteriorClos,
		generated:         true,
		suppressAutoHosts: true,
		distributable:     i.Distributable,
	}
	for n := 1; n <= spines; n++ {
		out.routers = append(out.routers, interiorRouter{
			name: fmt.Sprintf("spine%d", n), spec: &model.RouterSpec{ID: len(out.routers) + 1},
			role: model.InteriorRoleSpine, roleIndex: n,
		})
	}
	for n := 1; n <= leaves; n++ {
		out.routers = append(out.routers, interiorRouter{
			name: fmt.Sprintf("leaf%d", n), spec: &model.RouterSpec{ID: len(out.routers) + 1},
			role: model.InteriorRoleLeaf, roleIndex: n,
		})
	}
	for spine := 1; spine <= spines; spine++ {
		for leaf := 1; leaf <= leaves; leaf++ {
			out.links = append(out.links, interiorLink{
				a: fmt.Sprintf("spine%d", spine), b: fmt.Sprintf("leaf%d", leaf),
				props: i.LinkProps, class: model.LinkClassSpineLeaf,
			})
		}
	}
	for leaf := 1; leaf <= leaves; leaf++ {
		for host := 1; host <= i.HostsPerLeaf; host++ {
			out.hosts = append(out.hosts, interiorHost{
				name: fmt.Sprintf("leaf%d_host%d", leaf, host),
				leaf: fmt.Sprintf("leaf%d", leaf), leafIndex: leaf, index: host,
			})
		}
	}
	return out, nil
}

// generatedInteriorSubnet evaluates the scalable role-addressed expression
// when present. The legacy router_router expression remains a compatibility
// fallback for small generated fixtures, but new fabrics can use cidrSubnet
// with RoleLinkIndex and are not limited to a dotted-octet LinkIndex scheme.
func (e *expander) generatedInteriorSubnet(asn int, a, b *model.Device,
	linkIndex int, class model.LinkClass) (string, string, error) {
	field := ipam.FieldRouterRouter
	if e.plan.Has(ipam.FieldRouterRouterRole) {
		field = ipam.FieldRouterRouterRole
	}
	ctx := ipam.Ctx{
		AS: asn, RouterID: a.RouterID, PeerID: b.RouterID,
		LinkIndex: linkIndex,
		Role:      string(a.InteriorRole), PeerRole: string(b.InteriorRole),
		RoleIndex: a.InteriorRoleIndex, PeerRoleIndex: b.InteriorRoleIndex,
		RoleLinkIndex: linkIndex, LinkClass: string(class),
	}
	subnet, err := e.plan.Eval(field, ctx)
	if err != nil {
		return "", field, err
	}
	return subnet, field, nil
}

func closSpineGroupID(asn int) string {
	return fmt.Sprintf("as%d/spines", asn)
}

func closLeafGroupID(asn, leaf int) string {
	// The zero padding preserves numeric order under the lexical JSON map and
	// record ordering used by placement, even beyond leaf 9.
	return fmt.Sprintf("as%d/leaf-%04d", asn, leaf)
}

// definePlacementGroups makes ordinary ASes explicitly atomic and exposes the
// one permitted split for a declared distributable Clos. Devices such as an
// optional L2 attachment that are not intrinsically a leaf stay with the
// spines, which is the conservative side of the controlled boundary.
func (e *expander) definePlacementGroups(as *model.AS, shape *interiorShape) {
	if as == nil {
		return
	}
	groups := map[string]*model.PlacementGroup{}
	defaultID := fmt.Sprintf("as%d", as.ASN)
	if shape != nil && shape.kind == model.InteriorClos && shape.distributable {
		defaultID = closSpineGroupID(as.ASN)
	}
	for _, d := range as.Devices {
		id := d.PlacementGroup
		if id == "" {
			id = defaultID
			d.PlacementGroup = id
		}
		g := groups[id]
		if g == nil {
			class := "as"
			switch {
			case id == closSpineGroupID(as.ASN):
				class = "spine"
			case len(id) > 0 && id != defaultID:
				class = "leaf"
			}
			g = &model.PlacementGroup{ID: id, ASN: as.ASN, Class: class}
			groups[id] = g
		}
		g.Devices = append(g.Devices, d)
	}
	as.PlacementGroups = as.PlacementGroups[:0]
	for _, id := range sortedKeys(groups) {
		as.PlacementGroups = append(as.PlacementGroups, groups[id])
	}
}
