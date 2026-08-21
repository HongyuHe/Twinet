package expand

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func generatedFixture(interior *model.InteriorSpec) *model.Lab {
	no := false
	lab := &model.Lab{
		APIVersion: model.APIVersion,
		Kind:       model.KindLab,
		Metadata:   model.Meta{Name: "generated"},
		Addressing: model.Addressing{
			ASBlock:          "{{ .AS }}.0.0.0/8",
			RouterLoopback:   "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24",
			RouterRouter:     "{{ .AS }}.0.{{ .LinkIndex }}.0/24",
			RouterRouterRole: "{{ cidrSubnet (printf \"%d.0.0.0/8\" .AS) .RoleLinkIndex 24 }}",
			RouterHost:       "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24",
			InterAS:          "179.{{ .Low }}.{{ .High }}.0/24",
		},
		Templates: map[string]*model.ASTemplate{
			"fabric": {Interior: interior, Hosts: model.HostPolicy{PerRouter: &no}},
		},
		AutonomousSystems: []model.ASGroup{{
			List: []int{12}, ASSpec: model.ASSpec{Template: "fabric", Role: model.RoleStaff},
		}},
	}
	lab.Normalize()
	return lab
}

func TestExplicitInteriorCompilesToOrdinaryRoutersAndLinks(t *testing.T) {
	no := false
	lab := generatedFixture(&model.InteriorSpec{
		Kind:  model.InteriorExplicit,
		Links: []model.InternalLink{{A: "A", B: "B"}},
	})
	lab.Templates["fabric"].Routers = map[string]*model.RouterSpec{
		"A": {ID: 1}, "B": {ID: 2},
	}
	lab.Templates["fabric"].Hosts = model.HostPolicy{PerRouter: &no}

	res, err := Expand(lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology
	if len(top.ASes[12].Routers) != 2 || len(top.Links) != 1 {
		t.Fatalf("explicit shape produced %d routers and %d links, want 2 and 1",
			len(top.ASes[12].Routers), len(top.Links))
	}
	l := top.Links[0]
	if l.Class != "" || l.A.Role != model.RoleIntraAS || l.B.Role != model.RoleIntraAS {
		t.Errorf("explicit link is not the ordinary intra-AS representation: %+v", l)
	}
	if l.A.Device.InteriorRole != "" || l.B.Device.InteriorRole != "" {
		t.Errorf("explicit routers unexpectedly carry generated roles: %q, %q",
			l.A.Device.InteriorRole, l.B.Device.InteriorRole)
	}
}

func TestRingGenerationSupportsNamedAndCountRoutersWithHub(t *testing.T) {
	cases := []struct {
		name     string
		interior *model.InteriorSpec
		routers  int
		links    int
	}{
		{
			name: "named ring with hub",
			interior: &model.InteriorSpec{Kind: model.InteriorRing,
				Routers: model.RouterSet{Names: []string{"TOP", "RIGHT", "LEFT"}}, Hub: "CENTER"},
			routers: 4, links: 6,
		},
		{
			name:     "counted ring",
			interior: &model.InteriorSpec{Kind: model.InteriorRing, Count: 4, Prefix: "R"},
			routers:  4, links: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab := generatedFixture(tc.interior)
			first, err := Expand(lab)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Expand(generatedFixture(tc.interior))
			if err != nil {
				t.Fatal(err)
			}
			if first.Topology.Hash != second.Topology.Hash {
				t.Fatalf("same ring generated different hashes: %s and %s",
					first.Topology.Hash, second.Topology.Hash)
			}
			as := first.Topology.ASes[12]
			if len(as.Routers) != tc.routers {
				t.Fatalf("got %d routers, want %d", len(as.Routers), tc.routers)
			}
			var generatedLinks int
			for _, l := range first.Topology.Links {
				if l.Class == model.LinkClassRing || l.Class == model.LinkClassRingHub {
					generatedLinks++
				}
			}
			if generatedLinks != tc.links {
				t.Errorf("got %d generated ring links, want %d", generatedLinks, tc.links)
			}
		})
	}
}

func TestTwoTierGenerationUsesDeterministicRotatingUplinks(t *testing.T) {
	lab := generatedFixture(&model.InteriorSpec{
		Kind: model.InteriorTwoTier,
		Core: model.RouterSet{Count: 2}, Edge: model.RouterSet{Count: 3},
		EdgeUplinks: 2,
	})
	res, err := Expand(lab)
	if err != nil {
		t.Fatal(err)
	}
	as := res.Topology.ASes[12]
	if len(as.Routers) != 5 {
		t.Fatalf("got %d routers, want 5", len(as.Routers))
	}
	edges := map[string][]string{}
	for _, l := range res.Topology.Links {
		if l.Class != model.LinkClassCoreEdge {
			continue
		}
		a, b := l.A.Device, l.B.Device
		if a.InteriorRole == model.InteriorRoleEdge {
			edges[a.Name] = append(edges[a.Name], b.Name)
		} else {
			edges[b.Name] = append(edges[b.Name], a.Name)
		}
	}
	if len(edges) != 3 {
		t.Fatalf("got core links for %d edges, want 3: %v", len(edges), edges)
	}
	for edge, cores := range edges {
		if len(cores) != 2 {
			t.Errorf("%s has %d uplinks, want 2 (%v)", edge, len(cores), cores)
		}
	}
}

func TestClosGenerationUsesRoleAddressingAndPlacementBoundaries(t *testing.T) {
	lab := generatedFixture(&model.InteriorSpec{
		Kind: model.InteriorClos, Spines: 2, Leaves: 3, HostsPerLeaf: 2, Distributable: true,
	})
	res, err := Expand(lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology
	as := top.ASes[12]
	if len(as.Routers) != 5 {
		t.Fatalf("got %d routers, want 5", len(as.Routers))
	}
	if got := countKind(as.Devices, model.KindHost); got != 6 {
		t.Fatalf("got %d generated hosts, want 6", got)
	}
	if len(top.Links) != 12 {
		t.Fatalf("got %d links, want 12 (6 spine-leaf + 6 leaf-host)", len(top.Links))
	}
	classes := map[model.LinkClass]int{}
	for _, l := range top.Links {
		classes[l.Class]++
		if l.AddressingField != "router_router_role" {
			t.Errorf("%s used %q rather than scalable role addressing", l.ID, l.AddressingField)
		}
	}
	if classes[model.LinkClassSpineLeaf] != 6 || classes[model.LinkClassLeafHost] != 6 {
		t.Errorf("unexpected Clos classes: %v", classes)
	}
	if !as.Distributable || len(as.PlacementGroups) != 4 {
		t.Fatalf("Clos groups = distributable:%v groups:%d, want true and 4",
			as.Distributable, len(as.PlacementGroups))
	}
	for _, group := range as.PlacementGroups {
		if len(group.Devices) == 0 {
			t.Errorf("placement group %q has no devices", group.ID)
		}
	}
}

func TestRoleAddressingScalesBeyondLegacyLinkIndex(t *testing.T) {
	// A dotted-octet legacy plan cannot represent link 256. The role plan
	// uses cidrSubnet over the AS /8 instead, so this larger fabric still
	// expands and verifies every distinct subnet.
	lab := generatedFixture(&model.InteriorSpec{
		Kind: model.InteriorClos, Spines: 2, Leaves: 130, HostsPerLeaf: 0,
	})
	res, err := Expand(lab)
	if err != nil {
		t.Fatalf("role-addressed Clos did not expand: %v", err)
	}
	if got, want := len(res.Topology.Links), 260; got != want {
		t.Errorf("got %d generated links, want %d", got, want)
	}
}

func TestGeneratedInteriorValidationRejectsImpossibleOrDuplicateParameters(t *testing.T) {
	cases := []struct {
		name string
		tpl  *model.ASTemplate
		want string
	}{
		{
			name: "ring duplicate names",
			tpl:  &model.ASTemplate{Interior: &model.InteriorSpec{Kind: model.InteriorRing, Routers: model.RouterSet{Names: []string{"A", "A", "B"}}}},
			want: "declared twice",
		},
		{
			name: "two tier impossible fanout",
			tpl:  &model.ASTemplate{Interior: &model.InteriorSpec{Kind: model.InteriorTwoTier, Core: model.RouterSet{Count: 1}, Edge: model.RouterSet{Count: 2}, EdgeUplinks: 2}},
			want: "exceeds",
		},
		{
			name: "clos duplicate singular plural",
			tpl:  &model.ASTemplate{Interior: &model.InteriorSpec{Kind: model.InteriorClos, Spines: 2, Spine: 2, Leaves: 2}},
			want: "both set",
		},
		{
			name: "clos cannot mix explicit router declaration",
			tpl: &model.ASTemplate{
				Routers:  map[string]*model.RouterSpec{"spine1": {ID: 1}},
				Interior: &model.InteriorSpec{Kind: model.InteriorClos, Spines: 2, Leaves: 2},
			},
			want: "remove top-level routers",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tpl.ValidateInterior()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateInterior() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBundledExampleHashesStayByteCompatible(t *testing.T) {
	want := map[string]string{
		"../../examples/advnet": "33d42ba4e2334efb",
		// COS-461 explicitly selects BIRD for its two staff references as
		// O10's mixed-NOS acceptance fixture. Its changed hash is intentional;
		// the other legacy all-FRR examples retain their historic identity.
		"../../examples/cos461":    "67512321120953a4",
		"../../examples/demo":      "b2c6f717337aaddd",
		"../../examples/multicast": "26322a0da9ae995f",
		// Scale explicitly opts into O6 per-node service replicas. Its graph
		// and hash intentionally change; legacy manifests remain unchanged.
		"../../examples/scale": "acc8093d2242f073",
	}
	for dir, hash := range want {
		t.Run(strings.TrimPrefix(dir, "../../examples/"), func(t *testing.T) {
			l, err := manifest.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if d := l.Validate(); d.HasErrors() {
				t.Fatal(d.Err())
			}
			res, err := Expand(l.Lab)
			if err != nil {
				t.Fatal(err)
			}
			if res.Topology.Hash != hash {
				t.Errorf("%s hash = %s, want %s", dir, res.Topology.Hash, hash)
			}
		})
	}
}

func TestClosExampleManifestExpands(t *testing.T) {
	l, err := manifest.Load("../../examples/clos")
	if err != nil {
		t.Fatal(err)
	}
	if d := l.Validate(); d.HasErrors() {
		t.Fatal(d.Err())
	}
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Topology.ASes[42].InteriorKind; got != model.InteriorClos {
		t.Errorf("example interior kind = %q, want clos", got)
	}
}

func countKind(devices []*model.Device, kind model.DeviceKind) int {
	n := 0
	for _, d := range devices {
		if d.Kind == kind {
			n++
		}
	}
	return n
}
