package expand

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// An address that could not be allocated came out as an empty string, and every
// check downstream skipped empty strings. So a lab whose addressing plan cannot
// number its own links validated cleanly and deployed with nothing configured
// on the interfaces that join its routers.
//
// A /32 written as a point-to-point subnet is the clearest case: there is no
// room in it for two hosts, both allocations fail, and the two ends of every
// inter-AS cable come up bare.
func TestALinkSubnetTooSmallToNumberIsRefused(t *testing.T) {
	l, err := manifest.Load("../../examples/advnet")
	if err != nil {
		t.Fatal(err)
	}
	l.Lab.Addressing.InterAS = "179.{{ .Low }}.{{ .High }}.0/32"

	if _, err := Expand(l.Lab); err == nil {
		t.Fatal("a lab whose inter-AS subnets are /32 validated cleanly.\n" +
			"There is no room in a /32 for the two interfaces it has to number, so " +
			"both allocations fail, both addresses come out empty, and the routers " +
			"are deployed with nothing on the interface that joins them -- which " +
			"looks like a student's mistake rather than the lab's.")
	} else if !strings.Contains(err.Error(), "no address could be allocated") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// And an exchange fabric, whose ports are L2 and carry no address by design,
// must still validate -- or the check above makes every real lab fail.
func TestAnExchangeFabricStillValidates(t *testing.T) {
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatalf("the reference lab no longer validates: %v", err)
	}
	var fabricPorts int
	for _, d := range res.Topology.Devices {
		if d.Kind != model.KindSwitch {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Addr4 == "" {
				fabricPorts++
			}
		}
	}
	if fabricPorts == 0 {
		t.Skip("this lab has no unaddressed switch ports, so it does not exercise the exemption")
	}
}

// parallelLab builds the smallest lab that can carry two explicit parallel
// links: one AS of two routers, wired by whatever internal_links it is given.
// Two cables between the same pair of routers start with the same interface
// name on each side, which is the shape that exercises name uniquification.
func parallelLab(links ...model.InternalLink) *model.Lab {
	noHosts := false
	return &model.Lab{
		APIVersion: "twinet.dev/v1",
		Kind:       "Lab",
		Metadata:   model.Meta{Name: "parallel"},
		Addressing: model.Addressing{
			ASBlock:        "{{ .AS }}.0.0.0/8",
			RouterLoopback: "{{ .AS }}.{{ add 150 .RouterID }}.0.1/24",
			RouterRouter:   "{{ .AS }}.0.{{ add 1 .LinkIndex }}.0/24",
			RouterHost:     "{{ .AS }}.{{ add 100 .RouterID }}.0.0/24",
			InterAS:        "179.{{ .Low }}.{{ .High }}.0/24",
		},
		Templates: map[string]*model.ASTemplate{
			"pair": {
				Routers: map[string]*model.RouterSpec{
					"R1": {ID: 1},
					"R2": {ID: 2},
				},
				Hosts:         model.HostPolicy{PerRouter: &noHosts},
				InternalLinks: links,
			},
		},
		AutonomousSystems: []model.ASGroup{
			{List: []int{1}, ASSpec: model.ASSpec{Template: "pair", Role: model.RoleStaff}},
		},
	}
}

// addressingByLinkContent fingerprints an expanded topology by what each link
// carries, keyed by the link's own declared subnet -- its content -- rather
// than by the generated identity the bug made order-dependent. For each link it
// records the interface name and address at each end, so the fingerprint is
// sensitive to a bare name being swapped for a suffixed one even when the
// address behind it is unchanged.
func addressingByLinkContent(top *model.Topology) map[string][]string {
	out := map[string][]string{}
	for _, l := range top.Links {
		if l.A == nil || l.B == nil {
			continue
		}
		ends := []string{
			fmt.Sprintf("%s:%s=%s", l.A.Device.ID, l.A.Name, l.A.Addr4),
			fmt.Sprintf("%s:%s=%s", l.B.Device.ID, l.B.Name, l.B.Addr4),
		}
		sort.Strings(ends)
		out[l.Subnet] = ends
	}
	return out
}

// A student's saved submission records the addresses their interfaces were
// given, so re-reading the very same manifest must reproduce them exactly -- or
// the submission stops matching the lab it was taken from for a reason the
// student cannot see.
//
// Two explicit parallel links between one pair of routers begin with the same
// interface name on each side, so one side has to be suffixed. That choice was
// made in the order the links' identities sorted, but at that point the two
// identities are still equal, so the tie fell to whichever link the manifest
// listed first. Swapping the two links in the source therefore swapped which
// interface kept the bare name, and with it which address landed on it. This
// expands the manifest, expands it again with the two links swapped, and
// requires each link -- identified by its own declared subnet -- to come out
// with the same interface names and addresses both times.
func TestParallelLinksGetTheSameAddressesWhateverOrderTheManifestListsThem(t *testing.T) {
	l1 := model.InternalLink{A: "R1", B: "R2", Subnet: "10.0.1.0/24"}
	l2 := model.InternalLink{A: "R1", B: "R2", Subnet: "10.0.2.0/24"}

	forward, err := Expand(parallelLab(l1, l2))
	if err != nil {
		t.Fatalf("expand forward: %v", err)
	}
	reversed, err := Expand(parallelLab(l2, l1))
	if err != nil {
		t.Fatalf("expand reversed: %v", err)
	}

	f := addressingByLinkContent(forward.Topology)
	r := addressingByLinkContent(reversed.Topology)

	// Guard against a vacuous pass: both parallel links must actually be
	// present and distinct, or there is nothing for the swap to disturb.
	if len(f) < 2 || len(f) != len(r) {
		t.Fatalf("expected the same two parallel links in both orderings, got %v and %v", f, r)
	}
	if _, ok := f["10.0.1.0/24"]; !ok {
		t.Fatalf("the two parallel links were not expanded as expected: %v", f)
	}

	for subnet, fends := range f {
		if rends := r[subnet]; !reflect.DeepEqual(fends, rends) {
			t.Fatalf("the link with subnet %s was addressed differently after the two "+
				"parallel links were swapped in the source:\n forward=%v\n reversed=%v\n"+
				"a submission that recorded the forward addresses would no longer match "+
				"the lab", subnet, fends, rends)
		}
	}
}
