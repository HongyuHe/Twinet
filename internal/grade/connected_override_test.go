package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A border router as the plan describes one: a loopback, a host LAN, and an
// inter-AS link whose subnet the far end redistributes into BGP. The last is
// the case that must not be mistaken for cheating -- it is what every eBGP
// link looks like when the neighbour runs `redistribute connected`.
func borderRouterPlan() *Env {
	br := &model.Device{ID: "as20/BR", Name: "BR"}
	far := &model.Device{ID: "as1/R1", Name: "R1"}

	lo := &model.Iface{Name: "lo", Addr4: "20.151.0.1/32", Device: br}
	host := &model.Iface{Name: "host", Addr4: "20.101.0.2/24", Device: br}
	ext := &model.Iface{Name: "ext_1_R1", Addr4: "179.1.20.2/24", Device: br}
	farEnd := &model.Iface{Name: "ext_20_BR", Addr4: "179.1.20.1/24", Device: far}

	link := &model.Link{Subnet: "179.1.20.0/24", A: ext, B: farEnd}
	ext.Link, farEnd.Link = link, link

	br.Ifaces = []*model.Iface{lo, host, ext}
	far.Ifaces = []*model.Iface{farEnd}

	return &Env{Topology: &model.Topology{
		Devices: map[string]*model.Device{br.ID: br, far.ID: far},
		Links:   []*model.Link{link},
	}}
}

func TestAnEBGPLinkSubnetIsNotAnOverride(t *testing.T) {
	// The neighbour advertises the shared link subnet, so it is an externally
	// learned prefix with a connected route beating it. That is how the
	// internet works, not an attempt to sidestep the ranking -- and it depends
	// on what the *neighbour* configured, which in a class is another
	// student's submission.
	attached := subnetOwners(borderRouterPlan())
	if !attached[normalPrefix("179.1.20.0/24")]["as20/BR"] {
		t.Fatal("the plan attaches BR to its eBGP link subnet, but the check would call it an override")
	}
}

func TestABorrowedPrefixIsAnOverride(t *testing.T) {
	// The mutation this rule exists for: an address out of another AS's space
	// on an interface of your own, so their whole prefix is directly attached
	// and the ranking decides nothing for it.
	attached := subnetOwners(borderRouterPlan())
	if attached[normalPrefix("9.0.0.0/8")]["as20/BR"] {
		t.Fatal("a foreign AS's prefix was treated as one the plan attaches BR to")
	}
	if len(attached[normalPrefix("9.0.0.0/8")]) != 0 {
		t.Fatal("a prefix nobody in the plan is on came out owned")
	}
}

func TestASubnetIsTheSameSubnetHoweverItIsWritten(t *testing.T) {
	// The plan records an interface address; the routing table records the
	// subnet. Comparing them as text would find no eBGP link legitimate.
	if normalPrefix("179.1.20.2/24") != normalPrefix("179.1.20.0/24") {
		t.Fatal("an interface address and its own subnet were read as different subnets")
	}
	if normalPrefix("179.1.20.0/24") == normalPrefix("179.1.20.0/8") {
		t.Fatal("widening the mask kept the same subnet, so a borrowed /8 would pass as the /24 it covers")
	}
	if got := normalPrefix("not a prefix"); got != "not a prefix" {
		t.Fatalf("unparseable text should survive intact for comparison, got %q", got)
	}
}

func TestOnlyTheRouterOnTheLinkIsExcused(t *testing.T) {
	// Both ends of a link own its subnet, and nobody else does. A third
	// router carrying that prefix directly is standing in for the link.
	attached := subnetOwners(borderRouterPlan())
	owners := attached[normalPrefix("179.1.20.0/24")]
	for _, d := range []string{"as20/BR", "as1/R1"} {
		if !owners[d] {
			t.Fatalf("%s is on the link but does not own its subnet", d)
		}
	}
	if len(owners) != 2 {
		t.Fatalf("the link subnet is owned by %d routers, want the 2 that are on it", len(owners))
	}
	if attached[normalPrefix("20.101.0.0/24")]["as1/R1"] {
		t.Fatal("BR's host LAN came out owned by the router across the link")
	}
}
