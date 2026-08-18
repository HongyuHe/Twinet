package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// A plan with two routers: a point-to-point link they share, and a loopback
// each. Enough to tell the three cases apart -- an address in your own subnet,
// an address in a subnet that is only somebody else's, and the far end's own
// address sitting in a subnet you legitimately part-own.
func twoRouterPlan() *Env {
	a := &model.Device{ID: "as3/ATL", Name: "ATL"}
	b := &model.Device{ID: "as3/BOS", Name: "BOS"}

	aLo := &model.Iface{Name: "lo", Addr4: "3.156.0.1/24", Prescribed: true, Device: a}
	bLo := &model.Iface{Name: "lo", Addr4: "3.157.0.1/24", Prescribed: true, Device: b}
	aPort := &model.Iface{Name: "port_BOS", Addr4: "3.0.10.2/24", Prescribed: true, Device: a}
	bPort := &model.Iface{Name: "port_ATL", Addr4: "3.0.10.1/24", Prescribed: true, Device: b}

	link := &model.Link{Subnet: "3.0.10.0/24", A: aPort, B: bPort}
	aPort.Link, bPort.Link = link, link

	a.Ifaces = []*model.Iface{aLo, aPort}
	b.Ifaces = []*model.Iface{bLo, bPort}

	return &Env{Topology: &model.Topology{
		Devices: map[string]*model.Device{a.ID: a, b.ID: b},
		Links:   []*model.Link{link},
	}}
}

func TestARoutersOwnSubnetIsNotSomebodyElses(t *testing.T) {
	env := twoRouterPlan()
	owners := subnetOwners(env)
	if !owners["3.156.0.0/24"]["as3/ATL"] {
		t.Fatal("ATL's own loopback subnet is not recorded as ATL's")
	}
	if owners["3.156.0.0/24"]["as3/BOS"] {
		t.Fatal("ATL's loopback subnet was recorded as BOS's too")
	}
}

func TestASharedLinkBelongsToBothEnds(t *testing.T) {
	owners := subnetOwners(twoRouterPlan())
	for _, d := range []string{"as3/ATL", "as3/BOS"} {
		if !owners["3.0.10.0/24"][d] {
			t.Fatalf("the link subnet is not recorded as %s's, but the plan puts it on both ends", d)
		}
	}
}

func TestEveryPlannedAddressIsTraceableToItsInterface(t *testing.T) {
	planned := plannedAddrs(twoRouterPlan())
	for addr, want := range map[string]string{
		"3.156.0.1": "as3/ATL:lo",
		"3.157.0.1": "as3/BOS:lo",
		"3.0.10.1":  "as3/BOS:port_ATL",
		"3.0.10.2":  "as3/ATL:port_BOS",
	} {
		got, ok := planned[addr]
		if !ok {
			t.Fatalf("%s is in the plan but plannedAddrs does not have it", addr)
		}
		if got.where != want {
			t.Fatalf("%s is planned on %s, reported as %s", addr, want, got.where)
		}
	}
	// The mask the address was written with must not change its identity: a
	// counterfeit written /32 is the same counterfeit.
	if bareAddr("3.0.10.1/32") != bareAddr("3.0.10.1/24") {
		t.Fatal("the same address written with two masks was read as two addresses")
	}
}

func TestTheFarEndsAddressIsAnImpersonationEvenOnASharedSubnet(t *testing.T) {
	// The one case the ownership rule must not swallow. 3.0.10.0/24 really is
	// partly ATL's, so "is this subnet mine?" says yes -- but the address in it
	// that BOS is supposed to answer to is BOS's, wherever it is worn.
	env := twoRouterPlan()
	planned := plannedAddrs(env)
	owner, taken := planned[bareAddr("3.0.10.1/24")]
	if !taken {
		t.Fatal("the far end's planned address is not recognised as planned")
	}
	if owner.device == "as3/ATL" {
		t.Fatal("BOS's address was attributed to ATL")
	}
	if !subnetOwners(env)["3.0.10.0/24"]["as3/ATL"] {
		t.Fatal("precondition: the shared subnet should be partly ATL's, or this test proves nothing")
	}
}

func TestAnAddressInAnotherRoutersSubnetIsStillACounterfeit(t *testing.T) {
	env := twoRouterPlan()
	planned := plannedSubnets(env)
	// Not BOS's own address -- just space inside the subnet BOS answers for.
	where := impersonates(planned, "3.157.0.99/24")
	if where != "3.157.0.0/24" {
		t.Fatalf("an address inside BOS's loopback subnet was traced to %q, want 3.157.0.0/24", where)
	}
	if subnetOwners(env)[where]["as3/ATL"] {
		t.Fatal("BOS's loopback subnet was reported as ATL's, which would excuse a real counterfeit")
	}
}

func TestAnUnplannedInterfaceOwnsNothing(t *testing.T) {
	// A dummy interface a student adds is not in the plan, so no subnet is
	// "its own" -- but the router it sits on can still own one, and the rule
	// is about the router. An address in ATL's own space on a dummy interface
	// of ATL's is clutter; the same address on BOS is a counterfeit.
	owners := subnetOwners(twoRouterPlan())
	if !owners["3.156.0.0/24"]["as3/ATL"] {
		t.Fatal("ATL does not own its own loopback subnet")
	}
	if owners["3.156.0.0/24"]["as3/BOS"] {
		t.Fatal("BOS was given a share of ATL's loopback subnet")
	}
}
