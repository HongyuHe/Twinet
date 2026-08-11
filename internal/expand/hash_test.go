package expand

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

// The hash decides whether a submission may be graded against a lab. If it does
// not move when the lab's meaning changes, work done against one policy is
// accepted and marked against another, and nobody is told.
//
// Each case below is a change a course author could plausibly make between two
// runs of the same course. The former hand-written hash missed every one of
// them: relationship, segment, IPv6 subnet, loss, MTU, interface role.
func TestTheHashMovesWhenTheLabMeansSomethingDifferent(t *testing.T) {
	cases := []struct {
		what   string
		why    string
		change func(*model.Topology)
	}{
		{
			what: "a provider becomes a customer",
			why: "this inverts which routes are exported, which is the subject of " +
				"the assignment and what the rubric checks",
			change: func(top *model.Topology) {
				for _, l := range top.Links {
					if l.InterAS {
						l.Rel = model.RelCustomer
						return
					}
				}
			},
		},
		{
			what:   "a link is moved into a shared segment",
			why:    "a broadcast domain has different reachability from a point-to-point link",
			change: func(top *model.Topology) { top.Links[0].Segment = "lan-1" },
		},
		{
			what:   "the IPv6 prefix on a link changes",
			why:    "every IPv6 answer a student gives is now against different addresses",
			change: func(top *model.Topology) { top.Links[0].SubnetV6 = "2001:db8:99::/64" },
		},
		{
			what:   "loss is introduced on a link",
			why:    "a measurement exercise gets different numbers",
			change: func(top *model.Topology) { top.Links[0].Props.Loss = "5%" },
		},
		{
			what:   "the MTU changes",
			why:    "path MTU discovery and fragmentation answers change",
			change: func(top *model.Topology) { m := 1280; top.Links[0].Props.MTU = &m },
		},
		{
			what: "an interface changes role",
			why:  "it decides whether the platform or the student configures it",
			change: func(top *model.Topology) {
				i := firstIface(top)
				i.Role = "some-other-role"
			},
		},
		{
			what:   "an interface moves into a routing table",
			why:    "two customers sharing a table is the failure VRFs exist to prevent",
			change: func(top *model.Topology) { firstIface(top).VRF = "VRF_X" },
		},
		{
			what:   "the address plan changes",
			why:    "every address a student was told to use is different",
			change: func(top *model.Topology) { top.Links[0].Subnet = "10.99.0.0/24" },
		},
		{
			what: "an AS gains a different prefix",
			why:  "what it originates is what its neighbours are marked on seeing",
			change: func(top *model.Topology) {
				for _, asn := range top.SortedASNs() {
					top.ASes[asn].Block = "10.0.0.0/8"
					return
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			before := loadFixture(t)
			base := TopologyHash(before)

			after := loadFixture(t)
			c.change(after)
			got := TopologyHash(after)

			if got == base {
				t.Errorf("the hash did not move when %s.\n%s.\n"+
					"Work done against the old lab would be accepted against the new "+
					"one and graded as though nothing had changed.", c.what, c.why)
			}
		})
	}
}

// And it must not move for things that are not the topology, or the same lab
// deployed on two clusters would have two identities and no submission could
// travel between them.
func TestTheHashIgnoresWhereTheLabHappensToRun(t *testing.T) {
	a := loadFixture(t)
	base := TopologyHash(a)

	b := loadFixture(t)
	for _, d := range b.Devices {
		d.Node = "some-other-machine"
		if d.Labels == nil {
			d.Labels = map[string]string{}
		}
		d.Labels["twinet.node"] = "some-other-machine"
	}
	if got := TopologyHash(b); got != base {
		t.Errorf("moving the lab to different machines changed its identity "+
			"(%s -> %s); a submission made on one cluster could not be graded on "+
			"another, and rebalancing would invalidate every archive", base, got)
	}
}

// The hash has to be the same on every run of the same input. Go randomises map
// iteration, so a walk that reads a map in native order produces a different
// hash each time and rejects every archive, including correct ones.
func TestTheHashIsStableAcrossRuns(t *testing.T) {
	top := loadFixture(t)
	first := TopologyHash(top)
	for i := 0; i < 20; i++ {
		if got := TopologyHash(top); got != first {
			t.Fatalf("run %d gave %s, run 0 gave %s: the hash is not deterministic, "+
				"so it would reject archives at random", i, got, first)
		}
	}
}

func firstIface(top *model.Topology) *model.Iface {
	for _, d := range top.SortedDevices() {
		for _, i := range d.Ifaces {
			if !strings.EqualFold(i.Name, "lo") {
				return i
			}
		}
	}
	return nil
}

func loadFixture(t *testing.T) *model.Topology {
	t.Helper()
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	return res.Topology
}

// Two links must never share a tunnel number or a MAC.
//
// A link's identity is derived from the two interface names it joins, and it
// used to be computed when the link was created -- before those names were made
// unique. Two parallel links between the same pair of devices therefore started
// with the same name on each side, took the same identity, and kept it after
// the names were separated.
//
// Everything downstream comes from that identity. Two links sharing a tunnel
// number become one broadcast domain: a router sees its neighbour's traffic on
// the wrong interface, and the second link's addresses land on a segment that
// already has them. Nothing reports it. The lab behaves as though a cable were
// in the wrong socket, which is a very expensive thing for a student to debug
// when the answer is that the platform is lying to them.
func TestNoTwoLinksShareAnIdentity(t *testing.T) {
	for _, dir := range []string{
		"../../examples/cos461", "../../examples/advnet",
		"../../examples/demo", "../../examples/scale",
	} {
		l, err := manifest.Load(dir)
		if err != nil {
			t.Fatalf("load %s: %v", dir, err)
		}
		res, err := Expand(l.Lab)
		if err != nil {
			t.Fatalf("expand %s: %v", dir, err)
		}
		top := res.Topology

		byID := map[string]string{}
		byVNI := map[uint32]string{}
		for _, lk := range top.Links {
			if other, dup := byID[lk.ID]; dup {
				t.Errorf("%s: %s and %s have the same identity %q",
					dir, other, lk.ID, lk.ID)
			}
			byID[lk.ID] = lk.ID
			if lk.VNI == 0 {
				continue
			}
			if other, dup := byVNI[lk.VNI]; dup {
				t.Errorf("%s: %s and %s are both carried in tunnel %d, so they are one "+
					"broadcast domain and each sees the other's traffic",
					dir, other, lk.ID, lk.VNI)
			}
			byVNI[lk.VNI] = lk.ID
		}

		// A MAC must be unique within a device; two interfaces on one router
		// answering to the same address is a neighbour cache that resolves to
		// whichever replied last.
		for _, d := range top.SortedDevices() {
			seen := map[string]string{}
			for _, i := range d.Ifaces {
				if i.MAC == "" {
					continue
				}
				if other, dup := seen[i.MAC]; dup {
					t.Errorf("%s: %s has %s and %s both at %s",
						dir, d.ID, other, i.Name, i.MAC)
				}
				seen[i.MAC] = i.Name
			}
		}
	}
}

// The examples have no parallel links, so the check above cannot see this bug.
// This builds the case that triggers it: two links between the same pair of
// routers, which start with the same interface name on each side.
func TestParallelLinksGetSeparateIdentities(t *testing.T) {
	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	lab := l.Lab

	res, err := Expand(lab)
	if err != nil {
		t.Fatal(err)
	}
	top := res.Topology

	// Find two routers in one AS and give them a second link, named exactly as
	// the first would be.
	var a, b *model.Device
	byAS := map[int][]*model.Device{}
	for _, d := range top.SortedDevices() {
		if d.Kind == model.KindRouter {
			byAS[d.ASN] = append(byAS[d.ASN], d)
		}
	}
	for _, asn := range top.SortedASNs() {
		if rs := byAS[asn]; len(rs) >= 2 {
			a, b = rs[0], rs[1]
			break
		}
	}
	if a == nil || b == nil {
		t.Skip("no two routers in one AS")
	}

	e := &expander{lab: lab, top: top}
	mk := func() *model.Link {
		ai := &model.Iface{Device: a, Name: "port_dup", Role: model.RoleIntraAS}
		bi := &model.Iface{Device: b, Name: "port_dup", Role: model.RoleIntraAS}
		a.AddIface(ai)
		b.AddIface(bi)
		return e.link(ai, bi, model.LinkVeth, model.LinkProps{}, "", model.OwnerPlatform)
	}
	l1, l2 := mk(), mk()

	if l1.ID == l2.ID {
		t.Logf("before uniquification both links are %q, as expected", l1.ID)
	}
	e.uniquifyIfaceNames()
	e.assignVNIs()

	if l1.ID == l2.ID {
		t.Fatalf("two parallel links still share the identity %q after uniquification; "+
			"everything derived from it -- the tunnel number, the ownership tag, the "+
			"addressing -- collides too", l1.ID)
	}
	if l1.VNI == l2.VNI {
		t.Errorf("two parallel links are both carried in tunnel %d, so they are one "+
			"broadcast domain and each router sees the other link's traffic", l1.VNI)
	}
	if l1.A.MAC == l2.A.MAC {
		t.Errorf("both of %s's interfaces answer to %s, so its neighbour cache resolves "+
			"to whichever replied last", a.ID, l1.A.MAC)
	}
}
