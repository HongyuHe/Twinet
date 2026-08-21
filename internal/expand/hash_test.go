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

func TestNOSChangesHashOnlyWhenExplicit(t *testing.T) {
	legacy := oneDeviceTopology(func(*model.Device) {})
	base := TopologyHash(legacy)

	// The empty field is the historic implicit FRR selection, so it must not
	// invalidate archived submissions merely because the model gained NOS.
	implicit := oneDeviceTopology(func(d *model.Device) { d.NOS = "" })
	if got := TopologyHash(implicit); got != base {
		t.Fatalf("implicit legacy NOS changed topology hash: %s -> %s", base, got)
	}

	explicit := oneDeviceTopology(func(d *model.Device) { d.NOS = "bird" })
	if got := TopologyHash(explicit); got == base {
		t.Fatal("explicit BIRD selection did not change topology hash")
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

// oneDeviceTopology builds the smallest topology the hash accepts: one router,
// which the caller mutates. It exists so the encoding can be probed in
// isolation, without a whole manifest whose other fields might mask a change.
func oneDeviceTopology(mutate func(*model.Device)) *model.Topology {
	d := &model.Device{ID: "as1/R", Name: "R", Kind: model.KindRouter, ASN: 1}
	mutate(d)
	return &model.Topology{
		Name:     "probe",
		Devices:  map[string]*model.Device{d.ID: d},
		ASes:     map[int]*model.AS{},
		Services: map[string]*model.Service{},
	}
}

// The hash is the identity a submission is bound to: work saved against one lab
// must be refused against another that behaves differently. That holds only if
// the encoding is injective. The old one joined slice elements with a comma and
// no escaping, so a single argument containing a comma was indistinguishable
// from two arguments -- command ["a,b"], one program with a comma in its
// argument, hashed identically to command ["a","b"], which runs two things. A
// submission bound to one lab was silently accepted against the other.
func TestTwoLabsThatDifferOnlyInCommandArgumentsHashDifferently(t *testing.T) {
	joined := TopologyHash(oneDeviceTopology(func(d *model.Device) {
		d.Command = []string{"a,b"}
	}))
	split := TopologyHash(oneDeviceTopology(func(d *model.Device) {
		d.Command = []string{"a", "b"}
	}))
	if joined == split {
		t.Fatalf("command [\"a,b\"] and command [\"a\",\"b\"] both hash to %s, yet one "+
			"runs a single program with a comma in its argument and the other runs "+
			"two things; a submission bound to one lab would be accepted against the "+
			"other and graded as though nothing had changed", joined)
	}
}

// The same class of collision lived in the map encoding, which joined entries
// with a comma and keys to values with a colon, again without escaping. Two
// environments a container would actually run under -- two variables {a=b, c=d}
// versus one variable whose value contains the delimiters {a="b,c:d"} -- both
// rendered to "{a:b,c:d}" and hashed alike.
func TestTwoLabsWhoseMapDataDiffersOnlyAcrossDelimitersHashDifferently(t *testing.T) {
	twoVars := TopologyHash(oneDeviceTopology(func(d *model.Device) {
		d.Env = map[string]string{"a": "b", "c": "d"}
	}))
	oneVar := TopologyHash(oneDeviceTopology(func(d *model.Device) {
		d.Env = map[string]string{"a": "b,c:d"}
	}))
	if twoVars == oneVar {
		t.Fatalf("env {a=b, c=d} and env {a=\"b,c:d\"} both hash to %s, yet they set up "+
			"different container environments; the delimiters between map entries "+
			"are not escaped, so behaviourally different labs share an identity", twoVars)
	}
}

// An injective encoding is worthless if it is not also deterministic: a hash
// that varied from run to run would reject every archive, correct ones
// included. Go randomises map iteration, so the encoding must sort map keys.
// This packs a device with delimiter-heavy maps and slices -- exactly the
// shapes the fix touches -- and requires the hash never to move across many
// runs within one process, where the randomised seed differs each iteration.
func TestTheHashOfDelimiterHeavyDataIsStableAcrossRuns(t *testing.T) {
	build := func() *model.Topology {
		return oneDeviceTopology(func(d *model.Device) {
			d.Command = []string{"a,b", "c:d", "e"}
			d.Env = map[string]string{
				"PATH":  "/usr/bin:/bin",
				"A":     "x,y,z",
				"B":     "k=v;q=r",
				"comma": ",",
				"colon": ":",
			}
			d.Sysctls = map[string]string{
				"net.ipv4.ip_forward":                "1",
				"net.ipv6.conf.all.disable_ipv6":     "0",
				"net.ipv4.conf.all.rp_filter":        "0",
				"net.ipv4.fib_multipath_hash_policy": "1",
			}
		})
	}
	first := TopologyHash(build())
	for i := 0; i < 50; i++ {
		if got := TopologyHash(build()); got != first {
			t.Fatalf("run %d hashed to %s, run 0 to %s: the encoding reads a map in Go's "+
				"randomised order instead of sorting its keys, so it would reject "+
				"archives at random", i, got, first)
		}
	}
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

// Some of what a lab means is not in any device, link or AS.
//
// The RPKI trust anchor is the case that proved it. Which ASes are deliberately
// left without a ROA, and which hold one for somebody else's prefix, is the
// whole content of that exercise: the student's job is to notice exactly those
// and drop them. Both lists live on the lab, and the hash walked only the
// compiled topology -- so a course author could move an AS from "valid" to
// "not found", inverting the expected answer, and the identity would not move.
func TestTheHashMovesWhenTheLabsOwnDeclarationsChange(t *testing.T) {
	cases := []struct {
		what   string
		why    string
		change func(*model.Lab)
	}{
		{
			what: "an AS is deliberately left without a ROA",
			why: "a student who accepts only explicitly-valid routes now drops it; " +
				"that is the answer the exercise is testing for",
			change: func(l *model.Lab) { l.RPKI.NotFound = append(l.RPKI.NotFound, 2) },
		},
		{
			what: "an AS is given a ROA for somebody else's prefix",
			why:  "whoever announces it now looks like a hijacker to anyone validating",
			change: func(l *model.Lab) {
				if l.RPKI.Invalid == nil {
					l.RPKI.Invalid = map[int]string{}
				}
				l.RPKI.Invalid[7] = "11.128.0.0/9"
			},
		},
		{
			what:   "the addressing plan changes",
			why:    "every address in the lab moves, so no saved configuration still applies",
			change: func(l *model.Lab) { l.Addressing.ASBlock = "{{ add .AS 100 }}.0.0.0/8" },
		},
		{
			what: "a scripted misconfiguration is added",
			why:  "the lab now contains a fault the submission was not written against",
			change: func(l *model.Lab) {
				if l.Behaviours == nil {
					l.Behaviours = map[string]*model.Behaviour{}
				}
				l.Behaviours["surprise"] = &model.Behaviour{Kind: "link-down"}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			base := TopologyHash(loadFixture(t))
			l, err := manifest.Load("../../examples/cos461")
			if err != nil {
				t.Fatal(err)
			}
			c.change(l.Lab)
			res, err := Expand(l.Lab)
			if err != nil {
				t.Fatal(err)
			}
			if got := TopologyHash(res.Topology); got == base {
				t.Errorf("the hash did not move when %s.\n%s.\n"+
					"Work done against the old exercise would be accepted against the "+
					"new one and graded as though the answer had not changed.", c.what, c.why)
			}
		})
	}
}

// And still not for where it runs, which the lab also declares.
func TestTheHashIgnoresTheClusterTheLabIsDeployedOn(t *testing.T) {
	base := TopologyHash(loadFixture(t))

	l, err := manifest.Load("../../examples/cos461")
	if err != nil {
		t.Fatal(err)
	}
	l.Lab.Placement.Strategy = "single-node"
	l.Lab.Placement.Nodes = nil
	l.Lab.Access.Listen = ":41000"
	res, err := Expand(l.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if got := TopologyHash(res.Topology); got != base {
		t.Errorf("changing which machines run the lab changed its identity (%s -> %s); "+
			"a submission made on a laptop could not be graded on the cluster", base, got)
	}
}
