package grade

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// The load-balancing question asks whether a router forwards toward a
// particular neighbour. It decided that by looking for a next hop on an
// interface called "port_<neighbour>", which is not a fact about the network:
// it is how Twinet's own FRR renderer happens to name interfaces. The plan
// records which interface faces which neighbour, and that is what these tests
// pin down.

// link joins a and b, naming each end, and returns the two devices.
func link(a, b *model.Device, aName, aAddr, bName, bAddr string) {
	ai := &model.Iface{Name: aName, Device: a, Addr4: aAddr}
	bi := &model.Iface{Name: bName, Device: b, Addr4: bAddr}
	ai.Peer, bi.Peer = bi, ai
	a.Ifaces = append(a.Ifaces, ai)
	b.Ifaces = append(b.Ifaces, bi)
}

func hopEnv(routers ...*model.Device) *Env {
	byID := map[string]*model.Device{}
	for _, d := range routers {
		byID[d.ID] = d
	}
	return &Env{
		Topology: &model.Topology{
			Devices: byID,
			ASes:    map[int]*model.AS{3: {ASN: 3, Routers: routers}},
		},
		AS: 3,
	}
}

func devices(names ...string) []*model.Device {
	out := make([]*model.Device, 0, len(names))
	for _, n := range names {
		out = append(out, &model.Device{Name: n, ASN: 3, ID: "as3/" + n})
	}
	return out
}

// A device whose interfaces are not named by Twinet's FRR renderer -- which the
// topology explicitly supports, and which the heterogeneous-vendor goal
// requires -- still forwards toward its neighbour. Requiring the name
// "port_BOS" reported a router that forwards perfectly as not forwarding at
// all, and took the mark for a path that was installed and carrying packets.
func TestAHopIsFoundOverAnInterfaceNotNamedAfterThePeer(t *testing.T) {
	d := devices("ATL", "BOS")
	link(d[0], d[1], "eth0", "3.0.10.2/24", "GigabitEthernet0/1", "3.0.10.1/24")
	env := hopEnv(d...)

	leads := linksToward(env, "ATL", "BOS")
	if !leads.known() {
		t.Fatal("the plan has the link, but no interface toward BOS was found")
	}
	if !leads.installed([]installedHop{{iface: "eth0"}}) {
		t.Errorf("a next hop out eth0 does not count as forwarding toward BOS: %v", leads.ifaces)
	}
	if leads.installed([]installedHop{{iface: "port_BOS"}}) {
		t.Error("an interface that does not exist was accepted by its name alone")
	}
}

// The interface Twinet does render is still matched -- this is what the three
// shipped labs are made of, and the fix must not disturb them.
func TestThePortNamedAfterThePeerStillCounts(t *testing.T) {
	d := devices("ATL", "BOS")
	link(d[0], d[1], "port_BOS", "3.0.10.2/24", "port_ATL", "3.0.10.1/24")
	env := hopEnv(d...)

	leads := linksToward(env, "ATL", "BOS")
	if !leads.installed([]installedHop{{iface: "port_BOS", ip: "3.0.10.1"}}) {
		t.Fatal("the ordinary shipped case stopped matching")
	}
}

// A route may name only the address it hands the packet to, with no interface
// at all. The neighbour's address on the link is in the plan too.
func TestAHopIsFoundByTheNeighboursAddress(t *testing.T) {
	d := devices("ATL", "BOS")
	link(d[0], d[1], "eth0", "3.0.10.2/24", "eth3", "3.0.10.1/24")
	env := hopEnv(d...)

	leads := linksToward(env, "ATL", "BOS")
	if !leads.installed([]installedHop{{ip: "3.0.10.1"}}) {
		t.Fatalf("the neighbour's own address was not recognised: %v", leads.addrs)
	}
	if got := leads.peerAddrs(); len(got) != 1 || got[0] != "3.0.10.1" {
		t.Errorf("peerAddrs = %v, want [3.0.10.1]", got)
	}
}

// Forwarding to somewhere else is still forwarding somewhere else: the fix
// must not turn every next hop into a match, or exclusivity would stop
// detecting the fourth path it exists to detect.
func TestAHopToADifferentNeighbourIsNotAMatch(t *testing.T) {
	d := devices("ATL", "BOS", "PHY")
	link(d[0], d[1], "eth0", "3.0.10.2/24", "eth0", "3.0.10.1/24")
	link(d[0], d[2], "eth1", "3.0.11.2/24", "eth0", "3.0.11.1/24")
	env := hopEnv(d...)

	leads := linksToward(env, "ATL", "BOS")
	if leads.installed([]installedHop{{iface: "eth1", ip: "3.0.11.1"}}) {
		t.Fatal("a next hop toward PHY was counted as forwarding toward BOS")
	}
	if !leads.installed([]installedHop{{iface: "eth1"}, {iface: "eth0"}}) {
		t.Error("one matching next hop among several was not enough")
	}
}

// Two links between the same pair are two ways to carry one hop of a path that
// names routers rather than cables. Both ends must be found.
func TestBothLinksBetweenAPairAreFound(t *testing.T) {
	d := devices("ATL", "BOS")
	link(d[0], d[1], "eth0", "3.0.10.2/24", "eth0", "3.0.10.1/24")
	link(d[0], d[1], "eth1", "3.0.12.2/24", "eth1", "3.0.12.1/24")
	env := hopEnv(d...)

	leads := linksToward(env, "ATL", "BOS")
	if len(leads.ifaces) != 2 || len(leads.addrs) != 2 {
		t.Fatalf("a second link between the pair was lost: %v %v", leads.ifaces, leads.addrs)
	}
	for _, i := range []string{"eth0", "eth1"} {
		if !leads.installed([]installedHop{{iface: i}}) {
			t.Errorf("forwarding over %s was not accepted", i)
		}
	}
}

// A rubric may prescribe a path through a pair the topology does not join. The
// old test could only say "no next hop on port_X", which reads as a student
// error; it is a rubric error, and the two must not look alike.
func TestAPairWithNoLinkIsNotKnown(t *testing.T) {
	d := devices("ATL", "BOS", "PHY")
	link(d[0], d[2], "eth1", "3.0.11.2/24", "eth0", "3.0.11.1/24")
	env := hopEnv(d...)

	if linksToward(env, "ATL", "BOS").known() {
		t.Fatal("a pair with no link between them was reported as joined")
	}
	if linksToward(env, "ATL", "NOWHERE").known() {
		t.Fatal("a router that does not exist was reported as joined")
	}
}

// The label a next hop is reported under has to name something the student can
// act on, whichever half of it the routing table carried.
func TestAHopIsLabelledByWhateverTheTableCarried(t *testing.T) {
	for _, c := range []struct {
		hop  installedHop
		want string
	}{
		{installedHop{iface: "eth0", ip: "3.0.10.1"}, "eth0 (3.0.10.1)"},
		{installedHop{iface: "eth0"}, "eth0"},
		{installedHop{ip: "3.0.10.1"}, "3.0.10.1"},
	} {
		if got := c.hop.label(); got != c.want {
			t.Errorf("label(%+v) = %q, want %q", c.hop, got, c.want)
		}
	}
}
