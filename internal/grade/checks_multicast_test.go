package grade

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/mcast"
	"github.com/HongyuHe/twinet/internal/model"
)

// Every host has to be tested as a receiver, and as somebody who did not ask.
//
// One round covered every host but the source, and the source was always the
// same host, so that one site was never tested as a receiver at all: blocking
// the group at its own router kept full marks. The no-flooding half had the
// same hole in the other direction -- the source and the one receiver were
// never bystanders, so a submission flooding to exactly those two passed.
//
// This is a property of the rounds themselves, so it is pinned here rather than
// left to an end-to-end run that would only notice if a mutation happened to
// land on the untested host.
func TestEveryHostIsTestedAsAReceiverAndAsABystander(t *testing.T) {
	for _, n := range []int{2, 3, 4, 5, 6, 9} {
		hosts := make([]*model.Device, n)
		for i := range hosts {
			hosts[i] = &model.Device{Name: string(rune('A' + i))}
		}

		asReceiver := map[string]bool{}
		for _, c := range deliveryCasts(hosts) {
			for _, h := range c.recv {
				asReceiver[h.Name] = true
			}
		}
		for _, h := range hosts {
			if !asReceiver[h.Name] {
				t.Errorf("with %d hosts, %s is never a receiver, so multicast could be "+
					"blocked to that site for full marks", n, h.Name)
			}
		}

		if n < 3 {
			continue
		}
		asBystander := map[string]bool{}
		for _, c := range floodingCasts(hosts) {
			for _, h := range c.bystanders {
				asBystander[h.Name] = true
			}
			if len(c.recv) != 1 {
				t.Errorf("with %d hosts, a flooding round has %d receivers; the check reads "+
					"the first and would ignore the rest", n, len(c.recv))
			}
		}
		if n == 3 {
			// Three hosts leave exactly one to overhear, and moving the source
			// would leave the round with no bystander at all. The check says
			// which hosts it covered, and a lab this small is the operator's
			// choice.
			continue
		}
		for _, h := range hosts {
			if !asBystander[h.Name] {
				t.Errorf("with %d hosts, %s never listens without joining, so flooding to "+
					"that site would go unnoticed", n, h.Name)
			}
		}
	}
}

// A host can produce packets that look exactly like the ones it was supposed to
// receive.
//
// The delivery question was answered by a datagram socket, which reports what
// the kernel handed it and cannot say where it came from. A host that sends to
// the group on its own segment gets its own packets back, so a submission that
// dropped every genuine delivery and forged the traffic locally on each site
// scored full marks. The kernel does know -- a packet socket is told whether a
// frame was received, transmitted or looped back -- so that is what the probe
// reports and what these tests pin.
func TestPacketsAHostMadeForItselfAreNotDelivery(t *testing.T) {
	want := map[string]bool{"aa": true, "bb": true}
	s := mcastReport("twinet-mcast joined=true group=237.0.0.10 iface=host seconds=25 "+
		"wire=0 loopback=2 elsewhere=0 sources=none\n"+
		"packet aa 1.101.0.1 loopback\n"+
		"packet bb 1.101.0.1 outgoing\n", want)

	if s.arrived != 0 {
		t.Fatalf("counted %d packet(s) as delivered that the host produced itself", s.arrived)
	}
	if s.looped != 2 {
		t.Fatalf("looped = %d, want 2", s.looped)
	}

	h, r := hostBehindRouter("LEFT_host", "LEFT", "host")
	why, ok := deliveredTo(h, s, map[string]tree{
		r.Name: {carriesSource: true, oil: map[string]bool{"host": true}},
	}, "237.0.0.10", &model.Device{Name: "TOP_host"})
	if ok {
		t.Fatal("a host that forged its own copies of the traffic was credited with delivery")
	}
	if !strings.Contains(why, "generated on the host itself") {
		t.Fatalf("the report does not say what happened: %q", why)
	}
}

// The mirror: packets that really came off the wire, with the router on the
// segment putting the group there, are delivery.
func TestPacketsOffTheWireWithATreeBehindThemAreDelivery(t *testing.T) {
	want := map[string]bool{"aa": true, "bb": true}
	s := mcastReport("twinet-mcast joined=true group=237.0.0.10 iface=host seconds=25 "+
		"wire=2 loopback=0 elsewhere=0 sources=1.101.0.1\n"+
		"packet aa 1.101.0.1 multicast\n"+
		"packet bb 1.101.0.1 multicast\n", want)

	if s.arrived != 2 {
		t.Fatalf("arrived = %d, want 2", s.arrived)
	}
	h, r := hostBehindRouter("LEFT_host", "LEFT", "host")
	if why, ok := deliveredTo(h, s, map[string]tree{
		r.Name: {carriesSource: true, oil: map[string]bool{"host": true}},
	}, "237.0.0.10", &model.Device{Name: "TOP_host"}); !ok {
		t.Fatalf("a genuine delivery was not credited: %s", why)
	}
}

// Traffic that reached the host while the router on its segment was never asked
// to put the group there did not get there along a tree.
func TestTrafficWithoutTheLastHopBeingAskedForItIsNotDelivery(t *testing.T) {
	want := map[string]bool{"aa": true}
	s := mcastReport("twinet-mcast joined=true group=237.0.0.10 iface=host seconds=25 "+
		"wire=1 loopback=0 elsewhere=0 sources=1.101.0.1\n"+
		"packet aa 1.101.0.1 multicast\n", want)

	h, r := hostBehindRouter("LEFT_host", "LEFT", "host")
	why, ok := deliveredTo(h, s, map[string]tree{
		r.Name: {carriesSource: true, oil: map[string]bool{"port_CENTER": true}},
	}, "237.0.0.10", &model.Device{Name: "TOP_host"})
	if ok {
		t.Fatal("delivery was credited to a site whose router is not putting the group there")
	}
	if !strings.Contains(why, "not putting") {
		t.Fatalf("the report does not say what happened: %q", why)
	}
}

// Packets on the group that this run did not send are somebody else's, whoever
// sent them. A submission that leaves a sender running is the reason the tag
// exists.
func TestPacketsThisRunDidNotSendAreNotCounted(t *testing.T) {
	s := mcastReport("twinet-mcast joined=true group=237.0.0.10 iface=host seconds=25 "+
		"wire=2 loopback=0 elsewhere=0 sources=1.101.0.1\n"+
		"packet ff 1.101.0.1 multicast\n"+
		"packet ee 1.101.0.1 multicast\n", map[string]bool{"aa": true})

	if s.arrived != 0 {
		t.Fatalf("counted %d packet(s) from another run as this one's", s.arrived)
	}
	if s.foreign != 2 {
		t.Fatalf("foreign = %d, want 2", s.foreign)
	}
}

// The payloads the probe stamps and the digests the check looks for come from
// one place, so that a change to either cannot quietly turn every submission
// into one whose tree does not work.
func TestTheDigestsLookedForAreTheOnesSent(t *testing.T) {
	want := mcast.Digests("cafe", 3)
	if len(want) != 3 {
		t.Fatalf("want 3 digests, got %d", len(want))
	}
	for i := 0; i < 3; i++ {
		if !want[mcast.Digest([]byte(mcast.Stamp("cafe", i)))] {
			t.Fatalf("packet %d's payload is not among the digests looked for", i)
		}
	}
	if want[mcast.Digest([]byte(mcast.Stamp("beef", 0)))] {
		t.Fatal("another run's payload matches this run's digests")
	}
}

// A host on a shared segment reaches its router through a switch, and it is
// still the router's interface that has to carry the group.
func TestTheLastHopIsFoundThroughASwitch(t *testing.T) {
	host := &model.Device{Name: "H", Kind: model.KindHost}
	sw := &model.Device{Name: "S", Kind: model.KindSwitch}
	router := &model.Device{Name: "R", Kind: model.KindRouter}

	hi := &model.Iface{Name: "eth0", Device: host}
	sa := &model.Iface{Name: "p1", Device: sw}
	sb := &model.Iface{Name: "p2", Device: sw}
	ri := &model.Iface{Name: "seg", Device: router}
	hi.Link = &model.Link{A: hi, B: sa}
	sa.Link = hi.Link
	sb.Link = &model.Link{A: sb, B: ri}
	ri.Link = sb.Link
	host.Ifaces = []*model.Iface{hi}
	sw.Ifaces = []*model.Iface{sa, sb}
	router.Ifaces = []*model.Iface{ri}

	r, iface := lastHop(host)
	if r != router || iface != "seg" {
		t.Fatalf("last hop = %v/%q, want R/seg", r, iface)
	}
}

// hostBehindRouter builds the one-link case: a host, its router, and the name
// of the router's interface facing it.
func hostBehindRouter(host, router, iface string) (*model.Device, *model.Device) {
	h := &model.Device{Name: host, Kind: model.KindHost}
	r := &model.Device{Name: router, Kind: model.KindRouter}
	hi := &model.Iface{Name: "router", Device: h}
	ri := &model.Iface{Name: iface, Device: r}
	l := &model.Link{A: hi, B: ri}
	hi.Link, ri.Link = l, l
	h.Ifaces = []*model.Iface{hi}
	r.Ifaces = []*model.Iface{ri}
	return h, r
}

// A site that sees packets for the group from some other sender is told so.
//
// The commonest way a submission produces traffic on the group is a sender of
// its own, and after the source filter those packets never become sightings at
// all. Reporting only "never received" would hide the one fact that explains
// what the student is looking at.
func TestASiteToldWhatItSawInsteadOfTheSource(t *testing.T) {
	s := mcastReport("twinet-mcast joined=true group=237.0.0.10 iface=host seconds=25 "+
		"wire=0 loopback=0 elsewhere=12 sources=none\n", map[string]bool{"aa": true})
	if s.elsewhere != 12 {
		t.Fatalf("elsewhere = %d, want 12", s.elsewhere)
	}
	h, r := hostBehindRouter("LEFT_host", "LEFT", "host")
	why, ok := deliveredTo(h, s, map[string]tree{
		r.Name: {carriesSource: true, oil: map[string]bool{"host": true}},
	}, "237.0.0.10", &model.Device{Name: "TOP_host"})
	if ok {
		t.Fatal("a site that received nothing of the source's was credited with delivery")
	}
	if !strings.Contains(why, "somebody else's source address") {
		t.Fatalf("the report does not say what reached the host: %q", why)
	}
}

// A host that never said what it saw is not a host that saw nothing. The
// summary line is what separates the two, and a listener that did not run
// prints none.
func TestSilenceFromAListenerIsNotAnEmptyWire(t *testing.T) {
	if s := mcastReport("", map[string]bool{}); s.reported {
		t.Fatal("a host that printed nothing was read as having reported")
	}
	if s := mcastReport("twinet-mcast: no such interface\n", map[string]bool{}); s.reported {
		t.Fatal("a host whose listener failed was read as having reported")
	}
	s := mcastReport("twinet-mcast joined=false group=237.0.0.10 iface=host seconds=25 "+
		"wire=0 loopback=0 elsewhere=0 sources=none\n", map[string]bool{})
	if !s.reported {
		t.Fatal("a host that watched the wire and saw nothing was read as silent")
	}
	if s.arrived != 0 {
		t.Fatalf("packets were invented: %d", s.arrived)
	}
}
