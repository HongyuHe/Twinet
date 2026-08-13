package harness

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// The exchange is kept whole because its whole value is that it is shared. That
// is only true if the segment it sits on keeps its members: a reduced harness
// whose route server has no reachable member leaves the target's session to it
// stuck in Active, and the submission is quarantined for a network the harness
// built wrong.
func TestAReducedHarnessKeepsTheExchangeReachable(t *testing.T) {
	top := classTopology(t)
	h, err := Slice(top, 3, Options{Reduce: true, KeepHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	var rs *model.Device
	for _, d := range h.Devices {
		as, ok := h.ASes[d.ASN]
		if !ok || as.Role != model.RoleIXP {
			continue
		}
		rs = d
		break
	}
	if rs == nil {
		t.Fatal("no exchange in the harness is still an exchange: the role is what tells " +
			"the renderer to build a route server, and rewriting it to staff turns the " +
			"exchange into an ordinary transit system, so the session the target opens " +
			"to the route server is to something that is not one")
	}
	// Every interface of the route server must land on a device the harness
	// actually has, or the session it carries can never come up.
	for _, i := range rs.Ifaces {
		if i.Link == nil || i.Peer == nil || i.Peer.Device == nil {
			continue
		}
		if _, ok := h.Devices[i.Peer.Device.ID]; !ok {
			t.Errorf("the route server %s is cabled to %s, which the harness does not "+
				"contain, so its session stays in Active and the submission is "+
				"quarantined for something nobody did", rs.ID, i.Peer.Device.ID)
		}
	}
	// And the system under test must still reach it. At an exchange that is a
	// shared segment rather than a point-to-point link, so what matters is
	// that the target has an interface on the same segment as the route
	// server.
	segments := map[string]bool{}
	for _, l := range h.Links {
		if l.Segment == "" {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			if side != nil && side.Device != nil && side.Device.ID == rs.ID {
				segments[l.Segment] = true
			}
		}
	}
	found := false
	for _, l := range h.Links {
		if l.Segment == "" || !segments[l.Segment] {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			if side != nil && side.Device != nil && side.Device.ASN == 3 {
				found = true
			}
		}
	}
	for _, d := range h.ASes[3].Devices {
		for _, i := range d.Ifaces {
			if i.Peer != nil && i.Peer.Device != nil && i.Peer.Device.ID == rs.ID {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the system under test has no interface facing the exchange, so every " +
			"check about the exchange fails for a correct submission")
	}
}
