package expand

import (
	"fmt"

	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
)

// ixpFabric is the implicit switch every IXP gets.
//
// A real internet exchange is a shared layer-2 fabric: members plug into it and
// see each other on one subnet, which is why the assignment can tell a student
// to configure 180.142.0.6/24 and then ping the route server at 180.142.0.142.
// Modelling it as point-to-point cables would leave every member believing the
// whole /24 is on-link while being unable to ARP for any of it.
//
// So Twinet gives each IXP a switch and connects the route server and every
// member to it. That is what the hardware actually is, it needs no multi-access
// link type, and it keeps every cable two-ended, which is what makes the
// cross-node overlay a plain unicast tunnel.
const ixpFabric = "FABRIC"

// ensureIXPFabric creates the exchange's switch on first use and returns it.
func (e *expander) ensureIXPFabric(as *model.AS) (*model.Device, error) {
	id := model.DeviceID(as.ASN, ixpFabric)
	if d, ok := e.top.Devices[id]; ok {
		return d, nil
	}
	sw := e.newDevice(as, ixpFabric, model.KindSwitch, model.DeviceDefaults{})
	sw.L2Domain = ixpFabric
	e.top.Devices[sw.ID] = sw

	// The route server hangs off the fabric like any other member.
	if len(as.Routers) == 0 {
		return nil, fmt.Errorf("IXP %d has no route server router", as.ASN)
	}
	rs := as.Routers[0]

	subnet, err := e.ixpSubnet(as)
	if err != nil {
		return nil, err
	}
	rsAddr := hostInSubnet(subnet, as.ASN)

	rsIf := &model.Iface{
		Device: rs, Name: "fabric", Role: model.RoleIXPLink,
		Addr4: rsAddr, Owner: model.OwnerPlatform,
	}
	swIf := &model.Iface{
		Device: sw, Name: "port_rs", Role: model.RoleL2Access, Owner: model.OwnerPlatform,
	}
	rs.AddIface(rsIf)
	sw.AddIface(swIf)
	l := e.link(rsIf, swIf, model.LinkFabric, e.lab.LinkDefaults, subnet, model.OwnerPlatform)
	l.Segment = segmentName(as.ASN)
	return sw, nil
}

// ixpSubnet returns the exchange's peering LAN.
func (e *expander) ixpSubnet(as *model.AS) (string, error) {
	field := ipam.FieldIXPPeering
	if !e.plan.Has(field) {
		return "", fmt.Errorf("IXP %d needs addressing.ixp_peering to be defined", as.ASN)
	}
	return e.plan.Eval(field, ipam.Ctx{AS: as.ASN, IXP: as.ASN})
}

func segmentName(ixp int) string { return fmt.Sprintf("ixp%d", ixp) }

// connectToIXP attaches a member AS's router to the exchange fabric.
func (e *expander) connectToIXP(member *model.AS, memberRouter *model.Device, ixp *model.AS) error {
	sw, err := e.ensureIXPFabric(ixp)
	if err != nil {
		return err
	}
	subnet, err := e.ixpSubnet(ixp)
	if err != nil {
		return err
	}
	// The course prescribes the exact address a member must use at an exchange
	// (180.Z.0.<ASN>), so it is recorded as the expected value even though the
	// student is the one who types it in.
	addr := hostInSubnet(subnet, member.ASN)

	memberIf := &model.Iface{
		Device: memberRouter,
		Name:   fmt.Sprintf("ixp_%d", ixp.ASN),
		Role:   model.RoleIXPLink,
		Addr4:  addr,
		Owner:  ownerOf(member, model.OwnerStudent),
	}
	swIf := &model.Iface{
		Device: sw,
		Name:   fmt.Sprintf("port_as%d", member.ASN),
		Role:   model.RoleL2Access,
		Owner:  model.OwnerPlatform,
	}
	memberRouter.AddIface(memberIf)
	sw.AddIface(swIf)

	l := e.link(memberIf, swIf, model.LinkFabric, e.lab.LinkDefaults, subnet, model.OwnerPlatform)
	l.Segment = segmentName(ixp.ASN)
	l.InterAS = true
	l.Rel = model.RelPeer
	return nil
}
