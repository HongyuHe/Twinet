package model

import "testing"

func semanticTestRouter(asn int, role IfaceRole) *Device {
	peer := &Device{ID: "peer", Kind: KindRouter}
	peerIf := &Iface{Device: peer, Addr4: "180.141.0.2/24"}
	router := &Device{ID: "router", Kind: KindRouter, ASN: asn}
	router.Ifaces = []*Iface{{Device: router, Role: role, Peer: peerIf}}
	peerIf.Peer = router.Ifaces[0]
	return router
}

func TestSemanticHealthCapabilitiesFollowDeclaredASRole(t *testing.T) {
	ixp := semanticTestRouter(141, RoleIXPLink)
	ordinary := semanticTestRouter(5, RoleInterAS)
	host := &Device{ID: "host", Kind: KindHost, ASN: 5}
	top := &Topology{ASes: map[int]*AS{
		141: {ASN: 141, Role: RoleIXP, Devices: []*Device{ixp}},
		5:   {ASN: 5, Role: RoleStaff, Devices: []*Device{ordinary, host}},
	}}
	if got := top.SemanticHealthCapabilities(ixp); got.Forwarding || !got.BGPControl {
		t.Fatalf("IXP route server capabilities = %+v, want control-only BGP", got)
	}
	if got := top.SemanticHealthCapabilities(ordinary); !got.Forwarding || !got.BGPControl {
		t.Fatalf("ordinary router capabilities = %+v, want forwarding+BGP", got)
	}
	if got := top.SemanticHealthCapabilities(host); got.Forwarding || got.BGPControl {
		t.Fatalf("host capabilities = %+v, want no router predicates", got)
	}
}
