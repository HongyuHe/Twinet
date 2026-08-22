package model

// SemanticCapabilities declares what the topology expects a device to prove
// operationally. It is intentionally independent of a container name or an
// implementation detail: the agent combines it with the selected NOS
// capabilities before choosing health predicates.
type SemanticCapabilities struct {
	// Forwarding requires a router to have usable kernel routes toward the
	// lab's representative remote hosts.
	Forwarding bool
	// BGPControl requires a router to prove its declared external/IXP BGP
	// sessions and RIB. A route server is control-plane-only: this remains
	// true while Forwarding is false.
	BGPControl bool
}

// SemanticHealthCapabilities derives health obligations from the expanded
// topology role. IXP route servers are declared by RoleIXP, not inferred from
// their short name, image, or interface count.
func (t *Topology) SemanticHealthCapabilities(d *Device) SemanticCapabilities {
	if t == nil || d == nil || d.Kind != KindRouter {
		return SemanticCapabilities{}
	}
	as := t.ASes[d.ASN]
	if as == nil {
		return SemanticCapabilities{}
	}
	out := SemanticCapabilities{Forwarding: as.Role != RoleIXP}
	for _, iface := range d.Ifaces {
		if iface == nil || iface.Peer == nil || iface.Peer.Device == nil ||
			iface.Peer.Device.Kind != KindRouter {
			continue
		}
		switch iface.Role {
		case RoleInterAS, RoleIXPLink:
			out.BGPControl = true
			return out
		}
	}
	return out
}
