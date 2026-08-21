package svc

import (
	"encoding/json"
	"fmt"

	"github.com/HongyuHe/twinet/internal/model"
)

// DeclaredReplicaState is the immutable service input rendered to every
// replica. It is intentionally derived only from the topology declaration:
// replicas never need an undocumented side channel to agree on DNS zones or
// RTR VRPs.
type DeclaredReplicaState struct {
	Revision string   `json:"revision"`
	Service  string   `json:"service"`
	Kind     string   `json:"kind"`
	DNS      *DNSPlan `json:"dns,omitempty"`
	RPKI     *Payload `json:"rpki,omitempty"`
}

// BuildDeclaredReplicaState returns a stable JSON document suitable for
// distributing with every service replica. A declared topology change creates
// a new revision and reaches all replicas through ordinary render/apply state,
// rather than through mutable replica-to-replica coordination.
func BuildDeclaredReplicaState(top *model.Topology, device *model.Device) ([]byte, error) {
	if top == nil || device == nil || device.Kind != model.KindService {
		return nil, fmt.Errorf("declared service state needs a service device and topology")
	}
	service, _, ok := top.ServiceByDevice(device)
	if !ok || service == nil {
		return nil, fmt.Errorf("service device %s has no declared service", device.ID)
	}
	state := DeclaredReplicaState{
		Revision: top.Hash,
		Service:  service.Name,
		Kind:     service.Kind,
	}
	switch service.Kind {
	case "builtin.dns":
		state.DNS = BuildDNS(top, dnsSerialForState(top))
	case "builtin.rpki":
		state.RPKI = BuildRPKI(top, top.Lab.RPKI.NotFound, top.Lab.RPKI.Invalid)
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func dnsSerialForState(top *model.Topology) uint32 {
	var serial uint32 = 2166136261
	if top != nil {
		for _, c := range top.Hash {
			serial = (serial ^ uint32(c)) * 16777619
		}
	}
	if serial == 0 {
		return 1
	}
	return serial
}
