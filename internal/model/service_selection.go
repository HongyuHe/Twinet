package model

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// ServiceReplicaHealth is the health declaration consumed by a service
// selector. Unknown and unhealthy are deliberately both false: a caller must
// have affirmative evidence before directing a request to a replica.
type ServiceReplicaHealth map[string]bool

// SelectHealthyReplica returns the local healthy replica when one exists,
// otherwise a stable healthy fallback. It never returns an unknown or
// unhealthy replica. The health map is keyed by ServiceReplica.ID.
func (s *Service) SelectHealthyReplica(asn int, localNode string, healthy ServiceReplicaHealth) (*ServiceReplica, error) {
	if s == nil {
		return nil, fmt.Errorf("service is nil")
	}
	candidates := s.SortedReplicas()
	if len(candidates) == 0 && s.Device != nil {
		// Legacy singleton services did not carry replica metadata. Treat the
		// device ID as the one explicit health key rather than assuming it is
		// healthy because the service predates O6.
		if healthy[s.Device.ID] {
			return &ServiceReplica{ID: s.Device.ID, Node: s.Device.Node, Device: s.Device}, nil
		}
		return nil, fmt.Errorf("service %q has no healthy replica", s.Name)
	}

	local := make([]*ServiceReplica, 0, len(candidates))
	remote := make([]*ServiceReplica, 0, len(candidates))
	for _, r := range candidates {
		if r == nil || !healthy[r.ID] {
			continue
		}
		if localNode != "" && r.Node == localNode {
			local = append(local, r)
		} else {
			remote = append(remote, r)
		}
	}
	if len(local) > 0 {
		return rendezvousReplica(s.Name, asn, local), nil
	}
	if len(remote) > 0 {
		return rendezvousReplica(s.Name, asn, remote), nil
	}
	return nil, fmt.Errorf("service %q has no healthy replica", s.Name)
}

// rendezvousReplica is stable across process runs and input map order. It is
// intentionally used only after locality filtering; rendezvous hashing makes
// an existing healthy choice stable while adding a replica moves only the
// attachments that rank the new member highest.
func rendezvousReplica(service string, asn int, candidates []*ServiceReplica) *ServiceReplica {
	if len(candidates) == 0 {
		return nil
	}
	sorted := append([]*ServiceReplica(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var best *ServiceReplica
	var bestScore uint64
	for _, r := range sorted {
		h := fnv.New64a()
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%s", service, asn, r.ID)
		score := h.Sum64()
		if best == nil || score > bestScore {
			best, bestScore = r, score
		}
	}
	return best
}
