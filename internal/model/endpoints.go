package model

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Endpoint is one published control-plane entry point. Node is intentionally
// explicit even when Address is a DNS name: callers can show exactly which
// agent must report healthy before traffic is selected.
type Endpoint struct {
	Service string
	Node    string
	Address string
	Mode    EndpointMode
	Primary bool
	VIP     string
}

// ScalableServiceDefaults reports whether this lab deliberately opted into the
// versioned O6 default migration. Keeping it separate from APIVersion avoids
// making a controller upgrade silently rewrite old service graphs.
func (l *Lab) ScalableServiceDefaults() bool {
	return l != nil && l.ServicePolicyVersion == "v2"
}

// EffectiveReplication returns the service's fully specified policy, including
// the versioned built-in default when the manifest explicitly opted into it.
func (l *Lab) EffectiveReplication(s *ServiceSpec) ServiceReplicationPolicy {
	if s == nil {
		return ServiceReplicationPolicy{Mode: ServiceSingleton, Selector: ServiceShardByAS}
	}
	return s.Replication.Effective(s.Kind, s.Attach != nil, l.ScalableServiceDefaults())
}

// EndpointNodes returns a stable ordered list of eligible endpoint nodes. An
// explicit policy list wins; otherwise every declared node is eligible. The
// source manifest order is retained so appending a node does not reshuffle
// existing active/standby priorities.
func (l *Lab) EndpointNodes(p EndpointPolicy) []string {
	if l == nil {
		return nil
	}
	declared := map[string]bool{}
	for _, n := range l.Placement.Nodes {
		declared[n.Name] = true
	}
	raw := p.Nodes
	if len(raw) == 0 {
		raw = make([]string, 0, len(l.Placement.Nodes))
		for _, n := range l.Placement.Nodes {
			raw = append(raw, n.Name)
		}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, n := range raw {
		if n == "" || !declared[n] || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// GatewayEndpoints gives every eligible node an independently usable gateway
// address. Multi-endpoint mode is the required baseline; VIP merely adds a
// convenience address and is never the only result.
func (l *Lab) GatewayEndpoints() []Endpoint {
	if l == nil {
		return nil
	}
	p := l.Access.Endpoints
	if p.Mode == "" {
		if len(l.Placement.Nodes) > 1 {
			p.Mode = EndpointActiveActive
		} else {
			p.Mode = EndpointActiveStandby
		}
	}
	if len(p.Nodes) == 0 && l.Access.Node != "" {
		p.Nodes = []string{l.Access.Node}
	}
	return endpointsFor(l, "gateway", l.Access.Listen, p)
}

// WebEndpoints gives every selected web endpoint a deterministic address.
// A web service with no replication declaration still defaults to multi-node
// control-plane endpoints: unlike an attached data-plane service it has no
// old topology graph to preserve, and a web singleton would remain a front
// node dependency.
func (t *Topology) WebEndpoints() []Endpoint {
	if t == nil || t.Lab == nil {
		return nil
	}
	var spec *ServiceSpec
	var service *Service
	for _, name := range t.SortedServiceNames() {
		s := t.Services[name]
		if s != nil && s.Kind == "builtin.web" {
			service = s
			spec = s.Spec
			break
		}
	}
	if spec == nil && t.Lab != nil {
		for _, name := range sortedServiceSpecs(t.Lab.Services) {
			s := t.Lab.Services[name]
			if s != nil && s.Kind == "builtin.web" {
				spec = s
				break
			}
		}
	}
	listen := ":9000"
	if spec != nil && spec.Listen != "" {
		listen = spec.Listen
	} else if service != nil && service.Listen != "" {
		listen = service.Listen
	}
	p := EndpointPolicy{}
	if spec != nil {
		p = spec.Endpoints
		replication := t.Lab.EffectiveReplication(spec)
		switch replication.Mode {
		case ServiceSingleton:
			// Web uses the high-availability control-plane baseline even when
			// a legacy attached-service policy remains singleton.
			if p.Mode == "" {
				p.Mode = EndpointActiveActive
			}
		case ServicePerNode:
			if p.Mode == "" {
				p.Mode = EndpointActiveActive
			}
		case ServiceReplicas, ServiceSharded:
			if p.Mode == "" {
				p.Mode = EndpointActiveActive
			}
			if len(p.Nodes) == 0 {
				p.Nodes = replicaEndpointNodes(t.Lab, service, replication)
			}
		}
	}
	if p.Mode == "" {
		p.Mode = EndpointActiveActive
	}
	return endpointsFor(t.Lab, "web", listen, p)
}

func sortedServiceSpecs(m map[string]*ServiceSpec) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func replicaEndpointNodes(lab *Lab, service *Service, p ServiceReplicationPolicy) []string {
	if service != nil {
		var out []string
		for _, r := range service.SortedReplicas() {
			if r != nil && r.Node != "" {
				out = append(out, r.Node)
			}
		}
		if len(out) > 0 {
			return dedupStrings(out)
		}
	}
	if lab == nil {
		return nil
	}
	nodes := lab.EndpointNodes(EndpointPolicy{})
	count := p.Replicas
	if count <= 0 {
		// A sharded control-plane service has no AS attachment count from
		// which to derive shards. One deterministic endpoint is the narrow
		// fallback; per-node mode is handled by its own case above.
		count = 1
	}
	if count > len(nodes) {
		count = len(nodes)
	}
	return nodes[:count]
}

func endpointsFor(l *Lab, service, listen string, p EndpointPolicy) []Endpoint {
	nodes := l.EndpointNodes(p)
	if len(nodes) == 0 {
		return nil
	}
	mode := p.Mode
	if mode == "" {
		mode = EndpointActiveActive
	}
	out := make([]Endpoint, 0, len(nodes))
	for i, node := range nodes {
		out = append(out, Endpoint{
			Service: service,
			Node:    node,
			Address: endpointAddress(node, listen),
			Mode:    mode,
			Primary: i == 0,
			VIP:     p.VIP,
		})
	}
	return out
}

func endpointAddress(node, listen string) string {
	if listen == "" {
		return node
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		if strings.HasPrefix(listen, ":") {
			return node + listen
		}
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort(node, port)
	}
	// A concrete listener host may be a per-node DNS name supplied by the
	// operator. Do not rewrite it into a different address.
	return net.JoinHostPort(host, port)
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// SelectHealthyEndpoint chooses a usable endpoint without treating an absent
// health observation as healthy. The map is keyed by endpoint node. In
// active/active mode the stable endpoint order gives deterministic failover;
// in active/standby mode it first tries the primary then the ordered standbys.
func SelectHealthyEndpoint(endpoints []Endpoint, healthy map[string]bool) (Endpoint, error) {
	for _, endpoint := range endpoints {
		if !healthy[endpoint.Node] {
			continue
		}
		return endpoint, nil
	}
	return Endpoint{}, fmt.Errorf("no healthy endpoint is available")
}
