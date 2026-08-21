// Package service plans scalable auxiliary-service replicas and attachments.
package service

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/ipam"
	"github.com/HongyuHe/twinet/internal/model"
)

// ReplicaName returns a container-safe, stable name for a declared service
// replica. It is intentionally derived only from the policy and its stable
// ordinal, never from current load or a random scheduler decision.
func ReplicaName(service string, policy model.ServiceReplicationPolicy, index int, node string) string {
	switch policy.Mode {
	case model.ServicePerNode:
		return service + "-" + serviceNamePart(node)
	case model.ServiceSharded:
		return fmt.Sprintf("%s-shard-%03d", service, index+1)
	default:
		return fmt.Sprintf("%s-replica-%03d", service, index+1)
	}
}

// ReplicaID is the stable logical identity used in placement records and
// health reports. It remains stable when a replica is moved to recover a lost
// node, unlike a node-derived transient address.
func ReplicaID(service string, policy model.ServiceReplicationPolicy, index int, node string) string {
	switch policy.Mode {
	case model.ServicePerNode:
		return service + "/" + node
	case model.ServiceSharded:
		return fmt.Sprintf("%s/shard-%03d", service, index+1)
	default:
		return fmt.Sprintf("%s/replica-%03d", service, index+1)
	}
}

// ReplicaIdentity is what callers can publish independent of the container
// that currently serves it. Non-sharded replicas share an anycast identity;
// shards have distinct generated identities.
func ReplicaIdentity(service string, policy model.ServiceReplicationPolicy, index int) string {
	if policy.Mode == model.ServiceSharded {
		return fmt.Sprintf("shard:%s:%03d", service, index+1)
	}
	return "anycast:" + service
}

func serviceNamePart(in string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "node"
	}
	return out
}

// InitialAttachmentNodes provides a deterministic provisional placement used
// while expanding a scalable service. Place recomputes attachments after real
// AS and replica placement; this initial graph exists so expansion remains a
// complete, inspectable topology and does not depend on a controller.
func InitialAttachmentNodes(top *model.Topology) map[int]string {
	out := map[int]string{}
	if top == nil || top.Lab == nil || len(top.Lab.Placement.Nodes) == 0 {
		return out
	}
	nodes := make([]string, 0, len(top.Lab.Placement.Nodes))
	for _, n := range top.Lab.Placement.Nodes {
		nodes = append(nodes, n.Name)
	}
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as != nil && as.Node != "" {
			out[asn] = as.Node
			continue
		}
		// The declared node order is stable. Appending a node therefore does
		// not reshuffle this provisional mapping; a committed placement record
		// is still the authority once a lab has been deployed.
		out[asn] = nodes[(asn-1)%len(nodes)]
	}
	return out
}

// ReconcileAttachments regenerates scalable service cables from the committed
// AS and replica placement. It removes obsolete cables first, so a rebalance
// cannot leave duplicate service addresses or two replicas attached to one
// router interface.
//
// Legacy singleton services intentionally do not pass through this path: their
// historical graph and topology hash remain unchanged.
func ReconcileAttachments(top *model.Topology, byAS map[int]string) error {
	if top == nil || top.Lab == nil {
		return fmt.Errorf("service attachment reconciliation needs a topology and lab")
	}
	for _, name := range top.SortedServiceNames() {
		service := top.Services[name]
		if service == nil || len(service.Replicas) == 0 || service.Attach == nil {
			continue
		}
		if err := reconcileService(top, service, byAS, nil); err != nil {
			return err
		}
	}
	reassignVNIs(top)
	return nil
}

// ReconcileHealthyAttachments moves only service cables whose selected replica
// is no longer affirmatively healthy. It is intended for an event/collector
// consumer: callers pass health observations keyed by stable replica ID. A
// missing observation is not treated as healthy, and a service with no healthy
// target fails closed instead of silently wiring traffic to an unhealthy one.
func ReconcileHealthyAttachments(top *model.Topology, byAS map[int]string,
	health model.ServiceReplicaHealth) error {

	if top == nil || top.Lab == nil {
		return fmt.Errorf("service health reconciliation needs a topology and lab")
	}
	choices := map[string]map[int]*model.ServiceReplica{}
	for _, name := range top.SortedServiceNames() {
		service := top.Services[name]
		if service == nil || len(service.Replicas) == 0 || service.Attach == nil {
			continue
		}
		perAS := map[int]*model.ServiceReplica{}
		for _, asn := range eligibleASNs(top, service) {
			router, ok := top.DeviceInAS(asn, service.Attach.Router)
			if !ok {
				continue
			}
			local := router.Node
			if local == "" {
				local = byAS[asn]
			}
			replica, err := service.SelectHealthyReplica(asn, local, health)
			if err != nil {
				return fmt.Errorf("service %s AS %d: %w", service.Name, asn, err)
			}
			perAS[asn] = replica
		}
		choices[name] = perAS
	}
	for _, name := range top.SortedServiceNames() {
		service := top.Services[name]
		if perAS := choices[name]; len(perAS) > 0 {
			if err := reconcileService(top, service, byAS, perAS); err != nil {
				return err
			}
		}
	}
	reassignVNIs(top)
	return nil
}

func reconcileService(top *model.Topology, service *model.Service, byAS map[int]string,
	choices map[int]*model.ServiceReplica) error {
	clearServiceLinks(top, service)
	service.Attachments = map[int]string{}

	field := "svc_" + service.Name
	expr := top.Lab.Addressing.Services[service.Name]
	var plan *ipam.Plan
	if expr != "" {
		var err error
		plan, err = ipam.Compile(map[string]string{field: expr})
		if err != nil {
			return fmt.Errorf("service %s: compile addressing: %w", service.Name, err)
		}
	}

	eligible := eligibleASNs(top, service)
	shards := shardTargets(top, service, eligible, byAS)
	for _, asn := range eligible {
		as := top.ASes[asn]
		router, ok := top.DeviceInAS(asn, service.Attach.Router)
		if !ok {
			continue
		}
		local := router.Node
		if local == "" {
			local = byAS[asn]
		}
		replica := choices[asn]
		if replica == nil {
			replica = attachmentReplica(service, as, local, shards[asn])
		}
		if replica == nil || replica.Device == nil {
			return fmt.Errorf("service %s has no replica available for AS %d", service.Name, asn)
		}

		subnet := ""
		if plan != nil {
			var err error
			subnet, err = plan.Eval(field, ipam.Ctx{AS: asn, Name: service.Name, RouterID: router.RouterID})
			if err != nil {
				return fmt.Errorf("service %s AS %d: %w", service.Name, asn, err)
			}
		}
		routerAddr, serviceAddr := serviceHostPair(subnet)
		routerIface := &model.Iface{
			Device: router, Name: uniqueAttachmentIface(router, service.Attach.Iface, service.Name),
			Role: model.RoleService, Addr4: routerAddr, Owner: model.OwnerPlatform,
		}
		serviceIface := &model.Iface{
			Device: replica.Device, Name: fmt.Sprintf("as%d", asn),
			Role: model.RoleService, Addr4: serviceAddr, Owner: model.OwnerPlatform,
		}
		router.AddIface(routerIface)
		replica.Device.AddIface(serviceIface)
		link := &model.Link{
			ID:     model.MakeLinkID(router.ID, routerIface.Name, replica.Device.ID, serviceIface.Name),
			Kind:   model.LinkService,
			A:      routerIface,
			B:      serviceIface,
			Props:  top.Lab.LinkDefaults,
			Subnet: subnet,
			Owner:  model.OwnerPlatform,
		}
		routerIface.Link, serviceIface.Link = link, link
		routerIface.Peer, serviceIface.Peer = serviceIface, routerIface
		routerIface.MAC = alloc.MAC(top.Name, router.ID, routerIface.Name)
		serviceIface.MAC = alloc.MAC(top.Name, replica.Device.ID, serviceIface.Name)
		top.Links = append(top.Links, link)
		service.Attachments[asn] = replica.ID
	}
	return nil
}

func clearServiceLinks(top *model.Topology, service *model.Service) {
	replicaDevices := map[*model.Device]bool{}
	for _, replica := range service.Replicas {
		if replica != nil && replica.Device != nil {
			replicaDevices[replica.Device] = true
		}
	}
	if len(replicaDevices) == 0 {
		return
	}
	kept := top.Links[:0]
	for _, link := range top.Links {
		if link == nil || link.A == nil || link.B == nil ||
			!replicaDevices[link.A.Device] && !replicaDevices[link.B.Device] {
			kept = append(kept, link)
			continue
		}
		removeIface(link.A.Device, link.A)
		removeIface(link.B.Device, link.B)
	}
	top.Links = kept
}

func removeIface(device *model.Device, wanted *model.Iface) {
	if device == nil || wanted == nil {
		return
	}
	out := device.Ifaces[:0]
	for _, iface := range device.Ifaces {
		if iface != wanted {
			out = append(out, iface)
		}
	}
	device.Ifaces = out
}

func eligibleASNs(top *model.Topology, service *model.Service) []int {
	var out []int
	for _, asn := range top.SortedASNs() {
		as := top.ASes[asn]
		if as == nil || as.Role == model.RoleIXP {
			continue
		}
		if service.Attach.Template != "" && as.Template != service.Attach.Template {
			continue
		}
		if _, ok := top.DeviceInAS(asn, service.Attach.Router); !ok {
			continue
		}
		out = append(out, asn)
	}
	return out
}

func shardTargets(top *model.Topology, service *model.Service, asns []int,
	byAS map[int]string) map[int]string {
	out := map[int]string{}
	if service.Policy.Mode != model.ServiceSharded || len(service.Replicas) == 0 {
		return out
	}
	replicas := service.SortedReplicas()
	for index, asn := range asns {
		as := top.ASes[asn]
		var target *model.ServiceReplica
		switch service.Policy.Selector {
		case model.ServiceShardByAS:
			size := service.Policy.ShardSize
			if size <= 0 {
				size = 1
			}
			target = replicas[(index/size)%len(replicas)]
		case model.ServiceShardByRegion:
			target = rendezvous(service.Name+"\x00"+as.Region, replicas)
		case model.ServiceShardByNode:
			node := byAS[asn]
			if router, ok := top.DeviceInAS(asn, service.Attach.Router); ok && router.Node != "" {
				node = router.Node
			}
			target = rendezvous(service.Name+"\x00"+node, replicas)
		default:
			target = rendezvous(service.Name+"\x00"+strconv.Itoa(asn), replicas)
		}
		if target != nil {
			out[asn] = target.ID
		}
	}
	return out
}

func attachmentReplica(service *model.Service, as *model.AS, localNode, sharded string) *model.ServiceReplica {
	replicas := service.SortedReplicas()
	local := make([]*model.ServiceReplica, 0, len(replicas))
	for _, replica := range replicas {
		if replica != nil && localNode != "" && replica.Node == localNode {
			local = append(local, replica)
		}
	}
	if len(local) > 0 {
		return rendezvous(service.Name+"\x00"+strconv.Itoa(as.ASN), local)
	}
	if sharded != "" {
		if replica, ok := service.Replica(sharded); ok {
			return replica
		}
	}
	return rendezvous(service.Name+"\x00"+strconv.Itoa(as.ASN), replicas)
}

func rendezvous(key string, replicas []*model.ServiceReplica) *model.ServiceReplica {
	var best *model.ServiceReplica
	var bestScore uint64
	for _, replica := range replicas {
		if replica == nil {
			continue
		}
		h := fnv.New64a()
		_, _ = h.Write([]byte(key))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(replica.ID))
		score := h.Sum64()
		if best == nil || score > bestScore || score == bestScore && replica.ID < best.ID {
			best, bestScore = replica, score
		}
	}
	return best
}

func serviceHostPair(subnet string) (string, string) {
	if subnet == "" {
		return "", ""
	}
	first, err1 := ipam.Host(subnet, 1)
	second, err2 := ipam.Host(subnet, 2)
	if err1 != nil || err2 != nil {
		return "", ""
	}
	return first, second
}

func uniqueAttachmentIface(device *model.Device, wanted, service string) string {
	if device == nil {
		return wanted
	}
	used := map[string]bool{}
	for _, iface := range device.Ifaces {
		used[iface.Name] = true
	}
	if !used[wanted] {
		return wanted
	}
	suffix := "-" + serviceNamePart(service)
	base := wanted
	if len(base)+len(suffix) > 15 {
		base = base[:15-len(suffix)]
	}
	candidate := base + suffix
	for n := 2; used[candidate]; n++ {
		tail := fmt.Sprintf("-%d", n)
		head := candidate
		if len(head)+len(tail) > 15 {
			head = head[:15-len(tail)]
		}
		candidate = head + tail
	}
	return candidate
}

func reassignVNIs(top *model.Topology) {
	if top == nil {
		return
	}
	sort.Slice(top.Links, func(i, j int) bool { return top.Links[i].ID < top.Links[j].ID })
	ids := make([]string, 0, len(top.Links))
	for _, link := range top.Links {
		if link != nil {
			ids = append(ids, link.ID)
		}
	}
	vnis := alloc.AssignVNIs(top.Name, ids)
	for _, link := range top.Links {
		if link != nil {
			link.VNI = vnis[link.ID]
		}
	}
}
