package place

import (
	"fmt"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// placeServices resolves singleton services and every stable replica before AS
// placement consumes capacity. A legacy singleton deliberately keeps the old
// front-node result; replicas use their recorded or preferred nodes and never
// reshuffle merely because a node was appended to the manifest.
func placeServices(top *model.Topology, assignment *Assignment, names []string,
	caps map[string]demand, hasCap map[string]bool, loads map[string]demand,
	pinned map[string]string, fixed *Record, rebalance bool, front string,
) ([]string, error) {
	if assignment.ByService == nil {
		assignment.ByService = map[string]string{}
	}
	if assignment.ByServiceReplica == nil {
		assignment.ByServiceReplica = map[string]string{}
	}
	var moved []string
	nominal := nominalCapacity(names, caps, hasCap, len(top.Devices))
	for _, name := range top.SortedServiceNames() {
		service := top.Services[name]
		if service == nil {
			continue
		}
		pin := pinned[name]
		if pin == "" {
			pin = service.Node
		}
		replicas := service.SortedReplicas()
		if len(replicas) == 0 {
			node, wasMoved, err := serviceNode(name, "", "", pin, fixed, rebalance, front, names,
				loads, caps, hasCap, demandForService(service), nominal)
			if err != nil {
				return nil, err
			}
			assignment.ByService[name] = node
			if wasMoved != "" {
				moved = append(moved, wasMoved)
			}
			if service.Device != nil {
				loads[node] = loads[node].add(deviceDemand(service.Device))
			}
			continue
		}

		for _, replica := range replicas {
			if replica == nil {
				continue
			}
			home := replica.HomeNode
			// A per-node policy semantically keeps one replica on each node;
			// replicas/shards may be redistributed only by the explicit
			// --rebalance path. Normal placement never moves a recorded
			// replica merely because capacity or membership changed.
			if rebalance && service.Policy.Mode != model.ServicePerNode {
				home = ""
			}
			node, wasMoved, err := serviceNode(name, replica.ID, home, pin, fixed, rebalance,
				front, names, loads, caps, hasCap, deviceDemand(replica.Device), nominal)
			if err != nil {
				return nil, err
			}
			assignment.ByServiceReplica[replica.ID] = node
			if assignment.ByService[name] == "" {
				assignment.ByService[name] = node
			}
			if wasMoved != "" {
				moved = append(moved, wasMoved)
			}
			if replica.Device != nil {
				loads[node] = loads[node].add(deviceDemand(replica.Device))
			}
		}
	}
	return moved, nil
}

func demandForService(service *model.Service) demand {
	if service == nil || service.Device == nil {
		return demand{}
	}
	return deviceDemand(service.Device)
}

func serviceNode(service, replica, home, pin string, fixed *Record, rebalance bool,
	front string, names []string, loads map[string]demand, caps map[string]demand,
	hasCap map[string]bool, need demand, nominal int,
) (string, string, error) {
	if len(names) == 0 {
		return "", "", fmt.Errorf("service %s has no candidate node", service)
	}
	if pin != "" {
		if !contains(names, pin) {
			return "", "", fmt.Errorf("service %s is pinned to unavailable or unknown node %q", service, pin)
		}
		return pin, "", nil
	}
	if !rebalance && fixed != nil {
		recorded := ""
		if replica != "" {
			recorded = fixed.ByServiceReplica[replica]
			// A singleton record is a safe migration seed for the first
			// replica. Additional replicas keep their stable homes.
			if recorded == "" && fixed.ByService[service] != "" && stringsFirstReplica(replica) {
				recorded = fixed.ByService[service]
			}
		} else {
			recorded = fixed.ByService[service]
		}
		if recorded != "" {
			if contains(names, recorded) {
				return recorded, "", nil
			}
			what := service
			if replica != "" {
				what += " replica " + replica
			}
			return bestServiceNode(names, loads, caps, hasCap, need, nominal),
				fmt.Sprintf("%s was on %s, which is unavailable and is being rescheduled", what, recorded), nil
		}
	}
	if home != "" && contains(names, home) && fits(loads[home], need, caps[home], hasCap[home]) {
		return home, "", nil
	}
	if replica == "" && front != "" && contains(names, front) {
		return front, "", nil
	}
	return bestServiceNode(names, loads, caps, hasCap, need, nominal), "", nil
}

func stringsFirstReplica(replica string) bool {
	return strings.HasSuffix(replica, "/replica-001") || strings.HasSuffix(replica, "/shard-001")
}

func bestServiceNode(names []string, loads map[string]demand, caps map[string]demand,
	hasCap map[string]bool, need demand, nominal int) string {
	return bestGroupNode(names, loads, caps, hasCap, nil, need, nominal)
}

func serviceReplicaNode(top *model.Topology, assignment *Assignment, device *model.Device) string {
	service, replica, ok := top.ServiceByDevice(device)
	if !ok || service == nil {
		return ""
	}
	if replica != nil {
		return assignment.ByServiceReplica[replica.ID]
	}
	return assignment.ByService[service.Name]
}

func serviceDevices(service *model.Service) []*model.Device {
	if service == nil {
		return nil
	}
	if len(service.Replicas) == 0 {
		if service.Device == nil {
			return nil
		}
		return []*model.Device{service.Device}
	}
	out := make([]*model.Device, 0, len(service.Replicas))
	for _, replica := range service.SortedReplicas() {
		if replica != nil && replica.Device != nil {
			out = append(out, replica.Device)
		}
	}
	return out
}
