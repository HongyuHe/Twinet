package place

import (
	"reflect"
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/model"
)

func servicePlacementLab(nodes []string) *model.Lab {
	noHosts := false
	lab := &model.Lab{
		APIVersion: model.APIVersion,
		Kind:       model.KindLab,
		Metadata:   model.Meta{Name: "service-placement"},
		Addressing: model.Addressing{
			ASBlock:        "{{ .AS }}.0.0.0/8",
			RouterLoopback: "{{ .AS }}.150.0.1/24",
			RouterRouter:   "{{ .AS }}.0.1.0/24",
			RouterHost:     "{{ .AS }}.100.0.0/24",
			InterAS:        "179.{{ .Low }}.{{ .High }}.0/24",
			Services:       map[string]string{"dns": "198.{{ .AS }}.0.0/24"},
		},
		Kinds: map[model.DeviceKind]model.DeviceDefaults{
			model.KindRouter:  {Image: "router"},
			model.KindService: {Image: "service"},
		},
		Templates: map[string]*model.ASTemplate{
			"edge": {Routers: map[string]*model.RouterSpec{"R": {ID: 1}},
				Hosts: model.HostPolicy{PerRouter: &noHosts}},
		},
		AutonomousSystems: []model.ASGroup{{
			List:   []int{1, 2, 3},
			ASSpec: model.ASSpec{Template: "edge", Role: model.RoleStaff},
		}},
		Services: map[string]*model.ServiceSpec{
			"dns": {
				Kind:        "builtin.dns",
				Attach:      &model.ServiceAttach{Template: "edge", Router: "R", Iface: "dns"},
				Replication: model.ServiceReplicationPolicy{Mode: model.ServicePerNode},
			},
		},
		Placement: model.Placement{Strategy: "pack-by-as"},
	}
	for i, name := range nodes {
		lab.Placement.Nodes = append(lab.Placement.Nodes, model.NodeSpec{Name: name, Front: i == 0})
	}
	lab.Normalize()
	return lab
}

func placedServiceTopology(t *testing.T, nodes []string) (*model.Topology, *Assignment) {
	t.Helper()
	result, err := expand.Expand(servicePlacementLab(nodes))
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := Place(result.Topology, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return result.Topology, assignment
}

func TestReplicatedServiceAttachmentsAreLocalAndUnique(t *testing.T) {
	top, assignment := placedServiceTopology(t, []string{"node-0", "node-1", "node-2"})
	service := top.Services["dns"]
	if got := assignment.Locality[model.LinkClassService].CrossNode; got != 0 {
		t.Fatalf("%d service links cross nodes despite a local replica on every node", got)
	}
	if len(service.Attachments) != len(top.ASes) {
		t.Fatalf("attachments = %v, want one for each AS", service.Attachments)
	}
	addresses := map[string]string{}
	for _, replica := range service.SortedReplicas() {
		for _, iface := range replica.Device.Ifaces {
			if iface.Addr4 == "" {
				continue
			}
			if other, duplicate := addresses[iface.Addr4]; duplicate {
				t.Errorf("%s and %s both own service address %s", other, replica.ID, iface.Addr4)
			}
			addresses[iface.Addr4] = replica.ID
		}
	}
	for asn, replicaID := range service.Attachments {
		replica, ok := service.Replica(replicaID)
		if !ok {
			t.Fatalf("AS %d selects unknown replica %q", asn, replicaID)
		}
		router, _ := top.DeviceInAS(asn, "R")
		if router.Node != replica.Node {
			t.Errorf("AS %d on %s attaches to %s on %s instead of its local replica",
				asn, router.Node, replica.ID, replica.Node)
		}
	}
}

func TestReplicaPlacementSurvivesNodeAdditionUntilRebalance(t *testing.T) {
	before, first := placedServiceTopology(t, []string{"node-0", "node-1"})
	record := first.Record(before.Name, "pack-by-as")
	dir := t.TempDir()
	if err := SaveRecord(dir, record); err != nil {
		t.Fatal(err)
	}
	record, err := LoadRecord(dir, before.Name)
	if err != nil {
		t.Fatal(err)
	}

	result, err := expand.Expand(servicePlacementLab([]string{"node-0", "node-1", "node-2"}))
	if err != nil {
		t.Fatal(err)
	}
	next, err := Place(result.Topology, Options{Fixed: record})
	if err != nil {
		t.Fatal(err)
	}
	for asn, node := range record.ByAS {
		if next.ByAS[asn] != node {
			t.Errorf("node addition moved AS %d from %s to %s without --rebalance", asn, node, next.ByAS[asn])
		}
	}
	for replica, node := range record.ByServiceReplica {
		if next.ByServiceReplica[replica] != node {
			t.Errorf("node addition moved %s from %s to %s without --rebalance",
				replica, node, next.ByServiceReplica[replica])
		}
	}
	if got := next.ByServiceReplica["dns/node-2"]; got != "node-2" {
		t.Errorf("new node replica placed on %q, want node-2: %v", got, next.ByServiceReplica)
	}
}

func TestNodeLossReschedulesReplicasWithoutUnhealthySelection(t *testing.T) {
	top, first := placedServiceTopology(t, []string{"node-0", "node-1", "node-2"})
	record := first.Record(top.Name, "pack-by-as")

	result, err := expand.Expand(servicePlacementLab([]string{"node-0", "node-1", "node-2"}))
	if err != nil {
		t.Fatal(err)
	}
	rescheduled, err := Place(result.Topology, Options{
		Fixed: record, Unavailable: map[string]bool{"node-0": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range result.Topology.SortedDevices() {
		if device.Node == "node-0" {
			t.Errorf("node-loss placement left %s on node-0", device.ID)
		}
	}
	if len(rescheduled.ByServiceReplica) != 3 {
		t.Fatalf("lost-node placement dropped replicas: %v", rescheduled.ByServiceReplica)
	}
	if reflect.DeepEqual(record.ByServiceReplica, rescheduled.ByServiceReplica) {
		t.Fatal("node-loss placement retained every lost replica assignment")
	}
}
