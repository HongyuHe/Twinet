package expand

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

func replicatedServiceLab(policy model.ServiceReplicationPolicy) *model.Lab {
	noHosts := false
	lab := &model.Lab{
		APIVersion: model.APIVersion,
		Kind:       model.KindLab,
		Metadata:   model.Meta{Name: "replicas"},
		Addressing: model.Addressing{
			ASBlock:        "{{ .AS }}.0.0.0/8",
			RouterLoopback: "{{ .AS }}.150.0.1/24",
			RouterRouter:   "{{ .AS }}.0.1.0/24",
			RouterHost:     "{{ .AS }}.100.0.0/24",
			InterAS:        "179.{{ .Low }}.{{ .High }}.0/24",
			Services: map[string]string{
				"dns": "198.{{ .AS }}.0.0/24",
			},
		},
		Kinds: map[model.DeviceKind]model.DeviceDefaults{
			model.KindService: {Image: "service"},
			model.KindRouter:  {Image: "router"},
		},
		Templates: map[string]*model.ASTemplate{
			"edge": {
				Routers: map[string]*model.RouterSpec{"R": {ID: 1}},
				Hosts:   model.HostPolicy{PerRouter: &noHosts},
			},
		},
		AutonomousSystems: []model.ASGroup{{
			List:   []int{1, 2, 3},
			ASSpec: model.ASSpec{Template: "edge", Role: model.RoleStaff},
		}},
		Services: map[string]*model.ServiceSpec{
			"dns": {
				Kind:        "builtin.dns",
				Attach:      &model.ServiceAttach{Template: "edge", Router: "R", Iface: "dns"},
				Replication: policy,
			},
		},
		Placement: model.Placement{
			Strategy: "pack-by-as",
			Nodes: []model.NodeSpec{
				{Name: "node-0", Front: true},
				{Name: "node-1"},
				{Name: "node-2"},
			},
		},
	}
	lab.Normalize()
	return lab
}

func replicaFingerprint(top *model.Topology) []string {
	service := top.Services["dns"]
	var out []string
	for _, replica := range service.SortedReplicas() {
		out = append(out, replica.ID+"|"+replica.Identity+"|"+replica.Device.ID+"|"+replica.Node)
	}
	sort.Strings(out)
	return out
}

func TestServiceReplicaExpansionIsDeterministic(t *testing.T) {
	policy := model.ServiceReplicationPolicy{Mode: model.ServicePerNode}
	first, err := Expand(replicatedServiceLab(policy))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Expand(replicatedServiceLab(policy))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := replicaFingerprint(first.Topology), replicaFingerprint(second.Topology); !reflect.DeepEqual(got, want) {
		t.Fatalf("replica identities changed between equivalent expansions:\nfirst=%v\nsecond=%v", got, want)
	}
	service := first.Topology.Services["dns"]
	if len(service.Replicas) != 3 {
		t.Fatalf("per-node service expanded %d replicas, want 3", len(service.Replicas))
	}
	for _, replica := range service.SortedReplicas() {
		if replica.Identity != "anycast:dns" {
			t.Errorf("%s has identity %q, want the stable DNS anycast identity", replica.ID, replica.Identity)
		}
		if replica.Device.ServiceReplica != replica.ID {
			t.Errorf("%s lost its stable replica metadata: %#v", replica.ID, replica.Device)
		}
	}
}

func TestShardedServiceUsesGeneratedStableIdentities(t *testing.T) {
	result, err := Expand(replicatedServiceLab(model.ServiceReplicationPolicy{
		Mode: model.ServiceSharded, ShardSize: 2, Selector: model.ServiceShardByAS,
	}))
	if err != nil {
		t.Fatal(err)
	}
	service := result.Topology.Services["dns"]
	if len(service.Replicas) != 2 {
		t.Fatalf("three ASes at shard size two produced %d replicas, want 2", len(service.Replicas))
	}
	for index, replica := range service.SortedReplicas() {
		want := fmt.Sprintf("shard:dns:%03d", index+1)
		if replica.Identity != want {
			t.Errorf("shard %d identity = %q, want %q", index, replica.Identity, want)
		}
	}
}

func TestVersionedScalableDefaultDoesNotRewriteLegacyManifests(t *testing.T) {
	legacy := replicatedServiceLab(model.ServiceReplicationPolicy{})
	old, err := Expand(legacy)
	if err != nil {
		t.Fatal(err)
	}

	if got := len(old.Topology.Services["dns"].Replicas); got != 0 {
		t.Fatalf("legacy v1 service gained %d implicit replicas", got)
	}

	migrated := replicatedServiceLab(model.ServiceReplicationPolicy{})
	migrated.ServicePolicyVersion = "v2"
	newer, err := Expand(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(newer.Topology.Services["dns"].Replicas); got != 3 {
		t.Fatalf("versioned v2 default expanded %d replicas, want one per node", got)
	}
}

func TestReplicaAttachmentRebalanceDoesNotChangeCourseTopologyHash(t *testing.T) {
	result, err := Expand(replicatedServiceLab(model.ServiceReplicationPolicy{Mode: model.ServicePerNode}))
	if err != nil {
		t.Fatal(err)
	}
	before := result.Topology.Hash
	if _, err := place.Place(result.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	if got := TopologyHash(result.Topology); got != before {
		t.Fatalf("placement-selected replica cables changed course topology hash: %s -> %s", before, got)
	}
}
