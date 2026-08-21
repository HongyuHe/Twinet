package web

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestWebEndpointListFailsOverWithoutChangingTopology(t *testing.T) {
	top := webBatchTopology()
	spec := &model.ServiceSpec{
		Kind:        "builtin.web",
		Listen:      ":9000",
		Replication: model.ServiceReplicationPolicy{Mode: model.ServicePerNode},
		Endpoints: model.EndpointPolicy{
			Mode: model.EndpointActiveStandby, Nodes: []string{"node-1", "node-0"}, VIP: "web.example.test",
		},
	}
	top.Lab = &model.Lab{
		Metadata: model.Meta{Name: "web"},
		Services: map[string]*model.ServiceSpec{"web": spec},
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "node-0", Front: true}, {Name: "node-1"},
		}},
	}
	top.Lab.Normalize()
	top.Services = map[string]*model.Service{
		"web": {Name: "web", Kind: "builtin.web", Spec: spec, Policy: top.Lab.EffectiveReplication(spec)},
	}
	before := make(map[string]string, len(top.Devices))
	for id, device := range top.Devices {
		before[id] = device.Node
	}
	endpoints := top.WebEndpoints()
	if len(endpoints) != 2 {
		t.Fatalf("web endpoints = %#v, want one on each node", endpoints)
	}
	if endpoints[0].Node != "node-1" || !endpoints[0].Primary || endpoints[0].VIP != "web.example.test" {
		t.Fatalf("web endpoint policy was not preserved: %#v", endpoints)
	}
	selected, err := model.SelectHealthyEndpoint(endpoints, map[string]bool{
		"node-0": false, "node-1": true,
	})
	if err != nil || selected.Node != "node-1" {
		t.Fatalf("web failover selected %#v, %v; want node-1", selected, err)
	}
	for id, device := range top.Devices {
		if device.Node != before[id] {
			t.Errorf("web failover changed device %s placement from %q to %q", id, before[id], device.Node)
		}
	}
}
