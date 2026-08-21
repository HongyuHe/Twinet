package model

import "testing"

func endpointTestLab() *Lab {
	lab := &Lab{Placement: Placement{Nodes: []NodeSpec{
		{Name: "node-0", Front: true}, {Name: "node-1"},
	}}, Access: Access{Listen: ":2022"}}
	lab.Normalize()
	return lab
}

func TestGatewayEndpointsAreDeterministicAndHealthAware(t *testing.T) {
	lab := endpointTestLab()
	endpoints := lab.GatewayEndpoints()
	if len(endpoints) != 2 {
		t.Fatalf("gateway endpoints = %#v, want both nodes", endpoints)
	}
	if endpoints[0].Address != "node-0:2022" || endpoints[1].Address != "node-1:2022" {
		t.Fatalf("unexpected endpoint addresses: %#v", endpoints)
	}
	if got, err := SelectHealthyEndpoint(endpoints, map[string]bool{"node-0": false, "node-1": true}); err != nil || got.Node != "node-1" {
		t.Fatalf("failover selected %#v, %v; want healthy node-1", got, err)
	}
	if _, err := SelectHealthyEndpoint(endpoints, map[string]bool{"node-0": false, "node-1": false}); err == nil {
		t.Fatal("endpoint selection silently accepted an unhealthy endpoint")
	}
}

func TestActiveStandbyUsesStablePrimaryThenFailsOver(t *testing.T) {
	lab := endpointTestLab()
	lab.Access.Endpoints = EndpointPolicy{
		Mode: EndpointActiveStandby, Nodes: []string{"node-1", "node-0"},
	}
	endpoints := lab.GatewayEndpoints()
	if !endpoints[0].Primary || endpoints[0].Node != "node-1" {
		t.Fatalf("active/standby primary = %#v, want node-1", endpoints)
	}
	if got, err := SelectHealthyEndpoint(endpoints, map[string]bool{"node-1": true, "node-0": true}); err != nil || got.Node != "node-1" {
		t.Fatalf("healthy primary was not selected: %#v, %v", got, err)
	}
	if got, err := SelectHealthyEndpoint(endpoints, map[string]bool{"node-1": false, "node-0": true}); err != nil || got.Node != "node-0" {
		t.Fatalf("standby failover = %#v, %v; want node-0", got, err)
	}
}

func TestHealthyReplicaSelectionPrefersLocalAndRefusesUnknown(t *testing.T) {
	service := &Service{
		Name: "dns",
		Replicas: []*ServiceReplica{
			{ID: "dns/node-0", Node: "node-0"},
			{ID: "dns/node-1", Node: "node-1"},
		},
	}
	if got, err := service.SelectHealthyReplica(10, "node-1",
		ServiceReplicaHealth{"dns/node-0": true, "dns/node-1": true}); err != nil || got.ID != "dns/node-1" {
		t.Fatalf("local healthy replica was not selected: %#v, %v", got, err)
	}
	if got, err := service.SelectHealthyReplica(10, "node-1",
		ServiceReplicaHealth{"dns/node-0": true, "dns/node-1": false}); err != nil || got.ID != "dns/node-0" {
		t.Fatalf("healthy remote fallback = %#v, %v", got, err)
	}
	if _, err := service.SelectHealthyReplica(10, "node-1", ServiceReplicaHealth{}); err == nil {
		t.Fatal("unknown replicas were silently considered healthy")
	}
}
