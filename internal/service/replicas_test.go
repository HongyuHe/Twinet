package service_test

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
	serviceplan "github.com/HongyuHe/twinet/internal/service"
)

func TestHealthReconciliationNeverKeepsAnUnhealthyReplica(t *testing.T) {
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := place.Place(result.Topology, place.Options{})
	if err != nil {
		t.Fatal(err)
	}
	service := result.Topology.Services["dns"]
	if service == nil || len(service.Replicas) < 2 {
		t.Fatal("scale DNS lacks replicas")
	}
	healthy := model.ServiceReplicaHealth{}
	for _, name := range result.Topology.SortedServiceNames() {
		for _, replica := range result.Topology.Services[name].SortedReplicas() {
			healthy[replica.ID] = true
		}
	}
	fallback := service.SortedReplicas()[0]
	for _, replica := range service.SortedReplicas() {
		healthy[replica.ID] = replica.ID == fallback.ID
	}
	if err := serviceplan.ReconcileHealthyAttachments(result.Topology, assignment.ByAS, healthy); err != nil {
		t.Fatal(err)
	}
	for asn, replicaID := range service.Attachments {
		if replicaID != fallback.ID {
			t.Errorf("AS %d remains attached to %s after it was reported unhealthy; want %s",
				asn, replicaID, fallback.ID)
		}
	}
	if err := serviceplan.ReconcileHealthyAttachments(result.Topology, assignment.ByAS,
		model.ServiceReplicaHealth{}); err == nil {
		t.Fatal("all-unhealthy service state was silently reconciled")
	}
}
