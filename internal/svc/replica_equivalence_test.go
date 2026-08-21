package svc

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/expand"
	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/place"
)

func replicatedScaleTopology(t *testing.T) *model.Topology {
	t.Helper()
	loaded, err := manifest.Load("../../examples/scale")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expand.Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := place.Place(result.Topology, place.Options{}); err != nil {
		t.Fatal(err)
	}
	return result.Topology
}

func TestReplicatedDNSAndRTRAddressesFollowLocalAttachments(t *testing.T) {
	top := replicatedScaleTopology(t)
	for _, asn := range top.SortedASNs() {
		for _, kind := range []string{"builtin.dns", "builtin.rpki"} {
			var serviceName string
			for _, name := range top.SortedServiceNames() {
				if top.Services[name].Kind == kind {
					serviceName = name
					break
				}
			}
			if serviceName == "" {
				continue
			}
			service := top.Services[serviceName]
			replica, ok := service.ReplicaForAS(asn)
			if !ok {
				continue
			}
			router := top.ASes[asn].Routers[0]
			if router.Node != replica.Node {
				t.Errorf("%s AS %d chose replica %s on %s while its router is on %s",
					kind, asn, replica.ID, replica.Node, router.Node)
			}
			var got string
			if kind == "builtin.dns" {
				got = ResolverFor(top, asn)
			} else {
				got = RPKIAddrFor(top, asn)
			}
			if got == "" {
				t.Errorf("%s AS %d has no selected service address", kind, asn)
			}
		}
	}
}

func TestDeclaredRPKIPayloadIsReplicaEquivalent(t *testing.T) {
	top := replicatedScaleTopology(t)
	first := BuildRPKI(top, top.Lab.RPKI.NotFound, top.Lab.RPKI.Invalid).JSON()
	second := BuildRPKI(top, top.Lab.RPKI.NotFound, top.Lab.RPKI.Invalid).JSON()
	if string(first) != string(second) {
		t.Fatalf("equivalent replica renders produced different RTR state:\n%s\n---\n%s", first, second)
	}
}

func TestMatrixWorkersAreDeclaredPerNodeForCollectorAggregation(t *testing.T) {
	top := replicatedScaleTopology(t)
	workers := LocalWorkers(top, "matrix")
	if len(workers) != len(top.Lab.Placement.Nodes) {
		t.Fatalf("matrix workers = %#v, want one per placement node", workers)
	}
	seen := map[string]bool{}
	for _, worker := range workers {
		if worker.Service != "builtin.matrix" || worker.Node == "" || worker.Replica == "" {
			t.Errorf("invalid local matrix worker %#v", worker)
		}
		if seen[worker.Node] {
			t.Errorf("multiple matrix workers landed on %s: %#v", worker.Node, workers)
		}
		seen[worker.Node] = true
	}
}
