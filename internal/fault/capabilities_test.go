package fault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func taxonomyNames(t *testing.T) map[string]string {
	t.Helper()
	var names map[string]string
	if err := json.Unmarshal(nikaTypes, &names); err != nil {
		t.Fatal(err)
	}
	return names
}

func TestPinnedTaxonomyHasNativeOrDelegatedSupport(t *testing.T) {
	want := taxonomyNames(t)
	if len(want) != 60 {
		t.Fatalf("pinned taxonomy has %d names, want 60", len(want))
	}
	for name := range want {
		f, ok := Lookup(name)
		if !ok {
			t.Errorf("%s is missing from the registry", name)
			continue
		}
		if name == "k8s_clusterip_routing_broken" || name == "k8s_coredns_isolated" ||
			name == "k8s_networkpolicy_deny" || name == "k8s_worker_apiserver_partition" {
			if !f.Delegated {
				t.Errorf("%s must be explicitly delegated, not emulated by a container", name)
			}
			continue
		}
		if f.Delegated {
			t.Errorf("%s is unexpectedly delegated", name)
		}
	}
}

func TestKubernetesCapabilityRefusesBeforeInjection(t *testing.T) {
	env := &Env{}
	_, err := Inject(context.Background(), env, "k8s_coredns_isolated",
		Target{Device: "k8s/default/coredns"})
	if err == nil || !strings.Contains(err.Error(), "no NIKA Kubernetes endpoint/context") {
		t.Fatalf("delegated fault did not fail capability discovery before injection: %v", err)
	}
}

func TestDelegatedKubernetesUsesTheCommonLifecycle(t *testing.T) {
	backend := &fakeKubernetesBackend{}
	env := &Env{Kubernetes: backend}
	inj, err := Inject(context.Background(), env, "k8s_networkpolicy_deny",
		Target{Device: "k8s/demo/client"})
	if err != nil {
		t.Fatal(err)
	}
	if !inj.Evidence.Verified || inj.Truth.Category != string(CatMisconfig) {
		t.Fatalf("delegated result did not use common incident schema: %#v", inj)
	}
	if err := Resolve(context.Background(), env, inj); err != nil {
		t.Fatal(err)
	}
	if !backend.resolved {
		t.Fatal("common resolver did not call delegated backend")
	}
}

func TestP4CapabilityRequiresTypedTarget(t *testing.T) {
	f, ok := Lookup("p4_table_entry_missing")
	if !ok {
		t.Fatal("P4 fault is not registered")
	}

	top := &model.Topology{Devices: map[string]*model.Device{
		"as1/p4": {ID: "as1/p4", Kind: model.KindP4, ASN: 1, P4: &model.P4Runtime{
			Table: "ipv4_lpm", ForwardAction: "forward", ThriftPort: 9090,
		}},
	}}
	// A no-executor environment must explain the missing operation rather
	// than claim a P4 table fault is usable on a generic target.
	rows := AvailabilityFor(context.Background(), f, &Env{Topology: top}, Target{Device: "as1/p4"})
	if len(rows) != 1 || rows[0].Available {
		t.Fatalf("P4 capability did not refuse missing executor: %#v", rows)
	}
}

func TestScenarioMustDeclareItsTypedSubstrate(t *testing.T) {
	err := ValidateScenarioRequirements([]string{"p4_table_entry_missing"}, nil)
	if err == nil || !strings.Contains(err.Error(), "p4-bmv2") {
		t.Fatalf("missing P4 requirement was accepted: %v", err)
	}
	if err := ValidateScenarioRequirements([]string{"p4_table_entry_missing"}, []Substrate{SubstrateP4BMv2}); err != nil {
		t.Fatalf("declared P4 requirement was rejected: %v", err)
	}
}

type fakeKubernetesBackend struct {
	live     bool
	resolved bool
}

func (f *fakeKubernetesBackend) Available(context.Context) (bool, string, error) {
	return true, "fake NIKA Kubernetes contract", nil
}

func (f *fakeKubernetesBackend) Inject(_ context.Context, _ string, _ Target) (State, Evidence, error) {
	f.live = true
	return State{"resource": "networkpolicy/demo"}, Evidence{Verified: true, Observed: "policy denies traffic"}, nil
}

func (f *fakeKubernetesBackend) Verify(_ context.Context, _ string, _ Target, _ State) (Evidence, error) {
	return Evidence{Verified: f.live, Observed: "policy state"}, nil
}

func (f *fakeKubernetesBackend) Resolve(_ context.Context, _ string, _ Target, _ State) error {
	f.live, f.resolved = false, true
	return nil
}
