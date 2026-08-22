package deploy

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestFRRControlUsesSteadyRequestButRouterBurstLimits(t *testing.T) {
	d := &model.Device{
		ID: "as1/R1", Name: "R1", Kind: model.KindRouter, ASN: 1,
		Image: "router:latest", Container: "router-r1", Node: "node-a",
		CPUs: 2, Memory: "512Mi", Pids: 256,
		Requests: model.ResourceRequest{
			CPUs: 0.04, Memory: "128Mi", Pids: 64, EphemeralStorage: "256Mi",
			FileDescriptors: 1024, NetDevices: 8,
		},
	}
	top := &model.Topology{Name: "lab", Lab: &model.Lab{}, Devices: map[string]*model.Device{d.ID: d}}
	final, err := (&Engine{Runtime: hardeningRuntime{}, FRRControlRoot: "frr-control-test"}).finalRuntimeSpecs(top, d)
	if err != nil {
		t.Fatal(err)
	}
	if final.controlSpec == nil {
		t.Fatal("FRR router has no control sidecar spec")
	}
	if got := final.controlSpec.CPUs; got != 2 {
		t.Fatalf("sidecar burst CPU limit = %.2f, want router limit 2", got)
	}
	if got := final.controlSpec.Memory; got != "512Mi" {
		t.Fatalf("sidecar burst memory limit = %q, want router limit 512Mi", got)
	}
	if got := final.controlSpec.PidsLimit; got != 256 {
		t.Fatalf("sidecar PID limit = %d, want router limit 256", got)
	}
	if got := final.controlSpec.Labels[LabelRequestCPU]; got != "0.08" {
		t.Fatalf("sidecar request label = %q, want steady 0.08", got)
	}
}
