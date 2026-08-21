package model

import "testing"

func TestRequestsRemainSeparateFromHardLimits(t *testing.T) {
	limitCPU := 4.0
	limitPIDs := int64(512)
	base := DeviceDefaults{
		CPUs: &limitCPU, Memory: "2Gi", Pids: &limitPIDs,
		Requests: &ResourceRequest{
			CPUs: 0.5, Memory: "128Mi", Pids: 64, EphemeralStorage: "256Mi",
			FileDescriptors: 1024, NetDevices: 8,
		},
	}
	override := DeviceDefaults{Requests: &ResourceRequest{CPUs: 1}}
	got := override.Merge(base)
	if got.CPUs == nil || *got.CPUs != 4 || got.Memory != "2Gi" || got.Pids == nil || *got.Pids != 512 {
		t.Fatalf("hard limits changed while merging requests: %#v", got)
	}
	if got.Requests == nil || got.Requests.CPUs != 1 || got.Requests.Memory != "128Mi" ||
		got.Requests.Pids != 64 || got.Requests.NetDevices != 8 {
		t.Fatalf("requests did not inherit independently: %#v", got.Requests)
	}
}

func TestPerKindRequestDefaultsAreComplete(t *testing.T) {
	for _, kind := range []DeviceKind{KindRouter, KindHost, KindSwitch, KindService} {
		got := EffectiveResourceRequest(kind, nil)
		if got.CPUs <= 0 || got.Memory == "" || got.Pids <= 0 || got.Storage() == "" ||
			got.FileDescriptors <= 0 || got.NetDevices <= 0 {
			t.Errorf("%s default request is incomplete: %#v", kind, got)
		}
	}
}

func TestDiskAliasOverridesEphemeralDefault(t *testing.T) {
	got := EffectiveResourceRequest(KindRouter, &ResourceRequest{Disk: "1Gi"})
	if got.Storage() != "1Gi" || got.Disk != "" {
		t.Fatalf("disk alias was shadowed by the default: %#v", got)
	}
}
