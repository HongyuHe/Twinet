package deploy

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestRecoveryCompatibilityStripsLegacySysAdminOnlyDuringRollback(t *testing.T) {
	device := &model.Device{
		ID: "as1/R1", Kind: model.KindRouter,
		Capabilities: []string{"NET_ADMIN", "SYS_ADMIN"},
	}
	if _, err := (&Engine{}).hardenedRuntimeSpec(device, nil); err == nil {
		t.Fatal("ordinary deployment accepted legacy SYS_ADMIN")
	}
	spec, err := (&Engine{RecoveryCompatibility: true}).hardenedRuntimeSpec(device, nil)
	if err != nil {
		t.Fatalf("fenced recovery could not reconstruct legacy router: %v", err)
	}
	for _, capability := range spec.Capabilities {
		if capability == "SYS_ADMIN" {
			t.Fatal("recovery reintroduced SYS_ADMIN into a student container")
		}
	}
}
