package client

import (
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
)

// The agent and the placer name dimensions differently. A mistranslation here
// would silently exempt a dimension from strict admission, so only the
// allocatable names it knows are carried across.
func TestUnlimitedDimensionsAreTranslatedForAdmission(t *testing.T) {
	inventory := placementInventory("node-0", agent.HostInventory{
		Unlimited: []string{
			"allocatable.file_descriptors",
			"physical.file_descriptors",
			"allocatable.pids",
			"something.new",
		},
	})
	want := []string{"file descriptors", "pids"}
	if len(inventory.Unlimited) != len(want) {
		t.Fatalf("unlimited = %v, want %v", inventory.Unlimited, want)
	}
	for i, name := range want {
		if inventory.Unlimited[i] != name {
			t.Fatalf("unlimited = %v, want %v", inventory.Unlimited, want)
		}
	}
}
