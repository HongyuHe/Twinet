package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/agent"
)

func inventoryVector(fd *int64) agent.ResourceInventory {
	cpus := 32.0
	memory := int64(200 << 30)
	disk := int64(500 << 30)
	pids := int64(500000)
	netdevs := int64(4000)
	return agent.ResourceInventory{
		CPUs: &cpus, MemoryBytes: &memory, DiskBytes: &disk,
		Pids: &pids, FileDescriptors: fd, NetDevices: &netdevs,
	}
}

// `node status` printed 8301034833169298227fd on a host whose kernel imposes
// no file-handle ceiling. The column has to say that the dimension is
// unbounded, not offer an unreachable number as a budget.
func TestNodeStatusNamesAnUnlimitedDimension(t *testing.T) {
	got := inventorySummary(inventoryVector(nil), []string{"allocatable.file_descriptors"})
	if !strings.Contains(got, "unlimited-fd") {
		t.Errorf("allocatable summary = %q, want an explicit unlimited file-descriptor term", got)
	}
	if strings.Contains(got, "unknown") {
		t.Errorf("an unlimited dimension collapsed the whole vector to unknown: %q", got)
	}
}

// An unknown dimension is still unknown, and a real one is still a number.
func TestNodeStatusKeepsUnknownAndBoundedDimensionsUnchanged(t *testing.T) {
	if got := inventorySummary(inventoryVector(nil), nil); got != "unknown" {
		t.Errorf("summary with an unreadable dimension = %q, want unknown", got)
	}
	fd := int64(1048576)
	got := inventorySummary(inventoryVector(&fd), []string{"allocatable.pids"})
	if !strings.Contains(got, "1048576fd") {
		t.Errorf("summary = %q, want the measured file-descriptor budget", got)
	}
}
