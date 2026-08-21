package agent

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestUnknownInventoryIsExplicitAndNeverZeroCapacity(t *testing.T) {
	observer := newHostInventoryObserver()
	observer.readFile = func(string) ([]byte, error) { return nil, errors.New("unavailable") }
	observer.readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("unavailable") }
	observer.interfaces = func() ([]net.Interface, error) { return nil, errors.New("unavailable") }
	observer.statfs = func(string) (syscall.Statfs_t, error) {
		return syscall.Statfs_t{}, errors.New("unavailable")
	}
	inventory := observer.observe("", nil, nil)
	if inventory.Allocatable.MemoryBytes != nil || inventory.Allocatable.DiskBytes != nil ||
		inventory.Allocatable.Pids != nil || inventory.Allocatable.FileDescriptors != nil ||
		inventory.Allocatable.NetDevices != nil {
		t.Fatalf("unreadable inventory was represented as capacity: %+v", inventory.Allocatable)
	}
	if !containsInventoryUnknown(inventory.Unknown, "allocatable.memory") ||
		!containsInventoryUnknown(inventory.Unknown, "allocatable.disk") {
		t.Fatalf("unknown dimensions were not named: %v", inventory.Unknown)
	}
}

func TestReservationFallsBackToConservativeKindRequest(t *testing.T) {
	reservation := reservationForContainer(rt.Container{Labels: map[string]string{
		"twinet.kind": "router",
	}})
	if reservation.CPUs == nil || *reservation.CPUs <= 0 ||
		reservation.MemoryBytes == nil || *reservation.MemoryBytes <= 0 ||
		reservation.NetDevices == nil || *reservation.NetDevices <= 0 {
		t.Fatalf("legacy container was treated as free capacity: %+v", reservation)
	}
}

func containsInventoryUnknown(all []string, want string) bool {
	for _, value := range all {
		if value == want {
			return true
		}
	}
	return false
}
