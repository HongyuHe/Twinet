package agent

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// procFiles is a host's /proc and /sys as this observer reads them.
func procObserver(files map[string]string) *hostInventoryObserver {
	observer := newHostInventoryObserver()
	observer.readFile = func(path string) ([]byte, error) {
		if value, ok := files[path]; ok {
			return []byte(value), nil
		}
		return nil, errors.New("no such file")
	}
	observer.readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("unavailable") }
	observer.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Index: 1, Name: "lo"}}, nil
	}
	observer.statfs = func(string) (syscall.Statfs_t, error) {
		return syscall.Statfs_t{Bsize: 4096, Blocks: 1 << 20, Bavail: 1 << 19}, nil
	}
	return observer
}

func hostFiles(fileMax string) map[string]string {
	return map[string]string{
		"/proc/meminfo":              "MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\n",
		"/proc/sys/kernel/pid_max":   "4194304\n",
		"/proc/sys/fs/file-max":      fileMax,
		"/proc/sys/fs/file-nr":       "3200 0 " + fileMax,
		"/proc/loadavg":              "0.10 0.20 0.30 1/100 1234\n",
		"/sys/fs/cgroup/memory.max":  "max\n",
		"/sys/fs/cgroup/pids.max":    "max\n",
		"/sys/fs/cgroup/cpu.max":     "max 100000\n",
		"/proc/stat":                 "cpu 100 0 100 800 0 0 0 0 0 0\n",
		"/sys/fs/cgroup/cpu.stat":    "usage_usec 0\n",
		"/proc/sys/fs/nr_open":       "1048576\n",
		"/proc/sys/net/core/somaxco": "4096\n",
	}
}

func hasDimension(all []string, want string) bool {
	for _, value := range all {
		if value == want {
			return true
		}
	}
	return false
}

// A kernel that imposes no system-wide file-handle ceiling reports LONG_MAX.
// Reserving a tenth of that produced an allocatable budget of
// 8301034833169298227 descriptors and offered it to operators and to admission
// as though a lab could ask for it.
func TestUnboundedFileHandleCeilingIsReportedAsUnlimitedNotAsAQuantity(t *testing.T) {
	observer := procObserver(hostFiles(fmt.Sprint(int64(math.MaxInt64)) + "\n"))
	inventory := observer.observe("", nil, nil)

	if inventory.Allocatable.FileDescriptors != nil {
		t.Fatalf("unbounded file-handle ceiling became an allocatable budget of %d",
			*inventory.Allocatable.FileDescriptors)
	}
	if inventory.Physical.FileDescriptors != nil {
		t.Fatalf("unbounded file-handle ceiling became a physical quantity of %d",
			*inventory.Physical.FileDescriptors)
	}
	for _, want := range []string{"physical.file_descriptors", "allocatable.file_descriptors"} {
		if !hasDimension(inventory.Unlimited, want) {
			t.Errorf("%s is not reported as unlimited: %v", want, inventory.Unlimited)
		}
		if hasDimension(inventory.Unknown, want) {
			t.Errorf("%s is reported as unknown, which strict admission refuses: %v",
				want, inventory.Unknown)
		}
	}
	// The netdev estimate is derived from handle headroom. An unbounded
	// headroom bounds nothing, so the conservative constant must remain.
	if inventory.NetworkDevice.Limit == nil || *inventory.NetworkDevice.Limit != 5000 {
		t.Errorf("netdev limit = %v, want the conservative 5000 estimate",
			inventory.NetworkDevice.Limit)
	}
	if inventory.Allocatable.Containers == nil || *inventory.Allocatable.Containers < 1 {
		t.Errorf("container estimate collapsed with the unlimited dimension: %v",
			inventory.Allocatable.Containers)
	}
}

// A real ceiling is still a number, and an unreadable one is still unknown.
// The three states must stay distinct.
func TestFileHandleCeilingKeepsQuantityAndUnknownDistinctFromUnlimited(t *testing.T) {
	bounded := procObserver(hostFiles("1000000\n")).observe("", nil, nil)
	if bounded.Allocatable.FileDescriptors == nil || *bounded.Allocatable.FileDescriptors <= 0 {
		t.Fatalf("a real ceiling was not reported as a quantity: %+v", bounded.Allocatable)
	}
	if len(bounded.Unlimited) != 0 {
		t.Errorf("a bounded host reported unlimited dimensions: %v", bounded.Unlimited)
	}

	files := hostFiles("1000000\n")
	delete(files, "/proc/sys/fs/file-max")
	unknown := procObserver(files).observe("", nil, nil)
	if unknown.Allocatable.FileDescriptors != nil {
		t.Fatalf("an unreadable ceiling became a quantity: %+v", unknown.Allocatable)
	}
	if !hasDimension(unknown.Unknown, "allocatable.file_descriptors") {
		t.Errorf("an unreadable ceiling was not reported as unknown: %v", unknown.Unknown)
	}
	if hasDimension(unknown.Unlimited, "allocatable.file_descriptors") {
		t.Errorf("an unreadable ceiling was reported as unlimited: %v", unknown.Unlimited)
	}
}

// The metrics endpoint publishes the third state too, or a dashboard reading
// only "unknown" would still have to guess.
func TestInventoryMetricsPublishUnlimitedDimensions(t *testing.T) {
	var b strings.Builder
	appendInventoryMetrics(&b, HostInventory{
		Unknown:   []string{"used.file_descriptors"},
		Unlimited: []string{"allocatable.file_descriptors"},
	})
	out := b.String()
	if !strings.Contains(out, `twinet_inventory_unlimited{dimension="allocatable.file_descriptors"} 1`) {
		t.Errorf("unlimited dimensions are not published: %s", out)
	}
	if !strings.Contains(out, `twinet_inventory_unknown{dimension="used.file_descriptors"} 1`) {
		t.Errorf("unknown dimensions stopped being published: %s", out)
	}
}
