package agent

import (
	"bufio"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// ResourceInventory carries one observed resource vector. Nil explicitly means
// unknown; it never means zero capacity. Byte quantities avoid presentation
// parsing on the controller's admission path.
type ResourceInventory struct {
	CPUs            *float64 `json:"cpus"`
	MemoryBytes     *int64   `json:"memory_bytes"`
	DiskBytes       *int64   `json:"disk_bytes"`
	Pids            *int64   `json:"pids"`
	FileDescriptors *int64   `json:"file_descriptors"`
	NetDevices      *int64   `json:"netdevs"`
	Containers      *int     `json:"containers"`
}

// LoadAverage is the kernel's one-, five-, and fifteen-minute runnable/load
// estimate. It is reported separately from admission reservations because
// transient host load is useful to operators but must not make an already
// admitted topology move underneath students.
type LoadAverage struct {
	One     *float64 `json:"one"`
	Five    *float64 `json:"five"`
	Fifteen *float64 `json:"fifteen"`
}

// NetworkDeviceInventory exposes the observed host count and the conservative
// admission estimate separately. Linux has no portable hard maximum number of
// netdevs, so Limit is an estimate derived from file-handle headroom; nil is
// returned if that evidence cannot be read.
type NetworkDeviceInventory struct {
	Count *int64 `json:"count"`
	Limit *int64 `json:"limit"`
}

// ImageCacheInventory describes the local Docker image metadata cache. Bytes
// may remain unknown on storage drivers that do not expose per-image size.
type ImageCacheInventory struct {
	Count      *int     `json:"count"`
	Bytes      *int64   `json:"bytes"`
	Referenced int      `json:"referenced"`
	Unknown    []string `json:"unknown,omitempty"`
}

// HostInventory is the agent's admission and operator view of its host.
// Reserved is the sum of Twinet requests, while Used is system observation;
// admission subtracts Reserved, not a noisy instantaneous CPU sample.
type HostInventory struct {
	ObservedAt    time.Time                    `json:"observed_at"`
	Physical      ResourceInventory            `json:"physical"`
	Allocatable   ResourceInventory            `json:"allocatable"`
	Used          ResourceInventory            `json:"used"`
	Reserved      ResourceInventory            `json:"reserved"`
	Reservations  map[string]ResourceInventory `json:"reservations_by_lab,omitempty"`
	Load          LoadAverage                  `json:"load"`
	NetworkDevice NetworkDeviceInventory       `json:"network_devices"`
	ImageCache    ImageCacheInventory          `json:"image_cache"`
	Unknown       []string                     `json:"unknown,omitempty"`
}

type cpuSample struct {
	total uint64
	idled uint64
	at    time.Time
}

type hostInventoryObserver struct {
	mu       sync.Mutex
	previous *cpuSample

	readFile   func(string) ([]byte, error)
	readDir    func(string) ([]os.DirEntry, error)
	interfaces func() ([]net.Interface, error)
	statfs     func(string) (syscall.Statfs_t, error)
	now        func() time.Time
}

func newHostInventoryObserver() *hostInventoryObserver {
	return &hostInventoryObserver{
		readFile:   os.ReadFile,
		readDir:    os.ReadDir,
		interfaces: net.Interfaces,
		statfs: func(path string) (syscall.Statfs_t, error) {
			var st syscall.Statfs_t
			err := syscall.Statfs(path, &st)
			return st, err
		},
		now: time.Now,
	}
}

func (s *Server) observeHostInventory(containers []rt.Container, listErr error) HostInventory {
	s.inventoryMu.Lock()
	if s.inventory == nil {
		s.inventory = newHostInventoryObserver()
	}
	observer := s.inventory
	s.inventoryMu.Unlock()
	requests := map[string]model.ResourceRequest{}
	s.mu.Lock()
	for _, top := range s.current {
		if top == nil {
			continue
		}
		for _, d := range top.SortedDevices() {
			request := d.Requests
			if request.Empty() {
				request = model.DefaultResourceRequest(d.Kind)
			}
			requests[d.Container] = request
		}
	}
	s.mu.Unlock()
	return observer.observe(s.cfg.StateDir, containers, listErr, requests)
}

func (o *hostInventoryObserver) observe(stateDir string, containers []rt.Container, listErr error,
	desired ...map[string]model.ResourceRequest,
) HostInventory {
	now := o.now()
	inv := HostInventory{
		ObservedAt:   now.UTC(),
		Reservations: map[string]ResourceInventory{},
	}
	unknown := map[string]bool{}
	markUnknown := func(names ...string) {
		for _, name := range names {
			unknown[name] = true
		}
	}

	cpus := float64(runtime.NumCPU())
	if cpus > 0 {
		inv.Physical.CPUs = float64Ptr(cpus)
	} else {
		markUnknown("physical.cpus", "allocatable.cpus")
	}
	cpuLimit := cgroupCPUQuota(o.readFile)
	if inv.Physical.CPUs != nil {
		allocBase := *inv.Physical.CPUs
		if cpuLimit != nil && *cpuLimit < allocBase {
			allocBase = *cpuLimit
		}
		alloc := reserveCPU(allocBase)
		inv.Allocatable.CPUs = float64Ptr(alloc)
	} else {
		markUnknown("physical.cpus", "allocatable.cpus")
	}
	if used := o.cpuUsage(now); used != nil {
		inv.Used.CPUs = used
	} else {
		markUnknown("used.cpus")
	}

	memTotal, memAvailable, ok := memInfo(o.readFile)
	if !ok {
		markUnknown("physical.memory", "used.memory")
		if limit := cgroupMemoryLimit(o.readFile); limit != nil {
			inv.Allocatable.MemoryBytes = int64Ptr(reserveBytes(*limit, 256<<20))
		} else {
			markUnknown("allocatable.memory")
		}
	} else {
		allocTotal := memTotal
		if limit := cgroupMemoryLimit(o.readFile); limit != nil && *limit < allocTotal {
			allocTotal = *limit
			if memAvailable > allocTotal {
				memAvailable = allocTotal
			}
		}
		inv.Physical.MemoryBytes = int64Ptr(memTotal)
		inv.Allocatable.MemoryBytes = int64Ptr(reserveBytes(allocTotal, 256<<20))
		inv.Used.MemoryBytes = int64Ptr(maxInt64(0, allocTotal-memAvailable))
	}

	diskPath := inventoryPath(stateDir)
	if st, err := o.statfs(diskPath); err != nil || st.Bsize == 0 {
		markUnknown("physical.disk", "allocatable.disk", "used.disk")
	} else {
		total := int64(st.Blocks) * int64(st.Bsize)
		available := int64(st.Bavail) * int64(st.Bsize)
		inv.Physical.DiskBytes = int64Ptr(total)
		inv.Allocatable.DiskBytes = int64Ptr(reserveBytes(total, 1<<30))
		inv.Used.DiskBytes = int64Ptr(maxInt64(0, total-available))
	}

	pidLimit := readInt64(o.readFile, "/proc/sys/kernel/pid_max")
	if pidLimit == nil {
		markUnknown("physical.pids")
		if limit := cgroupPidsLimit(o.readFile); limit != nil {
			inv.Allocatable.Pids = int64Ptr(reserveCount(*limit, 64))
		} else {
			markUnknown("allocatable.pids")
		}
	} else {
		inv.Physical.Pids = int64Ptr(*pidLimit)
		allocLimit := *pidLimit
		if limit := cgroupPidsLimit(o.readFile); limit != nil && *limit < allocLimit {
			allocLimit = *limit
		}
		inv.Allocatable.Pids = int64Ptr(reserveCount(allocLimit, 64))
	}
	if pids, err := processCount(o.readDir); err == nil {
		inv.Used.Pids = int64Ptr(pids)
	} else {
		markUnknown("used.pids")
	}

	fdLimit := readInt64(o.readFile, "/proc/sys/fs/file-max")
	if fdLimit == nil {
		markUnknown("physical.file_descriptors", "allocatable.file_descriptors")
	} else {
		inv.Physical.FileDescriptors = int64Ptr(*fdLimit)
		inv.Allocatable.FileDescriptors = int64Ptr(reserveCount(*fdLimit, 1024))
	}
	if used, ok := fileHandles(o.readFile); ok {
		inv.Used.FileDescriptors = int64Ptr(used)
	} else {
		markUnknown("used.file_descriptors")
	}

	ifaces, err := o.interfaces()
	if err != nil {
		markUnknown("used.netdevs", "network_devices.count", "network_devices.limit", "allocatable.netdevs")
	} else {
		count := int64(len(ifaces))
		inv.Used.NetDevices = int64Ptr(count)
		inv.NetworkDevice.Count = int64Ptr(count)
		if fdLimit != nil {
			// A netdev carries queues, namespace bookkeeping, and file-backed
			// handles. The kernel has no portable netdev-count ceiling, so use
			// the conservative lower of 4096 and one eighth of handle capacity.
			limit := *fdLimit / 8
			if limit > 4096 {
				limit = 4096
			}
			if limit < count+64 {
				limit = count + 64
			}
			inv.NetworkDevice.Limit = int64Ptr(limit)
			inv.Physical.NetDevices = int64Ptr(limit)
			inv.Allocatable.NetDevices = int64Ptr(maxInt64(0, limit-count))
		} else {
			markUnknown("network_devices.limit", "physical.netdevs", "allocatable.netdevs")
		}
	}

	// An allocatable container estimate is intentionally subordinate to every
	// typed resource. It prevents a manifest with tiny requests from creating
	// thousands of containers simply because no legacy containers budget was
	// authored.
	if estimate := estimatedContainers(inv.Allocatable); estimate != nil {
		inv.Allocatable.Containers = estimate
		// Linux exposes no host-wide maximum container count. The count is
		// reported under Used; the allocation estimate is deliberately not
		// mislabeled as a physical limit.
		markUnknown("physical.containers")
	} else {
		markUnknown("physical.containers", "allocatable.containers")
	}
	if listErr == nil {
		inv.Used.Containers = intPtr(len(containers))
	} else {
		markUnknown("used.containers")
	}

	if listErr != nil {
		markUnknown("reserved")
		inv.Reservations = nil
	} else {
		want := map[string]model.ResourceRequest{}
		if len(desired) > 0 {
			want = desired[0]
		}
		for _, c := range containers {
			request := reservationForContainerWithOverride(c, want[c.Name])
			inv.Reserved = addInventory(inv.Reserved, request)
			lab := c.Label(deploy.LabelLab)
			if lab != "" {
				inv.Reservations[lab] = addInventory(inv.Reservations[lab], request)
			}
		}
		// Allocatable netdev capacity is the estimate after non-Twinet host
		// interfaces, not after all current interfaces. Existing Twinet
		// reservations are charged again by placement, so subtracting them
		// here would double-charge every currently running lab.
		if inv.NetworkDevice.Limit != nil && inv.NetworkDevice.Count != nil {
			reserved := int64(0)
			if inv.Reserved.NetDevices != nil {
				reserved = *inv.Reserved.NetDevices
			}
			nonTwinet := maxInt64(0, *inv.NetworkDevice.Count-reserved)
			inv.Allocatable.NetDevices = int64Ptr(maxInt64(0, *inv.NetworkDevice.Limit-nonTwinet))
		}
	}
	inv.ImageCache = imageCache(o.readDir, containers)
	for _, v := range inv.ImageCache.Unknown {
		markUnknown("image_cache." + v)
	}
	inv.Load = loadAverage(o.readFile)
	if inv.Load.One == nil {
		markUnknown("load")
	}
	for name := range unknown {
		inv.Unknown = append(inv.Unknown, name)
	}
	sortStrings(inv.Unknown)
	return inv
}

func (o *hostInventoryObserver) cpuUsage(now time.Time) *float64 {
	raw, err := o.readFile("/proc/stat")
	if err != nil {
		return nil
	}
	total, idle, ok := procCPU(raw)
	if !ok {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	previous := o.previous
	o.previous = &cpuSample{total: total, idled: idle, at: now}
	if previous == nil || total <= previous.total || idle < previous.idled {
		return nil
	}
	used := 1 - float64(idle-previous.idled)/float64(total-previous.total)
	if used < 0 {
		used = 0
	}
	cpus := used * float64(runtime.NumCPU())
	return float64Ptr(cpus)
}

func reservationForContainer(c rt.Container) ResourceInventory {
	return reservationForContainerWithOverride(c, model.ResourceRequest{})
}

func reservationForContainerWithOverride(c rt.Container, override model.ResourceRequest) ResourceInventory {
	kind := model.DeviceKind(c.Label(deploy.LabelKind))
	r := override
	if r.Empty() {
		r = model.DefaultResourceRequest(kind)
		parseFloatLabel(c, deploy.LabelRequestCPU, &r.CPUs)
		parseStringLabel(c, deploy.LabelRequestMemory, &r.Memory)
		parseInt64Label(c, deploy.LabelRequestPids, &r.Pids)
		parseStringLabel(c, deploy.LabelRequestDisk, &r.EphemeralStorage)
		parseInt64Label(c, deploy.LabelRequestFDs, &r.FileDescriptors)
		parseInt64Label(c, deploy.LabelRequestNetDevs, &r.NetDevices)
	}
	out := ResourceInventory{
		CPUs:            float64Ptr(r.CPUs),
		Pids:            int64Ptr(r.Pids),
		FileDescriptors: int64Ptr(r.FileDescriptors),
		NetDevices:      int64Ptr(r.NetDevices),
		Containers:      intPtr(1),
	}
	if n, err := rt.ParseMemory(r.Memory); err == nil {
		out.MemoryBytes = int64Ptr(n)
	}
	if n, err := rt.ParseMemory(r.Storage()); err == nil {
		out.DiskBytes = int64Ptr(n)
	}
	return out
}

func parseFloatLabel(c rt.Container, key string, dst *float64) {
	if raw := c.Label(key); raw != "" {
		if n, err := strconv.ParseFloat(raw, 64); err == nil && n > 0 {
			*dst = n
		}
	}
}

func parseStringLabel(c rt.Container, key string, dst *string) {
	if raw := c.Label(key); raw != "" {
		*dst = raw
	}
}

func parseInt64Label(c rt.Container, key string, dst *int64) {
	if raw := c.Label(key); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			*dst = n
		}
	}
}

func addInventory(a, b ResourceInventory) ResourceInventory {
	return ResourceInventory{
		CPUs:            addFloat(a.CPUs, b.CPUs),
		MemoryBytes:     addInt64(a.MemoryBytes, b.MemoryBytes),
		DiskBytes:       addInt64(a.DiskBytes, b.DiskBytes),
		Pids:            addInt64(a.Pids, b.Pids),
		FileDescriptors: addInt64(a.FileDescriptors, b.FileDescriptors),
		NetDevices:      addInt64(a.NetDevices, b.NetDevices),
		Containers:      addInt(a.Containers, b.Containers),
	}
}

func estimatedContainers(r ResourceInventory) *int {
	var candidates []int
	if r.MemoryBytes != nil {
		candidates = append(candidates, int(*r.MemoryBytes/(64<<20)))
	}
	if r.Pids != nil {
		candidates = append(candidates, int(*r.Pids/16))
	}
	if r.FileDescriptors != nil {
		candidates = append(candidates, int(*r.FileDescriptors/256))
	}
	if r.NetDevices != nil {
		candidates = append(candidates, int(*r.NetDevices/2))
	}
	if len(candidates) == 0 {
		return nil
	}
	limit := 600
	for _, n := range candidates {
		if n < limit {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	return intPtr(limit)
}

func imageCache(readDir func(string) ([]os.DirEntry, error), containers []rt.Container) ImageCacheInventory {
	seen := map[string]bool{}
	for _, c := range containers {
		if c.ImageID != "" {
			seen[c.ImageID] = true
		} else if c.Image != "" {
			seen[c.Image] = true
		}
	}
	out := ImageCacheInventory{Referenced: len(seen)}
	root := os.Getenv("TWINET_IMAGE_CACHE_DIR")
	if root == "" {
		root = "/var/lib/docker/image/overlay2/imagedb/content/sha256"
	}
	entries, err := readDir(root)
	if err != nil {
		out.Unknown = []string{"count", "bytes"}
		return out
	}
	count := len(entries)
	out.Count = intPtr(count)
	// Metadata sizes are not image-layer sizes. Be explicit rather than
	// emitting a plausible-looking but false byte total.
	out.Unknown = []string{"bytes"}
	return out
}

func memInfo(readFile func(string) ([]byte, error)) (total, available int64, ok bool) {
	raw, err := readFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var free int64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = n << 10
		case "MemAvailable":
			available = n << 10
		case "MemFree":
			free = n << 10
		}
	}
	if total == 0 {
		return 0, 0, false
	}
	if available == 0 {
		available = free
	}
	return total, available, true
}

func procCPU(raw []byte) (total, idle uint64, ok bool) {
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		for i := 1; i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			total += v
			if i == 4 || i == 5 {
				idle += v
			}
		}
		return total, idle, total > 0
	}
	return 0, 0, false
}

func loadAverage(readFile func(string) ([]byte, error)) LoadAverage {
	raw, err := readFile("/proc/loadavg")
	if err != nil {
		return LoadAverage{}
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return LoadAverage{}
	}
	parse := func(raw string) *float64 {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil
		}
		return float64Ptr(v)
	}
	return LoadAverage{One: parse(fields[0]), Five: parse(fields[1]), Fifteen: parse(fields[2])}
}

func cgroupCPUQuota(readFile func(string) ([]byte, error)) *float64 {
	if raw, err := readFile("/sys/fs/cgroup/cpu.max"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 2 && fields[0] != "max" {
			quota, qerr := strconv.ParseFloat(fields[0], 64)
			period, perr := strconv.ParseFloat(fields[1], 64)
			if qerr == nil && perr == nil && quota > 0 && period > 0 {
				return float64Ptr(quota / period)
			}
		}
	}
	quota := readInt64(readFile, "/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	period := readInt64(readFile, "/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if quota != nil && period != nil && *quota > 0 && *period > 0 {
		return float64Ptr(float64(*quota) / float64(*period))
	}
	return nil
}

func cgroupMemoryLimit(readFile func(string) ([]byte, error)) *int64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		if n := readLimit(readFile, path); n != nil {
			return n
		}
	}
	return nil
}

func cgroupPidsLimit(readFile func(string) ([]byte, error)) *int64 {
	for _, path := range []string{
		"/sys/fs/cgroup/pids.max",
		"/sys/fs/cgroup/pids/pids.max",
	} {
		if n := readLimit(readFile, path); n != nil {
			return n
		}
	}
	return nil
}

func readLimit(readFile func(string) ([]byte, error), path string) *int64 {
	raw, err := readFile(path)
	if err != nil {
		return nil
	}
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "max" {
		return nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/2 {
		return nil
	}
	return int64Ptr(n)
}

func readInt64(readFile func(string) ([]byte, error), path string) *int64 {
	raw, err := readFile(path)
	if err != nil {
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return int64Ptr(n)
}

func processCount(readDir func(string) ([]os.DirEntry, error)) (int64, error) {
	entries, err := readDir("/proc")
	if err != nil {
		return 0, err
	}
	var count int64
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 64); err == nil {
			count++
		}
	}
	return count, nil
}

func fileHandles(readFile func(string) ([]byte, error)) (int64, bool) {
	raw, err := readFile("/proc/sys/fs/file-nr")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 1 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	return n, err == nil
}

func reserveCPU(total float64) float64 {
	reserve := math.Max(0.10*total, 0.25)
	if total <= reserve {
		return math.Max(0.05, total*0.5)
	}
	return total - reserve
}

func reserveBytes(total, floor int64) int64 {
	reserve := maxInt64(total/10, floor)
	if total <= reserve {
		return maxInt64(1, total/2)
	}
	return total - reserve
}

func reserveCount(total, floor int64) int64 {
	reserve := maxInt64(total/10, floor)
	if total <= reserve {
		return maxInt64(1, total/2)
	}
	return total - reserve
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func float64Ptr(v float64) *float64 { return &v }
func int64Ptr(v int64) *int64       { return &v }
func intPtr(v int) *int             { return &v }

func addFloat(a, b *float64) *float64 {
	if a == nil && b == nil {
		return nil
	}
	var out float64
	if a != nil {
		out += *a
	}
	if b != nil {
		out += *b
	}
	return float64Ptr(out)
}

func addInt64(a, b *int64) *int64 {
	if a == nil && b == nil {
		return nil
	}
	var out int64
	if a != nil {
		out += *a
	}
	if b != nil {
		out += *b
	}
	return int64Ptr(out)
}

func addInt(a, b *int) *int {
	if a == nil && b == nil {
		return nil
	}
	var out int
	if a != nil {
		out += *a
	}
	if b != nil {
		out += *b
	}
	return intPtr(out)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

// inventoryPath is kept separate to make tests and diagnostics name the
// storage location whose statfs result was used.
func inventoryPath(stateDir string) string {
	if stateDir == "" {
		return "/"
	}
	return filepath.Clean(stateDir)
}
