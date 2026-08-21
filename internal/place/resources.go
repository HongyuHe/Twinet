package place

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// Resources is a schedulable reservation. Its fields are deliberately numeric
// so placement cannot confuse a container's hard limits with its requested
// host capacity.
type Resources struct {
	Containers  int     `json:"containers,omitempty"`
	CPUs        float64 `json:"cpus,omitempty"`
	MemoryBytes int64   `json:"memory_bytes,omitempty"`
	// MemBytes is retained for package-local callers written before resource
	// requests were extended. New code should use MemoryBytes.
	MemBytes        int64 `json:"-"`
	DiskBytes       int64 `json:"disk_bytes,omitempty"`
	Pids            int64 `json:"pids,omitempty"`
	FileDescriptors int64 `json:"file_descriptors,omitempty"`
	NetDevices      int64 `json:"netdevs,omitempty"`
}

// demand remains an internal-friendly name used throughout the placer.
type demand = Resources

func (d demand) memoryBytes() int64 {
	if d.MemoryBytes != 0 {
		return d.MemoryBytes
	}
	return d.MemBytes
}

func (d demand) add(o demand) demand {
	memory := d.memoryBytes() + o.memoryBytes()
	return demand{
		Containers:      d.Containers + o.Containers,
		CPUs:            d.CPUs + o.CPUs,
		MemoryBytes:     memory,
		MemBytes:        memory,
		DiskBytes:       d.DiskBytes + o.DiskBytes,
		Pids:            d.Pids + o.Pids,
		FileDescriptors: d.FileDescriptors + o.FileDescriptors,
		NetDevices:      d.NetDevices + o.NetDevices,
	}
}

func (d demand) sub(o demand) demand {
	memory := d.memoryBytes() - o.memoryBytes()
	return demand{
		Containers:      d.Containers - o.Containers,
		CPUs:            d.CPUs - o.CPUs,
		MemoryBytes:     memory,
		MemBytes:        memory,
		DiskBytes:       d.DiskBytes - o.DiskBytes,
		Pids:            d.Pids - o.Pids,
		FileDescriptors: d.FileDescriptors - o.FileDescriptors,
		NetDevices:      d.NetDevices - o.NetDevices,
	}
}

func (d demand) empty() bool {
	return d.Containers == 0 && d.CPUs == 0 && d.memoryBytes() == 0 &&
		d.DiskBytes == 0 && d.Pids == 0 && d.FileDescriptors == 0 &&
		d.NetDevices == 0
}

// Capacity represents observed allocatable capacity. Nil means the agent
// could not determine that dimension; it never means zero capacity.
type Capacity struct {
	Containers      *int     `json:"containers"`
	CPUs            *float64 `json:"cpus"`
	MemoryBytes     *int64   `json:"memory_bytes"`
	DiskBytes       *int64   `json:"disk_bytes"`
	Pids            *int64   `json:"pids"`
	FileDescriptors *int64   `json:"file_descriptors"`
	NetDevices      *int64   `json:"netdevs"`
}

// NodeInventory is the live reservation view used by placement and admission.
// ReservedByLab lets a redeploy replace its own reservation rather than count
// the current lab twice, while every other lab and grading harness remains
// charged to the node.
type NodeInventory struct {
	Name          string               `json:"name"`
	Allocatable   Capacity             `json:"allocatable"`
	Reserved      Resources            `json:"reserved"`
	ReservedByLab map[string]Resources `json:"reserved_by_lab,omitempty"`
	Unknown       []string             `json:"unknown,omitempty"`
}

// TopologyDemandByNode returns the requests of the topology as currently
// placed. It is also used by the grading scheduler to reserve a whole harness
// before any of its containers are created.
func TopologyDemandByNode(top *model.Topology) map[string]Resources {
	out := map[string]Resources{}
	if top == nil {
		return out
	}
	for _, d := range top.SortedDevices() {
		if d.Node == "" {
			continue
		}
		out[d.Node] = out[d.Node].add(deviceDemand(d))
	}
	return out
}

// deviceDemand is what one device requests from a node. Limits are consulted
// only for legacy in-memory topologies that predate requests; loaded manifests
// always materialise Requests in expand.
func deviceDemand(d *model.Device) demand {
	if d == nil {
		return demand{}
	}
	r := d.Requests
	if r.Empty() {
		// Direct callers built Device values long before requests existed. Keep
		// their safety properties while manifest compatibility takes the new
		// conservative defaults in the normal expansion path.
		if d.CPUs > 0 || d.Memory != "" || d.Pids > 0 {
			r = model.DefaultResourceRequest(d.Kind)
			if d.CPUs > 0 {
				r.CPUs = d.CPUs
			}
			if d.Memory != "" {
				r.Memory = d.Memory
			}
			if d.Pids > 0 {
				r.Pids = d.Pids
			}
		} else {
			// Direct package users from before requests represented an
			// unbounded device with the old small nominal charge. Expanded
			// manifests never take this path: they receive the conservative
			// per-kind requests above.
			r = model.DefaultResourceRequest(d.Kind)
			r.CPUs = 0.05
			r.Memory = "64Mi"
		}
	}
	dem := requestDemand(r)
	if d.Kind == model.KindRouter && d.EffectiveNOS() == model.DefaultNOS {
		dem = dem.add(requestDemand(model.FRRControlResourceRequest()))
	}
	return dem
}

func requestDemand(r model.ResourceRequest) demand {
	dem := demand{
		Containers:      1,
		CPUs:            r.CPUs,
		Pids:            r.Pids,
		FileDescriptors: r.FileDescriptors,
		NetDevices:      r.NetDevices,
	}
	if b, err := runtime.ParseMemory(r.Memory); err == nil {
		dem.MemoryBytes = b
		dem.MemBytes = b
	}
	if b, err := runtime.ParseMemory(r.Storage()); err == nil {
		dem.DiskBytes = b
	}
	return dem
}

// capacityOf reads a node's declared upper bound, minus its static reserve.
// It preserves the legacy helper contract for callers that only use manifest
// capacities; live inventory is merged by effectiveCapacityOf below.
func capacityOf(n model.NodeSpec, reserve map[string]model.Budget) (demand, bool) {
	if n.Capacity == nil {
		return demand{}, false
	}
	cap := budgetDemand(*n.Capacity)
	if r, ok := reserve[n.Name]; ok {
		cap = cap.sub(budgetDemand(r))
	}
	cap = clampCapacity(cap)
	return cap, !cap.empty()
}

func budgetDemand(b model.Budget) demand {
	out := demand{
		Containers: b.Containers, CPUs: b.CPUs, Pids: b.Pids,
		FileDescriptors: b.FileDescriptors, NetDevices: b.NetDevices,
	}
	if n, err := runtime.ParseMemory(b.Memory); err == nil {
		out.MemoryBytes = n
		out.MemBytes = n
	}
	if n, err := runtime.ParseMemory(b.Storage()); err == nil {
		out.DiskBytes = n
	}
	return out
}

// effectiveCapacityOf takes the minimum of the optional manifest upper bound
// and observed allocatable capacity. A missing value stays missing so strict
// admission can name uncertainty instead of silently treating it as zero or
// infinity.
func effectiveCapacityOf(n model.NodeSpec, reserve map[string]model.Budget,
	inv *NodeInventory,
) (demand, bool, []string) {
	var declared *model.Budget
	if n.Capacity != nil {
		declared = n.Capacity
	}
	var live Capacity
	if inv != nil {
		live = inv.Allocatable
	}

	var (
		out     demand
		missing []string
		have    bool
	)
	chooseInt := func(name string, declared int64, live *int64) int64 {
		okDeclared := declared > 0
		okLive := live != nil
		if !okDeclared && !okLive {
			missing = append(missing, name)
			return 0
		}
		have = true
		switch {
		case okDeclared && okLive:
			return minInt64(declared, *live)
		case okDeclared:
			return declared
		default:
			return *live
		}
	}
	chooseCount := func(name string, declared int, live *int) int {
		okDeclared := declared > 0
		okLive := live != nil
		if !okDeclared && !okLive {
			missing = append(missing, name)
			return 0
		}
		have = true
		switch {
		case okDeclared && okLive:
			if declared < *live {
				return declared
			}
			return *live
		case okDeclared:
			return declared
		default:
			return *live
		}
	}
	chooseFloat := func(name string, declared float64, live *float64) float64 {
		okDeclared := declared > 0
		okLive := live != nil
		if !okDeclared && !okLive {
			missing = append(missing, name)
			return 0
		}
		have = true
		switch {
		case okDeclared && okLive:
			return math.Min(declared, *live)
		case okDeclared:
			return declared
		default:
			return *live
		}
	}

	var decl demand
	if declared != nil {
		decl = budgetDemand(*declared)
	}
	out.Containers = chooseCount("containers", decl.Containers, live.Containers)
	out.CPUs = chooseFloat("cpu", decl.CPUs, live.CPUs)
	out.MemoryBytes = chooseInt("memory", decl.memoryBytes(), live.MemoryBytes)
	out.MemBytes = out.MemoryBytes
	out.DiskBytes = chooseInt("ephemeral storage", decl.DiskBytes, live.DiskBytes)
	out.Pids = chooseInt("pids", decl.Pids, live.Pids)
	out.FileDescriptors = chooseInt("file descriptors", decl.FileDescriptors, live.FileDescriptors)
	out.NetDevices = chooseInt("netdevs", decl.NetDevices, live.NetDevices)
	if r, ok := reserve[n.Name]; ok {
		out = out.sub(budgetDemand(r))
	}
	out = clampCapacity(out)
	// A nil source is unknown and appears in missing. A known zero is
	// exhausted, not unspecified: encode it as a negative sentinel so fits
	// can reject a positive request instead of silently skipping the
	// dimension's zero-value convention.
	if !containsString(missing, "containers") && out.Containers == 0 {
		out.Containers = -1
	}
	if !containsString(missing, "cpu") && out.CPUs == 0 {
		out.CPUs = -1
	}
	if !containsString(missing, "memory") && out.MemoryBytes == 0 {
		out.MemoryBytes, out.MemBytes = -1, -1
	}
	if !containsString(missing, "ephemeral storage") && out.DiskBytes == 0 {
		out.DiskBytes = -1
	}
	if !containsString(missing, "pids") && out.Pids == 0 {
		out.Pids = -1
	}
	if !containsString(missing, "file descriptors") && out.FileDescriptors == 0 {
		out.FileDescriptors = -1
	}
	if !containsString(missing, "netdevs") && out.NetDevices == 0 {
		out.NetDevices = -1
	}
	sort.Strings(missing)
	return out, have, missing
}

// clampCapacity preserves an exhausted known capacity as a negative sentinel
// rather than letting the zero-value convention turn it into an omitted
// dimension.
func clampCapacity(in demand) demand {
	if in.Containers < 0 {
		in.Containers = -1
	}
	if in.CPUs < 0 {
		in.CPUs = -1
	}
	if in.memoryBytes() < 0 {
		in.MemoryBytes = -1
		in.MemBytes = -1
	}
	if in.DiskBytes < 0 {
		in.DiskBytes = -1
	}
	if in.Pids < 0 {
		in.Pids = -1
	}
	if in.FileDescriptors < 0 {
		in.FileDescriptors = -1
	}
	if in.NetDevices < 0 {
		in.NetDevices = -1
	}
	return in
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// fits reports whether a node can take more request demand.
func fits(load, need, cap demand, has bool) bool {
	if !has {
		return true
	}
	if (cap.Containers < 0 && need.Containers > 0) ||
		(cap.CPUs < 0 && need.CPUs > 0) ||
		(cap.memoryBytes() < 0 && need.memoryBytes() > 0) ||
		(cap.DiskBytes < 0 && need.DiskBytes > 0) ||
		(cap.Pids < 0 && need.Pids > 0) ||
		(cap.FileDescriptors < 0 && need.FileDescriptors > 0) ||
		(cap.NetDevices < 0 && need.NetDevices > 0) {
		return false
	}
	if cap.Containers > 0 && load.Containers+need.Containers > cap.Containers {
		return false
	}
	if cap.CPUs > 0 && load.CPUs+need.CPUs > cap.CPUs {
		return false
	}
	if cap.memoryBytes() > 0 && load.memoryBytes()+need.memoryBytes() > cap.memoryBytes() {
		return false
	}
	if cap.DiskBytes > 0 && load.DiskBytes+need.DiskBytes > cap.DiskBytes {
		return false
	}
	if cap.Pids > 0 && load.Pids+need.Pids > cap.Pids {
		return false
	}
	if cap.FileDescriptors > 0 && load.FileDescriptors+need.FileDescriptors > cap.FileDescriptors {
		return false
	}
	if cap.NetDevices > 0 && load.NetDevices+need.NetDevices > cap.NetDevices {
		return false
	}
	return true
}

// pressure scores a node by its fullest requested dimension.
func pressure(load, cap demand, has bool, nominal int) float64 {
	if !has {
		if nominal <= 0 {
			nominal = 1
		}
		return float64(load.Containers) / float64(nominal)
	}
	worst := 0.0
	if cap.Containers > 0 {
		worst = max(worst, float64(load.Containers)/float64(cap.Containers))
	}
	if cap.CPUs > 0 {
		worst = max(worst, load.CPUs/cap.CPUs)
	}
	if cap.memoryBytes() > 0 {
		worst = max(worst, float64(load.memoryBytes())/float64(cap.memoryBytes()))
	}
	if cap.DiskBytes > 0 {
		worst = max(worst, float64(load.DiskBytes)/float64(cap.DiskBytes))
	}
	if cap.Pids > 0 {
		worst = max(worst, float64(load.Pids)/float64(cap.Pids))
	}
	if cap.FileDescriptors > 0 {
		worst = max(worst, float64(load.FileDescriptors)/float64(cap.FileDescriptors))
	}
	if cap.NetDevices > 0 {
		worst = max(worst, float64(load.NetDevices)/float64(cap.NetDevices))
	}
	return worst
}

func nominalCapacity(names []string, caps map[string]demand, hasCap map[string]bool, total int) int {
	best := 0
	for _, n := range names {
		if hasCap[n] && caps[n].Containers > best {
			best = caps[n].Containers
		}
	}
	if best == 0 && len(names) > 0 {
		best = (total + len(names) - 1) / len(names)
	}
	if best <= 0 {
		best = 1
	}
	return best
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func describeDemand(d demand) string {
	return fmt.Sprintf(
		"requests: %d container(s), %.2f cpu, %s memory, %s ephemeral storage, %d pids, %d file descriptors, %d netdevs",
		d.Containers, d.CPUs, humanBytes(d.memoryBytes()), humanBytes(d.DiskBytes),
		d.Pids, d.FileDescriptors, d.NetDevices)
}

func describeLoads(names []string, load map[string]demand, caps map[string]demand, hasCap map[string]bool) string {
	var parts []string
	for _, n := range names {
		if !hasCap[n] {
			parts = append(parts, fmt.Sprintf("%s: %s, no known capacity", n, describeDemand(load[n])))
			continue
		}
		parts = append(parts, fmt.Sprintf(
			"%s: %d/%d containers, %.2f/%.2f cpu, %s/%s memory, %s/%s disk, %d/%d pids, %d/%d fds, %d/%d netdevs",
			n, load[n].Containers, caps[n].Containers, load[n].CPUs, caps[n].CPUs,
			humanBytes(load[n].memoryBytes()), humanBytes(caps[n].memoryBytes()),
			humanBytes(load[n].DiskBytes), humanBytes(caps[n].DiskBytes),
			load[n].Pids, caps[n].Pids, load[n].FileDescriptors, caps[n].FileDescriptors,
			load[n].NetDevices, caps[n].NetDevices))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n  ")
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGi", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fMi", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// bestForLocality picks the node that keeps the most links local among
// capacity-fitting candidates.
func bestForLocality(names []string, load map[string]demand, caps map[string]demand,
	hasCap map[string]bool, need demand, tolerance float64, nominal int,
	localityOf func(node string) int) (string, error) {

	type cand struct {
		name     string
		pressure float64
		locality int
	}
	var cands []cand
	minP := 0.0
	for _, n := range names {
		if !fits(load[n], need, caps[n], hasCap[n]) {
			continue
		}
		p := pressure(load[n].add(need), caps[n], hasCap[n], nominal)
		if len(cands) == 0 || p < minP {
			minP = p
		}
		cands = append(cands, cand{n, p, localityOf(n)})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf(
			"no node has room for %s; reduce resource requests, add capacity, or use the audited --overcommit escape hatch.\n  %s",
			describeDemand(need), describeLoads(names, load, caps, hasCap))
	}

	best := cand{}
	found := false
	for _, c := range cands {
		if c.pressure > minP+tolerance {
			continue
		}
		if !found || c.locality > best.locality ||
			(c.locality == best.locality && c.pressure < best.pressure) ||
			(c.locality == best.locality && c.pressure == best.pressure && c.name < best.name) {
			best, found = c, true
		}
	}
	return best.name, nil
}
