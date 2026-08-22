package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netx"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/runtime"
)

const observationVersion = 2

// BuildDiff is the desired-versus-observed result used to construct a minimal
// executable deployment DAG. Its maps are keyed by canonical device/link IDs.
type BuildDiff struct {
	ObservedFor time.Duration
	DiffedFor   time.Duration

	Create map[string]bool
	// Recreate is the subset of Create whose primary runtime container is
	// replaced or first-created. Create also includes safe start and internal
	// sidecar repair work, neither of which changes a primary object's
	// creation generation.
	Recreate  map[string]bool
	Wire      map[string]bool
	Configure map[string]bool
	Ready     map[string]bool
	// Semantic names devices whose cheap live fingerprint disagreed with the
	// rendered topology despite matching OCI/config hashes.
	Semantic map[string]bool

	// Capture names student-owned devices whose container/configuration may
	// have been destructively touched. A delay-only qdisc change never enters
	// this set.
	Capture map[string]bool
}

// Empty reports whether the reconcile plan has no runtime mutations or
// readiness verification to perform.
func (d BuildDiff) Empty() bool {
	return len(d.Create) == 0 && len(d.Wire) == 0 && len(d.Configure) == 0 && len(d.Ready) == 0 && len(d.Semantic) == 0
}

// Counts returns deterministic dirty-set cardinalities for responses and
// metrics without exposing individual student/device identifiers.
func (d BuildDiff) Counts() map[string]int {
	return map[string]int{
		"create":    len(d.Create),
		"wire":      len(d.Wire),
		"configure": len(d.Configure),
		"ready":     len(d.Ready),
		"semantic":  len(d.Semantic),
		"capture":   len(d.Capture),
	}
}

// DeploymentStats is a bounded timing/mutation summary suitable for API
// responses and metrics. It contains no lab/device identifiers.
type DeploymentStats struct {
	ObserveMS int64          `json:"observe_ms"`
	DiffMS    int64          `json:"diff_ms"`
	Dirty     map[string]int `json:"dirty"`
	Mutations map[string]int `json:"mutations"`
}

type desiredDeviceState struct {
	files       map[string]FileSpec
	commands    []Command
	configHash  string
	fileHash    string
	commandHash string
	readyHash   string
	runtime     finalDeviceSpec
}

type nodeObservedState struct {
	Version int    `json:"version"`
	Lab     string `json:"lab"`
	Node    string `json:"node"`
	Mode    string `json:"mode,omitempty"`

	Devices map[string]observedDeviceState `json:"devices"`
	Links   map[string]observedLinkState   `json:"links"`
}

type observedDeviceState struct {
	SpecHash    string `json:"spec_hash"`
	ConfigHash  string `json:"config_hash"`
	FileHash    string `json:"file_hash"`
	CommandHash string `json:"command_hash"`
	ReadyHash   string `json:"ready_hash"`
}

type observedLinkState struct {
	Hash string `json:"hash"`
}

type observationTracker struct {
	e    *Engine
	path string

	mu      sync.Mutex
	state   nodeObservedState
	changed bool
}

func (e *Engine) observationPath(lab string) string {
	root := e.ObservationRoot
	if root == "" {
		root = filepath.Join("/run", "twinet", "observed")
	}
	sum := sha256.Sum256([]byte(lab + "\x00" + e.Node))
	return filepath.Join(root, hex.EncodeToString(sum[:])+".json")
}

func (e *Engine) loadObservation(lab string) (*observationTracker, error) {
	tracker := &observationTracker{
		e:    e,
		path: e.observationPath(lab),
		state: nodeObservedState{
			Version: observationVersion,
			Lab:     lab,
			Node:    e.Node,
			Devices: map[string]observedDeviceState{},
			Links:   map[string]observedLinkState{},
		},
	}
	raw, err := os.ReadFile(tracker.path)
	if os.IsNotExist(err) {
		return tracker, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read observed deployment state: %w", err)
	}
	var decoded nodeObservedState
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// A corrupted cache must never be trusted as proof that a mutation is
		// unnecessary. Start with an empty observation and converge again.
		return tracker, nil
	}
	if decoded.Version != observationVersion || decoded.Lab != lab || decoded.Node != e.Node {
		return tracker, nil
	}
	if decoded.Devices == nil {
		decoded.Devices = map[string]observedDeviceState{}
	}
	if decoded.Links == nil {
		decoded.Links = map[string]observedLinkState{}
	}
	tracker.state = decoded
	return tracker, nil
}

func (t *observationTracker) saveLocked() error {
	if !t.changed {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
		return fmt.Errorf("create observed deployment directory: %w", err)
	}
	raw, err := json.Marshal(t.state)
	if err != nil {
		return fmt.Errorf("encode observed deployment state: %w", err)
	}
	tmp := t.path + ".next"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write observed deployment state: %w", err)
	}
	if err := os.Rename(tmp, t.path); err != nil {
		return fmt.Errorf("publish observed deployment state: %w", err)
	}
	t.changed = false
	return nil
}

func (t *observationTracker) save() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.saveLocked()
}

func (t *observationTracker) device(id string) (observedDeviceState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, ok := t.state.Devices[id]
	return value, ok
}

func (t *observationTracker) link(id string) (observedLinkState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, ok := t.state.Links[id]
	return value, ok
}

func (t *observationTracker) markDevice(id string, value observedDeviceState) error {
	t.mu.Lock()
	t.state.Devices[id] = value
	if t.e.ModeKey != "" {
		t.state.Mode = t.e.ModeKey
	}
	t.changed = true
	err := t.saveLocked()
	t.mu.Unlock()
	return err
}

func (t *observationTracker) clearDeviceConfig(id string) error {
	t.mu.Lock()
	value := t.state.Devices[id]
	value.ConfigHash, value.FileHash, value.CommandHash, value.ReadyHash = "", "", "", ""
	t.state.Devices[id] = value
	t.changed = true
	err := t.saveLocked()
	t.mu.Unlock()
	return err
}

func (t *observationTracker) markLink(id, hash string) error {
	t.mu.Lock()
	t.state.Links[id] = observedLinkState{Hash: hash}
	t.changed = true
	err := t.saveLocked()
	t.mu.Unlock()
	return err
}

func (t *observationTracker) bootstrapDevice(id string, value observedDeviceState) {
	t.mu.Lock()
	if _, exists := t.state.Devices[id]; !exists {
		t.state.Devices[id] = value
		t.changed = true
	}
	t.mu.Unlock()
}

func (t *observationTracker) bootstrapLink(id, hash string) {
	t.mu.Lock()
	if _, exists := t.state.Links[id]; !exists {
		t.state.Links[id] = observedLinkState{Hash: hash}
		t.changed = true
	}
	t.mu.Unlock()
}

func (t *observationTracker) prune(devices map[string]bool, links map[string]bool) {
	t.mu.Lock()
	for id := range t.state.Devices {
		if !devices[id] {
			delete(t.state.Devices, id)
			t.changed = true
		}
	}
	for id := range t.state.Links {
		if !links[id] {
			delete(t.state.Links, id)
			t.changed = true
		}
	}
	t.mu.Unlock()
}

func (e *Engine) observeNode(ctx context.Context, top *model.Topology, devices []*model.Device) (
	*observationTracker, map[string]desiredDeviceState, BuildDiff, error,
) {
	start := time.Now()
	tracker, err := e.loadObservation(top.Name)
	if err != nil {
		return nil, nil, BuildDiff{}, err
	}
	var containers []runtime.Container
	if e.Runtime != nil {
		containers, err = e.Runtime.List(ctx, runtime.Filter{
			All: true, Labels: map[string]string{LabelLab: top.Name},
		})
		if err != nil {
			return nil, nil, BuildDiff{}, fmt.Errorf("observe containers for %s: %w", top.Name, err)
		}
	}
	byName := make(map[string]runtime.Container, len(containers))
	for _, container := range containers {
		byName[container.Name] = container
	}
	liveVNI := map[uint32]bool{}
	hasCrossNode := false
	for _, link := range top.Links {
		if link != nil && link.CrossNode() &&
			(link.A.Device.Node == e.Node || link.B.Device.Node == e.Node) {
			hasCrossNode = true
			break
		}
	}
	if hasCrossNode {
		overlays, err := netx.ListMultiplexOverlaysOfLab(top.Name)
		if err != nil {
			return nil, nil, BuildDiff{}, fmt.Errorf("observe overlays for %s: %w", top.Name, err)
		}
		for _, overlay := range overlays {
			for _, vni := range overlay.VNIs {
				liveVNI[vni] = true
			}
		}
	}
	observedFor := time.Since(start)
	diffStart := time.Now()
	desired := make(map[string]desiredDeviceState, len(devices))
	modeDirty := e.ModeKey != "" && tracker.state.Mode != e.ModeKey
	diff := BuildDiff{
		ObservedFor: observedFor,
		Create:      map[string]bool{},
		Recreate:    map[string]bool{},
		Wire:        map[string]bool{},
		Configure:   map[string]bool{},
		Ready:       map[string]bool{},
		Semantic:    map[string]bool{},
		Capture:     map[string]bool{},
	}
	wantDevices := make(map[string]bool, len(devices))
	for _, d := range devices {
		wantDevices[d.ID] = true
		state, err := e.renderDesired(d)
		if err != nil {
			return nil, nil, BuildDiff{}, err
		}
		state.runtime, err = e.finalRuntimeSpecs(top, d)
		if err != nil {
			return nil, nil, BuildDiff{}, err
		}
		desired[d.ID] = state
		container, ok := byName[d.Container]
		primaryRecreate := !ok || container.State == runtime.StateAbsent ||
			container.Labels[LabelSpec] != state.runtime.spec.Labels[LabelSpec] ||
			container.Labels[LabelRuntimeContract] != runtimeSpecContractVersion
		if e.RecoveryCompatibility && d.Kind == model.KindService {
			primaryRecreate = true
		}
		specDirty := primaryRecreate || !container.State.Joinable()
		if !specDirty && state.runtime.controlSpec != nil {
			control, controlOK := byName[FRRControlContainer(d)]
			specDirty = !controlOK || !control.State.Joinable() ||
				control.Labels[LabelSpec] != state.runtime.controlSpec.Labels[LabelSpec] ||
				control.Labels[LabelRuntimeContract] != runtimeSpecContractVersion
		}
		if specDirty {
			diff.Create[d.ID] = true
			if primaryRecreate {
				diff.Recreate[d.ID] = true
			}
			if studentOwned(top, d) {
				diff.Capture[d.ID] = true
			}
		}

		previous, known := tracker.device(d.ID)
		bootstrap := !specDirty && container.Labels[LabelHash] == top.Hash && d.ASN > 0
		if !known && bootstrap && !modeDirty {
			previous = observedDeviceState{
				SpecHash: state.runtime.spec.Labels[LabelSpec], ConfigHash: state.configHash,
				FileHash: state.fileHash, CommandHash: state.commandHash, ReadyHash: state.readyHash,
			}
			tracker.bootstrapDevice(d.ID, previous)
			known = true
		}
		if e.Renderer != nil && (modeDirty || specDirty || !known || previous.ConfigHash != state.configHash ||
			previous.FileHash != state.fileHash || previous.CommandHash != state.commandHash) {
			diff.Configure[d.ID] = true
			if studentOwned(top, d) {
				diff.Capture[d.ID] = true
			}
		}
		if e.Renderer != nil && e.Renderer.Ready(d, e.Runtime) != nil &&
			(modeDirty || specDirty || diff.Configure[d.ID] || !known || previous.ReadyHash != state.readyHash) {
			diff.Ready[d.ID] = true
		}
		if e.SemanticProbe != nil && !specDirty {
			if err := e.SemanticProbe(ctx, d); err != nil {
				// The renderer commands are deliberately idempotent. Mark the
				// device dirty so `deploy --solve` repairs a live address,
				// route, VLAN, or BGP-session drift even when every observed
				// file hash says the deploy is otherwise a no-op.
				diff.Semantic[d.ID] = true
				diff.Configure[d.ID] = true
				if studentOwned(top, d) {
					diff.Capture[d.ID] = true
				}
				if e.Renderer != nil && e.Renderer.Ready(d, e.Runtime) != nil {
					diff.Ready[d.ID] = true
				}
			}
		}
	}

	wantLinks := map[string]bool{}
	for _, link := range top.Links {
		if link == nil || (link.A.Device.Node != e.Node && link.B.Device.Node != e.Node) {
			continue
		}
		wantLinks[link.ID] = true
		hash, err := e.desiredWireHash(top, link)
		if err != nil {
			return nil, nil, BuildDiff{}, err
		}
		previous, known := tracker.link(link.ID)
		endpointCreate := (link.A.Device.Node == e.Node && diff.Create[link.A.Device.ID]) ||
			(link.B.Device.Node == e.Node && diff.Create[link.B.Device.ID])
		bootstrap := !endpointCreate && linkLabelHashMatches(byName, link, e.Node, top.Hash)
		if !known && bootstrap {
			tracker.bootstrapLink(link.ID, hash)
			known = true
			previous = observedLinkState{Hash: hash}
		}
		if endpointCreate || !known || previous.Hash != hash || (link.CrossNode() && !liveVNI[link.VNI]) {
			diff.Wire[link.ID] = true
		}
	}
	tracker.prune(wantDevices, wantLinks)
	if err := tracker.save(); err != nil {
		return nil, nil, BuildDiff{}, err
	}
	diff.DiffedFor = time.Since(diffStart)
	return tracker, desired, diff, nil
}

func linkLabelHashMatches(containers map[string]runtime.Container, link *model.Link, node, hash string) bool {
	for _, iface := range []*model.Iface{link.A, link.B} {
		if iface.Device.Node != node {
			continue
		}
		container, ok := containers[iface.Device.Container]
		if !ok || container.Labels[LabelHash] != hash || !container.State.Joinable() {
			return false
		}
	}
	return true
}

func (e *Engine) renderDesired(d *model.Device) (desiredDeviceState, error) {
	if e.Renderer == nil {
		return desiredDeviceState{}, nil
	}
	files, err := e.Renderer.Files(d)
	if err != nil {
		return desiredDeviceState{}, fmt.Errorf("render files for %s: %w", d.ID, err)
	}
	commands, err := e.Renderer.Commands(d)
	if err != nil {
		return desiredDeviceState{}, fmt.Errorf("render commands for %s: %w", d.ID, err)
	}
	fileHash := FileHash(files)
	commandHash := CommandHash(commands)
	return desiredDeviceState{
		files: files, commands: commands,
		configHash: ConfigHash(files, commands), fileHash: fileHash, commandHash: commandHash,
		readyHash: hashStrings(fileHash, commandHash),
	}, nil
}

// FileHash hashes platform file bytes and modes independently from commands.
func FileHash(files map[string]FileSpec) string {
	h := sha256.New()
	for _, path := range sortedKeys(files) {
		file := files[path]
		fmt.Fprintf(h, "%d:%s:%d:%d:", len(path), path, file.Mode, len(file.Content))
		_, _ = h.Write(file.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// CommandHash hashes post-configuration command state independently from
// rendered files.
func CommandHash(commands []Command) string {
	h := sha256.New()
	for _, command := range commands {
		fmt.Fprintf(h, "ignore=%t:frr=%t:", command.IgnoreError, command.FRRControl)
		for _, arg := range command.Args {
			fmt.Fprintf(h, "%d:%s:", len(arg), arg)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashStrings(values ...string) string {
	h := sha256.New()
	for _, value := range values {
		fmt.Fprintf(h, "%d:%s:", len(value), value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *Engine) desiredWireHash(top *model.Topology, link *model.Link) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "id=%s\nkind=%s\nvni=%d\nnode=%s\na=%s/%s/%s/%s/%s/%s\nb=%s/%s/%s/%s/%s/%s\n",
		link.ID, link.Kind, link.VNI, e.Node,
		link.A.Device.ID, link.A.Device.Node, link.A.Name, link.A.MAC, link.A.Addr4, link.A.Addr6,
		link.B.Device.ID, link.B.Device.Node, link.B.Name, link.B.MAC, link.B.Addr4, link.B.Addr6)
	fmt.Fprintf(h, "props=%s|%s|%s|%s|", link.Props.Bandwidth, link.Props.Delay, link.Props.Queue, link.Props.Loss)
	if link.Props.MTU != nil {
		fmt.Fprintf(h, "mtu=%d\n", *link.Props.MTU)
	}
	fmt.Fprintf(h, "authoritative=%t\n", e.Authoritative)
	for _, iface := range []*model.Iface{link.A, link.B} {
		if as := top.ASes[iface.Device.ASN]; as != nil {
			fmt.Fprintf(h, "as=%d:mpls=%t:vrf=%s\n", iface.Device.ASN, as.MPLS.Enabled, iface.VRF)
			if vrf := as.VRFs[iface.VRF]; vrf != nil {
				fmt.Fprintf(h, "vrf-table=%d\n", vrf.Table)
			}
		}
	}
	if link.CrossNode() {
		vlan, mtu, port, err := multiplexParameters(top, link.A.Device.Node, link.B.Device.Node, link.VNI)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "cross=%s|%s|%s|%s|vlan=%d|mtu=%d|port=%d\n",
			e.UnderlayIP, e.UnderlayDev, e.PeerUnderlay[link.A.Device.Node], e.PeerUnderlay[link.B.Device.Node],
			vlan, mtu, port)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (e *Engine) setBuildObservation(tracker *observationTracker, diff BuildDiff) {
	e.observationMu.Lock()
	e.observation = tracker
	e.lastDiff = diff
	e.observationMu.Unlock()
}

func (e *Engine) resetMutationCounts() {
	e.mutationMu.Lock()
	e.mutations = map[string]int{
		"image": 0, "create": 0, "wire": 0, "qdisc": 0,
		"configure": 0, "copy": 0, "command": 0,
	}
	e.mutationMu.Unlock()
}

func (e *Engine) recordMutation(kind string, count int) {
	if count <= 0 {
		return
	}
	e.mutationMu.Lock()
	if e.mutations == nil {
		e.mutations = map[string]int{}
	}
	e.mutations[kind] += count
	e.mutationMu.Unlock()
}

func (e *Engine) mutationCounts() map[string]int {
	e.mutationMu.Lock()
	defer e.mutationMu.Unlock()
	out := make(map[string]int, len(e.mutations))
	for key, value := range e.mutations {
		out[key] = value
	}
	return out
}

// LastBuildDiff returns the last desired/observed diff produced by Build.
func (e *Engine) LastBuildDiff() BuildDiff {
	e.observationMu.Lock()
	defer e.observationMu.Unlock()
	out := e.lastDiff
	out.Create = cloneBoolMap(out.Create)
	out.Recreate = cloneBoolMap(out.Recreate)
	out.Wire = cloneBoolMap(out.Wire)
	out.Configure = cloneBoolMap(out.Configure)
	out.Ready = cloneBoolMap(out.Ready)
	out.Semantic = cloneBoolMap(out.Semantic)
	out.Capture = cloneBoolMap(out.Capture)
	return out
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// DirtyCaptureDevices returns the canonical devices whose student state must
// be captured at this deployment's destructive boundary.
func (e *Engine) DirtyCaptureDevices() []string {
	diff := e.LastBuildDiff()
	out := make([]string, 0, len(diff.Capture))
	for id := range diff.Capture {
		out = append(out, id)
	}

	sort.Strings(out)
	return out
}

// DirtySemanticDevices returns devices whose runtime fingerprint drifted while
// OCI/config hashes remained current. Callers persist this set so commit cannot
// report an inventory-only success after a dynamic host or BGP repair.
func (e *Engine) DirtySemanticDevices() []string {
	diff := e.LastBuildDiff()
	out := make([]string, 0, len(diff.Semantic))
	for id := range diff.Semantic {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DirtyCreateDevices is the exact set whose primary runtime contract was
// created/recreated by the observed diff. Only these objects receive a new
// transaction generation label; configure-only work retains creation lineage.
func (e *Engine) DirtyCreateDevices() []string {
	diff := e.LastBuildDiff()
	out := make([]string, 0, len(diff.Recreate))
	for id := range diff.Recreate {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DirtyOverlayVNIs returns the cross-node bindings whose wire plan executes
// in this deployment. The agent persists these facts with device creates so
// a shared multiplex trunk can retain an older lineage when it was reused.
func (e *Engine) DirtyOverlayVNIs(top *model.Topology) []uint32 {
	if top == nil {
		return nil
	}
	diff := e.LastBuildDiff()
	seen := map[uint32]bool{}
	for _, link := range top.Links {
		if link == nil || !link.CrossNode() || !diff.Wire[link.ID] || link.VNI == 0 {
			continue
		}
		if link.A.Device.Node != e.Node && link.B.Device.Node != e.Node {
			continue
		}
		seen[link.VNI] = true
	}
	out := make([]uint32, 0, len(seen))
	for vni := range seen {
		out = append(out, vni)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DeploymentStats combines this build's observed diff with the executed plan.
func (e *Engine) DeploymentStats(report *plan.Report) DeploymentStats {
	diff := e.LastBuildDiff()
	stats := DeploymentStats{
		ObserveMS: diff.ObservedFor.Milliseconds(),
		DiffMS:    diff.DiffedFor.Milliseconds(),
		Dirty:     diff.Counts(),
		Mutations: e.mutationCounts(),
	}
	if report == nil {
		return stats
	}
	stats.Mutations["planned_create"] = report.Completed(plan.StageCreate)
	stats.Mutations["planned_wire"] = report.Completed(plan.StageWire)
	stats.Mutations["planned_configure"] = report.Completed(plan.StageConfigure)
	stats.Mutations["planned_ready"] = report.Completed(plan.StageReady)
	return stats
}

func (e *Engine) currentObservation() *observationTracker {
	e.observationMu.Lock()
	defer e.observationMu.Unlock()
	return e.observation
}
