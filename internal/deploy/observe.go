package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// observationVersion 3 invalidates mode markers written before mode state was
// published only after the complete transition plan succeeded.
const observationVersion = 3

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
	// Namespaces records the network namespace each device's state was last
	// configured in. It is kept beside the hashes rather than inside them
	// because the hashes describe what was asked for and this describes where
	// it was put, and because the ready step rewrites a device's hashes after
	// the configure step recorded this.
	Namespaces map[string]runtime.NetnsIdentity `json:"namespaces,omitempty"`
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
			Version:    observationVersion,
			Lab:        lab,
			Node:       e.Node,
			Devices:    map[string]observedDeviceState{},
			Links:      map[string]observedLinkState{},
			Namespaces: map[string]runtime.NetnsIdentity{},
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
		return tracker, nil //nolint:nilerr // an empty cache is the safe, self-repairing fallback
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
	if decoded.Namespaces == nil {
		decoded.Namespaces = map[string]runtime.NetnsIdentity{}
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

// namespace returns the network namespace this device's state was last
// configured in, and whether one was ever recorded.
func (t *observationTracker) namespace(id string) (runtime.NetnsIdentity, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, ok := t.state.Namespaces[id]
	return value, ok
}

func (t *observationTracker) markNamespace(id string, value runtime.NetnsIdentity) error {
	t.mu.Lock()
	if t.state.Namespaces == nil {
		t.state.Namespaces = map[string]runtime.NetnsIdentity{}
	}
	if t.state.Namespaces[id] != value {
		t.state.Namespaces[id] = value
		t.changed = true
	}
	err := t.saveLocked()
	t.mu.Unlock()
	return err
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
	t.changed = true
	err := t.saveLocked()
	t.mu.Unlock()
	return err
}

// markMode records a renderer mode only after the plan has completed every
// mode-sensitive wire/configure/readiness step. Marking it from the first
// configured device lets an interrupted platform->solve retry treat untouched
// hosts as current because their OCI/config hashes did not change.
func (t *observationTracker) markMode() error {
	if t.e.ModeKey == "" {
		return nil
	}
	t.mu.Lock()
	if t.state.Mode != t.e.ModeKey {
		t.state.Mode = t.e.ModeKey
		t.changed = true
	}
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
	for id := range t.state.Namespaces {
		if !devices[id] {
			delete(t.state.Namespaces, id)
			t.changed = true
		}
	}
	t.mu.Unlock()
}

// deviceObservation is one device's contribution to the build diff. It is
// computed independently per device so the work can be fanned out, then merged
// in device order.
type deviceObservation struct {
	state     desiredDeviceState
	create    bool
	recreate  bool
	configure bool
	ready     bool
	capture   bool
	semantic  bool
}

// observeDevice derives one device's desired state and dirty flags. It touches
// no shared state beyond the tracker, whose accessors are already serialised,
// and performs no runtime, netlink, or filesystem I/O.
func (e *Engine) observeDevice(top *model.Topology, d *model.Device,
	byName map[string]runtime.Container, tracker *observationTracker, modeDirty bool,
) (deviceObservation, error) {
	var out deviceObservation
	state, err := e.renderDesired(d)
	if err != nil {
		return deviceObservation{}, err
	}
	state.runtime, err = e.finalRuntimeSpecs(top, d)
	if err != nil {
		return deviceObservation{}, err
	}
	out.state = state
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
		out.create = true
		if primaryRecreate {
			out.recreate = true
		}
		if studentOwned(top, d) {
			out.capture = true
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
		out.configure = true
		if studentOwned(top, d) {
			out.capture = true
		}
	}
	if e.Renderer != nil && e.Renderer.Ready(d, e.Runtime) != nil &&
		(modeDirty || specDirty || out.configure || !known || previous.ReadyHash != state.readyHash) {
		out.ready = true
	}
	if e.SemanticProbe != nil && !specDirty {
		out.semantic = true
	}
	return out, nil
}

// observedControlNamespaceSplits names devices whose private FRR control
// sidecar is no longer in the network namespace of its router.
//
// It is a screen, not a verdict: it reads only the observation the caller
// already holds, so it costs no further engine round trip on a node with two
// hundred routers, and the create step it schedules proves the relationship
// again before it removes anything. Failing to resolve an identity marks the
// device dirty rather than clean -- a deployment that cannot see where a
// control plane is must do the work, not report a no-op. A backend that offers
// no proof at all stops the deployment outright, because every backend that
// runs split sidecars can prove where they are.
func (e *Engine) observedControlNamespaceSplits(ctx context.Context, devices []*model.Device,
	observations []deviceObservation, byName map[string]runtime.Container,
) (map[string]bool, error) {
	out := map[string]bool{}
	if e.Runtime == nil {
		return out, nil
	}
	for i, d := range devices {
		observation := observations[i]
		if observation.create || observation.state.runtime.controlSpec == nil {
			continue
		}
		primary, primaryOK := byName[d.Container]
		control, controlOK := byName[FRRControlContainer(d)]
		if !primaryOK || !controlOK {
			continue
		}
		primaryNS, err := runtime.ObservedNetnsIdentityOf(ctx, e.Runtime, primary)
		if errors.Is(err, runtime.ErrNamespaceIdentityUnsupported) {
			return nil, fmt.Errorf("%s manages split FRR control sidecars but cannot prove "+
				"network namespace identity: %w", runtimeName(e.Runtime), err)
		}
		if err != nil {
			out[d.ID] = true
			continue
		}
		controlNS, err := runtime.ObservedNetnsIdentityOf(ctx, e.Runtime, control)
		if err != nil || !primaryNS.SameAs(controlNS) {
			out[d.ID] = true
		}
	}
	return out, nil
}

// expandLostStateToPeers adds the neighbours of a device whose namespace-backed
// state is gone.
//
// A veth is a pair, and netx rebuilds it as one: when only one half survives it
// deletes the survivor so the pair can be recreated cleanly. So a router that
// restarted into a new namespace takes its neighbours' interfaces with it, and
// they come back bare -- which on a teaching deployment means with no address,
// because a student-owned address is never rendered by the platform. That is
// why a restarted router loses adjacencies its neighbour was not restarted for,
// and why repairing only the router that moved leaves the link down at the far
// end.
//
// The expansion is one hop. Only the links of the device that lost its
// namespace are rebuilt; its neighbours' other links are untouched, and a
// cross-node neighbour's half hangs off a shared overlay this node never
// deletes.
func expandLostStateToPeers(devices []*model.Device, lost map[string]bool, node string) {
	if len(lost) == 0 {
		return
	}
	peers := map[string]bool{}
	for _, d := range devices {
		if !lost[d.ID] {
			continue
		}
		for _, iface := range d.Ifaces {
			if iface.Link == nil || iface.Link.CrossNode() {
				continue
			}
			other := iface.Link.Other(iface)
			if other == nil || other.Device == nil || other.Device.Node != node {
				continue
			}
			peers[other.Device.ID] = true
		}
	}
	for id := range peers {
		lost[id] = true
	}
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
	overlayDirty := map[uint32]bool{}
	hasCrossNode := false
	for _, link := range top.Links {
		if link != nil && link.CrossNode() &&
			(link.A.Device.Node == e.Node || link.B.Device.Node == e.Node) {
			hasCrossNode = true
			break
		}
	}
	if hasCrossNode {
		expected, err := e.ExpectedOverlayInventory(top)
		if err != nil {
			return nil, nil, BuildDiff{}, fmt.Errorf("derive expected overlays for %s: %w", top.Name, err)
		}
		actual, err := e.observedOverlayInventory(top.Name)
		if err != nil {
			return nil, nil, BuildDiff{}, fmt.Errorf("observe overlays for %s: %w", top.Name, err)
		}
		overlayDirty = dirtyOverlayBindings(expected, actual)
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
	}
	// Rendering every device's configuration and deriving its final runtime
	// spec is the single largest pure-CPU stage of a scale deployment, and
	// each device is independent of every other. Fan it out and merge the
	// results in device order, so the diff, its error, and the observation
	// snapshot stay byte-for-byte what a sequential pass produced.
	observations := make([]deviceObservation, len(devices))
	_, observeErrs, ctxErr := e.runBoundedWidth(ctx, e.observationWorkers(len(devices)), len(devices),
		func(i int) error {
			observation, err := e.observeDevice(top, devices[i], byName, tracker, modeDirty)
			if err != nil {
				return err
			}
			observations[i] = observation
			return nil
		})
	if ctxErr != nil {
		return nil, nil, BuildDiff{}, ctxErr
	}
	for _, err := range observeErrs {
		if err != nil {
			return nil, nil, BuildDiff{}, err
		}
	}
	semanticDevices := make([]*model.Device, 0, len(devices))
	// A sidecar whose spec hash and state are both right may still be attached
	// to a namespace its router has left behind. That is invisible to every
	// label comparison above, so it is screened here from the observation
	// already in hand; the create step re-proves it before acting.
	splitControls, err := e.observedControlNamespaceSplits(ctx, devices, observations, byName)
	if err != nil {
		return nil, nil, BuildDiff{}, err
	}
	// A device may also have been restarted into a new namespace without any
	// sidecar to give it away. The sidecar split is one way of proving that;
	// the namespace a device was last configured in is the general one.
	replacedNamespaces := e.observedNamespaceReplacements(ctx, devices, byName, tracker)
	// An orphaned sidecar is proof that its router's namespace was replaced:
	// the sidecar joined that namespace when it was built and has not moved
	// since. Both findings mean the same repair.
	lost := map[string]bool{}
	for _, d := range devices {
		if splitControls[d.ID] || replacedNamespaces[d.ID] {
			lost[d.ID] = true
		}
	}
	expandLostStateToPeers(devices, lost, e.Node)
	for i, d := range devices {
		observation := observations[i]
		if splitControls[d.ID] {
			observation.create = true
		}
		if lost[d.ID] {
			e.markNamespaceStateLost(d.ID)
			// The configure step is where a device's saved state is replayed,
			// so it is scheduled whether or not there is anything to render
			// into the device. The replay is the reason, and it is not a
			// rendering concern.
			observation.configure = true
			if e.Renderer != nil && e.Renderer.Ready(d, e.Runtime) != nil {
				// A rebuilt sidecar starts with no daemons, and a replayed
				// device has just had its addressing put back. The readiness
				// gate is the check that the control plane came back, so a
				// deployment must not skip it here of all places.
				observation.ready = true
			}
			if studentOwned(top, d) {
				observation.capture = true
			}
			observation.semantic = false
			observations[i] = observation
		}
		desired[d.ID] = observation.state
		if observation.create {
			diff.Create[d.ID] = true
		}
		if observation.recreate {
			diff.Recreate[d.ID] = true
		}
		if observation.configure {
			diff.Configure[d.ID] = true
		}
		if observation.ready {
			diff.Ready[d.ID] = true
		}
		if observation.capture {
			diff.Capture[d.ID] = true
		}
		if observation.semantic {
			semanticDevices = append(semanticDevices, d)
		}
	}
	if len(semanticDevices) > 0 {
		_, semanticErrs, ctxErr := e.runBounded(ctx, len(semanticDevices), func(i int) error {
			return e.SemanticProbe(ctx, semanticDevices[i])
		})
		if ctxErr != nil {
			return nil, nil, BuildDiff{}, ctxErr
		}
		for i, semanticErr := range semanticErrs {
			if semanticErr == nil {
				continue
			}
			d := semanticDevices[i]
			// The renderer commands are deliberately idempotent. Mark the
			// device dirty so `deploy --solve` repairs a live address, route,
			// VLAN, or BGP-session drift even when every observed file hash
			// says the deploy is otherwise a no-op.
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

	wantLinks := map[string]bool{}
	nodeLinks := make([]*model.Link, 0, len(top.Links))
	for _, link := range top.Links {
		if link == nil || (link.A.Device.Node != e.Node && link.B.Device.Node != e.Node) {
			continue
		}
		wantLinks[link.ID] = true
		nodeLinks = append(nodeLinks, link)
	}
	// The desired wire hash is a pure function of the topology and this
	// engine's immutable underlay identity, so hashing every link this node
	// touches is independent CPU work. Compute it once here; the wire steps
	// reuse the result rather than hashing the same link a second time.
	linkHashes := make(map[string]string, len(nodeLinks))
	hashes := make([]string, len(nodeLinks))
	_, hashErrs, ctxErr := e.runBoundedWidth(ctx, e.observationWorkers(len(nodeLinks)), len(nodeLinks),
		func(i int) error {
			hash, err := e.desiredWireHash(top, nodeLinks[i])
			if err != nil {
				return err
			}
			hashes[i] = hash
			return nil
		})
	if ctxErr != nil {
		return nil, nil, BuildDiff{}, ctxErr
	}
	for _, err := range hashErrs {
		if err != nil {
			return nil, nil, BuildDiff{}, err
		}
	}
	for i, link := range nodeLinks {
		hash := hashes[i]
		linkHashes[link.ID] = hash
		previous, known := tracker.link(link.ID)
		endpointCreate := (link.A.Device.Node == e.Node && diff.Create[link.A.Device.ID]) ||
			(link.B.Device.Node == e.Node && diff.Create[link.B.Device.ID])
		bootstrap := !endpointCreate && linkLabelHashMatches(byName, link, e.Node, top.Hash)
		if !known && bootstrap {
			tracker.bootstrapLink(link.ID, hash)
			known = true
			previous = observedLinkState{Hash: hash}
		}
		if modeDirty || endpointCreate || !known || previous.Hash != hash ||
			(link.CrossNode() && overlayDirty[link.VNI]) {
			diff.Wire[link.ID] = true
		}
	}
	tracker.prune(wantDevices, wantLinks)
	if !e.ObservationReadOnly {
		if err := tracker.save(); err != nil {
			return nil, nil, BuildDiff{}, err
		}
	}
	diff.DiffedFor = time.Since(diffStart)
	e.setDesiredLinkHashes(linkHashes)
	return tracker, desired, diff, nil
}

// setDesiredLinkHashes publishes the wire hashes observation already computed
// so a wire step records the link without hashing it again.
func (e *Engine) setDesiredLinkHashes(hashes map[string]string) {
	e.observationMu.Lock()
	e.desiredLinkHashes = hashes
	e.observationMu.Unlock()
}

// observedWireHash returns the hash observation computed for a link, falling
// back to recomputing it if observation did not record one.
func (e *Engine) observedWireHash(top *model.Topology, link *model.Link) (string, error) {
	e.observationMu.Lock()
	hash, ok := e.desiredLinkHashes[link.ID]
	e.observationMu.Unlock()
	if ok {
		return hash, nil
	}
	return e.desiredWireHash(top, link)
}

func (e *Engine) observedOverlayInventory(lab string) (netx.OverlayInventory, error) {
	if e.inspectOverlayInventory != nil {
		return e.inspectOverlayInventory(lab)
	}
	return netx.InspectOverlayInventory(lab)
}

// dirtyOverlayBindings returns the logical links that cannot be accepted as a
// no-op. Logical VNI/VLAN/FDB facts and physical shared trunks are both
// verified: a present VNI alone is insufficient evidence that frames reach
// only the intended peer.
func dirtyOverlayBindings(expected, actual netx.OverlayInventory) map[uint32]bool {
	dirty := map[uint32]bool{}
	expectedByVNI := map[uint32]netx.LogicalBinding{}
	for _, binding := range expected.Bindings {
		expectedByVNI[binding.VNI] = binding
	}
	markAll := func() {
		for vni := range expectedByVNI {
			dirty[vni] = true
		}
	}
	markPair := func(a, b string) {
		for vni, binding := range expectedByVNI {
			if binding.NodeA == a && binding.NodeB == b {
				dirty[vni] = true
			}
		}
	}

	actualByVNI := map[uint32][]netx.LogicalBinding{}
	for _, binding := range actual.Bindings {
		actualByVNI[binding.VNI] = append(actualByVNI[binding.VNI], binding)
	}
	for vni, want := range expectedByVNI {
		got := actualByVNI[vni]
		if len(got) != 1 || !sameLogicalBinding(want, got[0]) {
			dirty[vni] = true
		}
	}
	for vni := range actualByVNI {
		if _, known := expectedByVNI[vni]; !known {
			markAll()
		}
	}

	expectedTrunks := map[string]netx.PhysicalTrunk{}
	for _, trunk := range expected.Trunks {
		expectedTrunks[trunkPairKey(trunk.NodeA, trunk.NodeB)] = trunk
	}
	actualTrunks := map[string][]netx.PhysicalTrunk{}
	for _, trunk := range actual.Trunks {
		if trunk.Legacy {
			continue
		}
		key := trunkPairKey(trunk.NodeA, trunk.NodeB)
		actualTrunks[key] = append(actualTrunks[key], trunk)
	}
	for key, want := range expectedTrunks {
		got := actualTrunks[key]
		if len(got) != 1 || !samePhysicalTrunk(want, got[0]) {
			markPair(want.NodeA, want.NodeB)
		}
	}
	for key := range actualTrunks {
		if _, known := expectedTrunks[key]; !known {
			markAll()
		}
	}
	return dirty
}

func sameLogicalBinding(a, b netx.LogicalBinding) bool {
	return a.VNI == b.VNI && a.VLAN == b.VLAN && a.Peer == b.Peer &&
		a.MTU == b.MTU && a.Port == b.Port && a.NodeA == b.NodeA && a.NodeB == b.NodeB
}

func samePhysicalTrunk(a, b netx.PhysicalTrunk) bool {
	return a.Bridge == b.Bridge && a.Vxlan == b.Vxlan && a.MTU == b.MTU &&
		a.Port == b.Port && a.NodeA == b.NodeA && a.NodeB == b.NodeB
}

func trunkPairKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
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
		vlan, mtu, port, err := e.multiplexParameters(top, link.A.Device.Node, link.B.Device.Node, link.VNI)
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
