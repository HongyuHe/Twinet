package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// recordNamespace puts a device's namespace into the persisted observation the
// way a completed configure step does.
func recordNamespace(t *testing.T, engine *Engine, top *model.Topology,
	d *model.Device, identity rt.NetnsIdentity,
) {
	t.Helper()
	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.markNamespace(d.ID, identity); err != nil {
		t.Fatal(err)
	}
}

// The defect this whole file is about: a containerd router whose pid 1 is
// killed comes back with the same name, the same image, the same specification
// hash and the same files, in a namespace that has nothing in it. Every
// comparison a deployment makes says it is current, and the addressing its
// student configured -- which on a teaching deployment lives in the state
// store and nowhere else -- is never asked for back.
func TestARestartedDeviceIsNotCurrentInItsNewNamespace(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	was := runtime.identity[device.Container]
	recordNamespace(t, engine, top, device, was)

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if engine.namespaceStateLost(device.ID) {
		t.Fatal("a device that never moved was reported as restarted")
	}

	// The router is killed and comes back. So does its sidecar, because the
	// sidecar joins whatever namespace the router is in now, which is exactly
	// why nothing else notices.
	now := rt.NetnsIdentity{Dev: was.Dev, Inode: was.Inode + 1}
	runtime.identity[device.Container] = now
	runtime.identity[FRRControlContainer(device)] = now

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.namespaceStateLost(device.ID) {
		t.Fatal("a deploy saw a router in a namespace it was never configured in and called it current")
	}
	diff := engine.LastBuildDiff()
	if !diff.Capture[device.ID] {
		t.Fatal("the restarted router's student state was not scheduled for capture")
	}
	if diff.Recreate[device.ID] {
		t.Fatal("a namespace replacement was repaired by destroying the student's router")
	}
	if diff.Empty() {
		t.Fatal("a deploy reported no work at all over a router with an empty namespace")
	}
}

// An orphaned sidecar is the other proof, and the only one available the first
// time a node runs this code: nothing has recorded a namespace yet, but a
// sidecar sitting in a namespace its router has left says the router moved.
func TestAnOrphanedSidecarProvesTheRouterMoved(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	runtime.identity[FRRControlContainer(device)] = rt.NetnsIdentity{Dev: 4, Inode: 4026535379}

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.namespaceStateLost(device.ID) {
		t.Fatal("an orphaned sidecar did not schedule the router's saved state for replay")
	}
	if !engine.LastBuildDiff().Create[device.ID] {
		t.Fatal("an orphaned sidecar was not scheduled for rebuilding")
	}
}

// Fail closed. An identity that could not be read is not evidence that the
// namespace survived, and the cost of being wrong is one replay of state the
// store already holds.
func TestAnUnreadableNamespaceIsNotEvidenceOfSurvival(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	recordNamespace(t, engine, top, device, runtime.identity[device.Container])
	runtime.failFor[device.Container] = errors.New("permission denied")

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.namespaceStateLost(device.ID) {
		t.Fatal("a namespace that could not be read was treated as the one the device was configured in")
	}
}

// The blind spot, stated as a test so it stays one line wide: a device nothing
// has ever recorded a namespace for is left alone. Inventing a replacement
// there would replay a snapshot over a device that is working.
func TestADeviceWithNoRecordedNamespaceIsLeftAlone(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	runtime.identity[device.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026599999}
	runtime.identity[FRRControlContainer(device)] = runtime.identity[device.Container]

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if engine.namespaceStateLost(device.ID) {
		t.Fatal("a device with no recorded namespace was reported as restarted")
	}
}

// A backend that cannot prove namespace identity is not asked to. Its
// containers are replaced rather than restarted when their task dies, and the
// create path restores through its own marker.
func TestABackendWithoutTheProofMakesNoNamespaceClaim(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	recordNamespace(t, engine, top, device, runtime.identity[device.Container])
	engine.Runtime = &observedRuntime{containers: runtime.containers, files: map[string][]byte{}}

	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]rt.Container{}
	for _, c := range runtime.containers {
		byName[c.Name] = c
	}
	replaced := engine.observedNamespaceReplacements(context.Background(),
		[]*model.Device{device}, byName, tracker)
	if len(replaced) != 0 {
		t.Fatalf("a backend with no namespace proof reported replacements: %v", replaced)
	}
	if err := engine.recordDeviceNamespace(context.Background(), tracker, device); err != nil {
		t.Fatalf("recording a namespace on a backend that has none failed: %v", err)
	}
	if _, known := tracker.namespace(device.ID + "-absent"); known {
		t.Fatal("a namespace was invented for a device that has none")
	}
}

// What the configure step records is what the next deployment compares
// against, so the round trip has to close.
func TestTheConfiguredNamespaceIsRecordedForTheNextPass(t *testing.T) {
	engine, top, device, runtime := namespaceAwareLab(t)
	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.recordDeviceNamespace(context.Background(), tracker, device); err != nil {
		t.Fatal(err)
	}
	recorded, known := tracker.namespace(device.ID)
	if !known || !recorded.SameAs(runtime.identity[device.Container]) {
		t.Fatalf("the configured namespace was recorded as %v (known=%t)", recorded, known)
	}

	byName := map[string]rt.Container{}
	for _, c := range runtime.containers {
		byName[c.Name] = c
	}
	if replaced := engine.observedNamespaceReplacements(context.Background(),
		[]*model.Device{device}, byName, tracker); replaced[device.ID] {
		t.Fatal("a device was reported as moved from the namespace just recorded for it")
	}

	runtime.identity[device.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026552128}
	byName[device.Container] = runtime.containers[0]
	if replaced := engine.observedNamespaceReplacements(context.Background(),
		[]*model.Device{device}, byName, tracker); !replaced[device.ID] {
		t.Fatal("a device that moved out of its recorded namespace was reported as current")
	}
}

func namespaceSnapshots() []state.Snapshot {
	return []state.Snapshot{
		{Lab: "l", Device: "as1/R1", Kind: state.KindFRR, Content: []byte("router ospf\n")},
		{Lab: "l", Device: "as1/R1", Kind: state.KindAddrs, Content: []byte("")},
		{Lab: "l", Device: "as1/R1", Kind: state.KindTunnels, Content: []byte("")},
		{Lab: "l", Device: "as1/R1", Kind: state.KindOVS, Content: []byte("")},
	}
}

func kinds(snaps []state.Snapshot) []state.Kind {
	out := make([]state.Kind, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, s.Kind)
	}
	return out
}

func contains(kinds []state.Kind, want state.Kind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

// A deployment captures at every destructive boundary, and the boundary a
// restarted router arrives at is the moment its namespace is empty. Capturing
// then overwrites the one copy of the work the very same pass is about to
// replay.
func TestNamespaceBackedStateIsNotCapturedOverTheSnapshot(t *testing.T) {
	device := &model.Device{ID: "as1/R1", Container: "tw-r1", Kind: model.KindRouter}
	engine := &Engine{Runtime: &markerRuntime{markers: map[string]bool{}}}

	kept := kinds(engine.storableSnapshots(context.Background(), device, namespaceSnapshots()))
	if len(kept) != 4 {
		t.Fatalf("an untouched device had state withheld: %v", kept)
	}

	engine.markNamespaceStateLost(device.ID)
	kept = kinds(engine.storableSnapshots(context.Background(), device, namespaceSnapshots()))
	if !contains(kept, state.KindFRR) {
		t.Fatalf("the routing configuration is a file and must still be captured: %v", kept)
	}
	for _, kind := range []state.Kind{state.KindAddrs, state.KindTunnels, state.KindOVS} {
		if contains(kept, kind) {
			t.Fatalf("%s was captured from a namespace the device had just been restarted into: %v",
				kind, kept)
		}
	}

	// Made good by the replay, so the device's state is its student's work
	// again and the next capture is the truth.
	engine.clearNamespaceStateLost(device.ID)
	if kept = kinds(engine.storableSnapshots(context.Background(), device, namespaceSnapshots())); len(kept) != 4 {
		t.Fatalf("a replayed device still had its state withheld: %v", kept)
	}
}

// Capture is also run by an engine that did no observing, and by a later agent
// entirely. The marker in the container is what carries the finding across
// those boundaries.
func TestAPendingRestoreWithholdsNamespaceBackedStateFromAnyEngine(t *testing.T) {
	device := &model.Device{ID: "as1/R1", Container: "tw-r1", Kind: model.KindRouter}
	runtime := &markerRuntime{markers: map[string]bool{device.Container: true}}
	engine := &Engine{Runtime: runtime}

	kept := kinds(engine.storableSnapshots(context.Background(), device, namespaceSnapshots()))
	if contains(kept, state.KindAddrs) {
		t.Fatalf("a device still owing a restore had its empty addressing captured: %v", kept)
	}
	if !contains(kept, state.KindFRR) {
		t.Fatalf("a device still owing a restore lost its routing configuration: %v", kept)
	}

	delete(runtime.markers, device.Container)
	if kept = kinds(engine.storableSnapshots(context.Background(), device, namespaceSnapshots())); len(kept) != 4 {
		t.Fatalf("a device owing nothing had its state withheld: %v", kept)
	}
}

// A veth is a pair and netx rebuilds it as one, so a router that restarted
// takes its neighbours' interfaces with it. Repairing only the router that
// moved leaves the link with an address at one end, which is a lab with no
// adjacency and a deployment that reported success.
func TestARestartedRoutersNeighboursAreReplayedToo(t *testing.T) {
	near := &model.Device{ID: "as1/R1", Container: "tw-r1", Node: "node-a"}
	far := &model.Device{ID: "as1/R2", Container: "tw-r2", Node: "node-a"}
	elsewhere := &model.Device{ID: "as1/R3", Container: "tw-r3", Node: "node-b"}
	bystander := &model.Device{ID: "as1/R4", Container: "tw-r4", Node: "node-a"}

	internal := &model.Link{ID: "l1"}
	internal.A = &model.Iface{Device: near, Name: "port_R2", Link: internal}
	internal.B = &model.Iface{Device: far, Name: "port_R1", Link: internal}
	near.Ifaces = append(near.Ifaces, internal.A)
	far.Ifaces = append(far.Ifaces, internal.B)

	crossNode := &model.Link{ID: "l2"}
	crossNode.A = &model.Iface{Device: near, Name: "port_R3", Link: crossNode}
	crossNode.B = &model.Iface{Device: elsewhere, Name: "port_R1", Link: crossNode}
	near.Ifaces = append(near.Ifaces, crossNode.A)

	// Two hops away: R4's cables were never touched, so replaying its state
	// would revert work nobody's restart affected.
	beyond := &model.Link{ID: "l3"}
	beyond.A = &model.Iface{Device: far, Name: "port_R4", Link: beyond}
	beyond.B = &model.Iface{Device: bystander, Name: "port_R2", Link: beyond}
	far.Ifaces = append(far.Ifaces, beyond.A)
	bystander.Ifaces = append(bystander.Ifaces, beyond.B)

	devices := []*model.Device{near, far, elsewhere, bystander}
	lost := map[string]bool{near.ID: true}
	expandLostStateToPeers(devices, lost, "node-a")

	if !lost[far.ID] {
		t.Fatal("the neighbour whose interface was rebuilt was left with no address")
	}
	if lost[elsewhere.ID] {
		t.Fatal("a cross-node neighbour was replayed; its half hangs off an overlay this node never deleted")
	}
	if lost[bystander.ID] {
		t.Fatal("a device two hops away was replayed over work no restart touched")
	}
}

// The devices a deployment repaired are the devices whose cached health
// verdict is now wrong, so the engine has to be able to name them after the
// repair rather than only during it.
func TestARepairedDeviceIsStillReportedAfterItIsMadeGood(t *testing.T) {
	engine := &Engine{}
	if got := engine.DirtyNamespaceStateDevices(); len(got) != 0 {
		t.Fatalf("an untouched deployment reported repairs: %v", got)
	}

	engine.markNamespaceStateLost("as1/R2")
	engine.markNamespaceStateLost("as1/R1")
	if !engine.namespaceStateLost("as1/R1") {
		t.Fatal("a device with state to replay was reported as settled")
	}

	engine.clearNamespaceStateLost("as1/R1")
	if engine.namespaceStateLost("as1/R1") {
		t.Fatal("a replayed device is still owed a replay")
	}
	got := engine.DirtyNamespaceStateDevices()
	if len(got) != 2 || got[0] != "as1/R1" || got[1] != "as1/R2" {
		t.Fatalf("the repaired devices were reported as %v", got)
	}
}

// namespaceAwareLinkedLab builds a lab of plain devices -- no FRR, so no
// control sidecar and none of the evidence a split one provides -- wired in a
// line, with the namespace of every container under the test's control.
func namespaceAwareLinkedLab(t *testing.T) (*Engine, *model.Topology,
	[]*model.Device, *namespaceAwareRuntime,
) {
	t.Helper()
	top := &model.Topology{
		Name: "linked", Hash: "linked-hash", Devices: map[string]*model.Device{},
		ASes: map[int]*model.AS{1: {ASN: 1, Role: model.RoleStudent}},
	}
	var devices []*model.Device
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("as1/H%d", i)
		d := &model.Device{
			ID: id, Name: fmt.Sprintf("H%d", i), Container: fmt.Sprintf("tw-h%d", i),
			Image: "host:stable", Node: "node-a", ASN: 1,
		}
		top.Devices[id] = d
		devices = append(devices, d)
	}
	for i := 0; i < 2; i++ {
		link := &model.Link{ID: fmt.Sprintf("l%d%d", i, i+1), Kind: model.LinkVeth}
		link.A = &model.Iface{Device: devices[i], Name: fmt.Sprintf("port_H%d", i+1), Link: link}
		link.B = &model.Iface{Device: devices[i+1], Name: fmt.Sprintf("port_H%d", i), Link: link}
		devices[i].Ifaces = append(devices[i].Ifaces, link.A)
		devices[i+1].Ifaces = append(devices[i+1].Ifaces, link.B)
		top.Links = append(top.Links, link)
	}
	runtime := &namespaceAwareRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		identity:        map[string]rt.NetnsIdentity{},
		failFor:         map[string]error{},
	}
	root := observeTestRoot(t)
	renderer := observedRenderer{revision: map[string]string{}}
	engine := &Engine{
		Runtime: runtime, Node: "node-a", ObservationRoot: root, Renderer: renderer,
		FRRControlRoot: filepath.Join(root, "frr-control"),
	}
	for i, d := range devices {
		renderer.revision[d.ID] = "one"
		hash, err := engine.FinalSpecHash(top, d)
		if err != nil {
			t.Fatal(err)
		}
		runtime.containers = append(runtime.containers, rt.Container{
			Name: d.Container, State: rt.StateRunning, PID: 5000 + i,
			Labels: map[string]string{
				LabelSpec: hash, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
			},
		})
		runtime.identity[d.Container] = rt.NetnsIdentity{Dev: 4, Inode: uint64(4026550000 + i)}
	}
	return engine, top, devices, runtime
}

// A device with no control sidecar has no orphan to give it away, so the
// recorded namespace is the only evidence it restarted -- and noticing is only
// half of the repair. Its cables went with the namespace it left, and a link is
// rebuilt only when one of its endpoints is being created. Marking the device
// for replay without that scheduled its saved addresses onto interfaces that
// were not there: the replay succeeded and put nothing anywhere.
func TestARestartedDeviceRebuildsItsOwnLinksAndOnlyThose(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if diff := engine.LastBuildDiff(); !diff.Empty() {
		t.Fatalf("an untouched lab planned work: %#v", diff)
	}

	moved := devices[1]
	runtime.identity[moved.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026559999}

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	diff := engine.LastBuildDiff()
	if !diff.Create[moved.ID] {
		t.Fatal("a restarted device was scheduled for a replay but not for the create " +
			"that rebuilds the links its addresses have to land on")
	}
	if diff.Recreate[moved.ID] {
		t.Fatal("a namespace replacement was repaired by destroying the student's device")
	}
	for _, link := range top.Links {
		if !diff.Wire[link.ID] {
			t.Fatalf("link %s touches the restarted device and was not rebuilt; its "+
				"interface is gone and the replay has nowhere to put an address", link.ID)
		}
	}
	// The neighbours lost the far half of a rebuilt pair, so their state is
	// replayed -- but nothing restarted them, and rebuilding their containers
	// or their other cables is a repair nobody asked for.
	for _, peer := range []*model.Device{devices[0], devices[2]} {
		if !diff.Configure[peer.ID] {
			t.Fatalf("%s lost its half of a rebuilt veth and was not scheduled to replay", peer.ID)
		}
		if diff.Create[peer.ID] {
			t.Fatalf("%s did not restart and was scheduled for a container repair", peer.ID)
		}
	}
}

// Only the device that moved brings its links with it. A neighbour dragged in
// by the expansion has no reason to have its own, untouched cables rebuilt.
func TestAPeersOtherLinksAreLeftAlone(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}

	moved := devices[0]
	runtime.identity[moved.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026558888}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	diff := engine.LastBuildDiff()
	if !diff.Wire["l01"] {
		t.Fatal("the restarted device's own link was not rebuilt")
	}
	if diff.Wire["l12"] {
		t.Fatal("a link neither endpoint of which restarted was torn down and rebuilt, " +
			"which deletes a working veth pair and strips both ends of their addresses")
	}
}

// The order is the repair. An address cannot be put on an interface that does
// not exist, so the configure step that replays a device's saved state must not
// be reachable until every link it owns has been rebuilt.
func TestAReplayCannotRunBeforeTheLinksItNeeds(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	moved := devices[1]
	runtime.identity[moved.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026557777}

	p, err := engine.Build(top)
	if err != nil {
		t.Fatal(err)
	}
	var configure *plan.Step
	for _, step := range p.Steps() {
		if step.ID == "configure:"+moved.ID {
			configure = step
		}
	}
	if configure == nil {
		t.Fatal("the restarted device has no configure step, so its state is never replayed")
	}
	needs := map[string]bool{}
	for _, need := range configure.Needs {
		needs[need] = true
	}
	for _, want := range []string{"create:" + moved.ID, "wire:l01", "wire:l12"} {
		if !needs[want] {
			t.Fatalf("the replay of %s does not wait for %q: %v", moved.ID, want, configure.Needs)
		}
	}

	// And prove the dependency is enforced rather than merely declared. Wiring
	// needs netlink, which a test does not have; a wire step that cannot run
	// must take the replay with it rather than leave it to configure a device
	// with no interfaces.
	runtime.nsPathErr = errors.New("no netlink in this test")
	rep, err := p.Execute(context.Background(), plan.Options{ContinueOnError: true})
	if err != nil {
		t.Fatal(err)
	}
	var ran, skipped bool
	for _, res := range rep.Results {
		if res.Step.ID != "configure:"+moved.ID {
			continue
		}
		ran = !res.Skipped
		skipped = res.Skipped
	}
	if ran || !skipped {
		t.Fatal("the replay ran even though the links it depends on could not be rebuilt, " +
			"so the student's addresses were applied to interfaces that do not exist")
	}
}

// persistedNamespaces reads back what the deployment actually wrote, rather
// than what an engine still holds in memory.
func persistedNamespaces(t *testing.T, engine *Engine, lab string) map[string]rt.NetnsIdentity {
	t.Helper()
	raw, err := os.ReadFile(engine.observationPath(lab))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	var observed nodeObservedState
	if err := json.Unmarshal(raw, &observed); err != nil {
		t.Fatal(err)
	}
	return observed.Namespaces
}

// The upgrade window. Every device on a node that has been running for a term
// has no recorded namespace the first time this code sees it, and a device
// that is healthy and stays healthy never configures -- so nothing would ever
// record one, and its first restart would be invisible for ever.
//
// A passing semantic probe is the proof that makes a baseline safe: the device
// has the network state the model says it should, in the namespace it is in
// now, which is the whole claim a baseline makes.
func TestAnUpgradeBaselinesTheDevicesItCanProveHealthy(t *testing.T) {
	engine, top, devices, runtime := namespaceAwareLinkedLab(t)
	engine.SemanticProbe = func(context.Context, *model.Device) error { return nil }

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if diff := engine.LastBuildDiff(); !diff.Empty() {
		t.Fatalf("baselining an upgraded node planned work on it: %#v", diff)
	}
	recorded := persistedNamespaces(t, engine, top.Name)
	for _, d := range devices {
		if recorded[d.ID] != runtime.identity[d.Container] {
			t.Fatalf("%s was left with no recorded namespace after a healthy apply, so "+
				"its next restart is invisible: %+v", d.ID, recorded)
		}
	}

	// And the point of having one: the next restart is now detectable on a
	// device that has no sidecar to give it away.
	moved := devices[2]
	runtime.identity[moved.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026551111}
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.namespaceStateLost(moved.ID) {
		t.Fatal("a device baselined by the upgrade restarted and the deploy called it current")
	}
}

// A plan reports what a deployment would do. It must not decide what the next
// deployment trusts, because nothing it observed was ever acted on.
func TestAReadOnlyPlanRecordsNoBaseline(t *testing.T) {
	engine, top, _, _ := namespaceAwareLinkedLab(t)
	engine.SemanticProbe = func(context.Context, *model.Device) error { return nil }
	engine.ObservationReadOnly = true

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if recorded := persistedNamespaces(t, engine, top.Name); len(recorded) != 0 {
		t.Fatalf("a read-only plan persisted namespace baselines: %+v", recorded)
	}
}

// The dangerous half of the upgrade window. A device that restarted weeks ago
// is unbaselined *and* empty: its student's addressing is in the state store
// and nowhere else. Recording its namespace would settle the question the
// wrong way for ever, and capturing from it would file the emptiness over the
// only copy of the work.
func TestAnAlreadyBrokenDeviceIsNeitherBlessedNorCaptured(t *testing.T) {
	engine, top, devices, _ := namespaceAwareLinkedLab(t)
	broken := devices[0]
	engine.SemanticProbe = func(_ context.Context, d *model.Device) error {
		if d.ID == broken.ID {
			return errors.New("no address on port_H1")
		}
		return nil
	}

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	recorded := persistedNamespaces(t, engine, top.Name)
	if _, ok := recorded[broken.ID]; ok {
		t.Fatal("a device whose network state is missing had its namespace recorded as " +
			"the one its student worked in; the restart can never be detected now")
	}
	if _, ok := recorded[devices[1].ID]; !ok {
		t.Fatal("one unhealthy device stopped its healthy neighbours being baselined")
	}
	if !engine.LastBuildDiff().Configure[broken.ID] {
		t.Fatal("an unhealthy device was left unrepaired as well as unbaselined")
	}

	kept := engine.storableSnapshots(context.Background(), broken, []state.Snapshot{
		{Device: broken.ID, Kind: state.KindFRR, Content: []byte("router ospf")},
		{Device: broken.ID, Kind: state.KindAddrs, Content: []byte("# nothing is here")},
	})
	if len(kept) != 1 || kept[0].Kind != state.KindFRR {
		t.Fatalf("an unbaselined device with no network state had it captured over the "+
			"snapshot that is the only copy: %+v", kept)
	}

	// Repairing it is what closes the window: once the probe passes, the
	// baseline is safe and capture resumes.
	engine.SemanticProbe = func(context.Context, *model.Device) error { return nil }
	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if _, ok := persistedNamespaces(t, engine, top.Name)[broken.ID]; !ok {
		t.Fatal("a device that is healthy again was never baselined, so it stays " +
			"unprotected and its state is never captured again")
	}
	if got := engine.storableSnapshots(context.Background(), broken, []state.Snapshot{
		{Device: broken.ID, Kind: state.KindAddrs, Content: []byte("ip addr add ...")},
	}); len(got) != 1 {
		t.Fatal("a repaired device's state is still being withheld from the store")
	}
}

// A configure step records the namespace it leaves a device in, which is the
// baseline the next pass compares against. It must not do so for a device
// whose network state was missing and unproven: configuring proves the
// platform's own rendering was applied, not that this namespace is the one the
// student's work was in.
func TestAnUnprovenDeviceIsNotBaselinedByConfiguringIt(t *testing.T) {
	engine, top, devices, _ := namespaceAwareLinkedLab(t)
	unproven := devices[1]
	engine.markNamespaceUnproven(unproven.ID)
	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.recordDeviceNamespace(context.Background(), tracker, unproven); err != nil {
		t.Fatal(err)
	}
	if _, known := tracker.namespace(unproven.ID); known {
		t.Fatal("configuring an unproven device recorded its namespace as a baseline")
	}
	if err := engine.recordDeviceNamespace(context.Background(), tracker, devices[0]); err != nil {
		t.Fatal(err)
	}
	if _, known := tracker.namespace(devices[0].ID); !known {
		t.Fatal("an ordinary configure stopped recording the namespace it left the device in")
	}
}

// orphanRuntime is a container that still exists, can be read, and remembers
// whether it carries the marker saying its student's configuration has not
// been replayed into it yet.
type orphanRuntime struct {
	rt.Runtime
	marked   map[string]bool
	removals []string
}

func (r *orphanRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	return rt.Container{Name: name, State: rt.StateRunning}, nil
}

func (r *orphanRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	return []rt.Container{{
		Name: "tw-atl", State: rt.StateRunning,
		Labels: map[string]string{
			LabelLab: "cos461", LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	}}, nil
}

func (r *orphanRuntime) Remove(_ context.Context, name string, _ bool) error {
	r.removals = append(r.removals, name)
	return nil
}

func (r *orphanRuntime) Exec(_ context.Context, c string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(cmd.Cmd, " ")
	switch {
	case strings.HasPrefix(body, "test -f "+restoreMarker):
		if !r.marked[c] {
			return rt.ExecResult{ExitCode: 1}, nil
		}
		return rt.ExecResult{}, nil
	case strings.HasPrefix(body, "vtysh"):
		return rt.ExecResult{Stdout: "router ospf\n network 3.0.8.0/24 area 0\n"}, nil
	}
	// Everything a namespace-backed capture reads: an empty namespace, which
	// is exactly what a device that has not been replayed into has.
	return rt.ExecResult{Stdout: "1: lo: <LOOPBACK>\n"}, nil
}

// Prune is the one path nobody gets to undo. It captures a container it is
// about to delete, and it stored what it read directly -- so a container that
// came back from a restart and has not had its student's addressing replayed
// filed an empty namespace over the snapshot that was the only copy of it, and
// then deleted the container.
func TestPruneDoesNotFileAnEmptyNamespaceOverTheSnapshotItIsAboutToNeed(t *testing.T) {
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &orphanRuntime{marked: map[string]bool{"tw-atl": true}}
	top := &model.Topology{
		Name: "cos461", Hash: "topology",
		Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	engine := &Engine{Runtime: runtime, Node: "node-a", Workers: 2, State: store}

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 {
		t.Fatalf("the orphan was not removed: %v", removed)
	}
	if _, err := store.Current("cos461", "as3/ATL", state.KindAddrs); err == nil {
		t.Fatal("prune filed the empty namespace of a device that still owed its " +
			"student a replay, over the addressing that replay was going to use")
	}
	if _, err := store.Current("cos461", "as3/ATL", state.KindFRR); err != nil {
		t.Fatalf("prune threw away the routing configuration too, which is a file "+
			"and survived the restart: %v", err)
	}
}

// The other half: an orphan that owes nothing is captured whole, because that
// is the work prune exists to save.
func TestPruneStillSavesTheStateOfAnOrphanThatOwesNothing(t *testing.T) {
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &orphanRuntime{marked: map[string]bool{}}
	top := &model.Topology{
		Name: "cos461", Hash: "topology",
		Devices: map[string]*model.Device{}, ASes: map[int]*model.AS{},
	}
	engine := &Engine{Runtime: runtime, Node: "node-a", Workers: 2, State: store}

	if _, err := engine.PruneOrphans(context.Background(), top); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Current("cos461", "as3/ATL", state.KindAddrs); err != nil {
		t.Fatalf("prune did not save the namespace state of the container it deleted: %v", err)
	}
}
