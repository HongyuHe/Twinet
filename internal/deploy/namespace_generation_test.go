package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
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
