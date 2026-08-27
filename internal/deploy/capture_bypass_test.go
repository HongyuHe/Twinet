package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// Two paths in the engine read a container and wrote what they read straight
// into the state store, without going anywhere near the capture API or the
// guard hanging off it.
//
// One is the destructive replacement: a device whose specification changed is
// captured and then deleted. The other is the prune: a device that left the
// manifest, or moved to another node, is captured and then deleted. Both are
// paths where the container is about to stop existing, so what they store is
// the last word on what was in it -- and both were storing an empty namespace
// over a term's work whenever the task behind the container had been replaced
// since anything last looked.

// orphanLab is a node holding one container the topology does not want: the
// shape a prune sees when a device leaves the manifest or moves elsewhere.
//
// The container's namespace, identity and routing configuration are all under
// the test's control, because the question every case below asks is what the
// prune stores when those three disagree with the store.
func orphanLab(t *testing.T) (*Engine, *model.Topology, *namespaceAwareRuntime, *state.Store) {
	t.Helper()
	top := &model.Topology{
		Name: "cos461", Hash: "topology",
		Devices: map[string]*model.Device{},
		ASes:    map[int]*model.AS{3: {ASN: 3, Role: model.RoleStudent}},
	}
	runtime := &namespaceAwareRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		identity:        map[string]rt.NetnsIdentity{},
		failFor:         map[string]error{},
		contents:        map[string]string{},
	}
	runtime.containers = append(runtime.containers, rt.Container{
		Name: "tw-atl", State: rt.StateRunning, PID: 4242,
		Labels: map[string]string{
			LabelLab: top.Name, LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	})
	runtime.setIdentity("tw-atl", rt.NetnsIdentity{Dev: 4, Inode: 4026531111})
	runtime.setFRR("tw-atl", "router ospf\n network 3.0.8.0/24 area 0\n")
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{
		Runtime: runtime, Node: "node-a", Workers: 2, State: store,
		ObservationRoot: observeTestRoot(t),
	}
	return engine, top, runtime, store
}

// orphanStandIn is the device a prune reconstructs from a container's labels
// when the manifest no longer describes it.
//
// It has no autonomous system, because a container's labels do not carry one
// and the manifest that did has forgotten the device. That is exactly why
// ownership cannot be the thing that decides whether an orphan has saved state
// worth protecting.
func orphanStandIn() *model.Device {
	return &model.Device{ID: "as3/ATL", Container: "tw-atl", Kind: model.KindRouter}
}

// orphanHolding puts an addressed interface into the orphan's namespace.
func orphanHolding(runtime *namespaceAwareRuntime, addrs map[string][]string) {
	links := make([]string, 0, len(addrs))
	for name := range addrs {
		links = append(links, name)
	}
	runtime.setContents("tw-atl", namespaceProbeOutput(links, addrs))
}

// emptyNamespace is what a container whose task was killed and restarted has:
// its name, its labels, its filesystem, and a namespace with nothing in it.
func emptyNamespace(runtime *namespaceAwareRuntime) {
	runtime.setContents("tw-atl", namespaceProbeOutput(nil, nil))
}

// (a) The reading a replacement takes, and the task that goes away underneath
// it.
//
// A destructive replacement captures the container it is about to delete, so
// that the student's work can be replayed into the one that takes its place.
// The build looked at this device minutes earlier and found its namespace
// where it had left it; the identity check that would notice otherwise ran
// then, not now. A task killed in between -- or during the reading itself --
// hands the capture an empty namespace, which went straight into the store
// over the snapshot the restore that follows the replacement was about to use.
func TestAReplacementCaptureDoesNotStoreANamespaceTheTaskHasLeft(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")

	// The restart happens while the capture is reading: the addressing comes
	// back out of the namespace the task had, and by the time anything asks
	// which namespace that was, it is a different one. A backend publishing a
	// restarted task's pid a moment late looks exactly like this.
	runtime.onCapture = func(container string) {
		if container != replaced.Container {
			return
		}
		runtime.setIdentity(container, rt.NetnsIdentity{Dev: 4, Inode: 4026579999})
		runtime.onCapture = nil
	}
	emptyNamespace(runtime)
	runtime.setContents(replaced.Container, namespaceProbeOutput(nil, nil))

	if err := engine.captureBeforeReplace(context.Background(), top, replaced); err != nil {
		t.Fatalf("capture before replace: %v", err)
	}
	if !engine.namespaceStateLost(replaced.ID) {
		t.Error("a replacement captured a container whose task had been replaced without " +
			"noticing that the namespace it read was not the one the saved state came from")
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the replacement filed the namespace the restarted task came back into "+
			"over the addressing it was about to replay: %v", facts)
	}
	if _, err := store.Current(top.Name, replaced.ID, state.KindFRR); err != nil {
		t.Fatalf("the replacement threw away the routing configuration too, which is a "+
			"file and survived the restart: %v", err)
	}
}

// The same path, with the restart already visible before the reading starts.
// This is the ordinary case: pid 1 died some minutes ago, the container is
// still there, and the manifest has since changed in a way that requires the
// container to be rebuilt.
func TestAReplacementCaptureRefusesAnAlreadyReplacedNamespace(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	runtime.setIdentity(replaced.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026579998})
	runtime.setContents(replaced.Container, namespaceProbeOutput(nil, nil))

	if err := engine.captureBeforeReplace(context.Background(), top, replaced); err != nil {
		t.Fatalf("capture before replace: %v", err)
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the replacement overwrote the student's addressing with the empty "+
			"namespace their router restarted into: %v", facts)
	}
}

// A replacement of a device whose namespace is where it was left still stores
// what it reads. The guard must not turn every rebuild into a lost capture.
func TestAReplacementCaptureOfAnIntactNamespaceStillStoresIt(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	wiredNamespace(runtime, replaced, map[string][]string{"port_R1": {"10.0.0.1/24"}})

	if err := engine.captureBeforeReplace(context.Background(), top, replaced); err != nil {
		t.Fatalf("capture before replace: %v", err)
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("a replacement stopped saving the work it is about to rebuild over: %v", facts)
	}
}

// A container that is stopped when the replacement reaches it is started, so
// that the configuration on its filesystem can be recovered before it is
// deleted. Starting it is also what gives it a new and empty network namespace
// -- a task's namespace dies with the task -- so the reading that follows is of
// a room nobody has been in, and it went into the store as the last word on
// what the student had.
func TestAReplacementThatStartsAStoppedContainerKeepsItsSavedNamespaceState(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	for i := range runtime.containers {
		if runtime.containers[i].Name == replaced.Container {
			runtime.containers[i].State = rt.StateExited
		}
	}
	runtime.onStart = func(container string) {
		runtime.setIdentity(container, rt.NetnsIdentity{Dev: 4, Inode: 4026579997})
		runtime.setContents(container, namespaceProbeOutput(nil, nil))
	}

	if err := engine.captureBeforeReplace(context.Background(), top, replaced); err != nil {
		t.Fatalf("capture before replace: %v", err)
	}
	if _, err := store.Current(top.Name, replaced.ID, state.KindFRR); err != nil {
		t.Fatalf("starting the container to recover its configuration stopped recovering "+
			"it: %v", err)
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the empty namespace a stopped container was started into was filed "+
			"over the student's addressing: %v", facts)
	}
}

// (b) A device removed from the manifest whose task was replaced.
//
// The prune reads the container it is about to delete. There is nothing in the
// new namespace, the store holds the only copy of what was in the old one, and
// the container is about to stop existing -- so this is the one write in the
// engine that nobody gets a second chance at.
func TestPruneDoesNotOverwriteTheStateOfARemovedDeviceThatRestarted(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	recordNamespace(t, engine, top, orphan, runtime.identity[orphan.Container])
	namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
		"addr inet port_BOS 3.0.8.1/24")
	runtime.setIdentity(orphan.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026537641})
	emptyNamespace(runtime)

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("a device whose namespace was proven replaced was not removed: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("prune filed the empty namespace a removed device restarted into over "+
			"the only saved copy of its student's addressing: %v", facts)
	}
	if _, err := store.Current(top.Name, orphan.ID, state.KindFRR); err != nil {
		t.Fatalf("prune threw away the routing configuration too, which is a file and "+
			"survived the restart: %v", err)
	}
}

// (c) The same device, moved to another node rather than removed.
//
// The manifest still describes it, so the model can be asked about it; what it
// cannot answer is which namespace the container on *this* node is in. Its
// state is about to be replicated to the node that now owns it, and this is
// the copy that replication reads.
func TestPruneDoesNotOverwriteTheStateOfAMovedDeviceThatRestarted(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	moved := &model.Device{
		ID: orphan.ID, Name: "ATL", Container: orphan.Container, ASN: 3,
		Node: "node-b", Kind: model.KindRouter,
	}
	link := &model.Link{ID: "l-bos", Kind: model.LinkVeth}
	link.A = &model.Iface{Device: moved, Name: "port_BOS", Link: link}
	moved.Ifaces = append(moved.Ifaces, link.A)
	top.Devices[moved.ID] = moved
	top.ASes[3].Devices = []*model.Device{moved}

	recordNamespace(t, engine, top, moved, runtime.identity[moved.Container])
	namespaceSnapshot(t, store, top.Name, moved, state.KindAddrs,
		"addr inet port_BOS 3.0.8.1/24")
	runtime.setIdentity(moved.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026537642})
	emptyNamespace(runtime)

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("a device that moved to another node was left running here, which is how "+
			"one autonomous system ends up announcing its prefixes twice: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, moved, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("prune filed the empty namespace over the state the node that now owns "+
			"this device is about to be sent: %v", facts)
	}
}

// (d) An orphan with no recorded namespace at all, whose saved addressing is
// not in the one it is using.
//
// Nothing here can say whether the container restarted before any of this was
// recorded or whether the student simply removed an address. Both readings end
// with the store holding work the container does not, and the difference
// between them is not something a prune is in a position to settle.
func TestPruneDoesNotOverwriteAnUnbaselinedOrphanWhoseSavedStateIsGone(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
		"addr inet port_BOS 3.0.8.1/24")
	emptyNamespace(runtime)

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err == nil {
		t.Fatal("prune removed a container whose namespace it could not account for, " +
			"and reported success")
	}
	if len(removed) != 0 {
		t.Fatalf("a refused prune removed something anyway: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("prune overwrote the saved addressing of a device it could not account "+
			"for: %v", facts)
	}
	if !strings.Contains(err.Error(), "as3/ATL") {
		t.Errorf("the refusal does not name the device an operator has to look at: %v", err)
	}
}

// (e) An orphan whose namespace is where it was left is captured whole and
// removed, because that is the work prune exists to save.
func TestPruneStillCapturesAndRemovesAnIntactOrphan(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	recordNamespace(t, engine, top, orphan, runtime.identity[orphan.Container])
	namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
		"addr inet port_BOS 3.0.8.9/24")
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("an orphan whose namespace was intact was not removed: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("prune stopped saving the current state of the container it deleted: %v", facts)
	}
}

// (f) What an unsafe orphan leaves behind, said out loud.
//
// The two outcomes are deliberately different, and the difference is whether
// this pass could establish what happened rather than how bad the answer was.
//
// A namespace proven to have been replaced is settled: what is in it now
// demonstrably is not the student's work, the saved copy was left alone, and
// deleting the container costs nothing -- which is what stops a device that
// moved to another node from announcing its prefixes from two places for ever.
//
// A namespace that could not be accounted for is not settled. This pass
// deliberately did not save what is in it, so removing the container would
// destroy the only thing that could still answer the question. The routing
// configuration is on a filesystem, survived whatever happened, and is stored
// either way.
func TestPruneKeepsTheConfigOfAnUnsafeOrphanAndSaysWhatItDidAboutIt(t *testing.T) {
	t.Run("unaccounted for: refused, config kept, namespace state untouched", func(t *testing.T) {
		engine, top, runtime, store := orphanLab(t)
		orphan := orphanStandIn()
		namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
			"addr inet port_BOS 3.0.8.1/24")
		emptyNamespace(runtime)

		removed, err := engine.PruneOrphans(context.Background(), top)
		if err == nil {
			t.Fatal("an orphan nothing could account for was removed and reported as success")
		}
		if len(removed) != 0 || len(runtime.removed) != 0 {
			t.Fatalf("the container was removed anyway: %v / %v", removed, runtime.removed)
		}
		if !strings.Contains(err.Error(), "refusing to remove") {
			t.Errorf("the refusal does not read as one: %v", err)
		}
		frr, err := store.Current(top.Name, orphan.ID, state.KindFRR)
		if err != nil {
			t.Fatalf("the routing configuration was not kept: %v", err)
		}
		if !strings.Contains(string(frr.Content), "router ospf") {
			t.Errorf("the routing configuration stored is not the one on the device: %q",
				frr.Content)
		}
		facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
		if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
			t.Fatalf("the saved namespace state was overwritten anyway: %v", facts)
		}
	})

	t.Run("proven replaced: removed, config kept, namespace state untouched", func(t *testing.T) {
		engine, top, runtime, store := orphanLab(t)
		orphan := orphanStandIn()
		recordNamespace(t, engine, top, orphan, runtime.identity[orphan.Container])
		namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
			"addr inet port_BOS 3.0.8.1/24")
		runtime.setIdentity(orphan.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026537643})
		emptyNamespace(runtime)

		removed, err := engine.PruneOrphans(context.Background(), top)
		if err != nil {
			t.Fatalf("prune: %v", err)
		}
		if len(removed) != 1 {
			t.Fatalf("a settled namespace replacement blocked the removal it does not "+
				"need to block: %v", removed)
		}
		if _, err := store.Current(top.Name, orphan.ID, state.KindFRR); err != nil {
			t.Fatalf("the routing configuration was not kept: %v", err)
		}
		facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
		if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
			t.Fatalf("the saved namespace state was overwritten: %v", facts)
		}
	})
}

// A prune whose candidate has no saved namespace state and no baseline has
// nothing to lose, and must not be turned into a permanent refusal by a guard
// that exists to protect state nobody ever took.
func TestPruneOfAnOrphanWithNothingSavedIsStillAllowed(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	orphan := orphanStandIn()
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(removed) != 1 {
		t.Fatalf("an orphan with nothing saved was refused: %v", removed)
	}
	facts := savedFacts(t, store, top.Name, orphan, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("prune did not save the state of the container it deleted: %v", facts)
	}
}

// Ownership is the model's answer, and the model is exactly what an orphan has
// left. A device removed from the manifest has no autonomous system to hold a
// role, so the ownership question that decides whether there is saved state
// worth protecting answers no for every orphan -- including the one whose
// namespace holds nothing and whose store holds a term's work.
func TestSavedNamespaceObjectsAreReadForADeviceTheManifestHasForgotten(t *testing.T) {
	_, top, _, store := orphanLab(t)
	orphan := orphanStandIn()
	namespaceSnapshot(t, store, top.Name, orphan, state.KindAddrs,
		"addr inet port_BOS 3.0.8.1/24")

	saved, err := savedNamespaceObjects(store, top, orphan)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFact(saved[state.KindAddrs], "addr inet port_BOS 3.0.8.1/24") {
		t.Fatalf("a device the manifest has forgotten has no saved state worth "+
			"protecting, which is the opposite of true: %v", saved)
	}

	// A device the manifest does describe, owned by nobody a capture works
	// for, is still ruled out: reading the store for every staff and transit
	// device on every prune would be work with no question behind it.
	top.ASes[9] = &model.AS{ASN: 9, Role: model.RoleStaff}
	reference := &model.Device{ID: "as9/CORE", Container: "tw-core", ASN: 9, Kind: model.KindRouter}
	top.Devices[reference.ID] = reference
	namespaceSnapshot(t, store, top.Name, reference, state.KindAddrs,
		"addr inet port_X 9.9.9.9/24")
	saved, err = savedNamespaceObjects(store, top, reference)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 0 {
		t.Fatalf("a staff-owned device the manifest still describes was judged against "+
			"saved state a capture never writes: %v", saved)
	}
}

// The container a prune is holding, and the container the manifest has moved
// the device into.
//
// An orphan usually has the same name the manifest gave it -- a device that
// moved to another node keeps its container name, which is why the resolution
// looked correct. When it does not, because the manifest renamed the device's
// container or because an older container is still running under the same
// identifier, the model answered with the *new* container and the prune read
// that one instead: it captured a live device that was never in danger, filed
// its reading as this device's saved state, and then deleted the container it
// had never looked inside.
func TestPruneReadsTheOrphanInFrontOfItAndNotTheDeviceTheManifestNowWants(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	// The manifest keeps the device and its identifier, and gives it a
	// different container on this same node.
	device := &model.Device{
		ID: "as3/ATL", Name: "ATL", Container: "tw-atl-v2", Image: "frr:stable",
		Node: "node-a", ASN: 3, Kind: model.KindRouter,
	}
	top.Devices[device.ID] = device
	runtime.containers = append(runtime.containers, rt.Container{
		Name: "tw-atl-v2", State: rt.StateRunning, PID: 5151,
		Labels: map[string]string{
			LabelLab: top.Name, LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	})
	runtime.setIdentity("tw-atl-v2", rt.NetnsIdentity{Dev: 4, Inode: 4026532222})
	runtime.setFRR("tw-atl-v2", "router ospf\n network 3.0.99.0/24 area 0\n")
	runtime.setContents("tw-atl-v2", namespaceProbeOutput(
		[]string{"port_BOS"}, map[string][]string{"port_BOS": {"3.0.8.1/24"}}))
	recordNamespace(t, engine, top, device, runtime.identity["tw-atl-v2"])
	// The leftover holds something else entirely -- both an address and a
	// routing configuration -- so that what ends up in the store says which
	// container was read, and so that deleting it would be a loss.
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.9.1/24"}})
	runtime.setFRR("tw-atl", "router ospf\n network 3.0.9.0/24 area 0\n")

	namespaceSnapshot(t, store, top.Name, device, state.KindAddrs,
		"addr inet port_BOS 3.0.8.1/24")
	if _, err := store.Put(state.Snapshot{Lab: top.Name, Device: device.ID,
		Kind: state.KindFRR, Content: []byte("router ospf\n network 3.0.8.0/24 area 0\n"),
	}); err != nil {
		t.Fatal(err)
	}

	removed, err := engine.PruneOrphans(context.Background(), top)
	// The leftover holds a configuration and an address that are not the ones
	// saved for this device, and there is one slot to hold either. Its reading
	// was deliberately kept out of that slot, which makes the container the
	// only copy of what is in it, and deleting it would settle the difference
	// by destroying one side.
	if err == nil {
		t.Fatal("a leftover container holding state nothing else has was deleted without " +
			"the difference ever being mentioned")
	}
	for _, want := range []string{"tw-atl", "as3/ATL", "tw-atl-v2", "frr", "addrs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so nobody can act on it: %v", want, err)
		}
	}
	if len(removed) != 0 {
		t.Fatalf("the prune removed %v after refusing", removed)
	}
	if runtime.readsOf("tw-atl") == 0 {
		t.Error("the prune deleted a container without ever looking inside it, and read a " +
			"different one instead")
	}
	if got := runtime.readsOf("tw-atl-v2"); got != 0 {
		t.Errorf("the prune read the live container the manifest gives this device (%d "+
			"commands): that container is not an orphan, is not in danger, and is not "+
			"what was about to be deleted", got)
	}
	config, err := store.Current(top.Name, device.ID, state.KindFRR)
	if err != nil {
		t.Fatalf("read the saved configuration of %s: %v", device.ID, err)
	}
	if !strings.Contains(string(config.Content), "3.0.8.0/24") {
		t.Errorf("a leftover container's reading replaced the saved state of the live "+
			"device that carries the same identifier: %q", string(config.Content))
	}
	facts := savedFacts(t, store, top.Name, device, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Errorf("a leftover container's namespace was filed as the live device's: %v", facts)
	}
}

// staleSpec makes a device's running container disagree with what the manifest
// now asks for, which is what sends a deployment down the replacement path.
func staleSpec(t *testing.T, engine *Engine, top *model.Topology, runtime *namespaceAwareRuntime,
	d *model.Device,
) finalDeviceSpec {
	t.Helper()
	final, err := engine.finalRuntimeSpecs(top, d)
	if err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	for i := range runtime.containers {
		if runtime.containers[i].Name == d.Container {
			runtime.containers[i].Labels[LabelSpec] = "a-previous-specification"
		}
	}
	runtime.mu.Unlock()
	return final
}

// A destructive replacement of a device nothing can vouch for.
//
// The capture guard withholds what it read and does not fail, which is right
// for a capture: one deferred snapshot of state the store already holds. It is
// not right for a replacement. The container is deleted immediately afterwards
// and it is the last object that could still answer what was in it -- a term's
// work this pass declined to save, or an empty room. Going ahead settled the
// question by destroying the evidence and reported success.
func TestAReplacementRefusesToDestroyANamespaceItCannotAccountFor(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	// No baseline for anything: the upgrade window, before any pass has
	// recorded which namespace a device was configured in.
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	runtime.setContents(replaced.Container, namespaceProbeOutput(nil, nil))
	final := staleSpec(t, engine, top, runtime, replaced)

	err := engine.ensureContainer(context.Background(), top, replaced, final)
	if err == nil {
		t.Fatal("a replacement destroyed the only container that could still say what was " +
			"in a namespace this pass could not account for")
	}
	if !strings.Contains(err.Error(), "could not be established") {
		t.Fatalf("the refusal does not say what it could not establish: %v", err)
	}
	if len(runtime.removed) != 0 {
		t.Fatalf("the refusal did not stop the deletion: %v", runtime.removed)
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the saved addressing was overwritten on the way to refusing: %v", facts)
	}
	if _, err := store.Current(top.Name, replaced.ID, state.KindFRR); err != nil {
		t.Fatalf("refusing threw away the routing configuration, which was safe to keep "+
			"and was read before anything was decided: %v", err)
	}
}

// The same refusal, with the doubt coming from the store rather than from the
// namespace.
//
// A saved snapshot that cannot be read -- a corrupted body, a digest that does
// not match it -- means there is nothing trustworthy to compare the namespace
// against. That is the case where going ahead is worst: the container is
// deleted, and the replacement then replays a copy that could not be read.
func TestAReplacementRefusesWhenTheSavedStateCannotBeRead(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	// The namespace is intact and holds exactly what is saved, so the only
	// thing standing between this and a clean proof is the unreadable copy.
	wiredNamespace(runtime, replaced, map[string][]string{"port_R1": {"10.0.0.1/24"}})
	corrupted := corruptSavedBody(t, store, top.Name, replaced.ID, state.KindAddrs)
	final := staleSpec(t, engine, top, runtime, replaced)

	err := engine.ensureContainer(context.Background(), top, replaced, final)
	if err == nil {
		t.Fatal("a replacement deleted a container whose saved state could not be read, " +
			"which is the one case where the container is the better copy")
	}
	if len(runtime.removed) != 0 {
		t.Fatalf("the refusal did not stop the deletion: %v", runtime.removed)
	}
	body, readErr := os.ReadFile(corrupted)
	if readErr != nil {
		t.Fatalf("read back the damaged snapshot: %v", readErr)
	}
	if string(body) != "not what the digest says" {
		t.Fatalf("the damaged snapshot was written over rather than left for somebody to "+
			"recover: %q", string(body))
	}
}

// And the other half of that policy: a namespace positively known to have been
// replaced does not block anything.
//
// There is no doubt here to preserve. What is in the namespace demonstrably is
// not the student's work, the saved copy is intact and was left alone, and the
// replacement is precisely the thing that puts it back. Refusing this would
// strand every device the guard is meant to repair.
func TestAReplacementGoesAheadWhenTheNamespaceIsKnownToHaveBeenReplaced(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	// The task died and came back somewhere else, which the recorded namespace
	// is what proves.
	runtime.setIdentity(replaced.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026579995})
	runtime.setContents(replaced.Container, namespaceProbeOutput(nil, nil))
	final := staleSpec(t, engine, top, runtime, replaced)

	// Whatever the rebuild that follows does -- it needs a good deal more of a
	// machine than this fixture is -- the container being gone is what says
	// the capture let the replacement through.
	err := engine.ensureContainer(context.Background(), top, replaced, final)
	if err != nil && strings.Contains(err.Error(), "could not be established") {
		t.Fatalf("a namespace this pass proved had been replaced was refused as one it "+
			"could not account for: %v", err)
	}
	if len(runtime.removed) == 0 {
		t.Fatal("a device whose namespace was proven replaced was refused instead of rebuilt")
	}
	if _, unproven := engine.unprovenNamespaceReason(replaced.ID); unproven {
		t.Error("a namespace this proved had been replaced was also filed as one it could " +
			"not account for, which is the finding that refuses the replacement")
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the empty namespace was filed over the state the rebuild replays: %v", facts)
	}
}

// corruptSavedBody damages the body of a saved snapshot so that reading it
// back fails its digest, and returns the file it damaged.
func corruptSavedBody(t *testing.T, store *state.Store, lab, device string,
	kind state.Kind,
) string {
	t.Helper()
	var found string
	err := filepath.Walk(store.Root(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".body") {
			return nil
		}
		if filepath.Base(filepath.Dir(path)) == string(kind) {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatalf("no saved %s body to damage for %s/%s", kind, lab, device)
	}
	if err := os.WriteFile(found, []byte("not what the digest says"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Current(lab, device, kind); err == nil {
		t.Fatal("the damaged snapshot still reads back cleanly, so this proves nothing")
	}
	return found
}

// The same stopped container, on the pass that has no record of where it used
// to be -- which is every device on the first pass after an upgrade.
//
// Starting it to read its filesystem is what empties its namespace, and the
// reading that follows is therefore of a namespace holding none of the saved
// state and carrying no evidence of ever having held it. That is exactly what
// a device nothing can vouch for looks like, and the policy for those is to
// refuse the replacement -- which here would strand every stopped device
// instead of rebuilding it, for a loss this pass caused deliberately and knows
// the extent of. The distinction has to be recorded rather than inferred.
func TestAStoppedContainerStartedToBeReadIsNotAlsoTreatedAsUnaccountedFor(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	replaced := devices[0]
	// No baseline: nothing has ever recorded which namespace this was in.
	namespaceSnapshot(t, store, top.Name, replaced, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	for i := range runtime.containers {
		if runtime.containers[i].Name == replaced.Container {
			runtime.containers[i].State = rt.StateExited
		}
	}
	runtime.onStart = func(container string) {
		runtime.setIdentity(container, rt.NetnsIdentity{Dev: 4, Inode: 4026579996})
		runtime.setContents(container, namespaceProbeOutput(nil, nil))
	}

	if err := engine.captureBeforeReplace(context.Background(), top, replaced); err != nil {
		t.Fatalf("a stopped device was stranded rather than rebuilt, because the empty "+
			"namespace this pass started it into was read as one it could not account "+
			"for: %v", err)
	}
	if !engine.namespaceStateLost(replaced.ID) {
		t.Error("starting the container emptied its namespace and nothing recorded that, " +
			"so what the reading proves rests on whether a baseline happened to exist")
	}
	if reason, unproven := engine.unprovenNamespaceReason(replaced.ID); unproven {
		t.Errorf("a loss this pass caused on purpose was filed as an open question: %s", reason)
	}
	if _, err := store.Current(top.Name, replaced.ID, state.KindFRR); err != nil {
		t.Fatalf("starting the container to recover its configuration stopped recovering "+
			"it: %v", err)
	}
	facts := savedFacts(t, store, top.Name, replaced, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the empty namespace a stopped container was started into was filed "+
			"over the student's addressing: %v", facts)
	}
}

// renamedInto gives the manifest a container for the device the orphan lab's
// leftover still claims, on this same node, and returns it.
func renamedInto(t *testing.T, engine *Engine, top *model.Topology,
	runtime *namespaceAwareRuntime, name string,
) *model.Device {
	t.Helper()
	device := &model.Device{
		ID: "as3/ATL", Name: "ATL", Container: name, Image: "frr:stable",
		Node: "node-a", ASN: 3, Kind: model.KindRouter,
	}
	top.Devices[device.ID] = device
	runtime.containers = append(runtime.containers, rt.Container{
		Name: name, State: rt.StateRunning, PID: 5151,
		Labels: map[string]string{
			LabelLab: top.Name, LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	})
	runtime.setIdentity(name, rt.NetnsIdentity{Dev: 4, Inode: 4026532222})
	runtime.setFRR(name, "router ospf\n network 3.0.8.0/24 area 0\n")
	runtime.setContents(name, namespaceProbeOutput(
		[]string{"port_BOS"}, map[string][]string{"port_BOS": {"3.0.8.1/24"}}))
	recordNamespace(t, engine, top, device, runtime.identity[name])
	return device
}

// durableATL puts the state the orphan lab's device is supposed to have into
// the store, as a capture would have written it.
func durableATL(t *testing.T, store *state.Store, top *model.Topology,
	d *model.Device, addr, network string,
) {
	t.Helper()
	namespaceSnapshot(t, store, top.Name, d, state.KindAddrs, "addr inet port_BOS "+addr)
	if _, err := store.Put(state.Snapshot{Lab: top.Name, Device: d.ID,
		Kind:    state.KindFRR,
		Content: []byte("router ospf\n network " + network + " area 0\n"),
	}); err != nil {
		t.Fatal(err)
	}
}

// A leftover that holds exactly what is already saved.
//
// Refusing this one would leave a stale container running after every rename
// and every interrupted deployment, for a difference that does not exist. The
// condition for removing a claimant is not that it is unimportant, it is that
// nothing is lost by removing it -- and a claimant whose complete reading is
// the state already held for the device has nothing to lose.
func TestPruneRemovesALeftoverHoldingExactlyWhatIsAlreadySaved(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	device := renamedInto(t, engine, top, runtime, "tw-atl-v2")
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	durableATL(t, store, top, device, "3.0.8.1/24", "3.0.8.0/24")

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err != nil {
		t.Fatalf("a leftover holding nothing that is not already saved was kept: %v", err)
	}
	if len(removed) != 1 || removed[0] != "tw-atl" {
		t.Fatalf("the prune removed %v rather than the leftover container", removed)
	}
	if runtime.readsOf("tw-atl") == 0 {
		t.Error("the leftover was removed without being read, so nothing established that " +
			"what it held was already saved")
	}
	facts := savedFacts(t, store, top.Name, device, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Errorf("the leftover's reading was written over the device's saved state: %v", facts)
	}
}

// The same leftover, and a store that cannot answer whether what it holds is
// already saved.
//
// A missing snapshot is a device nobody has configured yet. A body whose
// digest does not match what was written beside it is the one circumstance
// where the saved copy is already in question, and it used to give the same
// answer -- which made "the store is broken" the condition under which the
// other copy gets deleted.
func TestPruneKeepsALeftoverWhenTheSavedStateCannotBeRead(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	device := renamedInto(t, engine, top, runtime, "tw-atl-v2")
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	durableATL(t, store, top, device, "3.0.8.1/24", "3.0.8.0/24")
	corruptSavedBody(t, store, top.Name, device.ID, state.KindAddrs)

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err == nil {
		t.Fatal("a container was deleted on the strength of a comparison against a " +
			"snapshot that could not be read")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("the refusal does not say the saved state is what could not be read: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("the prune removed %v after refusing", removed)
	}
}

// Two containers claiming one device the manifest has forgotten.
//
// Nothing left says which of them is the device: the manifest that would have
// is the manifest that dropped it. Picking one and writing its reading into
// the single slot, then deleting the other, decides whose work survives by
// sort order.
func TestPruneWillNotChooseBetweenTwoContainersClaimingAForgottenDevice(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	runtime.containers = append(runtime.containers, rt.Container{
		Name: "tw-atl-old", State: rt.StateRunning, PID: 4243,
		Labels: map[string]string{
			LabelLab: top.Name, LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	})
	runtime.setIdentity("tw-atl-old", rt.NetnsIdentity{Dev: 4, Inode: 4026531112})
	runtime.setFRR("tw-atl-old", "router ospf\n network 3.0.7.0/24 area 0\n")
	runtime.setContents("tw-atl-old", namespaceProbeOutput(
		[]string{"port_BOS"}, map[string][]string{"port_BOS": {"3.0.7.1/24"}}))
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})
	durableATL(t, store, top, orphanStandIn(), "3.0.8.1/24", "3.0.8.0/24")

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err == nil {
		t.Fatal("two containers claiming one device were both deleted, and whichever of " +
			"them held the newer work went with them")
	}
	for _, want := range []string{"tw-atl-old", "claiming as3/ATL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q, so it is not the collision that "+
				"stopped it: %v", want, err)
		}
	}
	if len(removed) != 0 {
		t.Fatalf("the prune removed %v after refusing: neither claimant is established as "+
			"the device, so neither may be deleted on the other's evidence", removed)
	}
	facts := savedFacts(t, store, top.Name, orphanStandIn(), state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Errorf("one claimant's reading was written into the device's only slot, over "+
			"state that may have been the other's: %v", facts)
	}
}

// The device moved to another node, and a second container here claims it too.
//
// A moved device keeps its container name, which is what establishes the
// authority among the claimants: the container carrying that name is the one
// the manifest is talking about, is captured, and is removed. The other is
// not, and has to prove it has nothing to lose.
func TestPruneRemovesAMovedDeviceButNotTheStrangerBesideIt(t *testing.T) {
	engine, top, runtime, store := orphanLab(t)
	moved := &model.Device{
		ID: "as3/ATL", Name: "ATL", Container: "tw-atl", Image: "frr:stable",
		Node: "node-b", ASN: 3, Kind: model.KindRouter,
	}
	top.Devices[moved.ID] = moved
	runtime.containers = append(runtime.containers, rt.Container{
		Name: "tw-atl-old", State: rt.StateRunning, PID: 4243,
		Labels: map[string]string{
			LabelLab: top.Name, LabelNode: "node-a",
			LabelDeviceID: "as3/ATL", LabelKind: "router",
		},
	})
	runtime.setIdentity("tw-atl-old", rt.NetnsIdentity{Dev: 4, Inode: 4026531112})
	runtime.setFRR("tw-atl-old", "router ospf\n network 3.0.7.0/24 area 0\n")
	runtime.setContents("tw-atl-old", namespaceProbeOutput(
		[]string{"port_BOS"}, map[string][]string{"port_BOS": {"3.0.7.1/24"}}))
	orphanHolding(runtime, map[string][]string{"port_BOS": {"3.0.8.1/24"}})

	removed, err := engine.PruneOrphans(context.Background(), top)
	if err == nil {
		t.Fatal("a second container claiming a moved device was deleted with it, and " +
			"nothing looked at what it held")
	}
	if !strings.Contains(err.Error(), "tw-atl-old") || strings.Contains(err.Error(), "tw-atl:") {
		t.Errorf("the refusal should name only the stranger, not the moved device's own "+
			"container: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("the prune removed %v: a refusal keeps every candidate, since a lab with "+
			"a stale container is a nuisance and a deleted one is not", removed)
	}
	// The moved device is the authority among the claimants, so its reading is
	// what is held for the device -- and the stranger's is not.
	facts := savedFacts(t, store, top.Name, moved, state.KindAddrs)
	if !hasFact(facts, "addr inet port_BOS 3.0.8.1/24") {
		t.Errorf("the container the manifest moved is the one claimant it names, and its "+
			"reading was not what was saved: %v", facts)
	}
	if hasFact(facts, "addr inet port_BOS 3.0.7.1/24") {
		t.Errorf("a stranger's reading was written as the moved device's state: %v", facts)
	}
}
