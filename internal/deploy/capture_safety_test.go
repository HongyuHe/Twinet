package deploy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// capturableNamespaceLab is a lab of routers -- the kind Capture actually reads
// addressing out of -- wired in a line, with every container's namespace under
// the test's control and a state store to write into.
//
// The devices are routers rather than the plain hosts the other namespace
// fixtures use because this file is about what a capture stores: Capture
// switches on a device's kind, and a device with no kind produces no snapshots
// at all, which would make every assertion below pass for the wrong reason.
func capturableNamespaceLab(t *testing.T) (*Engine, *model.Topology, []*model.Device,
	*namespaceAwareRuntime, *state.Store,
) {
	t.Helper()
	top := &model.Topology{
		Name: "captured", Hash: "captured-hash", Devices: map[string]*model.Device{},
		ASes: map[int]*model.AS{1: {ASN: 1, Role: model.RoleStudent}},
	}
	var devices []*model.Device
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("as1/R%d", i)
		d := &model.Device{
			ID: id, Name: fmt.Sprintf("R%d", i), Container: fmt.Sprintf("tw-r%d", i),
			Image: "frr:stable", Node: "node-a", ASN: 1, Kind: model.KindRouter,
		}
		top.Devices[id] = d
		devices = append(devices, d)
	}
	link := &model.Link{ID: "l01", Kind: model.LinkVeth}
	link.A = &model.Iface{Device: devices[0], Name: "port_R1", Link: link}
	link.B = &model.Iface{Device: devices[1], Name: "port_R0", Link: link}
	devices[0].Ifaces = append(devices[0].Ifaces, link.A)
	devices[1].Ifaces = append(devices[1].Ifaces, link.B)
	top.Links = append(top.Links, link)

	runtime := &namespaceAwareRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		identity:        map[string]rt.NetnsIdentity{},
		failFor:         map[string]error{},
		contents:        map[string]string{},
	}
	root := observeTestRoot(t)
	renderer := observedRenderer{revision: map[string]string{}}
	engine := &Engine{
		Runtime: runtime, Node: "node-a", ObservationRoot: root, Renderer: renderer,
		FRRControlRoot: filepath.Join(root, "frr-control"),
	}
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine.State = store
	for i, d := range devices {
		renderer.revision[d.ID] = "one"
		hash, err := engine.FinalSpecHash(top, d)
		if err != nil {
			t.Fatal(err)
		}
		runtime.containers = append(runtime.containers, rt.Container{
			Name: d.Container, State: rt.StateRunning, PID: 7000 + i,
			Labels: map[string]string{
				LabelSpec: hash, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
			},
		})
		runtime.identity[d.Container] = rt.NetnsIdentity{Dev: 4, Inode: uint64(4026560000 + i)}
		runtime.setFRR(d.Container, "router ospf\n network 10.0.0.0/24 area 0\n")
	}
	return engine, top, devices, runtime, store
}

// wiredNamespace puts a device's modelled interfaces, and whatever addressing
// the test names, into its namespace.
func wiredNamespace(runtime *namespaceAwareRuntime, d *model.Device, addrs map[string][]string) {
	runtime.setContents(d.Container, namespaceProbeOutput(modelledNamespaceInterfaces(d), addrs))
}

// captureEngine is a second Engine over the same node, runtime and store, with
// no build behind it -- exactly what every caller that captures outside a
// deployment constructs.
func captureEngine(engine *Engine, runtime *namespaceAwareRuntime, store *state.Store) *Engine {
	return &Engine{
		Runtime: runtime, Node: engine.Node, ObservationRoot: engine.ObservationRoot,
		Renderer: engine.Renderer, FRRControlRoot: engine.FRRControlRoot, State: store,
	}
}

// savedFacts reads back the canonical facts one saved snapshot holds.
func savedFacts(t *testing.T, store *state.Store, lab string, d *model.Device,
	kind state.Kind,
) []string {
	t.Helper()
	snapshot, err := store.Current(lab, d.ID, kind)
	if err != nil {
		t.Fatalf("read the saved %s of %s: %v", kind, d.ID, err)
	}
	return stableNamespaceFacts(kind, string(snapshot.Content))
}

func hasFact(facts []string, want string) bool {
	for _, fact := range facts {
		if fact == want {
			return true
		}
	}
	return false
}

// (a) A capture from an engine that never observed anything.
//
// The whole namespace guard was armed by a build: a deployment observed the
// devices, found the one whose task had been replaced, and the capture that
// followed consulted what it had found. Nothing else that captures does any of
// that. Periodic durability builds an engine and calls the capture API; so does
// a destructive deployment boundary, a destroy, and a recovery after rollback.
// Each of them arrived at a restarted router's empty namespace with an engine
// that had no findings to consult, wrote it over the snapshot holding the
// student's addressing, and replicated the result.
func TestACaptureOnAFreshEngineDoesNotOverwriteAReplacedNamespace(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	restarted := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, restarted, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")

	// Killed and restarted: a new namespace, nothing in it, and a container
	// that is identical in every other respect.
	runtime.setIdentity(restarted.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026570001})
	runtime.setContents(restarted.Container, namespaceProbeOutput(nil, nil))

	fresh := captureEngine(engine, runtime, store)
	if _, err := fresh.CaptureDevices(context.Background(), top, store,
		[]string{restarted.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	facts := savedFacts(t, store, top.Name, restarted, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("a capture from an engine that never observed anything filed a restarted "+
			"router's empty namespace over its student's addressing: %v", facts)
	}
	// The routing configuration is on a filesystem. It survived the restart,
	// it is still the student's work, and withholding it would be a different
	// way of losing it.
	config, err := store.Current(top.Name, restarted.ID, state.KindFRR)
	if err != nil {
		t.Fatalf("the same capture did not store the configuration that did survive: %v", err)
	}
	if !strings.Contains(string(config.Content), "router ospf") {
		t.Fatalf("stored configuration = %q", config.Content)
	}
}

// (b) The same engine, for a device that never had a baseline.
//
// This is the upgrade window seen from the capture side. Nothing recorded the
// namespace this device's work was done in, so there is no identity to compare
// -- and the answer cannot be "carry on", because a device that restarted last
// week looks exactly like one that never restarted at all.
func TestAnUnbaselinedCaptureWhoseSavedStateIsGoneDoesNotOverwriteIt(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	emptied := devices[0]
	namespaceSnapshot(t, store, top.Name, emptied, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	// Rewired by a reconcile that put the cables back and knew nothing about
	// the addresses that used to be on them.
	wiredNamespace(runtime, emptied, nil)

	fresh := captureEngine(engine, runtime, store)
	if _, err := fresh.CaptureDevices(context.Background(), top, store,
		[]string{emptied.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	facts := savedFacts(t, store, top.Name, emptied, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("a capture of a device nothing could vouch for overwrote its saved "+
			"addressing: %v", facts)
	}
	reason := fresh.UnprovenNamespaceDevices()[emptied.ID]
	if !strings.Contains(reason, "10.0.0.1/24") {
		t.Fatalf("the refusal did not name the address that is missing: %q", reason)
	}
	if _, ok := persistedNamespaces(t, fresh, top.Name)[emptied.ID]; ok {
		t.Fatal("a namespace that could not be shown to hold the saved state was recorded " +
			"as the one that state was configured in")
	}
}

// (c) And the case that must still work, or the guard is a way of never
// capturing anything again.
//
// A device with no baseline whose namespace does hold what is saved is the
// device that has simply never restarted. It earns a baseline from the capture
// that proved it, and its capture goes through -- including whatever the
// student has done since.
func TestAProvenUnbaselinedNamespaceIsBaselinedAndCaptured(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	working := devices[0]
	namespaceSnapshot(t, store, top.Name, working, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	wiredNamespace(runtime, working, map[string][]string{
		"port_R1": {"10.0.0.1/24"},
		"lo":      {"10.255.0.1/32"},
	})

	fresh := captureEngine(engine, runtime, store)
	if _, err := fresh.CaptureDevices(context.Background(), top, store,
		[]string{working.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	facts := savedFacts(t, store, top.Name, working, state.KindAddrs)
	for _, want := range []string{"addr inet port_R1 10.0.0.1/24", "addr inet lo 10.255.0.1/32"} {
		if !hasFact(facts, want) {
			t.Fatalf("a proven namespace was not captured: %v is missing %s", facts, want)
		}
	}
	recorded, ok := persistedNamespaces(t, fresh, top.Name)[working.ID]
	if !ok || recorded != runtime.identity[working.Container] {
		t.Fatalf("the namespace a capture proved was not recorded as the baseline: %v, %v",
			recorded, ok)
	}
	if reason, ok := fresh.UnprovenNamespaceDevices()[working.ID]; ok {
		t.Fatalf("a device that proved continuity was reported as unresolved: %q", reason)
	}
}

// An identity that cannot be read is not evidence that a namespace survived.
//
// The backend refusing to answer is the same observation as the answer being
// different, for the purpose this serves: neither of them is the recorded
// namespace, and only one outcome is reversible.
func TestACaptureWhoseNamespaceIdentityIsUnreadableWithholdsTheNamespaceState(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	opaque := devices[0]
	recordNamespace(t, engine, top, opaque, runtime.identity[opaque.Container])
	namespaceSnapshot(t, store, top.Name, opaque, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	// Still holding exactly what it should. Only the proof is unavailable.
	wiredNamespace(runtime, opaque, map[string][]string{"port_R1": {"10.0.0.1/24"}})
	runtime.nsMu.Lock()
	runtime.failFor[opaque.Container] = errors.New("task exited while being inspected")
	runtime.nsMu.Unlock()

	fresh := captureEngine(engine, runtime, store)
	if _, err := fresh.CaptureDevices(context.Background(), top, store,
		[]string{opaque.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !fresh.namespaceStateLost(opaque.ID) {
		t.Fatal("a namespace whose identity could not be read was treated as the recorded one")
	}
	if facts := savedFacts(t, store, top.Name, opaque, state.KindAddrs); !hasFact(facts,
		"addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the saved addressing was overwritten anyway: %v", facts)
	}
}

// The other half of the rule, and the one that keeps it usable.
//
// A deployment that finds a replaced namespace rebuilds the device's links,
// reconfigures it, replays the store into it and records the namespace it did
// all that in. The capture at the end of that same pass is the one that files
// the student's work back where it belongs, and a guard that refused it would
// leave every repaired device permanently unbacked-up.
func TestADeviceRepairedInThisPassIsStillCapturable(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	restarted := devices[0]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, restarted, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	runtime.setIdentity(restarted.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026570002})
	runtime.setContents(restarted.Container, namespaceProbeOutput(nil, nil))

	if _, err := engine.Build(top); err != nil {
		t.Fatal(err)
	}
	if !engine.LastBuildDiff().Configure[restarted.ID] {
		t.Fatalf("a device found in a replaced namespace was not repaired: %#v",
			engine.LastBuildDiff())
	}
	if !engine.namespaceStateLost(restarted.ID) {
		t.Fatal("the build did not find the namespace-backed state gone")
	}
	// What the configure step does once it has rewired, reconfigured and
	// replayed: the loss is settled and the namespace it was settled in is
	// recorded. Driven directly because Build only plans -- the fake cannot
	// create containers -- and these two calls are the whole of what a repair
	// leaves behind for the capture that follows it.
	wiredNamespace(runtime, restarted, map[string][]string{"port_R1": {"10.0.0.1/24"}})
	tracker, err := engine.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	engine.clearNamespaceStateLost(restarted.ID)
	if err := engine.recordDeviceNamespace(context.Background(), tracker, restarted); err != nil {
		t.Fatal(err)
	}

	if _, err := engine.CaptureDevices(context.Background(), top, store,
		[]string{restarted.ID}); err != nil {
		t.Fatalf("capture after repair: %v", err)
	}
	if reason, ok := engine.UnprovenNamespaceDevices()[restarted.ID]; ok {
		t.Fatalf("a device this pass repaired and replayed was refused its capture: %q", reason)
	}
	facts := savedFacts(t, store, top.Name, restarted, state.KindAddrs)
	if !hasFact(facts, "addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the repaired device's state was not captured back: %v", facts)
	}
	recorded, ok := persistedNamespaces(t, engine, top.Name)[restarted.ID]
	if !ok || recorded != runtime.identity[restarted.Container] {
		t.Fatalf("the repaired device was not recorded in the namespace it was repaired in: "+
			"%v, %v", recorded, ok)
	}
}

// A capture is not allowed to decide the question by asking it late.
//
// The identity is resolved after the namespace has been read, so a task that
// was replaced before the reading is caught by the reading it invalidated. This
// is the ordering that matters: proving first and reading afterwards would
// bless a namespace and then store a different one.
func TestACaptureProvesTheNamespaceItActuallyRead(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	moving := devices[0]
	recordNamespace(t, engine, top, moving, runtime.identity[moving.Container])
	namespaceSnapshot(t, store, top.Name, moving, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	wiredNamespace(runtime, moving, map[string][]string{"port_R1": {"10.0.0.1/24"}})

	fresh := captureEngine(engine, runtime, store)
	// Restarted between the capture's reading and the identity check that
	// judges it. What was read is now historical, and it must not be filed as
	// current.
	restart := func(container string) {
		if container != moving.Container {
			return
		}
		runtime.setIdentity(container, rt.NetnsIdentity{Dev: 4, Inode: 4026570003})
	}
	runtime.nsMu.Lock()
	runtime.onProbe = restart
	runtime.nsMu.Unlock()
	// The capture reads through addrCapture rather than the continuity probe,
	// so the move is staged on the capture's own reading.
	runtime.setContents(moving.Container, namespaceProbeOutput(
		modelledNamespaceInterfaces(moving), map[string][]string{"port_R1": {"10.0.0.1/24"}}))
	restart(moving.Container)

	if _, err := fresh.CaptureDevices(context.Background(), top, store,
		[]string{moving.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !fresh.namespaceStateLost(moving.ID) {
		t.Fatal("a capture taken from a namespace the device had already left was accepted")
	}
}

// A device with nothing saved is not held back.
//
// The first capture a device ever has is the one that establishes what its
// namespace holds, and there is nothing yet to compare it against. Refusing
// that would mean a lab deployed once and left alone was never backed up at
// all -- the failure this guard exists to prevent, arrived at from the other
// direction.
func TestAFirstCaptureOfADeviceWithNothingSavedIsAllowed(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	fresh := devices[0]
	wiredNamespace(runtime, fresh, map[string][]string{"port_R1": {"10.0.0.1/24"}})

	capturing := captureEngine(engine, runtime, store)
	if _, err := capturing.CaptureDevices(context.Background(), top, store,
		[]string{fresh.ID}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if facts := savedFacts(t, store, top.Name, fresh, state.KindAddrs); !hasFact(facts,
		"addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("the first capture of a device with nothing saved stored nothing: %v", facts)
	}
}

// The destroy an operator runs on one machine, which selects by node and takes
// no list of devices.
//
// It is the same guard, reached through the other half of the capture API, and
// it is the call with the least margin for error: the containers are removed
// immediately afterwards, so the snapshot this writes is the only thing that
// will exist. Capturing the empty namespace of a router that had restarted was
// therefore not a deferred problem but an immediate, unrecoverable one.
func TestADestroysCaptureAllRefusesToOverwriteAReplacedNamespace(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	restarted, intact := devices[0], devices[1]
	for _, d := range devices {
		recordNamespace(t, engine, top, d, runtime.identity[d.Container])
	}
	namespaceSnapshot(t, store, top.Name, restarted, state.KindAddrs,
		"addr inet port_R1 10.0.0.1/24")
	namespaceSnapshot(t, store, top.Name, intact, state.KindAddrs,
		"addr inet port_R0 10.0.0.2/24")
	runtime.setIdentity(restarted.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026570004})
	runtime.setContents(restarted.Container, namespaceProbeOutput(nil, nil))
	// The other router never moved, and has since been given a loopback. A
	// destroy that refused the whole node because one device was in doubt
	// would lose that.
	wiredNamespace(runtime, intact, map[string][]string{
		"port_R0": {"10.0.0.2/24"},
		"lo":      {"10.255.0.2/32"},
	})

	fresh := captureEngine(engine, runtime, store)
	if _, err := fresh.CaptureAll(context.Background(), top, store); err != nil {
		t.Fatalf("capture all: %v", err)
	}
	if facts := savedFacts(t, store, top.Name, restarted, state.KindAddrs); !hasFact(facts,
		"addr inet port_R1 10.0.0.1/24") {
		t.Fatalf("a destroy filed a restarted router's empty namespace over its student's "+
			"addressing, and then removed the container: %v", facts)
	}
	facts := savedFacts(t, store, top.Name, intact, state.KindAddrs)
	if !hasFact(facts, "addr inet lo 10.255.0.2/32") {
		t.Fatalf("the doubt about one device stopped another's work being captured before "+
			"it was destroyed: %v", facts)
	}
}
