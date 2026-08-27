package deploy

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// What a rewire owes the rest of the process while it is halfway through one.
//
// Two things about a repair are easy to get wrong because neither of them is
// visible from inside the repair. The first is that the engine doing the
// repair is not the only engine on the node: periodic durability builds its
// own every few minutes, in the same process, and captures every student-owned
// device it can see. It has no idea a repair is in progress. It reads a
// namespace whose interfaces were deleted a moment ago by the rewire and
// stores what it finds, and what it finds is nothing. The neighbour's
// container never restarted, so its namespace identity is exactly what was
// recorded, and every identity-based guard says the reading is trustworthy.
//
// The second is that a device whose task really was replaced is in a namespace
// nobody wrote down. The repair puts its state back, and the record still
// names the namespace that died with the old task, so every capture from then
// on compares the two, finds a mismatch, calls it replaced and withholds the
// device's addressing from the store. For ever: nothing else revisits it. The
// device is repaired, reported repaired, and quietly stops being backed up.

// soloRewireLab is one student-owned device with no cables, which is the only
// shape of rewire a unit test can run to completion -- the wiring step itself
// is netlink and there is no seam in front of it.
//
// It is a host rather than a router because a router on a containerd-shaped
// backend brings a control sidecar with it, and this file is about addressing
// and the record, not about sidecars.
func soloRewireLab(t *testing.T) (*Engine, *model.Topology, *model.Device,
	*namespaceAwareRuntime, *state.Store,
) {
	t.Helper()
	device := &model.Device{
		ID: "as1/H", Name: "H", Container: "tw-h", Image: "alpine:3", Node: "node-a",
		ASN: 1, Kind: model.KindHost,
	}
	top := &model.Topology{
		Name: "solo-rewire", Hash: "solo-hash",
		Devices: map[string]*model.Device{device.ID: device},
		ASes:    map[int]*model.AS{1: {ASN: 1, Role: model.RoleStudent}},
	}
	runtime := &namespaceAwareRuntime{
		observedRuntime: observedRuntime{files: map[string][]byte{}},
		identity:        map[string]rt.NetnsIdentity{},
		failFor:         map[string]error{},
		contents:        map[string]string{},
		markers:         map[string]bool{},
		markerErr:       map[string]error{},
	}
	renderer := observedRenderer{revision: map[string]string{device.ID: "one"}}
	engine := &Engine{
		Runtime: runtime, Node: "node-a", ObservationRoot: observeTestRoot(t),
		Renderer: renderer,
	}
	store, err := testStateStore(t)
	if err != nil {
		t.Fatal(err)
	}
	engine.State = store
	hash, err := engine.FinalSpecHash(top, device)
	if err != nil {
		t.Fatal(err)
	}
	runtime.containers = append(runtime.containers, rt.Container{
		Name: device.Container, State: rt.StateRunning, PID: 4242,
		Labels: map[string]string{
			LabelSpec: hash, LabelHash: top.Hash, LabelRuntimeContract: runtimeSpecContractVersion,
		},
	})
	runtime.setIdentity(device.Container, rt.NetnsIdentity{Dev: 4, Inode: 4026570001})
	// A loopback address: this device has no cables, so what a student put on
	// it is all there is, which is also what a rewire of a link-less device is
	// about.
	wiredNamespace(runtime, device, map[string][]string{"lo": {"10.0.0.1/24"}})
	return engine, top, device, runtime, store
}

// recordedNamespaceOf reads back the namespace this node wrote down for a
// device, from the file rather than from anything in memory.
func recordedNamespaceOf(t *testing.T, engine *Engine, lab, id string) rt.NetnsIdentity {
	t.Helper()
	tracker, err := engine.loadObservation(lab)
	if err != nil {
		t.Fatalf("read the recorded network namespaces: %v", err)
	}
	identity, _ := tracker.namespace(id)
	return identity
}

// A repair that does not write down where it put the device back leaves it
// looking permanently replaced.
func TestARepairedDeviceIsRecordedInTheNamespaceItWasRepairedIn(t *testing.T) {
	engine, top, device, runtime, store := soloRewireLab(t)
	ctx := context.Background()
	if _, err := engine.CaptureDevices(ctx, top, store, []string{device.ID}); err != nil {
		t.Fatalf("the first capture, which is what baselines it: %v", err)
	}
	old := recordedNamespaceOf(t, engine, top.Name, device.ID)
	if !old.Known() {
		t.Fatal("the first capture did not write down which namespace it read from")
	}
	saved := savedFacts(t, store, top.Name, device, state.KindAddrs)
	if len(saved) == 0 {
		t.Fatal("the first capture saved no addressing, so nothing below is about losing it")
	}

	// The task is killed and comes back in a namespace of its own, empty.
	replacement := rt.NetnsIdentity{Dev: 4, Inode: 4026579999}
	runtime.setIdentity(device.Container, replacement)
	runtime.setContents(device.Container, namespaceProbeOutput(nil, nil))

	repair := &Engine{
		Runtime: runtime, Node: engine.Node, ObservationRoot: engine.ObservationRoot,
		Renderer: engine.Renderer, State: store,
	}
	replayed := 0
	if err := repair.RewireDeviceAndPeers(ctx, top, device,
		func(context.Context, *model.Device) error {
			replayed++
			// What Restore does: the saved addressing goes back into the
			// namespace the device is in now.
			wiredNamespace(runtime, device, map[string][]string{"lo": {"10.0.0.1/24"}})
			return nil
		}); err != nil {
		t.Fatalf("repairing the restarted device: %v", err)
	}
	if replayed != 1 {
		t.Fatalf("the saved state was replayed %d times, want once", replayed)
	}
	if now := recordedNamespaceOf(t, engine, top.Name, device.ID); !now.SameAs(replacement) {
		t.Fatalf("the repair put the device back in %s and wrote down %s; every later "+
			"capture compares against what was written down", replacement, now)
	}
	if runtime.owes(device.Container) {
		t.Fatal("the device was replayed and is still marked as owing its saved state, so " +
			"nothing will capture from it again")
	}

	// The student then does something new. A capture taken by an engine that
	// did none of the above -- which is what periodic durability is -- has to
	// be able to save it.
	wiredNamespace(runtime, device, map[string][]string{"lo": {"10.0.0.1/24", "10.9.9.9/32"}})
	fresh := &Engine{
		Runtime: runtime, Node: engine.Node, ObservationRoot: engine.ObservationRoot,
		Renderer: engine.Renderer, State: store,
	}
	if _, err := fresh.CaptureDevices(ctx, top, store, []string{device.ID}); err != nil {
		t.Fatalf("the capture after the repair: %v", err)
	}
	if got := strings.Join(savedFacts(t, store, top.Name, device, state.KindAddrs), "\n"); !strings.Contains(
		got, "10.9.9.9/32") {
		t.Fatalf("work done after the repair was never saved, because the device still "+
			"looks replaced to a capture that was not there:\n%s", got)
	}
}

// The neighbour is not the one that restarted, and that is the whole problem.
//
// Its namespace identity is exactly what was recorded, so every identity check
// says its namespace survived -- and it did. What did not survive is what was
// in it, because the rewire deleted the veths. An engine that was not part of
// the repair has no way to know that, so the repair has to leave something
// behind that it will find.
func TestACaptureRunningWhileARewireIsUnderwayCannotFileTheBareNamespace(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	target, neighbour := devices[0], devices[1]
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{target.ID, neighbour.ID}); err != nil {
		t.Fatalf("the first capture, which is what baselines them: %v", err)
	}
	before := strings.Join(savedFacts(t, store, top.Name, neighbour, state.KindAddrs), "\n")
	if !strings.Contains(before, "10.0.0.1/24") {
		t.Fatalf("the neighbour's addressing was never saved, so nothing here is about "+
			"losing it:\n%s", before)
	}
	// Wiring is netlink, so the rewire gets as far as asking for a namespace
	// path and stops. Everything before that -- which is the part under test --
	// has already run.
	runtime.nsPathErr = errors.New("a unit test builds no veth pairs")

	err := engine.RewireDeviceAndPeers(ctx, top, target,
		func(context.Context, *model.Device) error { return nil })
	if err == nil {
		t.Fatal("the wiring cannot succeed in a unit test and reported that it had")
	}
	if errors.Is(err, ErrRewireNotStarted) {
		t.Fatalf("the rewire refused before it began, so it never reached the part this "+
			"is about: %v", err)
	}
	if !runtime.owes(neighbour.Container) {
		t.Fatal("the neighbour is not marked as owing its saved state, so nothing outside " +
			"this engine knows its interfaces are being rebuilt")
	}

	// The veths are gone; the container is not. This is the reading a periodic
	// capture takes if it lands here, from an engine that did no observing.
	runtime.setContents(neighbour.Container, namespaceProbeOutput(nil, nil))
	runtime.setFRR(neighbour.Container, "router ospf\n network 10.0.0.0/24 area 0\n router-id 2.2.2.2\n")
	periodic := captureEngine(engine, runtime, store)
	if _, err := periodic.CaptureDevices(ctx, top, store, []string{neighbour.ID}); err != nil {
		t.Fatalf("the periodic capture: %v", err)
	}
	after := strings.Join(savedFacts(t, store, top.Name, neighbour, state.KindAddrs), "\n")
	if !strings.Contains(after, "10.0.0.1/24") {
		t.Fatalf("a capture taken while the neighbour's cables were being rebuilt filed "+
			"the empty namespace over the only copy of its addressing:\n%s", after)
	}
	// Its routing configuration is on a filesystem. It survived, it is still
	// the student's work, and withholding it would lose work for no reason.
	frr, err := store.Current(top.Name, neighbour.ID, state.KindFRR)
	if err != nil {
		t.Fatalf("read the saved routing configuration of %s: %v", neighbour.ID, err)
	}
	if !strings.Contains(string(frr.Content), "router-id 2.2.2.2") {
		t.Fatalf("the guard withheld filesystem-backed configuration as well:\n%s", frr.Content)
	}
}

// If the mark cannot be made, the cables stay up.
//
// The marker is the only thing standing between a half-finished repair and a
// capture that files an empty namespace over a term's work, so a rewire that
// cannot establish one has nothing to fall back on. It refuses, and says so as
// a refusal rather than as a broken device.
func TestARewireRefusesWhenItCannotMarkWhatItIsAboutToEmpty(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	target, neighbour := devices[0], devices[1]
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{target.ID, neighbour.ID}); err != nil {
		t.Fatalf("the first capture: %v", err)
	}
	runtime.nsPathErr = errors.New("a unit test builds no veth pairs")
	runtime.failMarker(neighbour.Container, errors.New("read-only filesystem"))

	err := engine.RewireDeviceAndPeers(ctx, top, target,
		func(context.Context, *model.Device) error { return nil })
	if err == nil {
		t.Fatal("a rewire that could not mark what it was about to empty went ahead anyway")
	}
	if !errors.Is(err, ErrRewireNotStarted) {
		t.Fatalf("the refusal is not reported as one, so a caller cannot tell a device that "+
			"is still working from one that is now broken: %v", err)
	}
	if !strings.Contains(err.Error(), neighbour.ID) {
		t.Fatalf("the refusal does not name the device it could not mark: %v", err)
	}
	// The mark this call did manage to make is taken back, so the target is
	// not left owing a replay for a rewire that never happened.
	if runtime.owes(target.Container) {
		t.Fatal("a rewire that refused left the target marked as owing a restore it was " +
			"never given, which withholds it from every later capture")
	}
}

// The other half of that rollback, and the dangerous half.
//
// A device can arrive at a rewire already owing a restore, because an earlier
// pass got as far as emptying it and no further. That marker is not this
// call's to take back: clearing it lets the next capture file the bare
// namespace it is still sitting in over the work the marker was protecting.
func TestARefusedRewireLeavesAnEarlierUnfinishedRepairMarked(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	target, neighbour := devices[0], devices[1]
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{target.ID, neighbour.ID}); err != nil {
		t.Fatalf("the first capture: %v", err)
	}
	// An earlier repair emptied the target and never got its state back.
	if err := engine.holdNamespaceState(ctx, target); err != nil {
		t.Fatal(err)
	}
	runtime.nsPathErr = errors.New("a unit test builds no veth pairs")
	runtime.failMarker(neighbour.Container, errors.New("read-only filesystem"))

	if err := engine.RewireDeviceAndPeers(ctx, top, target,
		func(context.Context, *model.Device) error { return nil }); err == nil {
		t.Fatal("a rewire that could not mark what it was about to empty went ahead anyway")
	}
	if !runtime.owes(target.Container) {
		t.Fatal("the rollback cleared a marker an earlier unfinished repair had left, so " +
			"the next capture would file the target's bare namespace over its saved state")
	}
}

// A refusal that quietly leaves a marker behind is the failure the marker
// exists to prevent, wearing the refusal's clothes.
//
// The rollback of a refused hold is best-effort by nature -- it is undoing
// work on a node that has just proved it is having trouble -- and every one of
// its failures used to be discarded. What that leaves is a device that is
// working, was never unplugged, is carrying a restore-pending file for a
// rewire that never happened, and is therefore withheld from every capture
// from then on. The caller was told "nothing was unplugged" and had no reason
// to look. So every marker that could not be taken back is named, with the
// device and what could not be done to it, and the rollback goes on to the
// devices after it either way.
func TestARefusedRewireReportsTheMarkersItCouldNotTakeBack(t *testing.T) {
	top, _ := rewireScopeLab()
	runtime := newRewireScopeRuntime()
	engine := &Engine{Runtime: runtime, Node: "n0", ObservationRoot: t.TempDir()}
	// as2/B is the one device in this lab with two same-node neighbours, so a
	// hold that fails on the last of the three has two markers to take back
	// and can be shown not to stop at the first one it cannot.
	target := top.Devices["as2/B"]
	if ids := LocalRewirePeers(top, "n0", target); len(ids) != 2 {
		t.Fatalf("this test needs a target with two local peers, got %d", len(ids))
	}
	refused := errors.New("no space left on device")
	stuck := errors.New("the container stopped answering")
	runtime.failMarkerWrite("c-d", refused)
	runtime.failMarkerRelease("c-b", stuck)

	err := engine.RewireDeviceAndPeers(context.Background(), top, target,
		func(context.Context, *model.Device) error { return nil })
	if err == nil {
		t.Fatal("a rewire that could not mark what it was about to empty went ahead anyway")
	}
	if !errors.Is(err, ErrRewireNotStarted) {
		t.Fatalf("the refusal is not reported as one: %v", err)
	}
	if !errors.Is(err, refused) || !strings.Contains(err.Error(), "as2/D") {
		t.Fatalf("the refusal does not carry the device it could not mark: %v", err)
	}
	// The rollback failed on the target itself, which is still carrying the
	// marker. Nothing else will ever mention it.
	if !runtime.owes("c-b") {
		t.Fatal("the fake released a marker it was told it could not release, so nothing " +
			"below is about reporting one that is stuck")
	}
	if !errors.Is(err, stuck) {
		t.Fatalf("the rollback failure was swallowed, so an operator is told a device that "+
			"is now withheld from every capture had nothing done to it: %v", err)
	}
	if !strings.Contains(err.Error(), "as2/B") {
		t.Fatalf("the refusal does not name the device left owing a restore it was never "+
			"given: %v", err)
	}
	// And the device after it is still let go of. A marker stuck on one device
	// is not a reason to leave one on the next.
	if runtime.owes("c-a") {
		t.Fatal("the rollback stopped at the first marker it could not take back and left " +
			"the rest of them behind")
	}
}

// A refusal says nothing was unplugged, and that has to be true of this engine
// as well as of the devices.
//
// The distrust a rewire establishes is not free-standing bookkeeping. It makes
// this engine withhold those devices' namespace-backed state from every
// capture it takes afterwards, and names them to the caller as devices a
// repair disturbed. Establishing it before the gates that refuse meant a
// rewire could decline to touch a working device and still leave it
// unbackupable and reported as repaired, on the strength of a repair that
// never began.
func TestARewireRefusedAtTheRecordLeavesNothingMarkedOrDistrusted(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	target, neighbour := devices[0], devices[1]
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{target.ID, neighbour.ID}); err != nil {
		t.Fatalf("the first capture: %v", err)
	}
	// A record that cannot be read at all: the first of the two gates.
	record := engine.observationPath(top.Name)
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(record, 0o700); err != nil {
		t.Fatal(err)
	}
	replayed := 0

	err := engine.RewireDeviceAndPeers(ctx, top, target,
		func(context.Context, *model.Device) error {
			replayed++
			return nil
		})
	if !errors.Is(err, ErrRewireNotStarted) {
		t.Fatalf("a rewire that could not reach the record it has to update did not refuse "+
			"as one: %v", err)
	}
	if replayed != 0 {
		t.Fatalf("a refused rewire replayed state onto %d devices", replayed)
	}
	for _, d := range devices {
		if runtime.owes(d.Container) {
			t.Fatalf("%s is marked as owing a restore for a rewire that refused before it "+
				"unplugged anything, so it is withheld from every later capture", d.ID)
		}
	}
	if dirty := engine.DirtyNamespaceStateDevices(); len(dirty) != 0 {
		t.Fatalf("a rewire that refused before it changed anything already refuses to vouch "+
			"for %v: this engine withholds their addressing from every capture it takes and "+
			"reports them to the caller as devices a repair disturbed, and no repair ran",
			dirty)
	}
}

// Reading the record is not the question a rewire needs answered.
//
// What it does at the end is write it: a directory, a temporary file beside the
// record, and a rename over it. A filesystem that has gone read-only or filled
// up since the record was written answers a read perfectly and refuses that
// write -- and the discovery lands after the interfaces are gone, at which
// point the device is repaired and recorded nowhere. Every capture from then on
// compares it against the namespace that died with its old task, calls it
// replaced, and withholds its addressing from the store for ever.
func TestARewireRefusesWhenTheRecordCannotBeWritten(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	target, neighbour := devices[0], devices[1]
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{target.ID, neighbour.ID}); err != nil {
		t.Fatalf("the first capture, which is what baselines them: %v", err)
	}
	baseline := recordedNamespaceOf(t, engine, top.Name, target.ID)
	if !baseline.Known() {
		t.Fatal("the first capture wrote down no namespace, so nothing here is about " +
			"keeping the record intact")
	}
	// The record reads exactly as it did. What it cannot do is publish an
	// update, because the file every write goes through on its way in cannot
	// be created.
	if err := os.Mkdir(engine.observationPath(top.Name)+".next", 0o700); err != nil {
		t.Fatal(err)
	}
	// If the guard lets this through, the wiring is what it reaches next, and
	// that fails as something other than a refusal.
	runtime.nsPathErr = errors.New("a unit test builds no veth pairs")

	err := engine.RewireDeviceAndPeers(ctx, top, target,
		func(context.Context, *model.Device) error { return nil })
	if !errors.Is(err, ErrRewireNotStarted) {
		t.Fatalf("a rewire went ahead over a record it could not have written the repaired "+
			"device into, so the device would come back repaired and permanently unbacked: %v",
			err)
	}
	for _, d := range devices {
		if runtime.owes(d.Container) {
			t.Fatalf("%s was marked as owing a restore by a rewire that refused: %v", d.ID, err)
		}
	}
	if dirty := engine.DirtyNamespaceStateDevices(); len(dirty) != 0 {
		t.Fatalf("a rewire that refused at the record already refuses to vouch for %v", dirty)
	}
	// And the proof left the record exactly as it found it. It is the only
	// copy of what this node believes about every device's namespace, and a
	// check that damaged it would cost far more than the one it prevents.
	if now := recordedNamespaceOf(t, engine, top.Name, target.ID); !now.SameAs(baseline) {
		t.Fatalf("the writeability check moved %s's recorded namespace from %s to %s",
			target.ID, baseline, now)
	}
	if now := recordedNamespaceOf(t, engine, top.Name, neighbour.ID); !now.Known() {
		t.Fatalf("the writeability check dropped %s's baseline out of the record", neighbour.ID)
	}
}

// The proof is a write, so it has to be a write that changes nothing.
//
// Republishing the record is how the check earns its answer, and the record is
// the only copy of what this node believes about every device's namespace. A
// check that moved a baseline would make the next capture call a device
// replaced -- which is the exact failure the record exists to prevent, caused
// by the code that checks it.
func TestTheRecordWriteabilityCheckMovesNoBaseline(t *testing.T) {
	engine, top, devices, runtime, store := capturableNamespaceLab(t)
	ctx := context.Background()
	for _, d := range devices {
		wiredNamespace(runtime, d, map[string][]string{
			modelledNamespaceInterfaces(d)[0]: {"10.0.0." + d.Name[1:] + "/24"},
		})
	}
	if _, err := engine.CaptureDevices(ctx, top, store,
		[]string{devices[0].ID, devices[1].ID}); err != nil {
		t.Fatalf("the first capture, which is what baselines them: %v", err)
	}
	before, err := os.ReadFile(engine.observationPath(top.Name))
	if err != nil {
		t.Fatal(err)
	}

	if err := engine.checkNamespaceRecordable(top); err != nil {
		t.Fatalf("a record that can be read and written was refused: %v", err)
	}
	after, err := os.ReadFile(engine.observationPath(top.Name))
	if err != nil {
		t.Fatalf("the check left no record where one was: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("proving the record could be written rewrote what it says:\nbefore: %s\nafter:  %s",
			before, after)
	}
	// A lab that has never had a record is not a lab that cannot have one.
	fresh := &Engine{
		Runtime: runtime, Node: engine.Node, ObservationRoot: t.TempDir(),
		Renderer: engine.Renderer, State: store,
	}
	if err := fresh.checkNamespaceRecordable(top); err != nil {
		t.Fatalf("a lab whose record does not exist yet was refused a rewire: %v", err)
	}
	written, err := os.ReadFile(fresh.observationPath(top.Name))
	if err != nil {
		t.Fatalf("the check did not prove it could write the record: %v", err)
	}
	empty, err := fresh.loadObservation(top.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, known := empty.namespace(devices[0].ID); known {
		t.Fatalf("the check invented a baseline for a lab it knows nothing about: %s", written)
	}
}
