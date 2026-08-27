package deploy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// rewireScopeRuntime cannot enter any namespace, which is how a unit test
// reaches the wiring step without building a veth pair on the host.
//
// It does keep the two things the rewire bookkeeping is made of honestly: the
// identity of each container's namespace, and the restore-pending file inside
// it.
type rewireScopeRuntime struct {
	rt.Runtime
	mu       sync.Mutex
	identity map[string]rt.NetnsIdentity
	markers  map[string]bool
	// writeErr and releaseErr make one container refuse to have the
	// restore-pending file written or removed. They are separate because the
	// two failures mean opposite things: a mark that cannot be written refuses
	// a rewire, and a mark that cannot be removed afterwards is a device left
	// owing a restore for a rewire that never happened.
	writeErr   map[string]error
	releaseErr map[string]error
}

func newRewireScopeRuntime() *rewireScopeRuntime {
	return &rewireScopeRuntime{
		identity: map[string]rt.NetnsIdentity{}, markers: map[string]bool{},
		writeErr: map[string]error{}, releaseErr: map[string]error{},
	}
}

// failMarkerWrite is a container that cannot be marked as owing its saved
// state back, which is what refuses a rewire before it unplugs anything.
func (r *rewireScopeRuntime) failMarkerWrite(container string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeErr[container] = err
}

// failMarkerRelease is a container whose marker cannot be taken back, which is
// what a rollback runs into.
func (r *rewireScopeRuntime) failMarkerRelease(container string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseErr[container] = err
}

func (*rewireScopeRuntime) Name() string { return "containerd" }

func (*rewireScopeRuntime) NSPath(context.Context, string) (string, error) {
	return "", errors.New("no namespace path in a unit test")
}

func (r *rewireScopeRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identity[name]
	if !ok {
		return rt.NetnsIdentity{Dev: 4, Inode: 4026530000 + uint64(len(name))}, nil
	}
	return identity, nil
}

func (r *rewireScopeRuntime) ObservedNetnsIdentity(ctx context.Context,
	container rt.Container,
) (rt.NetnsIdentity, error) {
	return r.NetnsIdentity(ctx, container.Name)
}

func (r *rewireScopeRuntime) Exec(_ context.Context, container string,
	cmd rt.ExecCmd,
) (rt.ExecResult, error) {
	joined := strings.Join(cmd.Cmd, " ")
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.HasPrefix(joined, "test -f "+restoreMarker):
		if r.markers[container] {
			return rt.ExecResult{}, nil
		}
		return rt.ExecResult{ExitCode: 1}, nil
	case strings.HasPrefix(joined, "rm -f "+restoreMarker):
		if err := r.releaseErr[container]; err != nil {
			return rt.ExecResult{}, err
		}
		delete(r.markers, container)
	case len(cmd.Cmd) == 3 && cmd.Cmd[0] == "sh" && cmd.Cmd[2] == restoreMarkerScript:
		if err := r.writeErr[container]; err != nil {
			return rt.ExecResult{}, err
		}
		r.markers[container] = true
	}
	return rt.ExecResult{}, nil
}

func (r *rewireScopeRuntime) owes(container string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.markers[container]
}

// rewireScopeLab is two routers on this node with a cable between them, one
// router on another node behind a shared overlay, and one router on this node
// attached to the neighbour rather than to the target.
func rewireScopeLab() (*model.Topology, *model.Device) {
	device := func(name, node string) *model.Device {
		return &model.Device{
			ID: "as2/" + name, Name: name, Container: "c-" + strings.ToLower(name),
			Kind: model.KindRouter, ASN: 2, Node: node,
		}
	}
	a, b, c, d := device("A", "n0"), device("B", "n0"), device("C", "n1"), device("D", "n0")
	link := func(x *model.Device, xi string, y *model.Device, yi string) *model.Link {
		l := &model.Link{ID: x.ID + "-" + y.ID}
		l.A = &model.Iface{Device: x, Name: xi, Link: l}
		l.B = &model.Iface{Device: y, Name: yi, Link: l}
		x.Ifaces = append(x.Ifaces, l.A)
		y.Ifaces = append(y.Ifaces, l.B)
		return l
	}
	top := &model.Topology{
		Name: "rewire-scope", Hash: "h",
		Devices: map[string]*model.Device{a.ID: a, b.ID: b, c.ID: c, d.ID: d},
		Links: []*model.Link{
			link(a, "port_B", b, "port_A"),
			link(a, "port_C", c, "port_A"),
			link(b, "port_D", d, "port_B"),
			// A second cable between the same pair: the neighbour is named
			// once, not once per cable.
			link(a, "port_B2", b, "port_A2"),
		},
		ASes: map[int]*model.AS{2: {ASN: 2, Role: model.RoleStudent,
			Devices: []*model.Device{a, b, c, d}}},
	}
	return top, a
}

// The scope of a rewire is one hop, on this node, over cables it rebuilds.
func TestTheScopeOfARewireIsOneHopOnThisNode(t *testing.T) {
	top, target := rewireScopeLab()
	var ids []string
	for _, peer := range LocalRewirePeers(top, "n0", target) {
		ids = append(ids, peer.ID)
	}
	if strings.Join(ids, ",") != "as2/B" {
		t.Fatalf("rewiring %s reaches %v; it rebuilds B's ends, C's half hangs off a shared "+
			"overlay this node never deletes, and D is not attached to it", target.ID, ids)
	}
	ids = nil
	for _, peer := range LocalRewirePeers(top, "n0", top.Devices["as2/B"]) {
		ids = append(ids, peer.ID)
	}
	if strings.Join(ids, ",") != "as2/A,as2/D" {
		t.Fatalf("rewiring as2/B reaches %v, want both its same-node neighbours once each, "+
			"in a stable order", ids)
	}
	if peers := LocalRewirePeers(top, "n1", top.Devices["as2/C"]); len(peers) != 0 {
		t.Fatalf("a device whose only cable crosses nodes has local peers %v", peers)
	}
	// The other side of the same cable. Its far end is the other node's to
	// rebuild and this node's half hangs off a shared overlay, so a cross-node
	// link is not an expansion whichever way round it is asked.
	if peers := LocalRewirePeers(top, "n1", target); len(peers) != 0 {
		t.Fatalf("rewiring a device over a cross-node cable named %d local peers; the far "+
			"end of an overlay is never rebuilt by a bounded repair", len(peers))
	}
}

// Wiring that failed has still deleted interfaces, so nothing on this engine
// may file what is in those namespaces as anybody's work, and nothing may be
// re-rendered or replayed as though the repair had happened.
func TestAFailedRewireReplaysNothingAndTrustsNothing(t *testing.T) {
	top, target := rewireScopeLab()
	engine := &Engine{Runtime: newRewireScopeRuntime(), Node: "n0", ObservationRoot: t.TempDir()}
	replayed := []string{}

	err := engine.RewireDeviceAndPeers(context.Background(), top, target,
		func(_ context.Context, d *model.Device) error {
			replayed = append(replayed, d.ID)
			return nil
		})
	if err == nil {
		t.Fatal("a rewire that could not build a single cable reported success")
	}
	if !strings.Contains(err.Error(), target.ID) {
		t.Fatalf("the failure does not name the device it was repairing: %v", err)
	}
	if len(replayed) != 0 {
		t.Fatalf("state was replayed onto %v after the wiring failed", replayed)
	}
	dirty := map[string]bool{}
	for _, id := range engine.DirtyNamespaceStateDevices() {
		dirty[id] = true
	}
	if !dirty[target.ID] || !dirty["as2/B"] {
		t.Fatalf("after a rewire attempt the engine still vouches for %v; the neighbour's "+
			"interfaces are rebuilt with the target's, so what is in either namespace is "+
			"not the students' work until it has been put back", engine.DirtyNamespaceStateDevices())
	}
	if dirty["as2/C"] || dirty["as2/D"] {
		t.Fatalf("a rewire distrusted devices it never touched: %v",
			engine.DirtyNamespaceStateDevices())
	}
}

// The half of a rewire that the live fault was missing entirely.
//
// The wiring rebuilds the neighbours' ends of the cables, so after it runs the
// neighbours need their rendered contract and their saved work back, in that
// order, and the device that was repaired needs its own work back first. On
// the live lab none of the four neighbours got any of it: their interfaces
// were up, carried no address, and formed no adjacency, and the repair
// reported success.
func TestARewirePutsBackEveryNeighbourItRebuilt(t *testing.T) {
	top, target := rewireScopeLab()
	runtime := newRewireScopeRuntime()
	engine := &Engine{Runtime: runtime, Node: "n0", ObservationRoot: t.TempDir()}
	engine.markNamespaceStateLost(target.ID)
	engine.markNamespaceStateLost("as2/B")
	var replayed []string

	peers := LocalRewirePeers(top, "n0", target)
	for _, d := range append([]*model.Device{target}, peers...) {
		if err := engine.holdNamespaceState(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.restoreRewiredPeers(context.Background(), top, target, peers,
		func(_ context.Context, d *model.Device) error {
			replayed = append(replayed, d.ID)
			return nil
		}); err != nil {
		t.Fatalf("putting the rewired devices back: %v", err)
	}
	if strings.Join(replayed, ",") != "as2/A,as2/B" {
		t.Fatalf("saved state was replayed onto %v; the device that was repaired comes "+
			"first and every neighbour whose end of a cable was rebuilt follows it",
			replayed)
	}
	// Once a device has been rewired, re-rendered and replayed, what is in its
	// namespace is its student's work again.
	for _, id := range []string{target.ID, "as2/B"} {
		if engine.namespaceStateLost(id) {
			t.Fatalf("%s was put back and the engine still refuses to vouch for it", id)
		}
	}
	// And nothing is left owing a replay it has already had. A marker that
	// outlives its restore withholds the device from every later capture, so
	// the next thing the student does on it is never saved.
	for _, container := range []string{"c-a", "c-b"} {
		if runtime.owes(container) {
			t.Fatalf("%s was put back and is still marked as owing its saved state", container)
		}
	}
}

// A replay that fails leaves the device it failed on distrusted, so a later
// capture cannot file the bare namespace it is still sitting in.
func TestARewireWhoseReplayFailsKeepsRefusingToVouchForIt(t *testing.T) {
	top, target := rewireScopeLab()
	runtime := newRewireScopeRuntime()
	engine := &Engine{Runtime: runtime, Node: "n0", ObservationRoot: t.TempDir()}
	engine.markNamespaceStateLost(target.ID)
	engine.markNamespaceStateLost("as2/B")

	peers := LocalRewirePeers(top, "n0", target)
	for _, d := range append([]*model.Device{target}, peers...) {
		if err := engine.holdNamespaceState(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	err := engine.restoreRewiredPeers(context.Background(), top, target, peers,
		func(_ context.Context, d *model.Device) error {
			if d.ID == "as2/B" {
				return errors.New("the neighbour would not take its addressing back")
			}
			return nil
		})
	if err == nil {
		t.Fatal("a rewire whose neighbour could not be put back reported success")
	}
	if !engine.namespaceStateLost("as2/B") {
		t.Fatal("the neighbour whose replay failed is vouched for anyway; a capture would " +
			"file its bare interfaces over the only copy of the student's addressing")
	}
	// The marker is what carries that refusal to every other engine and every
	// later process, which is where the periodic capture lives.
	if !runtime.owes("c-b") {
		t.Fatal("the neighbour whose replay failed is no longer marked as owing one, so " +
			"the next capture from any other engine would file its bare interfaces")
	}
}
