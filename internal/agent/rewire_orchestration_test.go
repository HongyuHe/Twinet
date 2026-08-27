package agent

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// The fault these cover was found on a live three-node lab holding a restored,
// signed group submission.
//
// Only one router's pid 1 was killed. It was rewired, its own addressing was
// replayed, its control sidecar was rebound, and the agent logged "device
// repaired and its configuration put back". The three routers on the far ends
// of its cables were left holding interfaces that were up, carried no address,
// and formed no adjacency -- so the repaired router had zero OSPF neighbours,
// and restoring the archive by hand was the only thing that brought the lab
// back.
//
// A veth pair is rebuilt as a pair. Rewiring one device therefore rebuilds its
// neighbours' ends too, and a student-owned address is never rendered by the
// platform: it exists in the kernel and in the state store and nowhere else.
// Repairing one device and nothing else is not a partial repair, it is a
// repair plus three new faults, reported as a success.

// rewireRuntime is a containerd-shaped backend with several containers whose
// namespaces the test controls, and which records the order it was asked for
// things in so "saved before it was destroyed" can be proven rather than
// assumed.
type rewireRuntime struct {
	rt.Runtime
	mu        sync.Mutex
	identity  map[string]rt.NetnsIdentity
	namespace map[string]string
	frr       map[string]string
	// unreadable makes a namespace refuse the continuity reading, which is
	// what an exec that cannot enter it looks like.
	unreadable map[string]bool
	ops        []string
	replayed   map[string][]string
}

func newRewireRuntime() *rewireRuntime {
	return &rewireRuntime{
		identity: map[string]rt.NetnsIdentity{}, namespace: map[string]string{},
		frr: map[string]string{}, unreadable: map[string]bool{},
		replayed: map[string][]string{},
	}
}

func (*rewireRuntime) Name() string { return "containerd" }

func (r *rewireRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	return rt.Container{Name: name, State: rt.StateRunning, PID: 909}, nil
}

func (r *rewireRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]rt.Container, 0, len(r.identity))
	for name := range r.identity {
		out = append(out, rt.Container{Name: name, State: rt.StateRunning, PID: 909})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *rewireRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identity[name]
	if !ok {
		return rt.NetnsIdentity{}, fmt.Errorf("no namespace for %s", name)
	}
	return identity, nil
}

func (r *rewireRuntime) ObservedNetnsIdentity(ctx context.Context,
	container rt.Container,
) (rt.NetnsIdentity, error) {
	return r.NetnsIdentity(ctx, container.Name)
}

func (r *rewireRuntime) CopyTo(_ context.Context, name, path string, _ int64, body []byte) error {
	r.record("copy " + name + " " + path)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replayed[name] = append(r.replayed[name], "config:"+strings.TrimSpace(string(body)))
	return nil
}

func (r *rewireRuntime) record(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
}

func (r *rewireRuntime) Exec(_ context.Context, container string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	joined := strings.Join(cmd.Cmd, " ")
	if strings.HasPrefix(joined, "test -f ") {
		return rt.ExecResult{ExitCode: 1}, nil
	}
	if cmd.Cmd[0] == "vtysh" {
		r.mu.Lock()
		defer r.mu.Unlock()
		return rt.ExecResult{Stdout: r.frr[container]}, nil
	}
	if len(cmd.Cmd) == 3 && cmd.Cmd[0] == "sh" {
		script := cmd.Cmd[2]
		r.mu.Lock()
		body, unreadable := r.namespace[container], r.unreadable[container]
		r.mu.Unlock()
		switch {
		case strings.HasPrefix(script, "ip -o link show"):
			r.record("read " + container)
			if unreadable {
				return rt.ExecResult{ExitCode: 1, Stderr: "cannot enter namespace"}, nil
			}
			return rt.ExecResult{Stdout: body}, nil
		case strings.HasPrefix(script, "ip -o addr show"):
			r.record("read " + container)
			if unreadable {
				return rt.ExecResult{ExitCode: 1, Stderr: "cannot enter namespace"}, nil
			}
			if _, addrs, ok := strings.Cut(body, "\n---\n"); ok {
				return rt.ExecResult{Stdout: addrs}, nil
			}
			return rt.ExecResult{}, nil
		case strings.HasPrefix(script, "ip addr replace"),
			strings.HasPrefix(script, "ip -6 addr replace"),
			strings.HasPrefix(script, "ip route replace"):
			r.record("replay " + container)
			r.mu.Lock()
			r.replayed[container] = append(r.replayed[container], script)
			r.mu.Unlock()
		}
	}
	return rt.ExecResult{}, nil
}

func (r *rewireRuntime) opsAfter(marker string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, op := range r.ops {
		if op == marker {
			return append([]string(nil), r.ops[i+1:]...)
		}
	}
	return nil
}

func (r *rewireRuntime) opsBefore(marker string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, op := range r.ops {
		if op == marker {
			return append([]string(nil), r.ops[:i]...)
		}
	}
	return append([]string(nil), r.ops...)
}

func (r *rewireRuntime) replaysOf(container string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.replayed[container]...)
}

// fakeRewireEngine stands in for the deployment engine, because building a
// veth pair inside a unit test cannot be done. It records the one thing the
// orchestration owes the engine -- that it is called at all, once, after the
// state it destroys has been saved -- and then drives the replay callback the
// way the real RewireDeviceAndPeers does: target first, then each neighbour.
type fakeRewireEngine struct {
	runtime *rewireRuntime
	top     *model.Topology
	node    string
	calls   []string
	err     error
	// reconfigured records the neighbours whose rendered contract was put
	// back, which the real engine does between the wiring and the replay.
	reconfigured []string
}

func (f *fakeRewireEngine) RewireDeviceAndPeers(ctx context.Context, top *model.Topology,
	d *model.Device, replay func(context.Context, *model.Device) error,
) error {
	f.calls = append(f.calls, d.ID)
	f.runtime.record("rewire " + d.ID)
	if f.err != nil {
		return f.err
	}
	peers := deploy.LocalRewirePeers(top, f.node, d)
	for _, peer := range peers {
		f.reconfigured = append(f.reconfigured, peer.ID)
		f.runtime.record("configure " + peer.ID)
	}
	if replay == nil {
		return nil
	}
	for _, dev := range append([]*model.Device{d}, peers...) {
		if err := replay(ctx, dev); err != nil {
			return err
		}
	}
	return nil
}

// rewireLab is one autonomous system whose routers sit on two nodes:
//
//	A -- B      both on n0, so rewiring A rebuilds B's end
//	A == C      C is on n1, so its half hangs off a shared overlay
//	B -- D      D is on n0 but is not attached to A
//
// Rewiring A must therefore reach exactly A and B.
func rewireLab(t *testing.T) (*Server, *model.Topology, *state.Store, *rewireRuntime) {
	t.Helper()
	lab := &model.Lab{
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "n0", Front: true}, {Name: "n1"},
		}},
		State: model.StatePolicy{ReplicationFactor: 1, CaptureInterval: "1h", ReplicaRetention: "168h"},
	}
	lab.Normalize()
	device := func(name, node string) *model.Device {
		return &model.Device{
			ID: "as1/" + name, Name: name, Container: "tw-" + strings.ToLower(name),
			Kind: model.KindRouter, ASN: 1, Node: node,
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
	links := []*model.Link{
		link(a, "port_B", b, "port_A"),
		link(a, "port_C", c, "port_A"),
		link(b, "port_D", d, "port_B"),
	}
	as := &model.AS{ASN: 1, Role: model.RoleStudent,
		Devices: []*model.Device{a, b, c, d}, Routers: []*model.Device{a, b, c, d}}
	top := &model.Topology{
		Lab: lab, Name: "rewire-lab", Hash: "topology",
		Devices: map[string]*model.Device{
			a.ID: a, b.ID: b, c.ID: c, d.ID: d,
		},
		Links:    links,
		ASes:     map[int]*model.AS{1: as},
		Services: map[string]*model.Service{},
	}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtime := newRewireRuntime()
	for _, dev := range []*model.Device{a, b, c, d} {
		runtime.identity[dev.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026590000 + uint64(len(dev.ID))}
		runtime.frr[dev.Container] = "router ospf\n network 1.0.0.0/8 area 0\n"
	}
	// Different inodes per container, so a namespace can be told from another.
	runtime.identity[a.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026590001}
	runtime.identity[b.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026590002}
	runtime.identity[c.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026590003}
	runtime.identity[d.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026590004}
	runtime.namespace[a.Container] = namespaceHolding([]string{"port_B", "port_C"},
		map[string]string{"port_B": "1.0.1.1/24", "port_C": "1.0.2.1/24"})
	runtime.namespace[b.Container] = namespaceHolding([]string{"port_A", "port_D"},
		map[string]string{"port_A": "1.0.1.2/24", "port_D": "1.0.3.1/24"})
	runtime.namespace[c.Container] = namespaceHolding([]string{"port_A"},
		map[string]string{"port_A": "1.0.2.2/24"})
	runtime.namespace[d.Container] = namespaceHolding([]string{"port_B"},
		map[string]string{"port_B": "1.0.3.2/24"})

	server := &Server{
		cfg: Config{Node: "n0"}, store: store, rt: runtime,
		current: map[string]*model.Topology{top.Name: top},
		modes:   map[string]string{}, ungraded: map[string]int{},
		peers: map[string]map[string]string{}, ops: map[string]*lease{},
		holds: map[string]*hold{}, lastCapture: map[string]time.Time{},
		durabilityBusy: map[string]bool{},
	}
	return server, top, store, runtime
}

func saveAddrs(t *testing.T, store *state.Store, top *model.Topology, id, body string) {
	t.Helper()
	if _, err := store.Put(state.Snapshot{
		Lab: top.Name, AS: 1, Device: id, Kind: state.KindAddrs,
		Content: []byte(body),
	}); err != nil {
		t.Fatal(err)
	}
}

func savedAddrsOf(t *testing.T, store *state.Store, lab, id string) string {
	t.Helper()
	snapshot, err := store.Current(lab, id, state.KindAddrs)
	if err != nil {
		t.Fatalf("read the saved addressing of %s: %v", id, err)
	}
	return string(snapshot.Content)
}

// A repair reaches exactly one hop, on this node, over cables it is rebuilding.
func TestARewireReachesItsOwnNodeNeighboursAndNoFurther(t *testing.T) {
	_, top, _, _ := rewireLab(t)
	peers := deploy.LocalRewirePeers(top, "n0", top.Devices["as1/A"])
	var ids []string
	for _, peer := range peers {
		ids = append(ids, peer.ID)
	}
	if strings.Join(ids, ",") != "as1/B" {
		t.Fatalf("rewiring as1/A was expanded to %v; it rebuilds B's end of one cable, "+
			"C's half hangs off a shared overlay this node never deletes, and D is not "+
			"attached to it at all", ids)
	}
	// And it is symmetric: rewiring B reaches A and D, not C.
	peers = deploy.LocalRewirePeers(top, "n0", top.Devices["as1/B"])
	ids = nil
	for _, peer := range peers {
		ids = append(ids, peer.ID)
	}
	if strings.Join(ids, ",") != "as1/A,as1/D" {
		t.Fatalf("rewiring as1/B was expanded to %v, want its two same-node neighbours "+
			"in a stable order", ids)
	}
}

// The ordering. A neighbour's work is destroyed by the wiring, so it has to be
// read out of its namespace before the wiring runs -- not by the periodic
// capture that may be an hour old, and not afterwards, when what is there is a
// bare interface.
func TestARewireSavesTheNeighbourBeforeItUnplugsIt(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	// What the periodic capture last saw. The student has addressed port_D
	// since, and that is in the namespace and nowhere else.
	saveAddrs(t, store, top, "as1/B", "twinet-state/v2 addrs\naddr inet port_A 1.0.1.2/24\n")
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	if err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"], mode: render.ModePlatform,
	}); err != nil {
		t.Fatalf("rewire: %v", err)
	}

	before := runtime.opsBefore("rewire as1/A")
	read := map[string]bool{}
	for _, op := range before {
		if strings.HasPrefix(op, "read ") {
			read[strings.TrimPrefix(op, "read ")] = true
		}
	}
	if !read["tw-b"] {
		t.Fatalf("the neighbour was never read before its interfaces were rebuilt; ops were %v",
			runtime.ops)
	}
	if !read["tw-a"] {
		t.Fatalf("the device being repaired was not read before it was rewired either; ops were %v",
			runtime.ops)
	}
	if read["tw-d"] || read["tw-c"] {
		t.Fatalf("a rewire of as1/A read devices it does not unplug: %v", before)
	}
	// The address the student added since the last periodic capture is now in
	// the store, so the replay puts back their current work rather than an
	// hour-old copy of it.
	saved := savedAddrsOf(t, store, top.Name, "as1/B")
	if !strings.Contains(saved, "addr inet port_D 1.0.3.1/24") {
		t.Fatalf("the neighbour's newest address was destroyed by the rewire without ever "+
			"being saved:\n%s", saved)
	}
}

// The live defect itself: the neighbour has to be put back, not merely saved.
func TestARewirePutsTheNeighbourBackAndNotOnlyTheDeviceThatBroke(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	saveAddrs(t, store, top, "as1/B", "twinet-state/v2 addrs\naddr inet port_A 1.0.1.2/24\n")
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	if err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"], mode: render.ModePlatform,
	}); err != nil {
		t.Fatalf("rewire: %v", err)
	}

	if strings.Join(engine.reconfigured, ",") != "as1/B" {
		t.Fatalf("the neighbours re-rendered after the wiring were %v, want as1/B",
			engine.reconfigured)
	}
	replays := runtime.replaysOf("tw-b")
	if len(replays) == 0 {
		t.Fatal("the neighbour's saved addressing was never replayed: its end of the cable " +
			"came back bare, which is the fault this exists for")
	}
	found := false
	for _, cmd := range replays {
		if strings.Contains(cmd, "1.0.1.2/24") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the neighbour was replayed without its address: %v", replays)
	}
	if len(runtime.replaysOf("tw-a")) == 0 {
		t.Fatal("the repaired device itself was not replayed")
	}
	if len(runtime.replaysOf("tw-d")) != 0 || len(runtime.replaysOf("tw-c")) != 0 {
		t.Fatal("a rewire replayed state onto devices whose cables it never touched")
	}
	// Everything the neighbour got happened after the wiring, in the order a
	// deployment uses: interfaces, then the rendered contract, then the work.
	after := runtime.opsAfter("rewire as1/A")
	configureAt, replayAt := -1, -1
	for i, op := range after {
		if op == "configure as1/B" && configureAt < 0 {
			configureAt = i
		}
		if op == "replay tw-b" && replayAt < 0 {
			replayAt = i
		}
	}
	if configureAt < 0 || replayAt < 0 || configureAt > replayAt {
		t.Fatalf("the neighbour's repair ran out of order: %v", after)
	}
}

// A namespace nobody can vouch for is a namespace whose contents may be the
// only copy of somebody's work. Destroying its interfaces on the way to
// repairing a different device is refused, and refused before anything is
// mutated.
func TestARewireRefusesWhenTheNeighbourNamespaceCannotBeVouchedFor(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	saveAddrs(t, store, top, "as1/B", "twinet-state/v2 addrs\naddr inet port_A 1.0.1.2/24\n")
	// Unbaselined and unreadable: nothing can say whether what is in it is the
	// student's work or an empty room with their name on it.
	runtime.unreadable[top.Devices["as1/B"].Container] = true
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"], mode: render.ModePlatform,
	})
	if err == nil {
		t.Fatal("a rewire that would rebuild an unvouched-for neighbour's interfaces reported success")
	}
	if !strings.Contains(err.Error(), "as1/B") {
		t.Fatalf("the refusal does not name the neighbour it is protecting: %v", err)
	}
	if rewireStageOf(err) != stagePreserve {
		t.Fatalf("the refusal is reported as stage %q, not as a refusal before any mutation",
			rewireStageOf(err))
	}
	if len(engine.calls) != 0 {
		t.Fatalf("the wiring ran anyway: %v", engine.calls)
	}
	if saved := savedAddrsOf(t, store, top.Name, "as1/B"); !strings.Contains(saved,
		"addr inet port_A 1.0.1.2/24") {
		t.Fatalf("the refusal still overwrote the neighbour's saved state:\n%s", saved)
	}
}

// The other half of that rule. The device being repaired is the one that was
// reported broken, and a namespace that is provably a replacement is a known
// loss rather than an open question: its snapshot is the only copy of what used
// to be in it, and replaying it is the repair. Refusing here would leave every
// restarted router permanently broken.
func TestARewireProceedsWhenTheBrokenDeviceHasProvablyLostItsNamespace(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	target := top.Devices["as1/A"]
	saveAddrs(t, store, top, target.ID,
		"twinet-state/v2 addrs\naddr inet port_B 1.0.1.1/24\naddr inet port_C 1.0.2.1/24\n")
	saveAddrs(t, store, top, "as1/B", "twinet-state/v2 addrs\naddr inet port_A 1.0.1.2/24\n")
	// Baselined where its state was configured, then restarted into a new,
	// empty namespace -- the exact live fault.
	baselineNamespaces(t, server, top, []string{target.ID, "as1/B"})
	runtime.mu.Lock()
	runtime.identity[target.Container] = rt.NetnsIdentity{Dev: 4, Inode: 4026599999}
	runtime.namespace[target.Container] = namespaceHolding(nil, nil)
	runtime.mu.Unlock()
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	if err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: target, mode: render.ModePlatform,
	}); err != nil {
		t.Fatalf("a known namespace replacement was treated as an open question: %v", err)
	}
	if saved := savedAddrsOf(t, store, top.Name, target.ID); !strings.Contains(saved,
		"addr inet port_B 1.0.1.1/24") {
		t.Fatalf("the capture taken before the rewire filed the empty namespace over the "+
			"only copy of the student's addressing:\n%s", saved)
	}
	if len(runtime.replaysOf(target.Container)) == 0 {
		t.Fatal("the restarted router was rewired and never had its saved addressing put back")
	}
}

// baselineNamespaces records the namespaces these devices are currently in, the
// way a capture that could vouch for them does.
func baselineNamespaces(t *testing.T, server *Server, top *model.Topology, ids []string) {
	t.Helper()
	if _, err := server.captureAndReplicateDirty(context.Background(), top, ids); err != nil {
		t.Fatalf("baseline capture: %v", err)
	}
}

// Not onto a lab deployed at the reference. Reading a solved router files the
// answer as somebody's work, and replaying a snapshot onto one leaves the class
// being marked against a converged network that is not the answer.
func TestASolvedRewireNeitherReadsNorReplaysTheAnswer(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	saveAddrs(t, store, top, "as1/B", "twinet-state/v2 addrs\naddr inet port_A 9.9.9.9/32\n")
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	if err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"], mode: render.ModeSolve,
	}); err != nil {
		t.Fatalf("solved rewire: %v", err)
	}
	for _, op := range runtime.opsBefore("rewire as1/A") {
		if strings.HasPrefix(op, "read ") {
			t.Fatalf("a solved rewire read %s; the reference answer is not anybody's work", op)
		}
	}
	if len(runtime.replaysOf("tw-a")) != 0 || len(runtime.replaysOf("tw-b")) != 0 {
		t.Fatal("a solved rewire replayed a student snapshot over the reference answer")
	}
	if saved := savedAddrsOf(t, store, top.Name, "as1/B"); !strings.Contains(saved, "9.9.9.9/32") {
		t.Fatalf("a solved rewire overwrote a saved student snapshot:\n%s", saved)
	}
}

// A private grading harness is solved everywhere except the one system being
// marked, and that system keeps its own work. Reading the lab's mode instead of
// each device's is how a repair installs the reference answer on the router
// whose work is about to be graded.
func TestAGradedSystemIsPreservedByARewireOfItsSolvedNeighbour(t *testing.T) {
	server, top, store, runtime := rewireLab(t)
	graded := top.Devices["as1/B"]
	graded.ASN = 7
	top.ASes[7] = &model.AS{ASN: 7, Role: model.RoleStudent,
		Devices: []*model.Device{graded}, Routers: []*model.Device{graded}}
	saveAddrs(t, store, top, graded.ID, "twinet-state/v2 addrs\naddr inet port_A 1.0.1.2/24\n")
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	if err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"],
		mode: render.ModeSolve, ungraded: 7,
	}); err != nil {
		t.Fatalf("harness rewire: %v", err)
	}
	readGraded := false
	for _, op := range runtime.opsBefore("rewire as1/A") {
		if op == "read "+graded.Container {
			readGraded = true
		}
		if op == "read tw-a" {
			t.Fatal("the harness rewire read the solved router it is repairing")
		}
	}
	if !readGraded {
		t.Fatal("the graded system's work was destroyed by a rewire of its solved neighbour " +
			"without ever being saved")
	}
	if len(runtime.replaysOf(graded.Container)) == 0 {
		t.Fatal("the graded system was left with a bare interface after the rewire")
	}
	if len(runtime.replaysOf("tw-a")) != 0 {
		t.Fatal("the solved router had a student snapshot replayed onto it")
	}
}

// A rollback may take the lab between the wiring and the replay, and a
// student's snapshot must not land underneath it.
func TestARewireStopsBeforeTheReplayWhenARollbackTakesTheLab(t *testing.T) {
	server, top, _, runtime := rewireLab(t)
	engine := &fakeRewireEngine{runtime: runtime, top: top, node: "n0"}

	err := server.rewireWithPeers(context.Background(), rewireRequest{
		engine: engine, top: top, device: top.Devices["as1/A"], mode: render.ModePlatform,
		beforeReplay: func() error { return errRepairSuppressed },
	})
	if !errors.Is(err, errRepairSuppressed) {
		t.Fatalf("rewire under a rollback returned %v, want the suppression sentinel", err)
	}
	if len(runtime.replaysOf("tw-a")) != 0 || len(runtime.replaysOf("tw-b")) != 0 {
		t.Fatal("a snapshot was replayed into a lab a rollback had taken")
	}
}

// The drift guard.
//
// There were four calls to RewireDevice in this package and every one of them
// repaired a device and silently broke its neighbours. They were fixed
// together because there is now one way to do it; this is what keeps the fifth
// from being written.
func TestEveryRewireInThisPackageGoesThroughTheOneOrchestration(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	direct := map[string][]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					switch selector.Sel.Name {
					case "RewireDevice", "RewireDeviceAndPeers":
						direct[selector.Sel.Name] = append(direct[selector.Sel.Name], fn.Name.Name)
					}
					return true
				})
			}
		}
	}
	if callers := direct["RewireDevice"]; len(callers) > 0 {
		sort.Strings(callers)
		t.Errorf("%v call Engine.RewireDevice directly. It rebuilds the neighbours' ends of "+
			"the cables it repairs and puts none of them back, so every caller has to go "+
			"through rewireWithPeers, which saves them first and restores them after",
			callers)
	}
	callers := direct["RewireDeviceAndPeers"]
	sort.Strings(callers)
	if len(callers) != 1 || callers[0] != "rewireWithPeers" {
		t.Errorf("Engine.RewireDeviceAndPeers is called from %v; the capture that has to "+
			"happen before it and the replay that has to happen after it live in "+
			"rewireWithPeers, so that is the only place it may be called from", callers)
	}
}
