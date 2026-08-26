package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// captureNamespaceRuntime is a containerd-shaped backend whose containers have
// network namespaces the test controls, and which answers the two readings a
// capture and a continuity proof make out of them.
type captureNamespaceRuntime struct {
	rt.Runtime
	mu       sync.Mutex
	identity map[string]rt.NetnsIdentity
	// namespace is the `ip -o link show`/addrCapture pair the container's
	// namespace would print, in the shape the deployment reads it.
	namespace map[string]string
	frr       map[string]string
}

func (*captureNamespaceRuntime) Name() string { return "containerd" }

func (r *captureNamespaceRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	return rt.Container{Name: name, State: rt.StateRunning, PID: 4242}, nil
}

func (r *captureNamespaceRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []rt.Container
	for name := range r.identity {
		out = append(out, rt.Container{Name: name, State: rt.StateRunning, PID: 4242})
	}
	return out, nil
}

func (r *captureNamespaceRuntime) NetnsIdentity(_ context.Context, name string) (rt.NetnsIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.identity[name]
	if !ok {
		return rt.NetnsIdentity{}, fmt.Errorf("no namespace for %s", name)
	}
	return identity, nil
}

func (r *captureNamespaceRuntime) ObservedNetnsIdentity(ctx context.Context,
	container rt.Container,
) (rt.NetnsIdentity, error) {
	return r.NetnsIdentity(ctx, container.Name)
}

// Exec answers the restore marker, the two namespace readings and vtysh.
//
// The readings are told apart by the command each begins with rather than by
// comparing against the deployment's unexported constants: the continuity
// proof lists the netdevs first and then reads the addressing, and a capture
// reads only the addressing.
func (r *captureNamespaceRuntime) Exec(_ context.Context, container string,
	cmd rt.ExecCmd,
) (rt.ExecResult, error) {
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
		r.mu.Lock()
		body := r.namespace[container]
		r.mu.Unlock()
		switch {
		case strings.HasPrefix(cmd.Cmd[2], "ip -o link show"):
			return rt.ExecResult{Stdout: body}, nil
		case strings.HasPrefix(cmd.Cmd[2], "ip -o addr show"):
			if _, addrs, ok := strings.Cut(body, "\n---\n"); ok {
				return rt.ExecResult{Stdout: addrs}, nil
			}
			return rt.ExecResult{}, nil
		}
	}
	return rt.ExecResult{}, nil
}

func (r *captureNamespaceRuntime) setNamespace(container, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.namespace[container] = body
}

// namespaceHolding renders what a namespace with these interfaces and these
// addresses on them prints, in the two sections the deployment reads.
func namespaceHolding(ifaces []string, addrs map[string]string) string {
	var body strings.Builder
	body.WriteString("1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN\n")
	for i, name := range ifaces {
		fmt.Fprintf(&body, "%d: %s@if%d: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP\n",
			i+2, name, i+40)
	}
	body.WriteString("---\n")
	body.WriteString("1: lo    inet 127.0.0.1/8 scope host lo\n")
	for i, name := range ifaces {
		fmt.Fprintf(&body, "%d: %s    inet6 fe80::1/64 scope link \n", i+2, name)
		if addr := addrs[name]; addr != "" {
			fmt.Fprintf(&body, "%d: %s    inet %s scope global %s\n", i+2, name, addr, name)
		}
	}
	// The routes, the VLANs and the VRFs, all empty.
	body.WriteString("---\n---\n---\n---\n")
	return body.String()
}

// capturableAgentLab is one student router on this node, with a saved snapshot
// of the addressing its student configured and a namespace that has been
// rewired without it -- which is what a device whose task was replaced and then
// reconciled looks like.
func capturableAgentLab(t *testing.T) (*Server, *model.Topology, *model.Device,
	*state.Store, *captureNamespaceRuntime,
) {
	t.Helper()
	lab := &model.Lab{
		Placement: model.Placement{Nodes: []model.NodeSpec{
			{Name: "n0", FailureDomain: "rack-a", Front: true},
		}},
		State: model.StatePolicy{ReplicationFactor: 1, CaptureInterval: "1h", ReplicaRetention: "168h"},
	}
	lab.Normalize()
	device := &model.Device{
		ID: "as1/R", Name: "R", Container: "twinet-capture-ns-as1-r",
		Kind: model.KindRouter, ASN: 1, Node: "n0",
	}
	device.Ifaces = []*model.Iface{{Device: device, Name: "port_S", Link: &model.Link{ID: "l0"}}}
	as := &model.AS{ASN: 1, Role: model.RoleStudent, Devices: []*model.Device{device},
		Routers: []*model.Device{device}}
	top := &model.Topology{
		Lab: lab, Name: "capture-ns", Hash: "topology",
		Devices:  map[string]*model.Device{device.ID: device},
		ASes:     map[int]*model.AS{1: as},
		Services: map[string]*model.Service{},
	}
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The signed submission: the student's addressing, captured out of the
	// kernel, in the only place it exists.
	if _, err := store.Put(state.Snapshot{
		Lab: top.Name, AS: 1, Device: device.ID, Kind: state.KindAddrs,
		Content: []byte("twinet-state/v2 addrs\naddr inet port_S 10.0.0.1/24\n"),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &captureNamespaceRuntime{
		identity:  map[string]rt.NetnsIdentity{device.Container: {Dev: 4, Inode: 4026590001}},
		namespace: map[string]string{},
		frr:       map[string]string{device.Container: "router ospf\n network 10.0.0.0/24 area 0\n"},
	}
	// Rewired by a reconcile that put the cable back and knew nothing about
	// the address that used to be on it.
	runtime.setNamespace(device.Container, namespaceHolding([]string{"port_S"}, nil))

	server := &Server{
		cfg: Config{Node: "n0"}, store: store, rt: runtime,
		current: map[string]*model.Topology{top.Name: top},
		modes:   map[string]string{}, ungraded: map[string]int{},
		peers: map[string]map[string]string{}, ops: map[string]*lease{},
		holds: map[string]*hold{}, lastCapture: map[string]time.Time{},
		durabilityBusy: map[string]bool{},
	}
	return server, top, device, store, runtime
}

// savedAddressing reads back the addressing the store is holding for a device.
func savedAddressing(t *testing.T, store *state.Store, lab, device string) string {
	t.Helper()
	snapshot, err := store.Current(lab, device, state.KindAddrs)
	if err != nil {
		t.Fatalf("read the saved addressing of %s: %v", device, err)
	}
	return string(snapshot.Content)
}

// The destructive boundary. handleApplyPrepare captures every dirty device
// before the apply that replaces them, through captureAndReplicateDirty -- and
// that call builds an Engine for the purpose, so nothing it had observed came
// with it. A router whose task had been replaced arrived at that boundary with
// an empty namespace and had it filed over the snapshot the boundary exists to
// protect.
func TestADestructiveBoundaryCaptureCannotOverwriteAReplacedNamespace(t *testing.T) {
	server, top, device, store, _ := capturableAgentLab(t)
	if _, err := server.captureAndReplicateDirty(context.Background(), top,
		[]string{device.ID}); err != nil {
		t.Fatalf("boundary capture: %v", err)
	}
	if saved := savedAddressing(t, store, top.Name, device.ID); !strings.Contains(saved,
		"addr inet port_S 10.0.0.1/24") {
		t.Fatalf("the capture taken before a destructive apply overwrote the student's "+
			"addressing with the empty namespace their router restarted into:\n%s", saved)
	}
	// The routing configuration is a file. It survived, and it is captured.
	if _, err := store.Current(top.Name, device.ID, state.KindFRR); err != nil {
		t.Fatalf("the same capture withheld the configuration that did survive: %v", err)
	}
}

// The timer. Periodic durability captures the whole student-owned set with no
// deployment anywhere near it, which is the path most likely to reach a
// restarted router first -- it runs every capture interval, and nothing has to
// have gone wrong for it to run.
func TestPeriodicCaptureCannotOverwriteAReplacedNamespace(t *testing.T) {
	server, top, device, store, _ := capturableAgentLab(t)
	if _, err := server.captureAndReplicate(context.Background(), top); err != nil {
		t.Fatalf("periodic capture: %v", err)
	}
	if saved := savedAddressing(t, store, top.Name, device.ID); !strings.Contains(saved,
		"addr inet port_S 10.0.0.1/24") {
		t.Fatalf("a periodic capture filed a restarted router's empty namespace over its "+
			"student's addressing:\n%s", saved)
	}
}

// A fresh export, which is the capture with the shortest path to somebody
// else's disk.
//
// It read the containers itself rather than going through the capture API, so
// it had no guard at all: a device that had restarted was captured empty,
// written over the store, and then handed to the destination node as the
// student's work. The device moves, and what arrives is an empty room.
func TestAFreshExportCannotOverwriteAReplacedNamespace(t *testing.T) {
	server, top, device, store, _ := capturableAgentLab(t)
	if err := server.captureBeforeExport(context.Background(), top.Name,
		[]string{device.ID}); err != nil {
		t.Fatalf("fresh export capture: %v", err)
	}
	if saved := savedAddressing(t, store, top.Name, device.ID); !strings.Contains(saved,
		"addr inet port_S 10.0.0.1/24") {
		t.Fatalf("a fresh export captured a restarted router's empty namespace over the "+
			"state it was about to hand over:\n%s", saved)
	}
}

// And the capture that must still work, so the guard is not simply a way of
// never storing anything again.
//
// A namespace that holds what the store says it should is the device that never
// restarted. Its capture goes through, including what the student has done
// since the last one.
func TestAnAgentCaptureOfAnIntactNamespaceStillStoresIt(t *testing.T) {
	server, top, device, store, runtime := capturableAgentLab(t)
	runtime.setNamespace(device.Container, namespaceHolding([]string{"port_S"},
		map[string]string{"port_S": "10.0.0.1/24"}))
	if _, err := server.captureAndReplicate(context.Background(), top); err != nil {
		t.Fatalf("periodic capture: %v", err)
	}
	saved := savedAddressing(t, store, top.Name, device.ID)
	if !strings.Contains(saved, "addr inet port_S 10.0.0.1/24") {
		t.Fatalf("a capture of an intact namespace stored nothing:\n%s", saved)
	}
	if !strings.Contains(saved, deploy.CanonicalDynamicSnapshot(state.KindAddrs, saved)) {
		t.Fatalf("what was stored is not the canonical form a restore replays:\n%s", saved)
	}
}
