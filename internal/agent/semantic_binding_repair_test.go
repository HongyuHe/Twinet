package agent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// driftedEndpointRuntime is one node's half of a cross-node link that lost
// both its overlay binding and the address the reference solution put on it.
//
// It answers the probes the agent actually runs, and it applies the repair
// commands the renderer actually emits, so a test proves the repair converged
// rather than that a fake was asked politely.
type driftedEndpointRuntime struct {
	rt.Runtime
	mu sync.Mutex

	links     string
	addresses map[string]string
	commands  []string
	spec      string
}

func (r *driftedEndpointRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{
		State:  rt.StateRunning,
		Labels: map[string]string{deploy.LabelSpec: r.spec},
	}, nil
}

func (r *driftedEndpointRuntime) List(context.Context, rt.Filter) ([]rt.Container, error) {
	return nil, nil
}

func (r *driftedEndpointRuntime) CopyTo(context.Context, string, string, int64, []byte) error {
	return nil
}

func (r *driftedEndpointRuntime) CopyFrom(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (r *driftedEndpointRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(cmd.Cmd, " ")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, body)
	switch {
	case strings.Contains(body, "ip -o link show"):
		return rt.ExecResult{Stdout: r.links}, nil
	case body == "ip -o addr show":
		out := ""
		for iface, address := range r.addresses {
			out += "2: " + iface + "    inet " + address + " scope global " + iface + "\n"
		}
		return rt.ExecResult{Stdout: out}, nil
	case strings.HasPrefix(body, "ip -o route show") || strings.HasPrefix(body, "ip -o -6 route show"):
		return rt.ExecResult{}, nil
	case strings.Contains(body, "ip addr replace"):
		fields := strings.Fields(body)
		for i := range fields {
			if fields[i] == "replace" && i+1 < len(fields) {
				address := fields[i+1]
				for j := i; j < len(fields)-1; j++ {
					if fields[j] == "dev" {
						r.addresses[fields[j+1]] = address
					}
				}
			}
		}
		return rt.ExecResult{}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *driftedEndpointRuntime) addressOf(iface string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addresses[iface]
}

func (r *driftedEndpointRuntime) ran(fragment string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, command := range r.commands {
		if strings.Contains(command, fragment) {
			return true
		}
	}
	return false
}

// solvedCrossNodeHost mirrors the shape the incident had: a solved endpoint on
// node-0 whose peer half of the link lives on the node hosting the shared IXP
// fabric.
func solvedCrossNodeHost() (*model.Topology, *model.Device) {
	host := &model.Device{
		ID: "as3/CHI_host", Name: "CHI_host", Kind: model.KindHost, ASN: 3,
		Node: "node-0", Container: "twinet-cos461-as3-chi-host",
	}
	fabric := &model.Device{
		ID: "as140/FABRIC", Name: "FABRIC", Kind: model.KindHost, ASN: 140,
		Node: "node-1", Container: "twinet-cos461-as140-fabric",
	}
	local := &model.Iface{Device: host, Name: "ixp_140", Owner: model.OwnerStudent,
		Addr4: "179.2.3.2/24"}
	remote := &model.Iface{Device: fabric, Name: "ixp_3", Owner: model.OwnerPlatform,
		Addr4: "179.2.3.140/24"}
	local.Peer, remote.Peer = remote, local
	link := &model.Link{ID: "as3/CHI_host:as140/FABRIC", VNI: 7140, A: local, B: remote}
	local.Link, remote.Link = link, link
	host.Ifaces, fabric.Ifaces = []*model.Iface{local}, []*model.Iface{remote}
	top := &model.Topology{
		Name: "cos461", Hash: "cos461-hash",
		Devices: map[string]*model.Device{host.ID: host, fabric.ID: fabric},
		Links:   []*model.Link{link},
		ASes: map[int]*model.AS{
			3:   {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{host}},
			140: {ASN: 140, Role: model.RoleIXP, Devices: []*model.Device{fabric}},
		},
		Lab: &model.Lab{},
	}
	return top, host
}

func driftedSolvedServer(t *testing.T) (*Server, *model.Topology, *model.Device, *driftedEndpointRuntime) {
	t.Helper()
	top, host := solvedCrossNodeHost()
	runtime := &driftedEndpointRuntime{
		// The cable is present; the binding behind it and the solved address
		// on it are not. That is exactly what a destroyed overlay binding
		// leaves behind once the endpoint has been rewired without its
		// address.
		links:     "lo\nixp_140\n",
		addresses: map[string]string{},
		spec:      deploy.SpecHash(host),
	}
	server := &Server{
		cfg:            Config{Node: "node-0"},
		rt:             runtime,
		current:        map[string]*model.Topology{top.Name: top},
		modes:          map[string]string{top.Name: "solve"},
		ungraded:       map[string]int{},
		peers:          map[string]map[string]string{top.Name: {"node-1": "10.0.1.2"}},
		health:         map[string]deviceObservation{},
		repairFails:    map[string]int{},
		repairNext:     map[string]time.Time{},
		semanticCycles: map[string]int{},
		repairTerminal: map[string]string{},
		partial:        map[string]int{},
	}
	return server, top, host, runtime
}

// A missing cross-node binding and a missing solved address must both be put
// back by ordinary automatic repair, and the device must still be healthy when
// the next audit looks at it.
//
// The failure this covers scored a correctly solved lab 10/10 and then 7.79
// five minutes later: the repair loop destroyed the bindings it was meant to
// protect, and every later audit deferred the resulting drift as "not locally
// repairable" for ever.
func TestSemanticRepairRestoresMissingBindingAndSolvedAddress(t *testing.T) {
	server, top, host, runtime := driftedSolvedServer(t)
	bindings := 0
	server.overlayBindingRepair = func(_ context.Context, _ *model.Topology,
		device *model.Device,
	) (deploy.OverlayRepairReport, error) {
		if device.ID != host.ID {
			t.Errorf("binding repair was asked for %s, not the drifted device", device.ID)
		}
		bindings++
		return deploy.OverlayRepairReport{Repaired: []string{"vni:7140"}}, nil
	}

	observation := server.observeDevice(context.Background(), top.Name, host, false)
	if observation.Health != healthBroken || !isSemanticOnlyDrift(observation.Reason) {
		t.Fatalf("drifted endpoint observed as %+v, want semantic drift", observation)
	}
	if !strings.Contains(observation.Reason, "is missing expected address 179.2.3.2/24 on ixp_140") {
		t.Fatalf("drift reason = %q, want the exact missing solved address", observation.Reason)
	}

	server.repairLab(context.Background(), top, []*model.Device{host})

	if bindings != 1 {
		t.Fatalf("cross-node binding repair ran %d times, want exactly one bounded attempt", bindings)
	}
	if !runtime.ran("ip addr replace 179.2.3.2/24") {
		t.Fatal("the repair never reapplied the solved address")
	}
	if got := runtime.addressOf("ixp_140"); got != "179.2.3.2/24" {
		t.Fatalf("address on ixp_140 = %q, want the solved address restored", got)
	}
	if reason := server.semanticRepairTerminalReason(top.Name, host.ID); reason != "" {
		t.Fatalf("a repaired device was abandoned as terminal: %q", reason)
	}
	server.mu.Lock()
	fails, cycles := server.repairFails[repairKey(top.Name, host.ID)],
		server.semanticCycles[repairKey(top.Name, host.ID)]
	server.mu.Unlock()
	if fails != 0 || cycles != 0 {
		t.Fatalf("repair history after success = %d failures, %d cycles, want none", fails, cycles)
	}

	// The later audit. A repair that only looked fixed until the next sweep is
	// how the original fault stayed invisible for five minutes at a time.
	if broken := server.survey(context.Background(), top); len(broken) != 0 {
		observation := server.observeDevice(context.Background(), top.Name, host, false)
		t.Fatalf("later audit found %d broken device(s): %+v", len(broken), observation)
	}
	if bindings != 1 {
		t.Fatalf("the later audit repaired bindings again (%d); repair is not stable", bindings)
	}
	if health := server.labSemanticHealth(top.Name); health.Degraded() != 0 || health.Healthy != 1 {
		t.Fatalf("published health after repair = %+v, want one healthy device", health)
	}
}

// The other half of the same fault: when the binding cannot be restored from
// this node, repair must stop after a bounded number of cycles and say so,
// rather than deferring for ever while the lab is quietly wrong.
func TestUnrepairableBindingEndsInTerminalAlertedState(t *testing.T) {
	server, top, host, _ := driftedSolvedServer(t)
	attempts := 0
	server.overlayBindingRepair = func(_ context.Context, _ *model.Topology,
		_ *model.Device,
	) (deploy.OverlayRepairReport, error) {
		attempts++
		return deploy.OverlayRepairReport{
			Failed: map[string]string{"vni:7140": "endpoint as3/CHI_host container is absent"},
		}, nil
	}
	for cycle := 1; cycle <= semanticRepairCycles+2; cycle++ {
		server.mu.Lock()
		delete(server.repairNext, repairKey(top.Name, host.ID))
		server.mu.Unlock()
		server.repairLab(context.Background(), top, []*model.Device{host})
	}
	if attempts != semanticRepairCycles {
		t.Fatalf("local repair ran %d times, want exactly %d bounded cycles",
			attempts, semanticRepairCycles)
	}
	reason := server.semanticRepairTerminalReason(top.Name, host.ID)
	if reason == "" {
		t.Fatal("distributed repair never reached a terminal state; it would retry for ever")
	}
	if !strings.Contains(reason, "vni:7140") {
		t.Fatalf("terminal reason = %q, want the binding that could not be restored", reason)
	}
	health := server.labSemanticHealth(top.Name)
	if health.Terminal != 1 || health.Degraded() != 1 {
		t.Fatalf("published health = %+v, want one terminal degraded device", health)
	}
	if drift := health.Drift(); !strings.HasPrefix(drift, host.ID+": "+terminalReasonPrefix) {
		t.Fatalf("published drift = %q, want it to name the abandoned device", drift)
	}
}

// Terminal is not permanent. A device that becomes healthy -- because the
// remote half was repaired, or because an operator did it -- clears the alert
// and becomes eligible for automatic repair again.
func TestTerminalStateClearsWhenTheDeviceRecovers(t *testing.T) {
	server, top, host, runtime := driftedSolvedServer(t)
	server.deferSemanticRepair(top.Name, host.ID, "no route to reference host address")
	server.deferSemanticRepair(top.Name, host.ID, "no route to reference host address")
	server.deferSemanticRepair(top.Name, host.ID, "no route to reference host address")
	if server.semanticRepairTerminalReason(top.Name, host.ID) == "" {
		t.Fatal("bounded cycles did not end in a terminal state")
	}
	runtime.mu.Lock()
	runtime.addresses["ixp_140"] = "179.2.3.2/24"
	runtime.mu.Unlock()
	if broken := server.survey(context.Background(), top); len(broken) != 0 {
		t.Fatalf("a recovered device was still reported broken: %d", len(broken))
	}
	if reason := server.semanticRepairTerminalReason(top.Name, host.ID); reason != "" {
		t.Fatalf("terminal state survived recovery: %q", reason)
	}
	if health := server.labSemanticHealth(top.Name); health.Terminal != 0 || health.Degraded() != 0 {
		t.Fatalf("published health after recovery = %+v", health)
	}
}
