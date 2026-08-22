package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type semanticRuntime struct {
	rt.Runtime
	output map[string]rt.ExecResult
}

func (r *semanticRuntime) Exec(_ context.Context, _ string, command rt.ExecCmd) (rt.ExecResult, error) {
	return r.output[strings.Join(command.Cmd, "\x00")], nil
}

func semanticHostTopology(owner model.ConfigOwner) (*model.Topology, *model.Device) {
	router := &model.Device{ID: "as5/R", Name: "R", Kind: model.KindRouter, ASN: 5}
	host := &model.Device{ID: "as5/MSP_host", Name: "MSP_host", Kind: model.KindHost,
		ASN: 5, Node: "node-0", Container: "twinet-lab-as5-msp-host"}
	hostIface := &model.Iface{Device: host, Name: "host", Owner: owner,
		Role: model.RoleHostLink, Addr4: "10.5.0.2/24"}
	routerIface := &model.Iface{Device: router, Name: "host", Owner: model.OwnerPlatform,
		Role: model.RoleHostLink, Addr4: "10.5.0.1/24"}
	hostIface.Peer, routerIface.Peer = routerIface, hostIface
	host.Ifaces, router.Ifaces = []*model.Iface{hostIface}, []*model.Iface{routerIface}
	top := &model.Topology{
		Name: "lab", Devices: map[string]*model.Device{host.ID: host, router.ID: router},
		ASes: map[int]*model.AS{5: {ASN: 5, Role: model.RoleStudent,
			Devices: []*model.Device{router, host}, Routers: []*model.Device{router}}},
	}
	return top, host
}

func TestSolveHostSemanticVerificationRequiresAddressAndDefaultRoute(t *testing.T) {
	top, host := semanticHostTopology(model.OwnerStudent)
	server := &Server{rt: &semanticRuntime{output: map[string]rt.ExecResult{
		"ip\x00-o\x00addr\x00show":  {Stdout: "2: host    inet 10.5.0.2/24 scope global host\n"},
		"ip\x00-o\x00route\x00show": {Stdout: "default via 10.5.0.1 dev host\n"},
	}}}
	if err := server.verifyNetworkSemantics(context.Background(), top, host, "solve"); err != nil {
		t.Fatalf("solve host semantics unexpectedly failed: %v", err)
	}
	server.rt = &semanticRuntime{output: map[string]rt.ExecResult{
		"ip\x00-o\x00addr\x00show":  {Stdout: "2: host    inet 10.5.0.2/24 scope global host\n"},
		"ip\x00-o\x00route\x00show": {Stdout: ""},
	}}
	if err := server.verifyNetworkSemantics(context.Background(), top, host, "solve"); err == nil ||
		!strings.Contains(err.Error(), "default route") {
		t.Fatalf("missing solve default route passed semantic verification: %v", err)
	}
}

func TestTeachingHostBlankStudentStartIsNotInvented(t *testing.T) {
	top, host := semanticHostTopology(model.OwnerStudent)
	server := &Server{rt: &semanticRuntime{output: map[string]rt.ExecResult{
		"ip\x00-o\x00addr\x00show":  {Stdout: ""},
		"ip\x00-o\x00route\x00show": {Stdout: ""},
	}}}
	if err := server.verifyNetworkSemantics(context.Background(), top, host, "platform"); err != nil {
		t.Fatalf("teaching-mode blank student host was treated as drift: %v", err)
	}
}

func TestHarnessModeCapturesOnlyUngradedStudentState(t *testing.T) {
	top, host := semanticHostTopology(model.OwnerStudent)
	if capturesStudentState(top, "solve", 0, host) {
		t.Fatal("reference solve host was eligible for student snapshot capture")
	}

	{
		top, host := semanticHostTopology(model.OwnerPlatform)
		server := &Server{rt: &semanticRuntime{output: map[string]rt.ExecResult{
			"cat\x00/etc/twinet/device.json": {Stdout: "stale artifact\n"},
		}}}
		artifact := transactionArtifact{
			Path: "/etc/twinet/device.json", Content: []byte("fresh artifact\n"),
			Digest: artifactDigest([]byte("fresh artifact\n")),
		}
		if err := server.verifyRenderedArtifacts(context.Background(), top, host, "solve",
			[]transactionArtifact{artifact}); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("stale rendered artifact passed semantic verification: %v", err)
		}
	}

	{
		top, host := semanticHostTopology(model.OwnerStudent)
		harness := render.NewHarness(top, host.ASN)
		if harness.AuthoritativeDevice(host) {
			t.Fatal("harness treated the ungraded submission host as reference-authoritative")
		}
		peer := &model.Device{ID: "as6/H", Kind: model.KindHost, ASN: 6}
		if !harness.AuthoritativeDevice(peer) {
			t.Fatal("harness did not restore reference authority for surrounding ASes")
		}
	}

	if !capturesStudentState(top, "solve", 5, host) {
		t.Fatal("ungraded harness host was not eligible for student snapshot capture")
	}
	if renderModeForDevice("solve", 5, host) != "platform" {
		t.Fatal("ungraded harness host was rendered as reference solve")
	}
}

func TestModeCommitSemanticsIncludesUntouchedLocalDevices(t *testing.T) {
	top := &model.Topology{Devices: map[string]*model.Device{
		"as5/MSP_host":  {ID: "as5/MSP_host", Node: "node-0"},
		"as10/SFO_host": {ID: "as10/SFO_host", Node: "node-0"},
		"as3/ATL":       {ID: "as3/ATL", Node: "node-1"},
	}}
	tx := applyTransaction{
		PreviousMode: string(render.ModePlatform), Mode: string(render.ModeSolve),
		Touched: []string{"as5/MSP_host"},
	}
	got := semanticCommitDevices(top, "node-0", tx, render.ModeSolve)
	if strings.Join(got, ",") != "as10/SFO_host,as5/MSP_host" {
		t.Fatalf("solve mode commit skipped untouched local device: %v", got)
	}

	tx.PreviousMode = string(render.ModeSolve)
	tx.Mode = string(render.ModeSolve)
	got = semanticCommitDevices(top, "node-0", tx, render.ModeSolve)
	if strings.Join(got, ",") != "as5/MSP_host" {
		t.Fatalf("unchanged mode expanded semantic proof unexpectedly: %v", got)
	}
}
