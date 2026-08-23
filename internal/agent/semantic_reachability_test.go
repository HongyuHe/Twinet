package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestReferenceReachabilityTargetsCoverRemoteASHosts(t *testing.T) {
	makeHost := func(asn int, address string) *model.Device {
		host := &model.Device{ID: "as-host", Kind: model.KindHost, ASN: asn}
		host.Ifaces = []*model.Iface{{Device: host, Name: "host", Addr4: address}}
		return host
	}
	h5 := makeHost(5, "5.101.0.1/24")
	h10 := makeHost(10, "10.101.0.1/24")
	top := &model.Topology{
		ASes: map[int]*model.AS{
			3:  {ASN: 3},
			5:  {ASN: 5, Devices: []*model.Device{h5}},
			10: {ASN: 10, Devices: []*model.Device{h10}},
		},
	}
	got := referenceReachabilityTargets(top, 3)
	if len(got) != 2 || got[0] != "10.101.0.1" || got[1] != "5.101.0.1" {
		t.Fatalf("reference targets = %v", got)
	}
}

func TestHarnessSemanticCommitDefersRemoteForwarding(t *testing.T) {
	if !verifyReferenceForwardingAtCommit(0) {
		t.Fatal("ordinary solved lab stopped checking reference forwarding at commit")
	}
	if verifyReferenceForwardingAtCommit(3) {
		t.Fatal("ungraded harness held its apply transaction for asynchronous remote forwarding")
	}
	if !verifyReferenceBGPAtCommit(0) {
		t.Fatal("ordinary solved lab stopped checking reference BGP at commit")
	}
	if verifyReferenceBGPAtCommit(3) {
		t.Fatal("ungraded harness held its apply transaction for asynchronous reference BGP")
	}
}

func TestSemanticHealthRequirementsUseRoleAndNOSCapabilities(t *testing.T) {
	makeRouter := func(asn int, role model.ASRole, nosName string) (*model.Topology, *model.Device) {
		peer := &model.Device{ID: "peer", Kind: model.KindRouter}
		peerIf := &model.Iface{Device: peer, Addr4: "180.141.0.2/24"}
		device := &model.Device{ID: "as/router", Kind: model.KindRouter, ASN: asn, NOS: nosName}
		device.Ifaces = []*model.Iface{{Device: device, Role: model.RoleIXPLink, Peer: peerIf}}
		peerIf.Peer = device.Ifaces[0]
		return &model.Topology{ASes: map[int]*model.AS{
			asn: {ASN: asn, Role: role, Devices: []*model.Device{device}},
		}}, device
	}
	for _, nosName := range []string{"frr", "bird"} {
		top, rs := makeRouter(141, model.RoleIXP, nosName)
		got, err := semanticHealthRequirements(top, rs)
		if err != nil {
			t.Fatalf("%s IXP requirements: %v", nosName, err)
		}
		if got.Forwarding || !got.BGPControl {
			t.Errorf("%s IXP requirements = %+v, want BGP control without forwarding", nosName, got)
		}
		top, router := makeRouter(5, model.RoleStaff, nosName)
		got, err = semanticHealthRequirements(top, router)
		if err != nil {
			t.Fatalf("%s ordinary requirements: %v", nosName, err)
		}
		if !got.Forwarding || !got.BGPControl {
			t.Errorf("%s ordinary requirements = %+v, want forwarding+BGP", nosName, got)
		}
	}
	host := &model.Device{ID: "as5/H", Kind: model.KindHost, ASN: 5}
	top := &model.Topology{ASes: map[int]*model.AS{
		5: {ASN: 5, Role: model.RoleStaff, Devices: []*model.Device{host}},
	}}
	got, err := semanticHealthRequirements(top, host)
	if err != nil {
		t.Fatal(err)
	}
	if got.Forwarding || got.BGPControl {
		t.Fatalf("host requirements = %+v, want no router predicates", got)
	}
}

type ixpSemanticRuntime struct {
	rt.Runtime
	commands []string
}

func (r *ixpSemanticRuntime) Name() string { return "memory" }

func (*ixpSemanticRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateAbsent}, nil
}

func (r *ixpSemanticRuntime) Exec(_ context.Context, _ string, command rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(command.Cmd, " ")
	r.commands = append(r.commands, body)
	switch {
	case strings.Contains(body, "show ip bgp summary json"):
		return rt.ExecResult{Stdout: `{"ipv4Unicast":{"peers":{"180.141.0.2":{"state":"Established"}}}}`}, nil
	case strings.Contains(body, "show ip bgp json"):
		return rt.ExecResult{Stdout: `{"routes":{"5.0.0.0/8":[{"valid":true,"bestpath":true}]}}`}, nil
	case strings.Contains(body, "ip route get"):
		return rt.ExecResult{}, nil
	}
	return rt.ExecResult{}, nil
}

func TestIXPSemanticProbeChecksBGPWithoutForwardingProbe(t *testing.T) {
	peer := &model.Device{ID: "as5/R", Kind: model.KindRouter}
	peerIf := &model.Iface{Device: peer, Addr4: "180.141.0.2/24"}
	rs := &model.Device{ID: "as141/RS", Container: "rs", Kind: model.KindRouter, ASN: 141}
	rs.Ifaces = []*model.Iface{{Device: rs, Role: model.RoleIXPLink, Peer: peerIf}}
	peerIf.Peer = rs.Ifaces[0]
	top := &model.Topology{Name: "lab", ASes: map[int]*model.AS{
		141: {ASN: 141, Role: model.RoleIXP, Devices: []*model.Device{rs}},
	}}
	runtime := &ixpSemanticRuntime{}
	server := &Server{rt: runtime}
	if err := server.semanticProbe(context.Background(), top, "solve", 0, rs); err != nil {
		t.Fatal(err)
	}
	for _, command := range runtime.commands {
		if strings.Contains(command, "ip route get") {
			t.Fatalf("IXP route server was asked to forward to reference hosts: %s", command)
		}
	}
}

func TestSemanticDriftDefersWithoutImmediateRewireRetries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := &Server{repairFails: map[string]int{}, repairNext: map[string]time.Time{}}
	server.now = func() time.Time { return now }
	server.deferSemanticRepair("lab", "as9/SFO", "network semantics drifted: no remote route")
	if !server.givingUpOn("lab", "as9/SFO") {
		t.Fatal("semantic drift did not enter immediate bounded backoff")
	}
	now = now.Add(repairDelay(repairAttemptsBeforeGivingUp) + time.Millisecond)
	if server.givingUpOn("lab", "as9/SFO") {
		t.Fatal("semantic drift was permanently abandoned rather than retryable")
	}
}
