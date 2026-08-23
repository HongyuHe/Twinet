package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type baselineStateReader struct {
	state string
}

func (r baselineStateReader) ReadState(_ context.Context, device *model.Device,
	_ netstate.Executor, query netstate.Query,
) (netstate.State, error) {
	state := netstate.State{}
	if query.Has(netstate.QueryBGPSessions) {
		switch device.ID {
		case "as4/R":
			state.BGP.Sessions = []netstate.BGPSession{{Neighbor: "10.45.0.2", RemoteAS: 5, State: r.state}}
		case "as5/R":
			state.BGP.Sessions = []netstate.BGPSession{{Neighbor: "10.45.0.1", RemoteAS: 4, State: "Established"}}
		}
	}
	return state, nil
}

func TestReferenceBaselineRejectsBrokenSolvedPeerBeforeStudentGrade(t *testing.T) {
	top := referenceBaselineTopology()
	err := checkReferenceBaseline(context.Background(), top, 3, nil,
		func(context.Context, string, []string) (rt.ExecResult, error) {
			return rt.ExecResult{}, nil
		}, baselineStateReader{state: "Active"})
	if err == nil || !strings.Contains(err.Error(), "as4/R") || !strings.Contains(err.Error(), "Active") {
		t.Fatalf("broken solved peer passed reference baseline: %v", err)
	}
}

func TestReferenceBaselineIgnoresOnlyUngradedTargetPeer(t *testing.T) {
	top := referenceBaselineTopology()
	// AS4's only solved peer is AS5; target AS3 is deliberately absent from
	// the BGP state and must not make the baseline pass or fail by itself.
	if err := checkReferenceBaseline(context.Background(), top, 3, nil,
		func(context.Context, string, []string) (rt.ExecResult, error) {
			return rt.ExecResult{}, nil
		}, baselineStateReader{state: "Established"}); err != nil {
		t.Fatalf("healthy solved reference baseline was rejected: %v", err)
	}

}

func TestReferenceBaselineRejectsBrokenSolvedForwarding(t *testing.T) {
	top := referenceBaselineTopology()
	host := &model.Device{ID: "as5/H", Name: "H", Kind: model.KindHost, ASN: 5}
	host.Ifaces = []*model.Iface{{Device: host, Name: "eth0", Addr4: "3.5.0.1/24"}}
	top.Devices[host.ID] = host
	top.ASes[5].Devices = append(top.ASes[5].Devices, host)
	err := checkReferenceBaseline(context.Background(), top, 3,
		referenceBaselineTargets(top, 3),
		func(_ context.Context, device string, command []string) (rt.ExecResult, error) {
			if device == "as4/R" && len(command) >= 3 && command[0] == "sh" {
				return rt.ExecResult{Stdout: " 3.5.0.1\n"}, nil
			}
			return rt.ExecResult{}, nil
		}, baselineStateReader{state: "Established"})
	if err == nil || !strings.Contains(err.Error(), "as4/R") || !strings.Contains(err.Error(), "3.5.0.1") {
		t.Fatalf("broken solved forwarding passed reference baseline: %v", err)
	}
}

func referenceBaselineTopology() *model.Topology {
	target := &model.Device{ID: "as3/R", Name: "R", Kind: model.KindRouter, ASN: 3}
	left := &model.Device{ID: "as4/R", Name: "R", Kind: model.KindRouter, ASN: 4}
	right := &model.Device{ID: "as5/R", Name: "R", Kind: model.KindRouter, ASN: 5}
	leftIface := &model.Iface{Device: left, Name: "to5", Role: model.RoleInterAS, Addr4: "10.45.0.1/24"}
	rightIface := &model.Iface{Device: right, Name: "to4", Role: model.RoleInterAS, Addr4: "10.45.0.2/24"}
	leftIface.Peer, rightIface.Peer = rightIface, leftIface
	left.Ifaces, right.Ifaces = []*model.Iface{leftIface}, []*model.Iface{rightIface}
	return &model.Topology{
		Devices: map[string]*model.Device{target.ID: target, left.ID: left, right.ID: right},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, Devices: []*model.Device{target}, Routers: []*model.Device{target}},
			4: {ASN: 4, Role: model.RoleStaff, Devices: []*model.Device{left}, Routers: []*model.Device{left}},
			5: {ASN: 5, Role: model.RoleStaff, Devices: []*model.Device{right}, Routers: []*model.Device{right}},
		},
	}
}
