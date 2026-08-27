package grade

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type stableStateReader struct {
	state netstate.State
}

func (r *stableStateReader) ReadState(context.Context, *model.Device,
	netstate.Executor, netstate.Query,
) (netstate.State, error) {
	return r.state, nil
}

func TestControlPlaneFingerprintTracksStateButNotLiveCounters(t *testing.T) {
	router := &model.Device{
		ID: "as3/R", Name: "R", Kind: model.KindRouter, ASN: 3,
	}
	topology := &model.Topology{
		Devices: map[string]*model.Device{router.ID: router},
		ASes: map[int]*model.AS{
			3: {ASN: 3, Routers: []*model.Device{router}, Devices: []*model.Device{router}},
		},
	}
	reader := &stableStateReader{state: netstate.State{
		OSPF: []netstate.OSPFPeer{{
			RouterID: "3.152.0.1", Interface: "port_R2", State: "Full",
			DeadTimerMsec: 30000,
		}},
		BGP: netstate.BGP{
			Sessions: []netstate.BGPSession{{
				Neighbor: "3.152.0.1", RemoteAS: 3, State: "Established",
				PrefixesIn: 2, PrefixesOut: 2, UpdatesReceived: 10,
			}},
			Paths: []netstate.BGPPath{{
				Prefix: "1.0.0.0/8", ASPath: "1", Best: true, Valid: true,
				LocalPref: 100, Peer: "192.0.2.1",
			}, {
				Prefix: "1.0.0.0/8", ASPath: "1", Valid: true,
				LocalPref: 100, Peer: "192.0.2.2",
			}},
		},
	}}
	env := &Env{
		Topology: topology, AS: 3, StateReader: reader,
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
			return rt.ExecResult{}, nil
		},
	}
	first, routers, err := controlPlaneFingerprint(context.Background(), env)
	if err != nil || routers != 1 {
		t.Fatalf("first fingerprint = %q/%d: %v", first, routers, err)
	}
	reader.state.OSPF[0].DeadTimerMsec = 29000
	reader.state.BGP.Sessions[0].UpdatesReceived = 11
	reader.state.BGP.Paths[0], reader.state.BGP.Paths[1] =
		reader.state.BGP.Paths[1], reader.state.BGP.Paths[0]
	second, _, err := controlPlaneFingerprint(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("live timers/counters prevented an otherwise stable control plane from settling")
	}
	reader.state.BGP.Sessions[0].State = "Active"
	third, _, err := controlPlaneFingerprint(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("a changed BGP session state did not change the convergence fingerprint")
	}
}
