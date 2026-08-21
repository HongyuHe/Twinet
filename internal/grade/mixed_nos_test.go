package grade

import (
	"context"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// mixedStateReader deliberately serves both an implicit-FRR student router and
// an explicit-BIRD reference router through the same vendor-neutral API.
type mixedStateReader struct{}

func (mixedStateReader) ReadState(_ context.Context, d *model.Device, _ netstate.Executor, query netstate.Query) (netstate.State, error) {
	state := netstate.State{}
	if query.Has(netstate.QueryInterfaces) {
		for _, iface := range d.Ifaces {
			observed := netstate.Interface{Name: iface.Name}
			if iface.Addr4 != "" {
				observed.Addresses = append(observed.Addresses, netstate.Address{Prefix: iface.Addr4, Family: "ipv4"})
			}
			state.Interfaces = append(state.Interfaces, observed)
		}
	}
	if query.Has(netstate.QueryBGPSessions) {
		switch d.ID {
		case "as3/EDGE":
			state.BGP.Sessions = []netstate.BGPSession{{
				Neighbor: "192.0.2.2", RemoteAS: 1, State: "Established",
			}}
		case "as1/ALL":
			state.BGP.Sessions = []netstate.BGPSession{{
				Neighbor: "192.0.2.1", RemoteAS: 3, State: "Established",
			}}
		}
	}
	return state, nil
}

func TestMixedNOSRubricUsesProviderNeutralSessionState(t *testing.T) {
	student := &model.Device{ID: "as3/EDGE", Name: "EDGE", Kind: model.KindRouter, ASN: 3}
	reference := &model.Device{ID: "as1/ALL", Name: "ALL", Kind: model.KindRouter, ASN: 1, NOS: "bird"}
	studentIface := &model.Iface{
		Device: student, Name: "ext_1_ALL", Role: model.RoleInterAS, Addr4: "192.0.2.1/24",
	}
	referenceIface := &model.Iface{
		Device: reference, Name: "ext_3_EDGE", Role: model.RoleInterAS, Addr4: "192.0.2.2/24",
	}
	link := &model.Link{
		A: studentIface, B: referenceIface, InterAS: true, Rel: model.RelProvider, Subnet: "192.0.2.0/24",
	}
	studentIface.Link, studentIface.Peer = link, referenceIface
	referenceIface.Link, referenceIface.Peer = link, studentIface
	student.Ifaces = []*model.Iface{studentIface}
	reference.Ifaces = []*model.Iface{referenceIface}
	topology := &model.Topology{
		Name: "mixed", Hash: "mixed-hash",
		Devices: map[string]*model.Device{student.ID: student, reference.ID: reference},
		Links:   []*model.Link{link},
		ASes: map[int]*model.AS{
			1: {ASN: 1, Role: model.RoleStaff, Routers: []*model.Device{reference}, Devices: []*model.Device{reference}},
			3: {ASN: 3, Role: model.RoleStudent, Routers: []*model.Device{student}, Devices: []*model.Device{student}},
		},
	}
	rubric := &Rubric{
		Metadata: RubricMeta{Name: "mixed"},
		Questions: []QuestionSpec{{
			ID: "bgp", Title: "External BGP", Points: 1,
			Checks: []CheckSpec{{Check: "bgp.ebgp_established"}},
		}},
	}
	report := Run(context.Background(), rubric, &Env{
		Topology: topology, AS: 3, StateReader: mixedStateReader{},
		Exec: func(context.Context, string, []string) (rt.ExecResult, error) {
			return rt.ExecResult{}, nil
		},
	}, RunOptions{CheckTimeout: 12 * time.Second})
	if report.NeedsReview || report.Total != 1 {
		t.Fatalf("mixed NOS rubric report = %#v", report)
	}
}
