package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// policy.traffic_engineering end to end against the lab this course ships:
// an FRR submission whose two providers are the staff-operated BIRD transits.
//
// The check is unchanged -- the same four things are asked of the same
// submission -- but not one of the questions may be put to a BIRD router in
// FRR's language. The inbound half asks the slow provider whether the
// announcement sent to it survived, and it used to ask with `vtysh`. On a
// BIRD image that binary does not exist, the exec fails as a transport error,
// a transport error is a fault of the grading machinery, and the reference
// solution came back quarantined instead of marked full.
func TestTrafficEngineeringGradesAnFRRSubmissionWithBIRDProviders(t *testing.T) {
	env, log := mixedNOSTrafficEngineeringEnv(map[string]string{"3.0.0.0/8": "3 3 3"})
	result := checkTrafficEngineering(context.Background(), env)
	if result.Status != StatusPass {
		t.Fatalf("the reference answer did not pass: %s %s\n%s",
			result.Status, result.Evidence.Observed, result.Evidence.Detail)
	}
	for _, device := range []string{"as1/ALL", "as2/ALL"} {
		assertNoFRRCommands(t, log, device)
	}
	// And the BIRD provider really was consulted: a check that silently asked
	// nobody anything would also issue no FRR command.
	asked := false
	for _, command := range log.forDevice("as1/ALL") {
		if strings.Contains(strings.Join(command, " "), "show route") {
			asked = true
		}
	}
	if !asked {
		t.Fatalf("the slow BIRD provider was never asked for its table: %v", log.forDevice("as1/ALL"))
	}
}

// The other half of the same guarantee: a BIRD neighbour whose table shows
// nothing learnt from us must still be assessed as such, rather than excused
// because the grader could not read it. Prepending the neighbour's own number
// is the mistake the question is about, and it is invisible from this side.
func TestTrafficEngineeringSeesABIRDNeighbourDiscardOurAnnouncement(t *testing.T) {
	// AS 1 holds 3.0.0.0/8 only through AS 2, so nothing we sent survived.
	env, _ := mixedNOSTrafficEngineeringEnv(map[string]string{"3.0.0.0/8": "2 3"})
	result := checkTrafficEngineering(context.Background(), env)
	if result.Status == StatusPass {
		t.Fatal("an announcement the BIRD neighbour discarded was marked correct")
	}
	if !strings.Contains(result.Evidence.Detail, "holds no route for 3.0.0.0/8 learnt from us") {
		t.Fatalf("the BIRD neighbour's evidence was not reported: %s", result.Evidence.Detail)
	}
}

// The passive survey chooses commands from the provider too. A BIRD router in
// the batched state shell would be just as fatal as one in a check.
func TestTheStateSurveySendsNoFRRCommandToABIRDRouter(t *testing.T) {
	device := &model.Device{ID: "as1/ALL", Name: "ALL", ASN: 1, Kind: model.KindRouter, NOS: "bird"}
	for _, command := range stateCommands(device, netstate.All) {
		line := strings.Join(command, " ")
		for _, word := range frrOnly {
			if strings.Contains(line, word) {
				t.Fatalf("the BIRD survey includes %q", line)
			}
		}
	}
}

// And the survey knows the inbound half needs the neighbour's table, so it is
// collected once through that neighbour's own provider rather than fetched ad
// hoc by the check.
func TestTrafficEngineeringDeclaresTheNeighbourRIBItReads(t *testing.T) {
	env, _ := mixedNOSTrafficEngineeringEnv(map[string]string{"3.0.0.0/8": "3 3 3"})
	plan := buildObservationPlan(&Rubric{Questions: []QuestionSpec{{
		ID: "q", Checks: []CheckSpec{{Check: "policy.traffic_engineering"}},
	}}}, env)
	if got := plan.state["as1/ALL"]; !got.Has(netstate.QueryBGPRIB) {
		t.Fatalf("the slow provider's RIB is not surveyed: %s", got)
	}
}

// mixedNOSTrafficEngineeringEnv builds AS 3 on FRR with a slow provider (AS 1)
// and a fast one (AS 2), both on BIRD, and answers each device in its own
// NOS's language. slowPaths is what the slow provider's table holds.
func mixedNOSTrafficEngineeringEnv(slowPaths map[string]string) (*Env, *commandLog) {
	bird := map[string]map[string]string{
		"as1/ALL": slowPaths,
		"as2/ALL": {"3.0.0.0/8": "3"},
	}
	log := newCommandLog()
	student := &model.Device{ID: "as3/MSP", Name: "MSP", ASN: 3, Kind: model.KindRouter}
	slow := &model.Device{ID: "as1/ALL", Name: "ALL", ASN: 1, Kind: model.KindRouter, NOS: "bird"}
	fast := &model.Device{ID: "as2/ALL", Name: "ALL", ASN: 2, Kind: model.KindRouter, NOS: "bird"}

	link := func(ours *model.Device, ourIface, ourAddr string,
		theirs *model.Device, theirIface, theirAddr, delay, subnet string,
	) *model.Link {
		near := &model.Iface{Device: ours, Name: ourIface, Role: model.RoleInterAS, Addr4: ourAddr}
		far := &model.Iface{Device: theirs, Name: theirIface, Role: model.RoleInterAS, Addr4: theirAddr}
		// Rel is read from A's side, so a customer there is a provider here.
		l := &model.Link{
			A: near, B: far, InterAS: true, Rel: model.RelCustomer, Subnet: subnet,
			Props: model.LinkProps{Delay: delay},
		}
		near.Link, near.Peer = l, far
		far.Link, far.Peer = l, near
		ours.Ifaces = append(ours.Ifaces, near)
		theirs.Ifaces = append(theirs.Ifaces, far)
		return l
	}
	slowLink := link(student, "ext_1_ALL", "179.1.1.1/24", slow, "ext_3_MSP", "179.1.1.2/24",
		"100ms", "179.1.1.0/24")
	fastLink := link(student, "ext_2_ALL", "179.1.2.1/24", fast, "ext_3_MSP", "179.1.2.2/24",
		"10ms", "179.1.2.0/24")

	topology := &model.Topology{
		Name: "mixed-te", Hash: "mixed-te",
		Devices: map[string]*model.Device{student.ID: student, slow.ID: slow, fast.ID: fast},
		Links:   []*model.Link{slowLink, fastLink},
		ASes: map[int]*model.AS{
			1: {ASN: 1, Role: model.RoleStaff, Routers: []*model.Device{slow}, Devices: []*model.Device{slow}},
			2: {ASN: 2, Role: model.RoleStaff, Routers: []*model.Device{fast}, Devices: []*model.Device{fast}},
			3: {ASN: 3, Role: model.RoleStudent, Block: "3.0.0.0/8",
				Routers: []*model.Device{student}, Devices: []*model.Device{student}},
		},
	}
	env := &Env{
		Topology: topology, AS: 3,
		Exec: func(_ context.Context, id string, cmd []string) (rt.ExecResult, error) {
			log.record(id, cmd)
			return mixedNOSReply(bird, id, cmd), nil
		},
	}
	return env, log
}

func mixedNOSReply(bird map[string]map[string]string, device string, cmd []string) rt.ExecResult {
	line := strings.Join(cmd, " ")
	switch {
	case strings.Contains(line, "ip -j address show"):
		return rt.ExecResult{Stdout: "[]"}
	case cmd[0] == "sh":
		// The kernel half of the forwarding question: no policy rules and no
		// route-get answers, which is the honest shape for a fixture that
		// answers the routing daemon instead.
		return rt.ExecResult{Stdout: ""}
	}
	if paths, ok := bird[device]; ok {
		if strings.Contains(line, "show route all") {
			return rt.ExecResult{Stdout: birdRoutesText(paths)}
		}
		return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}
	}
	switch {
	case strings.Contains(line, "show ip bgp json"):
		return rt.ExecResult{Stdout: `{"routes":{
		  "1.0.0.0/8":[{"valid":true,"bestpath":true,"locPrf":100,"path":"1",
		    "peerId":"179.1.1.2","nexthops":[{"ip":"179.1.1.2"}]}],
		  "2.0.0.0/8":[{"valid":true,"bestpath":true,"locPrf":200,"path":"2",
		    "peerId":"179.1.2.2","nexthops":[{"ip":"179.1.2.2"}]}]
		}}`}
	case strings.Contains(line, "show ip route json"):
		return rt.ExecResult{Stdout: `{
		  "2.0.0.0/8":[{"protocol":"bgp","selected":true,
		    "nexthops":[{"ip":"179.1.2.2","fib":true,"interfaceName":"ext_2_ALL"}]}]
		}`}
	case strings.Contains(line, "neighbors 179.1.1.2 advertised-routes json"):
		// Three of our own numbers toward the slow provider.
		return rt.ExecResult{Stdout: `{"advertisedRoutes":{
		  "3.0.0.0/8":{"path":"3 3 3","nextHop":"179.1.1.1"}}}`}
	case strings.Contains(line, "neighbors 179.1.2.2 advertised-routes json"):
		return rt.ExecResult{Stdout: `{"advertisedRoutes":{
		  "3.0.0.0/8":{"path":"3","nextHop":"179.1.2.1"}}}`}
	}
	return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}
}
