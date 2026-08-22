package grade

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func batchMarker(t *testing.T, script string) string {
	t.Helper()
	start := strings.Index(script, "__TWINET_OBS_")
	if start < 0 {
		t.Fatalf("no observation marker in %q", script)
	}
	end := strings.Index(script[start:], "_0_RC")
	if end < 0 {
		t.Fatalf("no first observation marker terminator in %q", script)
	}
	return script[start : start+end]
}

func TestObservationBatchUsesOneExecAndSeedsNativeCommandCache(t *testing.T) {
	var calls atomic.Int64
	snapshot := newObservationSnapshot(func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
		calls.Add(1)
		if len(command) != 3 || command[0] != "sh" || command[1] != "-c" {
			t.Fatalf("batch command = %v, want one agent-side shell", command)
		}
		marker := batchMarker(t, command[2])
		return rt.ExecResult{Stdout: strings.Join([]string{
			fmt.Sprintf("%s_0_RC=0", marker), "first", fmt.Sprintf("%s_0_END", marker),
			fmt.Sprintf("%s_1_RC=0", marker), "second", fmt.Sprintf("%s_1_END", marker),
		}, "\n") + "\n"}, nil
	})
	commands := [][]string{{"ip", "-j", "address", "show"}, {"vtysh", "-c", "show ip bgp json"}}
	results, err := snapshot.observationBatch(context.Background(), "test", "as3/R", commands)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Stdout != "first" || results[1].Stdout != "second" {
		t.Fatalf("batch results = %#v", results)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("batch raw exec calls = %d, want 1", got)
	}
	got, err := snapshot.command(context.Background(), "test", "as3/R", commands[1])
	if err != nil || got.Stdout != "second" || calls.Load() != 1 {
		t.Fatalf("native command did not reuse batch cache: result=%#v err=%v calls=%d",
			got, err, calls.Load())
	}
}

func TestStateCommandsBatchKernelAndFRRState(t *testing.T) {
	device := &model.Device{ID: "as3/R", Name: "R", ASN: 3, Kind: model.KindRouter}
	commands := stateCommands(device, netstate.All)
	if len(commands) != 8 {
		t.Fatalf("FRR all-state survey has %d native commands, want 8 batched into one exec: %v",
			len(commands), commands)
	}
}

func TestObservationPlanDoesNotPrefetchUnrelatedASes(t *testing.T) {
	target := &model.Device{ID: "as3/R", Name: "R", ASN: 3, Kind: model.KindRouter}
	neighbor := &model.Device{ID: "as1/P", Name: "P", ASN: 1, Kind: model.KindRouter}
	distant := &model.Device{ID: "as99/X", Name: "X", ASN: 99, Kind: model.KindRouter}
	target.Ifaces = []*model.Iface{{Name: "ext", Device: target, Role: model.RoleInterAS,
		Peer: &model.Iface{Name: "back", Device: neighbor}}}
	topology := &model.Topology{
		Devices: map[string]*model.Device{target.ID: target, neighbor.ID: neighbor, distant.ID: distant},
		ASes: map[int]*model.AS{
			1:  {ASN: 1, Routers: []*model.Device{neighbor}, Devices: []*model.Device{neighbor}},
			3:  {ASN: 3, Routers: []*model.Device{target}, Devices: []*model.Device{target}},
			99: {ASN: 99, Routers: []*model.Device{distant}, Devices: []*model.Device{distant}},
		},
	}
	plan := buildObservationPlan(&Rubric{Questions: []QuestionSpec{{Checks: []CheckSpec{{
		Check: "bgp.ebgp_established",
	}}}}}, &Env{Topology: topology, AS: 3})
	if _, found := plan.state[distant.ID]; found {
		t.Fatalf("snapshot prefetch included unrelated device %s: %#v", distant.ID, plan.state)
	}
	if _, found := plan.state[target.ID]; !found {
		t.Fatalf("snapshot omitted target router: %#v", plan.state)
	}
	if _, found := plan.state[neighbor.ID]; !found {
		t.Fatalf("snapshot omitted direct reference peer: %#v", plan.state)
	}
}
