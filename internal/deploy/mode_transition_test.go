package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestSolveToPlatformResetSkipsPreviouslyUngradedHarnessAS(t *testing.T) {
	engine := &Engine{
		ForceStudentReset: true,
		PreviousMode:      "solve",
		PreviousUngraded:  7,
	}
	ungraded := &model.Device{ASN: 7}
	reference := &model.Device{ASN: 8}
	if engine.shouldForceStudentReset(ungraded) {
		t.Fatal("solve->platform reset would erase the previously ungraded harness AS")
	}
	if !engine.shouldForceStudentReset(reference) {
		t.Fatal("solve->platform reset did not clear a previous reference AS")
	}
}

func TestSolveToPlatformResetFailsClosedWhenAddressResetIsRejected(t *testing.T) {
	runtime := &resetRejectingRuntime{}
	engine := &Engine{Runtime: runtime}
	device := &model.Device{
		ID: "as8/R1", Container: "as8-r1",
		Ifaces: []*model.Iface{{Name: "eth0", Owner: model.OwnerStudent}},
	}
	err := engine.resetStudentNetworkState(context.Background(), device)
	if err == nil || !strings.Contains(err.Error(), "reset reference address state") {
		t.Fatalf("rejected reference reset was ignored: %v", err)
	}
	if len(runtime.commands) != 1 || strings.Contains(runtime.commands[0], "|| true") ||
		!strings.Contains(runtime.commands[0], "|| exit") {
		t.Fatalf("reset command did not fail closed: %q", runtime.commands)
	}
}

func TestPlatformToSolveWiringTakesOwnershipOfStudentHostAddress(t *testing.T) {
	host := &model.Device{ID: "as10/SFO_host", ASN: 10, Kind: model.KindHost}
	iface := &model.Iface{
		Name: "host", Owner: model.OwnerStudent, Device: host,
		Addr4: "10.107.0.2/24",
	}
	top := &model.Topology{
		Name: "lab",
		ASes: map[int]*model.AS{10: {ASN: 10, Role: model.RoleStudent}},
	}
	link := &model.Link{}
	platform := &Engine{}
	if got := platform.endpoint(top, iface, "", link); got.OwnAddrs || len(got.Addrs) != 0 {
		t.Fatalf("platform wire unexpectedly owns student address: %+v", got)
	}
	solve := &Engine{Authoritative: true}
	got := solve.endpoint(top, iface, "", link)
	if !got.OwnAddrs || len(got.Addrs) != 1 || got.Addrs[0] != "10.107.0.2/24" {
		t.Fatalf("solve wire did not restore reference host address: %+v", got)
	}
}

type resetRejectingRuntime struct {
	rt.Runtime
	commands []string
}

func (r *resetRejectingRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	r.commands = append(r.commands, strings.Join(cmd.Cmd, " "))
	return rt.ExecResult{ExitCode: 19, Stderr: "interface reset rejected"}, nil
}
