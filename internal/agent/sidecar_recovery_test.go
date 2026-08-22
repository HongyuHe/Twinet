package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type sidecarDaemonRuntime struct {
	rt.Runtime
	primary      string
	control      string
	primaryCount int
	controlCount int
	calls        []string
}

func (r *sidecarDaemonRuntime) Name() string { return "docker" }
func (r *sidecarDaemonRuntime) Inspect(_ context.Context, name string) (rt.Container, error) {
	if name == r.control {
		return rt.Container{Name: name, State: rt.StateRunning,
			Labels: map[string]string{deploy.LabelFRRControl: "true", deploy.LabelInternal: "true"}}, nil
	}
	return rt.Container{Name: name, State: rt.StateRunning}, nil
}
func (r *sidecarDaemonRuntime) Exec(_ context.Context, container string, command rt.ExecCmd) (rt.ExecResult, error) {
	body := strings.Join(command.Cmd, " ")
	r.calls = append(r.calls, container+"|"+body)
	switch {
	case container == r.primary && strings.Contains(body, "find_frr"):
		r.primaryCount = 0
		return rt.ExecResult{}, nil
	case container == r.primary && strings.Contains(body, "ps -eo args"):
		return rt.ExecResult{Stdout: strconv.Itoa(r.primaryCount) + "\n"}, nil
	case container == r.control && strings.Contains(body, "__TWINET_DAEMON__"):
		var out strings.Builder
		for _, daemon := range render.EnabledDaemons() {
			fmt.Fprintf(&out, "__TWINET_DAEMON__%s\t%d\n", daemon, r.controlCount)
		}
		return rt.ExecResult{Stdout: out.String()}, nil
	case container == r.control && strings.Contains(body, "find_frr"):
		r.controlCount = 0
		return rt.ExecResult{}, nil
	case container == r.control && strings.Contains(body, "wc -l"):
		return rt.ExecResult{Stdout: strconv.Itoa(r.controlCount) + "\n"}, nil
	case container == r.control && strings.Contains(body, "frrinit.sh start"):
		r.controlCount = 1
		return rt.ExecResult{}, nil
	case container == r.control && len(command.Cmd) >= 3 && command.Cmd[0] == "vtysh":
		return rt.ExecResult{}, nil
	case container == r.control && strings.Contains(body, "pidof"):
		return rt.ExecResult{Stdout: "\n"}, nil
	}
	return rt.ExecResult{}, nil
}

func sidecarRouter() *model.Device {
	return &model.Device{ID: "as7/BOS", Name: "BOS", Kind: model.KindRouter,
		Container: "twinet-lab-as7-bos", ASN: 7}
}

func TestLegacyPrimaryFRRDaemonsAreRemovedBeforeSidecarControl(t *testing.T) {
	router := sidecarRouter()
	runtime := &sidecarDaemonRuntime{
		primary: router.Container, control: deploy.FRRControlContainer(router), primaryCount: 3,
	}
	server := &Server{rt: runtime}
	if count, err := server.primaryFRRDaemonCount(context.Background(), router); err != nil || count != 3 {
		t.Fatalf("primary daemon count = %d, %v", count, err)
	}
	if err := server.stopPrimaryFRRDaemons(context.Background(), router); err != nil {
		t.Fatalf("migrating primary daemon set: %v", err)
	}
	if count, err := server.primaryFRRDaemonCount(context.Background(), router); err != nil || count != 0 {
		t.Fatalf("primary daemon set remained after migration: count=%d err=%v", count, err)
	}
}

func TestDuplicateSidecarDaemonsRemainRecoveryFailure(t *testing.T) {
	router := sidecarRouter()
	runtime := &sidecarDaemonRuntime{
		primary: router.Container, control: deploy.FRRControlContainer(router), controlCount: 2,
	}
	server := &Server{rt: runtime}
	as := &model.AS{ASN: 7}
	if dup, err := server.duplicateDaemonsResult(context.Background(), router, as); err != nil || dup == "" {
		t.Fatalf("duplicate sidecar daemons were accepted: dup=%q err=%v", dup, err)
	}
	// The cleanup path targets the primary only for legacy migration; daemon
	// restart commands execute in the control namespace, never the shell.
	if err := server.startDaemons(context.Background(), "lab", router); err != nil {
		t.Fatalf("restart control daemon set: %v", err)
	}
	if runtime.controlCount != 1 {
		t.Fatalf("sidecar daemon count after repair = %d, want one", runtime.controlCount)
	}
	stopAt, startAt, countAt, vtyAt := -1, -1, -1, -1
	for _, call := range runtime.calls {
		if strings.Contains(call, "frrinit.sh start") && !strings.HasPrefix(call, runtime.control+"|") {
			t.Fatalf("FRR was started in primary container: %s", call)
		}
	}
	for index, call := range runtime.calls {
		switch {
		case strings.HasPrefix(call, runtime.control+"|") && strings.Contains(call, "find_frr"):
			stopAt = index
		case strings.HasPrefix(call, runtime.control+"|") && strings.Contains(call, "frrinit.sh start"):
			startAt = index
		case strings.HasPrefix(call, runtime.control+"|") && strings.Contains(call, "__TWINET_DAEMON__"):
			countAt = index
		case strings.HasPrefix(call, runtime.control+"|vtysh -c show version"):
			vtyAt = index
		}
	}
	if stopAt < 0 || startAt < 0 || stopAt >= startAt {
		t.Fatalf("control repair did not prove zero daemons before start: calls=%v", runtime.calls)
	}
	if countAt < startAt || vtyAt < countAt {
		t.Fatalf("control repair did not verify exact daemon count and vty socket: calls=%v", runtime.calls)
	}
	_ = render.EnabledDaemons // keep the test coupled to the daemon contract
}

func TestControlAuditReportsDuplicateReason(t *testing.T) {
	router := sidecarRouter()
	router.Node = "node-0"
	top := &model.Topology{
		Name: "lab", Devices: map[string]*model.Device{router.ID: router},
		ASes: map[int]*model.AS{router.ASN: {ASN: router.ASN, Devices: []*model.Device{router}}},
	}
	runtime := &sidecarDaemonRuntime{
		primary: router.Container, control: deploy.FRRControlContainer(router), controlCount: 2,
	}
	server := &Server{
		cfg: Config{Node: "node-0"}, rt: runtime,
		current: map[string]*model.Topology{top.Name: top},
	}
	audit := server.auditControls(context.Background(), top.Name)
	if len(audit) != 1 || audit[0].Healthy || !strings.Contains(audit[0].Reason, "want exactly one") {
		t.Fatalf("duplicate control audit = %+v", audit)
	}
	runtime.controlCount = 1
	audit = server.auditControls(context.Background(), top.Name)
	if len(audit) != 1 || !audit[0].Healthy || !audit[0].VTY {
		t.Fatalf("healthy control audit = %+v", audit)
	}
}
