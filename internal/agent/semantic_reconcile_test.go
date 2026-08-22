package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

type semanticObserveRuntime struct {
	semanticRuntime
	spec string
}

func (r *semanticObserveRuntime) Inspect(_ context.Context, _ string) (rt.Container, error) {
	return rt.Container{
		State:  rt.StateRunning,
		Labels: map[string]string{deploy.LabelSpec: r.spec},
	}, nil
}

func TestRecoveredUntouchedHostAddressDriftIsAuditedAsBroken(t *testing.T) {
	top, host := semanticHostTopology(model.OwnerStudent)
	// A real topology link is present after recovery; the interface is not
	// missing, only the address/default route is gone.
	host.Ifaces[0].Link = &model.Link{}
	runtime := &semanticObserveRuntime{spec: deploy.SpecHash(host), semanticRuntime: semanticRuntime{output: map[string]rt.ExecResult{
		"sh\x00-c\x00ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1": {Stdout: "lo\nhost\n"},
		"ip\x00-o\x00addr\x00show":  {Stdout: ""},
		"ip\x00-o\x00route\x00show": {Stdout: ""},
	}}}
	server := &Server{
		cfg:      Config{Node: "node-0"},
		rt:       runtime,
		current:  map[string]*model.Topology{top.Name: top},
		modes:    map[string]string{top.Name: "solve"},
		ungraded: map[string]int{},
	}
	observation := server.observeDevice(context.Background(), top.Name, host, false)
	if observation.Health != healthBroken || !strings.Contains(observation.Reason, "semantic") {
		t.Fatalf("recovered untouched host drift = %+v, want semantic broken", observation)
	}
}
