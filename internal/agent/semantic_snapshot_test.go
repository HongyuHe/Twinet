package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

type emptyStateRuntime struct{ rt.Runtime }

func (emptyStateRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (emptyStateRuntime) Exec(context.Context, string, rt.ExecCmd) (rt.ExecResult, error) {
	return rt.ExecResult{}, nil
}

func TestSemanticRestoreRejectsMissingDynamicSnapshot(t *testing.T) {
	device := &model.Device{
		ID: "as5/MSP_host", Name: "MSP_host", Container: "twinet-lab-as5-msp-host",
		Kind: model.KindHost, ASN: 5,
	}
	_, err := verifyRestoredState(context.Background(), emptyStateRuntime{}, device, "lab", "topology",
		[]state.Snapshot{{
			Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
			Content: []byte("2: host inet 10.5.0.2/24 scope global host\n---\ndefault via 10.5.0.1 dev host\n"),
		}})
	if err == nil || !strings.Contains(err.Error(), "restored no addrs") {
		t.Fatalf("missing dynamic host snapshot passed restore verification: %v", err)
	}
}
