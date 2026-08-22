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

type capturedStateRuntime struct {
	rt.Runtime
	output string
}

func (capturedStateRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (r capturedStateRuntime) Exec(context.Context, string, rt.ExecCmd) (rt.ExecResult, error) {
	return rt.ExecResult{Stdout: r.output}, nil
}

func TestSemanticRestoreRejectsMissingDynamicState(t *testing.T) {
	device := &model.Device{
		ID: "as5/MSP_host", Name: "MSP_host", Container: "twinet-lab-as5-msp-host",
		Kind: model.KindHost, ASN: 5,
	}
	_, err := verifyRestoredState(context.Background(), emptyStateRuntime{}, device, "lab", "topology",
		[]state.Snapshot{{
			Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
			Content: []byte("2: host inet 10.5.0.2/24 scope global host\n---\ndefault via 10.5.0.1 dev host\n"),
		}})
	if err == nil || !strings.Contains(err.Error(), "dynamic facts differ") {
		t.Fatalf("missing dynamic host state passed restore verification: %v", err)
	}
}

func TestSemanticRestoreUsesCanonicalDynamicFacts(t *testing.T) {
	device := &model.Device{
		ID: "as10/SFO_host", Name: "SFO_host", Container: "twinet-lab-as10-sfo-host",
		Kind: model.KindHost, ASN: 10,
	}
	expected := state.Snapshot{
		Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
		Content: []byte("2: host inet 10.107.0.2/24 scope global host\n---\n" +
			"default via 10.107.0.1 dev host proto static src 10.107.0.2\n---\n"),
	}
	noisyEquivalent := "27: host@if29 inet 10.107.0.2/24 brd 10.107.0.255 scope global dynamic host " +
		"valid_lft 86399sec preferred_lft 86399sec\n1: lo inet 127.0.0.1/8 scope host lo\n---\n" +
		"default via 10.107.0.1 dev host proto dhcp src 10.107.0.2\n---\n"
	verified, err := verifyRestoredState(context.Background(),
		capturedStateRuntime{output: noisyEquivalent}, device, "lab", "topology", []state.Snapshot{expected})
	if err != nil || strings.Join(verified, ",") != "addrs" {
		t.Fatalf("semantically exact dynamic restore rejected: verified=%v err=%v", verified, err)
	}

	extraAddress := strings.Replace(noisyEquivalent, "1: lo", "28: host inet 10.107.0.99/24 scope global host\n1: lo", 1)
	_, err = verifyRestoredState(context.Background(),
		capturedStateRuntime{output: extraAddress}, device, "lab", "topology", []state.Snapshot{expected})
	if err == nil || !strings.Contains(err.Error(), "dynamic facts differ") {
		t.Fatalf("extra dynamic state passed verification: %v", err)
	}
}
