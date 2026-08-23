package nos

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

type nosExecutor struct {
	birdConfig string
}

func (e nosExecutor) Exec(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
	joined := strings.Join(command, " ")
	switch joined {
	case "vtysh -c show ip bgp summary json":
		return runtime.ExecResult{Stdout: `{"ipv4Unicast":{"peers":{"192.0.2.2":{"remoteAs":2,"state":"Established","pfxRcd":3,"pfxSnt":4,"msgRcvd":5,"msgSent":6}}}}`}, nil
	case "birdc -r -s /run/bird.ctl show protocols all":
		return runtime.ExecResult{Stdout: "peer1 BGP --- up\n  Neighbor address: 192.0.2.2\n  Neighbor AS: 2\n"}, nil
	case "cat /etc/bird/bird.conf":
		return runtime.ExecResult{Stdout: e.birdConfig}, nil
	default:
		return runtime.ExecResult{ExitCode: 1, Stderr: "unexpected command " + joined}, nil
	}
}

func TestRegistryDeclaresFRRAndBIRD(t *testing.T) {
	for _, name := range []string{"frr", "bird"} {
		provider, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s is not registered: %v", name, Names())
		}
		if !provider.Capabilities().Supports(FeatureBGP) {
			t.Fatalf("%s does not declare BGP", name)
		}
	}
	bird, _ := Lookup("bird")
	if bird.Capabilities().Supports(FeatureMPLS) || bird.Capabilities().Supports(FeatureLDP) {
		t.Fatal("BIRD incorrectly declares unsupported MPLS/LDP")
	}
}

func TestCapabilityErrorNamesDeviceNOSAndFeature(t *testing.T) {
	bird, _ := Lookup("bird")
	err := FeatureSet(bird, "as10/ALL", []Feature{FeatureMPLS})
	if err == nil {
		t.Fatal("BIRD accepted MPLS")
	}
	message := err.Error()
	for _, want := range []string{"as10/ALL", "bird", "mpls"} {
		if !strings.Contains(message, want) {
			t.Fatalf("%q does not name %q", message, want)
		}
	}
}

func TestFRRAndBIRDNormalizeSessionState(t *testing.T) {
	frr, _ := Lookup("frr")
	bird, _ := Lookup("bird")
	executor := nosExecutor{}
	frrState, err := frr.ReadState(context.Background(),
		&model.Device{ID: "as1/R", Kind: model.KindRouter}, executor, netstate.QueryBGPSessions)
	if err != nil {
		t.Fatal(err)
	}
	birdState, err := bird.ReadState(context.Background(),
		&model.Device{ID: "as2/R", Kind: model.KindRouter, NOS: "bird"}, executor, netstate.QueryBGPSessions)
	if err != nil {
		t.Fatal(err)
	}
	if len(frrState.BGP.Sessions) != 1 || len(birdState.BGP.Sessions) != 1 {
		t.Fatalf("normalized sessions: FRR=%#v BIRD=%#v", frrState.BGP, birdState.BGP)
	}
	left, right := frrState.BGP.Sessions[0], birdState.BGP.Sessions[0]
	if left.Neighbor != right.Neighbor || left.RemoteAS != right.RemoteAS || left.State != right.State {
		t.Fatalf("BGP state differs: FRR=%#v BIRD=%#v", left, right)
	}
}

func TestProvidersRenderTheirOwnConfigurationPaths(t *testing.T) {
	device := &model.Device{ID: "as1/R", Kind: model.KindRouter}
	cases := []struct {
		name, path string
		request    RenderRequest
	}{
		{
			name: "frr", path: frrConfigPath,
			request: RenderRequest{Device: device, Platform: "router bgp 1\n", Daemons: "bgpd=yes\n"},
		},
		{
			name: "bird", path: birdConfigPath,
			request: RenderRequest{Device: device, Platform: "router id 192.0.2.1;\n"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			provider, _ := Lookup(test.name)
			rendered, err := provider.Render(test.request)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := rendered.Files[test.path]; !ok {
				t.Fatalf("%s rendered files %v, missing %s", test.name, rendered.Files, test.path)
			}
		})
	}
}

type restoreRuntime struct {
	runtime.Runtime
	copiedPath string
	copiedBody []byte
	command    []string
}

func (r *restoreRuntime) CopyTo(_ context.Context, _ string, path string, _ int64, body []byte) error {
	r.copiedPath, r.copiedBody = path, append([]byte(nil), body...)
	return nil
}

func (r *restoreRuntime) Exec(_ context.Context, _ string, command runtime.ExecCmd) (runtime.ExecResult, error) {
	r.command = append([]string(nil), command.Cmd...)
	return runtime.ExecResult{}, nil
}

func TestBIRDSaveRestoreUsesOwnSnapshotKind(t *testing.T) {
	provider, _ := Lookup("bird")
	device := &model.Device{ID: "as1/R", Kind: model.KindRouter, NOS: "bird", Container: "bird-r"}
	snapshots, err := provider.Save(context.Background(), device,
		nosExecutor{birdConfig: "router id 192.0.2.1;\nprotocol device {}\n"}, "lab", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || snapshots[0].Kind != state.KindBIRD {
		t.Fatalf("snapshots = %#v, want one BIRD snapshot", snapshots)
	}
	rt := &restoreRuntime{}
	if err := provider.Restore(context.Background(), device, rt, snapshots[0]); err != nil {
		t.Fatal(err)
	}
	if rt.copiedPath != birdRestorePath || !strings.Contains(string(rt.copiedBody), "router id") {
		t.Fatalf("restore copied %q %q", rt.copiedPath, rt.copiedBody)
	}
	if strings.Join(rt.command, " ") == "" || !strings.Contains(strings.Join(rt.command, " "), "birdc") {
		t.Fatalf("restore did not reload BIRD: %v", rt.command)
	}
}
