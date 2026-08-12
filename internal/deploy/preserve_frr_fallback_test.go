package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// FRR being down is not the same as a router with no configuration. vtysh asks
// the running daemons for the configuration, so it fails when they are not
// answering -- but the student's work is /etc/frr/frr.conf, a file that is
// still on disk. Capturing must fall back to that file rather than report the
// router as empty, because the caller destroys the container on that answer and
// the file goes with it.
func TestADeadFRRDaemonFallsBackToTheConfigurationFileOnDisk(t *testing.T) {
	router := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL",
	}
	const onDisk = "frr version 10.0\nrouter bgp 3\n neighbor 3.0.0.2 remote-as 4\n"

	r := &readFailingRuntime{exec: func(cmd []string) (rt.ExecResult, error) {
		switch {
		case cmd[0] == "vtysh":
			return rt.ExecResult{ExitCode: 2, Stderr: "failed to connect to any daemons"}, nil
		case cmd[0] == "cat" && cmd[1] == "/etc/frr/frr.conf":
			return rt.ExecResult{Stdout: onDisk}, nil
		default:
			// Tunnels and addresses read cleanly (and empty), so the only
			// configuration in play is the one recovered from disk.
			return rt.ExecResult{Stdout: ""}, nil
		}
	}}

	snaps, err := Capture(context.Background(), r, router, "cos461", "abc123")
	if err != nil {
		t.Fatalf("capture refused a router whose configuration was readable from disk: %v", err)
	}
	var frr *state.Snapshot
	for i := range snaps {
		if snaps[i].Kind == state.KindFRR {
			frr = &snaps[i]
		}
	}
	if frr == nil {
		t.Fatal("the student's routing configuration was not recovered from /etc/frr/frr.conf " +
			"when the daemons were down; the replacement would delete it")
	}
	if !strings.Contains(string(frr.Content), "router bgp 3") ||
		!strings.Contains(string(frr.Content), "neighbor 3.0.0.2 remote-as 4") {
		t.Errorf("the configuration recovered from disk is not the student's:\n%s", frr.Content)
	}
}

// When the daemons are down and the file cannot be read either, the
// configuration is genuinely unreachable. Capture must fail so the caller
// refuses the replacement, because proceeding would destroy a configuration
// that could not be shown to be gone -- silent loss of a term's work.
func TestADeadFRRDaemonAndAnUnreadableFileRefusesTheReplacement(t *testing.T) {
	router := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL",
	}
	r := &readFailingRuntime{exec: func(cmd []string) (rt.ExecResult, error) {
		switch {
		case cmd[0] == "vtysh":
			return rt.ExecResult{ExitCode: 2, Stderr: "failed to connect to any daemons"}, nil
		case cmd[0] == "cat" && cmd[1] == "/etc/frr/frr.conf":
			return rt.ExecResult{ExitCode: 1, Stderr: "cat: /etc/frr/frr.conf: No such file or directory"}, nil
		default:
			return rt.ExecResult{Stdout: ""}, nil
		}
	}}

	_, err := Capture(context.Background(), r, router, "cos461", "abc123")
	if err == nil {
		t.Fatal("capture reported success when neither FRR nor /etc/frr/frr.conf could be read.\n" +
			"The caller destroys the container on that answer, so a configuration that could " +
			"not be shown to be gone would be deleted with the deployment reporting success.")
	}
	if !strings.Contains(err.Error(), "could not be read") ||
		!strings.Contains(err.Error(), "as3/ATL") {
		t.Fatalf("the refusal does not name the device and what failed: %v", err)
	}
}
