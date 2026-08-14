package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// Capture is called immediately before a container is destroyed, and the caller
// decides whether to go ahead based on what it returns. So "I read nothing" and
// "I could not read" have to be different answers.
//
// They were the same answer. Every read was guarded by `err == nil &&
// res.ExitCode == 0`, and a failure simply left the snapshot out. A device
// whose configuration could not be read looked exactly like a device that had
// none, and the caller -- being told there was nothing to preserve -- destroyed
// it. An image change, a container under load, a busy vtysh: any of those, and
// a term's work is gone with the deployment reporting success.
func TestCaptureSaysSoWhenItCouldNotRead(t *testing.T) {
	router := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL",
	}

	cases := []struct {
		what string
		why  string
		exec func(cmd []string) (rt.ExecResult, error)
	}{
		{
			what: "the exec never ran",
			why:  "a container that cannot be entered has not been shown to be empty",
			exec: func([]string) (rt.ExecResult, error) {
				return rt.ExecResult{}, errors.New("container is restarting")
			},
		},
		{
			what: "vtysh failed",
			why:  "FRR being unreachable says nothing about whether it holds configuration",
			exec: func(cmd []string) (rt.ExecResult, error) {
				if cmd[0] == "vtysh" {
					return rt.ExecResult{ExitCode: 1, Stderr: "cannot connect to zebra"}, nil
				}
				return rt.ExecResult{Stdout: "1: lo\n"}, nil
			},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			r := &readFailingRuntime{exec: c.exec}
			_, err := Capture(context.Background(), r, router, "cos461", "abc123")
			if err == nil {
				t.Fatalf("capture reported success when %s.\n%s.\n"+
					"The caller destroys the container on the strength of this answer, "+
					"so a failed read is indistinguishable from a device with nothing "+
					"to preserve -- and the work is deleted with the deployment "+
					"reporting success.", c.what, c.why)
			}
			if !strings.Contains(err.Error(), "could not be read") {
				t.Fatalf("failed for the wrong reason: %v", err)
			}
		})
	}
}

// And it must not complain about a device it read perfectly well, or the
// refusal above becomes noise that gets switched off.
func TestCaptureIsQuietWhenItCouldRead(t *testing.T) {
	router := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL",
	}
	r := &readFailingRuntime{exec: func(cmd []string) (rt.ExecResult, error) {
		if cmd[0] == "vtysh" {
			return rt.ExecResult{Stdout: "Building configuration...\n\nrouter bgp 3\n"}, nil
		}
		return rt.ExecResult{Stdout: "1: lo inet 127.0.0.1/8\n"}, nil
	}}
	snaps, err := Capture(context.Background(), r, router, "cos461", "abc123")
	if err != nil {
		t.Fatalf("capture of a healthy router failed: %v", err)
	}
	if len(snaps) == 0 {
		t.Fatal("capture of a healthy router produced nothing")
	}
	for _, s := range snaps {
		if strings.Contains(string(s.Content), "Building configuration") {
			t.Error("the vtysh preamble was captured; replaying it fails on the first line")
		}
	}
}

// readFailingRuntime implements only what Capture uses. The embedded interface
// is nil, so a call to anything else panics loudly rather than passing silently
// -- which is the point: this must stop being a valid double the moment Capture
// starts doing something else.
type readFailingRuntime struct {
	rt.Runtime
	exec func(cmd []string) (rt.ExecResult, error)
}

func (f *readFailingRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: rt.StateRunning}, nil
}

func (f *readFailingRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	return f.exec(cmd.Cmd)
}

// A stopped container is not an empty one.
//
// Capture returned (nil, nil) for any container that was not joinable, and the
// caller that asks before destroying one reads that as "there is nothing to
// preserve". A stopped container still holds the student's work: the
// configuration is a file on its filesystem, not something the daemons keep in
// memory. So the device most likely to be replaced -- the one that had crashed
// -- was the one whose term of work was silently deleted.
func TestCaptureRefusesToCallAStoppedContainerEmpty(t *testing.T) {
	router := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "twinet_as3_ATL",
	}
	r := &stateRuntime{state: rt.StateExited}
	snaps, err := Capture(context.Background(), r, router, "cos461", "abc123")
	if err == nil {
		t.Fatalf("capture of a stopped container reported success with %d snapshots, so the "+
			"caller destroys it believing there was nothing inside", len(snaps))
	}
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("failed for the wrong reason: %v", err)
	}

	// And a container that is genuinely absent really does hold nothing, or
	// creating a device for the first time would refuse.
	absent := &stateRuntime{state: rt.StateAbsent}
	if snaps, err := Capture(context.Background(), absent, router, "cos461", "abc123"); err != nil || len(snaps) != 0 {
		t.Fatalf("capture of an absent container: %d snapshots, err %v", len(snaps), err)
	}
}

type stateRuntime struct {
	rt.Runtime
	state rt.State
}

func (f *stateRuntime) Inspect(context.Context, string) (rt.Container, error) {
	return rt.Container{State: f.state}, nil
}
