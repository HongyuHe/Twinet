package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// studentTopology builds a one-AS student lab out of the given devices, enough
// for saveAS to run against.
func studentTopology(devices ...*model.Device) *model.Topology {
	return &model.Topology{
		Name: "cos461",
		Hash: "abc123",
		ASes: map[int]*model.AS{
			3: {ASN: 3, Role: model.RoleStudent, OwnerGroup: "group3", Devices: devices},
		},
	}
}

// saveAS collected each device with a helper that returned "" both when the
// device genuinely had nothing to capture and when the read of it failed. The
// caller could not tell the two apart, so a failed read of a host, a switch or
// a router's shell state was dropped -- and as long as the router's .conf came
// back, the save signed and reported success on an archive missing the
// student's work. A save that could not read a device must fail loudly instead.
func TestASaveThatCouldNotReadADeviceIsNotSigned(t *testing.T) {
	t.Setenv("TWINET_PKI", t.TempDir())
	key, err := submissionKey()
	if err != nil {
		t.Fatal(err)
	}

	router := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3}

	// healthy reads the router's configuration and answers every other read as
	// empty-but-successful. A save over this alone succeeds; each case below
	// breaks exactly one read, and the whole save must then refuse.
	healthy := func(_ context.Context, _ string, cmd []string) (execResult, error) {
		if len(cmd) > 0 && cmd[0] == "vtysh" {
			return execResult{Stdout: "Building configuration...\n\nrouter bgp 3\n"}, nil
		}
		return execResult{Stdout: ""}, nil
	}

	cases := []struct {
		what    string
		device  string
		devices []*model.Device
		exec    func(context.Context, string, []string) (execResult, error)
	}{
		{
			what:    "a host whose shell state could not be read",
			device:  "as3/h1",
			devices: []*model.Device{router, {ID: "as3/h1", Name: "h1", Kind: model.KindHost, ASN: 3}},
			exec: func(ctx context.Context, id string, cmd []string) (execResult, error) {
				if id == "as3/h1" {
					return execResult{}, errors.New("container is restarting")
				}
				return healthy(ctx, id, cmd)
			},
		},
		{
			what:    "a switch whose ports could not be read",
			device:  "as3/S1",
			devices: []*model.Device{router, {ID: "as3/S1", Name: "S1", Kind: model.KindSwitch, ASN: 3}},
			exec: func(ctx context.Context, id string, cmd []string) (execResult, error) {
				if id == "as3/S1" {
					return execResult{ExitCode: 1, Stderr: "ovs-vsctl: cannot connect to server"}, nil
				}
				return healthy(ctx, id, cmd)
			},
		},
		{
			what:    "a router whose shell state could not be read",
			device:  "as3/ATL",
			devices: []*model.Device{router},
			exec: func(_ context.Context, _ string, cmd []string) (execResult, error) {
				if len(cmd) > 0 && cmd[0] == "vtysh" {
					return execResult{Stdout: "Building configuration...\n\nrouter bgp 3\n"}, nil
				}
				return execResult{ExitCode: 1, Stderr: "device or resource busy"}, nil
			},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			outDir := t.TempDir()
			top := studentTopology(c.devices...)
			_, err := saveAS(context.Background(), top, 3, outDir, c.exec, key)
			if err == nil {
				t.Fatalf("save succeeded while %s.\n"+
					"The router's .conf was read, which used to be enough to declare the "+
					"whole save a success -- so it checksummed and signed an archive "+
					"missing the student's work.", c.what)
			}
			if !strings.Contains(err.Error(), c.device) {
				t.Errorf("the failure does not name the device that could not be read: %v", err)
			}
			if !strings.Contains(err.Error(), "could not be read") {
				t.Errorf("the failure does not say what went wrong: %v", err)
			}
			// Nothing may reach disk: an archive left behind is one a later
			// step could pick up and grade as the student's submission.
			if _, statErr := os.Stat(filepath.Join(outDir, "group3.tar.gz")); !os.IsNotExist(statErr) {
				t.Errorf("an archive was written for a save that failed (stat err: %v)", statErr)
			}
		})
	}
}

// The refusal above must not become "refuse whenever a capture is empty", or it
// would fail every honest save of a device the student has not touched. An
// empty read is a successful read, and the archive is still produced and signed.
func TestASaveWithEmptyButReadableDevicesIsStillSigned(t *testing.T) {
	t.Setenv("TWINET_PKI", t.TempDir())
	key, err := submissionKey()
	if err != nil {
		t.Fatal(err)
	}

	top := studentTopology(
		&model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3},
		&model.Device{ID: "as3/h1", Name: "h1", Kind: model.KindHost, ASN: 3},
	)
	exec := func(_ context.Context, _ string, cmd []string) (execResult, error) {
		if len(cmd) > 0 && cmd[0] == "vtysh" {
			return execResult{Stdout: "Building configuration...\n\nrouter bgp 3\n neighbor 3.0.0.2 remote-as 4\n"}, nil
		}
		return execResult{Stdout: ""}, nil // read fine, nothing extra configured
	}

	outDir := t.TempDir()
	p, err := saveAS(context.Background(), top, 3, outDir, exec, key)
	if err != nil {
		t.Fatalf("a save of readable devices with empty captures failed: %v", err)
	}
	b, files, err := readBundle(p)
	if err != nil {
		t.Fatalf("the produced archive did not read back as a valid signed submission: %v", err)
	}
	if b.Group != "group3" || b.AS != 3 {
		t.Errorf("the manifest identity is wrong: group=%q as=%d", b.Group, b.AS)
	}
	if _, ok := files["ATL.conf"]; !ok {
		t.Errorf("the router's configuration is missing from the signed archive")
	}
}
