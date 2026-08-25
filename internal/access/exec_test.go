package access

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestLocalAttachCLIUsesSelectedRuntime(t *testing.T) {
	args := []string{"exec", "--interactive", "router", "sh"}
	tests := []struct {
		name     string
		runtime  string
		endpoint string
		wantCLI  string
		wantArgs []string
		wantEnv  []string
		wantErr  bool
	}{
		{
			name: "docker endpoint", runtime: "docker",
			endpoint: "unix:///run/docker.sock", wantCLI: "docker",
			wantArgs: args, wantEnv: []string{"DOCKER_HOST=unix:///run/docker.sock"},
		},
		{
			name: "local podman", runtime: "podman",
			wantCLI: "podman", wantArgs: args,
		},
		{
			name: "remote podman", runtime: "podman",
			endpoint: "unix:///run/podman/podman.sock", wantCLI: "podman",
			wantArgs: append([]string{
				"--remote", "--url", "unix:///run/podman/podman.sock",
			}, args...),
		},
		{name: "unsupported", runtime: "unknown", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli, gotArgs, env, err := localAttachCLI(tt.runtime, tt.endpoint, args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if cli != tt.wantCLI || !reflect.DeepEqual(gotArgs, tt.wantArgs) ||
				!reflect.DeepEqual(env, tt.wantEnv) {
				t.Fatalf("plan = (%q, %#v, %#v), want (%q, %#v, %#v)",
					cli, gotArgs, env, tt.wantCLI, tt.wantArgs, tt.wantEnv)
			}
		})
	}
}

type streamRuntime struct {
	rt.Runtime
	gotName string
	gotCmd  rt.ExecCmd
	gotRows uint32
	gotCols uint32
}

func (r *streamRuntime) Name() string { return "containerd" }

func (r *streamRuntime) StreamExec(_ context.Context, name string, cmd rt.ExecCmd,
	rows, cols uint32, stdout, stderr io.Writer,
) (int, error) {
	r.gotName, r.gotCmd, r.gotRows, r.gotCols = name, cmd, rows, cols
	_, _ = io.WriteString(stdout, "out")
	_, _ = io.WriteString(stderr, "err")
	return 7, nil
}

func TestLocalExecStreamsThroughNativeRuntime(t *testing.T) {
	top := twoASTopology()
	device := top.Devices[model.DeviceID(3, "MSP")]
	device.Container = "twinet-router"
	runtime := &streamRuntime{}
	var stdout, stderr bytes.Buffer
	stdin := bytes.NewBufferString("input")

	code, err := (&LocalExec{Topology: top, Runtime: runtime}).Shell(
		context.Background(), string(device.ID), []string{"sh"}, stdin,
		&stdout, &stderr, true, 31, 97)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if runtime.gotName != device.Container ||
		!reflect.DeepEqual(runtime.gotCmd.Cmd, []string{"sh"}) ||
		runtime.gotCmd.Stdin != stdin || !runtime.gotCmd.TTY ||
		runtime.gotRows != 31 || runtime.gotCols != 97 {
		t.Fatalf("stream exec = name %q cmd %#v rows %d cols %d",
			runtime.gotName, runtime.gotCmd, runtime.gotRows, runtime.gotCols)
	}
	wantEnv := map[string]string{
		"LINES": "31", "COLUMNS": "97", "TERM": "xterm-256color",
	}
	if !reflect.DeepEqual(runtime.gotCmd.Env, wantEnv) {
		t.Fatalf("environment = %#v, want %#v", runtime.gotCmd.Env, wantEnv)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("streams = (%q, %q)", stdout.String(), stderr.String())
	}
}
