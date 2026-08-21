package deploy

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

type hardeningRuntime struct{ runtime.Runtime }

func (hardeningRuntime) Name() string { return "docker" }

func TestEveryDeviceSpecUsesTheLeastPrivilegeProfile(t *testing.T) {
	device := &model.Device{
		ID: "as1/R1", Kind: model.KindRouter, Image: "router",
		Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		Requests: model.ResourceRequest{
			CPUs: 0.5, Memory: "256Mi", Pids: 64, EphemeralStorage: "256Mi",
			FileDescriptors: 1024, NetDevices: 10,
		},
	}
	spec, err := (&Engine{Runtime: hardeningRuntime{}}).hardenedRuntimeSpec(device, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.NetworkMode != "none" || !spec.ReadOnlyRootfs ||
		!containsString(spec.CapDrop, "ALL") || containsString(spec.Capabilities, "SYS_ADMIN") ||
		!containsString(spec.Capabilities, "NET_BIND_SERVICE") {
		t.Fatalf("router hardening = %#v", spec)
	}
	for _, option := range []string{"no-new-privileges", "seccomp=default", "apparmor=docker-default"} {
		if !containsString(spec.SecurityOpt, option) {
			t.Errorf("missing security option %q in %#v", option, spec.SecurityOpt)
		}
	}
	for _, path := range []string{"/tmp", "/run", "/proc/kcore", "/proc/sys"} {
		if _, writable := spec.Tmpfs[path]; path == "/tmp" && !writable {
			t.Errorf("writable scratch path %s is absent", path)
		}
	}
	if len(spec.MaskedPaths) == 0 || len(spec.ReadonlyPaths) == 0 {
		t.Fatalf("sensitive OCI path restrictions were not mapped: %#v", spec)
	}
	if spec.PidMode != "private" {
		t.Fatalf("default hardening PID mode = %q, want private model policy", spec.PidMode)
	}
	if dockerPIDMode, err := runtime.NormalizePIDMode(spec.PidMode); err != nil || dockerPIDMode != "" {
		t.Fatalf("private model policy did not map to Docker's empty default: %q, %v", dockerPIDMode, err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestHardeningRejectsHostEscapeAndHashesPolicy(t *testing.T) {
	device := &model.Device{
		ID: "as1/R1", Kind: model.KindRouter, Image: "router",
		Capabilities: []string{"NET_ADMIN", "NET_RAW"},
		Requests:     model.DefaultResourceRequest(model.KindRouter),
	}
	before := SpecHash(device)
	device.Hardening.RuntimeClass = "sandboxed"
	if SpecHash(device) == before {
		t.Fatal("runtime hardening selection did not change the container spec hash")
	}
	device.Binds = []string{"/var/run/docker.sock:/var/run/docker.sock"}
	if _, err := (&Engine{Runtime: hardeningRuntime{}}).hardenedRuntimeSpec(device, nil); err == nil ||
		!strings.Contains(err.Error(), "sensitive host path") {
		t.Fatalf("Docker socket bind = %v, want refusal", err)
	}
	device.Binds = nil
	device.Capabilities = append(device.Capabilities, "SYS_ADMIN")
	if _, err := (&Engine{Runtime: hardeningRuntime{}}).hardenedRuntimeSpec(device, nil); err == nil ||
		!strings.Contains(err.Error(), "SYS_ADMIN") {
		t.Fatalf("SYS_ADMIN device capability = %v, want refusal", err)
	}
}
