package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestContainerdSpecPreservesHardeningAndResources(t *testing.T) {
	memory := int64(256 << 20)
	spec := &Spec{
		Name: "router", Hostname: "r1",
		Entrypoint: []string{"/bin/sh", "-c"}, Command: []string{"sleep 60"},
		Env:            map[string]string{"B": "override", "C": "three"},
		Capabilities:   []string{"NET_ADMIN", "CAP_NET_RAW"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=default", "apparmor=docker-default"},
		ReadOnlyRootfs: true, CPUs: 1.5, Memory: "256Mi", PidsLimit: 128,
		MaskedPaths: []string{"/proc/kcore"}, ReadonlyPaths: []string{"/proc/sys"},
		Sysctls:     map[string]string{"net.ipv4.ip_forward": "1"},
		Binds:       []Bind{{Source: "/host/config", Target: "/etc/router", ReadOnly: true}},
		Tmpfs:       map[string]string{"/run": "rw,nosuid,nodev"},
		NetworkMode: "container:primary", PidMode: "host",
	}
	out := &specs.Spec{
		Process: &specs.Process{},
		Root:    &specs.Root{},
		Linux: &specs.Linux{Namespaces: []specs.LinuxNamespace{
			{Type: specs.NetworkNamespace}, {Type: specs.PIDNamespace},
		}},
	}
	err := containerdSpecOption(spec, ocispec.ImageConfig{
		Entrypoint: []string{"/image-entry"}, Cmd: []string{"image-command"},
		Env: []string{"A=one", "B=two"},
	}, map[specs.LinuxNamespaceType]string{
		specs.NetworkNamespace: "/proc/42/ns/net",
	}, nil)(context.Background(), nil, &containers.Container{}, out)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Process.Args; len(got) != 3 || got[0] != "/bin/sh" ||
		got[1] != "-c" || got[2] != "sleep 60" {
		t.Fatalf("process args = %v", got)
	}
	if !out.Root.Readonly || !out.Process.NoNewPrivileges ||
		out.Process.ApparmorProfile != "docker-default" || out.Linux.Seccomp == nil {
		t.Fatalf("hardening was not preserved: process=%+v root=%+v linux=%+v",
			out.Process, out.Root, out.Linux)
	}
	if out.Linux.Resources == nil || out.Linux.Resources.Memory == nil ||
		out.Linux.Resources.Memory.Limit == nil || *out.Linux.Resources.Memory.Limit != memory ||
		out.Linux.Resources.Pids == nil || out.Linux.Resources.Pids.Limit == nil ||
		*out.Linux.Resources.Pids.Limit != 128 {
		t.Fatalf("resource limits were not preserved: %+v", out.Linux.Resources)
	}
	var networkPath string
	hasPID := false
	for _, namespace := range out.Linux.Namespaces {
		switch namespace.Type {
		case specs.NetworkNamespace:
			networkPath = namespace.Path
		case specs.PIDNamespace:
			hasPID = true
		}
	}
	if networkPath != "/proc/42/ns/net" || hasPID {
		t.Fatalf("namespace contract = %+v", out.Linux.Namespaces)
	}
	if len(out.Process.Capabilities.Bounding) != 2 ||
		out.Process.Capabilities.Bounding[0] != "CAP_NET_ADMIN" ||
		out.Process.Capabilities.Bounding[1] != "CAP_NET_RAW" {
		t.Fatalf("capabilities = %+v", out.Process.Capabilities)
	}
}

func TestContainerdRejectsUnsafeNamespaceAndUnsupportedPorts(t *testing.T) {
	runtime := NewContainerd()
	if err := runtime.SetRuntimeNamespace("../moby"); err == nil {
		t.Fatal("unsafe containerd namespace was accepted")
	}
	out := &specs.Spec{Process: &specs.Process{}, Root: &specs.Root{}, Linux: &specs.Linux{}}
	err := containerdSpecOption(&Spec{
		Name: "service", Ports: []PortMap{{HostPort: 8080, Container: 80}},
	}, ocispec.ImageConfig{Cmd: []string{"true"}}, nil, nil)(
		context.Background(), nil, &containers.Container{}, out)
	if err == nil {
		t.Fatal("unsupported native containerd port publishing was silently ignored")
	}
	out = &specs.Spec{Process: &specs.Process{}, Root: &specs.Root{}, Linux: &specs.Linux{}}
	err = containerdSpecOption(&Spec{
		Name: "service", Health: &Health{Test: []string{"CMD", "true"}},
	}, ocispec.ImageConfig{Cmd: []string{"true"}}, nil, nil)(
		context.Background(), nil, &containers.Container{}, out)
	if err == nil {
		t.Fatal("unsupported native containerd healthcheck was silently ignored")
	}
}

func TestContainerdExecClassifiesFRRLifecycle(t *testing.T) {
	start := containerdFRRAction(ExecCmd{Cmd: []string{
		"sh", "-c", "/usr/lib/frr/frrinit.sh restart\n/usr/lib/frr/frrinit.sh start",
	}})
	if start != "restart" {
		t.Fatalf("FRR restart classification = %q", start)
	}
	stop := containerdFRRAction(ExecCmd{Cmd: []string{
		"sh", "-c", "/usr/lib/frr/frrinit.sh stop >/dev/null",
	}})
	if stop != "stop" {
		t.Fatalf("FRR stop classification = %q", stop)
	}
	ensure := containerdFRRAction(ExecCmd{Cmd: []string{
		"sh", "-c", "missing() { :; }\n/usr/lib/frr/frrinit.sh start",
	}})
	if ensure != "ensure" {
		t.Fatalf("FRR ensure classification = %q", ensure)
	}
	for _, body := range []string{
		"echo /usr/lib/frr/frrinit.sh stop",
		"printf '%s' '/usr/lib/frr/frrinit.sh start'",
		"# /usr/lib/frr/frrinit.sh restart",
	} {
		if got := containerdFRRAction(ExecCmd{Cmd: []string{"sh", "-c", body}}); got != "" {
			t.Fatalf("non-executed FRR text %q classified as %q", body, got)
		}
	}
}

func TestParseContainerdBatchResultsKeepsOutputsSeparate(t *testing.T) {
	raw := []byte("__TWINET_BATCH__ 2 0 5 3\nfirsterr" +
		"__TWINET_BATCH__ 5 7 6 6\nsecondstderr")
	results, err := parseContainerdBatchResults(raw, []int{2, 5})
	if err != nil {
		t.Fatal(err)
	}
	if got := results[2]; got.ExitCode != 0 || got.Stdout != "first" || got.Stderr != "err" {
		t.Fatalf("first framed result = %+v", got)
	}
	if got := results[5]; got.ExitCode != 7 || got.Stdout != "second" || got.Stderr != "stderr" {
		t.Fatalf("second framed result = %+v", got)
	}
	if _, err := parseContainerdBatchResults(
		[]byte("__TWINET_BATCH__ 2 0 100 0\nshort"), []int{2}); err == nil {
		t.Fatal("truncated framed output was accepted")
	}
}

func TestContainerdListOnlyIgnoresDisappearingObjects(t *testing.T) {
	if !containerdNotFound(errors.New(`task "router" not found`)) {
		t.Fatal("a task removed during a concurrent list was treated as a persistent failure")
	}
	if !containerdAlreadyExists(errors.New(`task "router" already exists`)) {
		t.Fatal("an idempotent task-create race was treated as a persistent failure")
	}
	if containerdNotFound(errors.New("permission denied")) {
		t.Fatal("a persistent containerd error would be hidden as a concurrent removal")
	}
	if containerdAlreadyExists(errors.New("permission denied")) {
		t.Fatal("a persistent task-create error would be hidden as an existing task")
	}
}
