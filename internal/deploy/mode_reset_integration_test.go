package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestReferenceResetUsesAlpineCompatibleExactDeletes(t *testing.T) {
	device := &model.Device{
		ID: "as7/BOS", Kind: model.KindRouter, L2Gateway: "bos",
		Ifaces: []*model.Iface{
			{Name: "lo", Owner: model.OwnerStudent, Addr4: "7.7.7.7/32", Addr6: "2001:db8:7::7/128"},
			{Name: "veth0", Owner: model.OwnerStudent, Addr4: "10.7.0.2/24"},
			{Name: "vlan10", Owner: model.OwnerStudent, Addr4: "10.7.10.2/24", VLAN: 10},
			{Name: "platform0", Owner: model.OwnerPlatform, Addr4: "192.0.2.2/24"},
		},
	}
	commands := referenceNetworkResetCommands(device)
	joined := strings.Join(commands, "\n")
	for _, forbidden := range []string{"addr flush", "scope global", "platform0"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("reference reset contains %q:\n%s", forbidden, joined)
		}
	}
	for _, want := range []string{
		"ip addr del 7.7.7.7/32 dev lo",
		"ip -6 addr del 2001:db8:7::7/128 dev lo",
		"ip addr del 10.7.0.2/24 dev veth0",
		"ip addr del 10.7.10.2/24 dev vlan10",
		"ip route flush dev veth0",
		"ip -6 route flush dev tun6",
		"ip tunnel del tun6",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("reference reset omitted %q:\n%s", want, joined)
		}
	}

	// Execute each generated command through a small iproute2 contract
	// harness. It accepts only Alpine-valid family-specific addr deletes,
	// route flushes, and tunnel deletes; an invalid flush form exits 2.
	dir, err := os.MkdirTemp(".", ".test-mode-reset-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	log := filepath.Join(dir, "ip.log")
	ip := filepath.Join(dir, "ip")
	script := `#!/bin/sh
echo "$*" >> "$RESET_LOG"
case "$*" in
  "link show dev "*) exit 0 ;;
  "link show tun6") exit 0 ;;
  "-o -4 addr show dev lo") echo "1: lo inet 7.7.7.7/32 scope global lo"; exit 0 ;;
  "-o -6 addr show dev lo") echo "1: lo inet6 2001:db8:7::7/128 scope global"; exit 0 ;;
  "-o -4 addr show dev veth0") echo "2: veth0 inet 10.7.0.2/24 scope global"; exit 0 ;;
  "-o -6 addr show dev veth0") exit 0 ;;
  "-o -4 addr show dev vlan10") echo "3: vlan10 inet 10.7.10.2/24 scope global"; exit 0 ;;
  "-o -6 addr show dev vlan10") exit 0 ;;
  "addr del "*) exit 0 ;;
  "-6 addr del "*) exit 0 ;;
  "route flush dev "*) exit 0 ;;
  "-6 route flush dev "*) exit 0 ;;
  "tunnel del tun6") exit 0 ;;
  *) echo "invalid iproute2 command: $*" >&2; exit 2 ;;
esac
`
	if err := os.WriteFile(ip, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		run := exec.Command("sh", "-c", command)
		run.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "RESET_LOG="+log)
		if output, err := run.CombinedOutput(); err != nil {
			t.Fatalf("generated reset failed Alpine iproute contract:\n%s\n%s", command, output)
		}
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "tunnel del tun6") {
		t.Fatalf("tunnel reset was not executed: %s", got)
	}
}

func TestPlatformRoutingResetUsesProviderLifecycle(t *testing.T) {
	t.Run("BIRD skips FRR lifecycle", func(t *testing.T) {
		runtime := &routingResetRuntime{}
		engine := &Engine{Runtime: runtime}
		device := &model.Device{ID: "as1/ALL", Kind: model.KindRouter, NOS: "bird", Container: "bird"}
		if err := engine.restartPlatformRouting(context.Background(), device); err != nil {
			t.Fatal(err)
		}
		if len(runtime.commands) != 0 {
			t.Fatalf("BIRD reset invoked FRR lifecycle: %v", runtime.commands)
		}
	})
	t.Run("FRR targets control sidecar", func(t *testing.T) {
		runtime := &dockerRoutingResetRuntime{routingResetRuntime: routingResetRuntime{}}
		engine := &Engine{Runtime: runtime}
		device := &model.Device{ID: "as3/ATL", Kind: model.KindRouter, Container: "atl"}
		if err := engine.restartPlatformRouting(context.Background(), device); err != nil {
			t.Fatal(err)
		}
		if len(runtime.commands) != 1 || runtime.containers[0] != FRRControlContainer(device) ||
			!strings.Contains(runtime.commands[0], "frrinit.sh restart") {
			t.Fatalf("FRR reset did not target control sidecar: containers=%v commands=%v",
				runtime.containers, runtime.commands)
		}
	})
}

func TestMixedProviderSolveToPlatformConfiguresEachProvider(t *testing.T) {
	runtime := &dockerRoutingResetRuntime{routingResetRuntime: routingResetRuntime{}}
	frr := &model.Device{
		ID: "as3/ATL", Kind: model.KindRouter, Container: "atl",
		Ifaces: []*model.Iface{{Name: "student0", Owner: model.OwnerStudent, Addr4: "10.3.0.2/24"}},
	}
	bird := &model.Device{ID: "as1/ALL", Kind: model.KindRouter, NOS: "bird", Container: "bird"}
	renderer := transitionResetRenderer{commands: map[string][]Command{
		frr.ID:  {{Args: []string{"sh", "-c", "provider-frr-apply"}, FRRControl: true}},
		bird.ID: {{Args: []string{"sh", "-c", "provider-bird-apply birdc configure"}}},
	}}
	engine := &Engine{
		Runtime: runtime, Renderer: renderer,
		ForceStudentReset: true, PreviousMode: "solve",
	}
	for _, device := range []*model.Device{frr, bird} {
		desired, err := engine.renderDesired(device)
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.configureDesired(context.Background(), device, desired); err != nil {
			t.Fatal(err)
		}
	}
	var birdFRR, birdApply, frrRestart bool
	for i, command := range runtime.commands {
		container := runtime.containers[i]
		switch {
		case container == bird.Container && strings.Contains(command, "frrinit.sh"):
			birdFRR = true
		case container == bird.Container && strings.Contains(command, "provider-bird-apply"):
			birdApply = true
		case container == FRRControlContainer(frr) && strings.Contains(command, "frrinit.sh restart"):
			frrRestart = true
		}
	}
	if birdFRR || !birdApply || !frrRestart {
		t.Fatalf("mixed provider transition commands incorrect: containers=%v commands=%v",
			runtime.containers, runtime.commands)
	}
}

type transitionResetRenderer struct{ commands map[string][]Command }

func (r transitionResetRenderer) Files(*model.Device) (map[string]FileSpec, error) {
	return map[string]FileSpec{}, nil
}

func (r transitionResetRenderer) Commands(device *model.Device) ([]Command, error) {
	return append([]Command(nil), r.commands[device.ID]...), nil
}

func (transitionResetRenderer) Ready(*model.Device, rt.Runtime) *plan.Waiter { return nil }

type routingResetRuntime struct {
	rt.Runtime
	containers []string
	commands   []string
}

func (r *routingResetRuntime) Exec(_ context.Context, container string, command rt.ExecCmd) (rt.ExecResult, error) {
	r.containers = append(r.containers, container)
	r.commands = append(r.commands, strings.Join(command.Cmd, " "))
	return rt.ExecResult{}, nil
}

type dockerRoutingResetRuntime struct{ routingResetRuntime }

func (*dockerRoutingResetRuntime) Name() string { return "docker" }
