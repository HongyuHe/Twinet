//go:build o12integration

package integration

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/deploy"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/plan"
	"github.com/HongyuHe/twinet/internal/render"
	"github.com/HongyuHe/twinet/internal/runtime"
)

// TestO12HardenedDNSAndRTRRedeploy proves the control-plane bind-volume
// contract against real Docker. It deliberately changes a generated DNS file,
// reconciles it, verifies both daemons, then proves a third deploy has no
// dirty work. A tmpfs-only implementation fails here because Docker refuses
// CopyToContainer on a read-only rootfs before it reaches the tmpfs target.
func TestO12HardenedDNSAndRTRRedeploy(t *testing.T) {
	if os.Getenv("TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE") != "1" {
		t.Fatal("O12 integration needs TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE=1")
	}
	if err := runO12("info"); err != nil {
		t.Fatalf("Docker is required for O12 integration: %v", err)
	}
	top := hardenedServiceTopology(t)
	engine := &deploy.Engine{
		Runtime: runtime.NewDocker(), Node: "local", PullPolicy: runtime.PullNever,
		Renderer: render.New(top, render.ModeSolve), WritableRoot: t.TempDir(), Workers: 4,
	}
	t.Cleanup(func() {
		if err := engine.Destroy(context.Background(), top.Name); err != nil {
			// This isolated service topology creates no overlays. A concurrent
			// host netlink survey can make the generic empty-overlay sweep
			// unreadable after both service containers were removed; it is not
			// a leaked test object or a writable-path failure.
			if !strings.Contains(err.Error(), "remove empty multiplex overlays") {
				t.Errorf("destroy hardened service integration lab: %v", err)
			}
		}
	})
	createLegacyReadonlyServices(t, engine.Runtime, top)
	executeServicePlan(t, engine, top)
	verifyLegacyServicesMigrated(t, engine, top)
	verifyHardenedServices(t, engine, top)

	dns := top.Devices["svc/dns"]
	if err := engine.Runtime.CopyTo(context.Background(), dns.Container, "/etc/bind/named.conf", 0o644,
		[]byte("options { directory \"/var/named\"; recursion yes; };\n; O12 generated-file drift\n")); err != nil {
		t.Fatalf("change generated DNS file through the runtime API: %v", err)
	}
	executeServicePlan(t, engine, top)
	verifyHardenedServices(t, engine, top)

	plan := buildServicePlan(t, engine, top)
	if diff := engine.LastBuildDiff(); !diff.Empty() || plan.Len() != 0 {
		t.Fatalf("no-change hardened service redeploy has dirty work: diff=%+v steps=%d", diff.Counts(), plan.Len())
	}
}

func verifyLegacyServicesMigrated(t *testing.T, engine *deploy.Engine, top *model.Topology) {
	t.Helper()
	for _, id := range []string{"svc/dns", "svc/rpki"} {
		device := top.Devices[id]
		final, err := engine.FinalSpecHash(top, device)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := engine.Runtime.Inspect(context.Background(), device.Container)
		if err != nil {
			t.Fatal(err)
		}
		if observed.Label(deploy.LabelSpec) != final || observed.Label(deploy.LabelSpec) == deploy.SpecHash(device) ||
			observed.Label(deploy.LabelRuntimeContract) == "" {
			t.Fatalf("%s was not migrated from legacy spec label: %#v", id, observed.Labels)
		}
	}
}

func createLegacyReadonlyServices(t *testing.T, engine runtime.Runtime, top *model.Topology) {
	t.Helper()
	for _, id := range []string{"svc/dns", "svc/rpki"} {
		device := top.Devices[id]
		if device == nil {
			t.Fatalf("missing integration device %s", id)
		}
		if _, err := engine.Create(context.Background(), &runtime.Spec{
			Name: device.Container, Image: device.Image, Command: []string{"sleep", "infinity"},
			NetworkMode: "none", ReadOnlyRootfs: true, Init: true,
			Labels: map[string]string{
				deploy.LabelManaged: "true", deploy.LabelLab: top.Name,
				deploy.LabelSpec: deploy.SpecHash(device),
			},
		}); err != nil {
			t.Fatalf("create legacy readonly %s: %v", id, err)
		}
		if err := engine.Start(context.Background(), device.Container); err != nil {
			t.Fatalf("start legacy readonly %s: %v", id, err)
		}
	}
}

// Docker's Engine API and explicit CLI compatibility backend must both copy
// into a declared writable bind target under ReadOnlyRootfs. Neither backend
// is allowed to claim a shell-based read-only-rootfs bypass.
func TestO12DockerAPICLIWritableCopy(t *testing.T) {
	if os.Getenv("TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE") != "1" {
		t.Fatal("O12 integration needs TWINET_O12_INTEGRATION_ALLOW_DESTRUCTIVE=1")
	}
	for _, backend := range []string{"api", "cli"} {
		t.Run(backend, func(t *testing.T) {
			t.Setenv("TWINET_DOCKER_BACKEND", backend)
			name := "twinet-o12-copy-" + backend + "-" + strconv.Itoa(os.Getpid())
			targetRoot := t.TempDir()
			engine := runtime.NewDocker()
			t.Cleanup(func() { _ = engine.Remove(context.Background(), name, true) })
			if _, err := engine.Create(context.Background(), &runtime.Spec{
				Name: name, Image: "hyhe/twinet-svc:0.1", Command: []string{"sleep", "infinity"},
				NetworkMode: "none", ReadOnlyRootfs: true,
				Binds: []runtime.Bind{{Source: targetRoot, Target: "/etc/bind"}},
			}); err != nil {
				t.Fatal(err)
			}
			if err := engine.Start(context.Background(), name); err != nil {
				t.Fatal(err)
			}
			want := []byte("options { recursion no; };\n")
			if err := engine.CopyTo(context.Background(), name, "/etc/bind/named.conf", 0o644, want); err != nil {
				t.Fatalf("copy into declared writable bind: %v", err)
			}
			got, err := engine.CopyFrom(context.Background(), name, "/etc/bind/named.conf")
			if err != nil || string(got) != string(want) {
				t.Fatalf("copied config = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func executeServicePlan(t *testing.T, engine *deploy.Engine, top *model.Topology) {
	t.Helper()
	p := buildServicePlan(t, engine, top)
	report, err := p.Execute(context.Background(), plan.Options{Workers: 4, ContinueOnError: true})
	if err != nil {
		t.Fatalf("execute hardened service plan: %v", err)
	}
	if report.Failed() {
		if dns := top.Devices["svc/dns"]; dns != nil {
			res, _ := engine.Runtime.Exec(context.Background(), dns.Container, runtime.ExecCmd{
				Cmd: []string{"sh", "-c", "ps -ef; ls -la /etc/bind /var/named; cat /var/log/named/* 2>/dev/null || true; dig +time=1 +tries=1 @127.0.0.1 group1 SOA"},
			})
			t.Logf("DNS failure diagnostics:\n%s\n%s", res.Stdout, res.Stderr)
		}
		t.Fatalf("hardened service plan failed: %v", report.ScopeErrors)
	}
}

func buildServicePlan(t *testing.T, engine *deploy.Engine, top *model.Topology) *plan.Plan {
	t.Helper()
	p, err := engine.Build(top)
	if err != nil {
		t.Fatalf("build hardened service plan: %v", err)
	}
	return p
}

func verifyHardenedServices(t *testing.T, engine *deploy.Engine, top *model.Topology) {
	t.Helper()
	dns := top.Devices["svc/dns"]
	res, err := engine.Runtime.Exec(context.Background(), dns.Container, runtime.ExecCmd{
		Cmd: []string{"sh", "-c", "dig +time=1 +tries=1 @127.0.0.1 group1 SOA | grep -q 'status: NOERROR'"},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("hardened DNS is not authoritative: result=%+v err=%v", res, err)
	}
	rtr := top.Devices["svc/rpki"]
	res, err = engine.Runtime.Exec(context.Background(), rtr.Container, runtime.ExecCmd{
		Cmd: []string{"sh", "-c", "test -s /etc/twinet/rpki.json && socat -u /dev/null TCP:127.0.0.1:3323"},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("hardened RTR is not serving: result=%+v err=%v", res, err)
	}
}

func hardenedServiceTopology(t *testing.T) *model.Topology {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid())
	lab := &model.Lab{Metadata: model.Meta{Name: "o12-hardened-services-" + suffix}}
	lab.Normalize()
	router := &model.Device{
		ID: "as1/R1", Name: "R1", Kind: model.KindRouter, ASN: 1, Node: "remote",
		Ifaces: []*model.Iface{{Name: "lo", Addr4: "1.150.0.1/32"}},
	}
	router.Ifaces[0].Device = router
	as := &model.AS{ASN: 1, Role: model.RoleStaff, Block: "1.0.0.0/8",
		Devices: []*model.Device{router}, Routers: []*model.Device{router}}
	service := func(id, name, kind string) *model.Device {
		d := &model.Device{
			ID: id, Name: name, Kind: model.KindService, ServiceKind: kind, Node: "local",
			Image: "hyhe/twinet-svc:0.1", Container: "twinet-" + lab.Metadata.Name + "-" + name,
			Capabilities: []string{"NET_ADMIN", "NET_RAW"},
			Requests:     model.DefaultResourceRequest(model.KindService),
		}
		return d
	}
	dns := service("svc/dns", "dns", "builtin.dns")
	rpki := service("svc/rpki", "rpki", "builtin.rpki")
	return &model.Topology{
		Lab: lab, Name: lab.Metadata.Name, Hash: "o12-hardened-services",
		Devices: map[string]*model.Device{
			router.ID: router, dns.ID: dns, rpki.ID: rpki,
		},
		ASes: map[int]*model.AS{1: as},
		Services: map[string]*model.Service{
			"dns":  {Name: "dns", Kind: "builtin.dns", Device: dns},
			"rpki": {Name: "rpki", Kind: "builtin.rpki", Device: rpki},
		},
	}
}
