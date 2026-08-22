package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

func TestCanonicalAddressSnapshotIgnoresRuntimeNoiseAndOrdering(t *testing.T) {
	first := `2: host@if9    inet 10.107.0.2/24 brd 10.107.0.255 scope global host
1: lo    inet 127.0.0.1/8 scope host lo
---
default via 10.107.0.1 dev host proto dhcp src 10.107.0.2 metric 100
---
`
	second := `17: host    inet 10.107.0.2/24 scope global dynamic host valid_lft 86399sec preferred_lft 86399sec
1: lo    inet 127.0.0.1/8 scope host lo
---
default via 10.107.0.1 dev host metric 100 proto dhcp src 10.107.0.2
---
`
	a := CanonicalDynamicSnapshot(state.KindAddrs, first)
	b := CanonicalDynamicSnapshot(state.KindAddrs, second)
	if a != b {
		t.Fatalf("runtime-noisy address snapshots differ:\n%s\n---\n%s", a, b)
	}
	extra := strings.Replace(second, "10.107.0.2/24", "10.107.0.2/24\n18: host inet 10.107.0.99/24", 1)
	if CanonicalDynamicSnapshot(state.KindAddrs, extra) == a {
		t.Fatal("true extra student address was erased from canonical state")
	}
	ipv6 := CanonicalDynamicSnapshot(state.KindAddrs,
		"2: host inet6 ::10/128 scope global host\n---\n---\n")
	if !strings.Contains(ipv6, "addr inet6 host ::10/128") {
		t.Fatalf("valid ::10 address was mistaken for the ::1 loopback: %q", ipv6)
	}
}

func TestCanonicalAddressReplayIsIdempotent(t *testing.T) {
	body := CanonicalDynamicSnapshot(state.KindAddrs, `2: host inet 10.107.0.2/24 scope global host
---
default via 10.107.0.1 dev host
10.108.0.0/16 via 10.107.0.1 dev host proto static src 10.107.0.2
---
`)
	if again := CanonicalDynamicSnapshot(state.KindAddrs, body); again != body {
		t.Fatalf("canonical address snapshot is not idempotent:\n%s\n---\n%s", body, again)
	}
	commands := addrReplay(body)
	if len(commands) != 3 ||
		!strings.Contains(commands[0], "ip addr replace 10.107.0.2/24 dev host") ||
		!strings.Contains(strings.Join(commands, "\n"), "ip route replace default via 10.107.0.1 dev host") ||
		!strings.Contains(strings.Join(commands, "\n"), "ip route replace 10.108.0.0/16 via 10.107.0.1 dev host") {
		t.Fatalf("canonical address replay commands = %v", commands)
	}
}

func TestCanonicalSnapshotsPreserveIntentionalBlankState(t *testing.T) {
	for _, kind := range []state.Kind{state.KindAddrs, state.KindTunnels, state.KindOVS} {
		body := CanonicalDynamicSnapshot(kind, "")
		want := "twinet-state/v2 " + string(kind) + "\n"
		if body != want {
			t.Errorf("%s blank state = %q, want %q", kind, body, want)
		}
	}
}

func TestCanonicalTunnelAndOVSSnapshotsIgnoreOrderingNoise(t *testing.T) {
	tunnelA := `tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64
	default via 2001:db8::1 dev tun6 metric 1024 pref medium
	`
	tunnelB := `default via 2001:db8::1 dev tun6 metric 1024 pref high
	tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 255
	`
	if CanonicalDynamicSnapshot(state.KindTunnels, tunnelA) !=
		CanonicalDynamicSnapshot(state.KindTunnels, tunnelB) {
		t.Fatal("volatile tunnel details changed canonical state")
	}

	ovsA := "port trunk_S2 tag= trunks=20,10 mode=trunk\nport access_S3 tag=30 trunks= mode=access\n"
	ovsB := "port access_S3 tag=30 trunks= mode=access\nport trunk_S2 tag= trunks=10,20 mode=trunk\n"
	if CanonicalDynamicSnapshot(state.KindOVS, ovsA) != CanonicalDynamicSnapshot(state.KindOVS, ovsB) {
		t.Fatal("port or VLAN order changed canonical OVS state")
	}
	withEmptyRuntimePort := ovsB + "port host-veth tag=[] trunks=[] mode=[]\n"
	if CanonicalDynamicSnapshot(state.KindOVS, ovsB) != CanonicalDynamicSnapshot(state.KindOVS, withEmptyRuntimePort) {
		t.Fatal("empty runtime OVS port was treated as student VLAN state")
	}
	withExtraVLAN := ovsB + "port unexpected tag=99 trunks= mode=access\n"
	if CanonicalDynamicSnapshot(state.KindOVS, ovsB) == CanonicalDynamicSnapshot(state.KindOVS, withExtraVLAN) {
		t.Fatal("extra student-significant OVS VLAN state was erased")
	}
	legacyV2 := "twinet-state/v2 ovs\nport host-veth tag= trunks= mode=\n" +
		"port trunk_S2 tag= trunks=20,10 mode=trunk\n"
	if got := CanonicalDynamicSnapshot(state.KindOVS, legacyV2); strings.Contains(got, "host-veth") ||
		!strings.Contains(got, "trunks=10,20") {
		t.Fatalf("legacy canonical OVS state was not renormalized: %q", got)
	}
}

func TestCanonicalTunnelSnapshotExcludesKernelDefaults(t *testing.T) {
	raw := `sit0: ipv6/ip remote any local any ttl 64
	tunl0: ipip/ip remote any local any ttl inherit
	gre0@NONE: gre/ip remote 0.0.0.0 local 0.0.0.0 ttl inherit
gretap0: gretap/ip remote 0.0.0.0 local 0.0.0.0 ttl inherit
erspan0: erspan/ip remote any local any ttl inherit
ip6tnl0: ip6tnl/ip6 remote :: local :: encaplimit 0
tun6: ipv6/ip remote 3.153.0.1 local 3.156.0.1 ttl 64
`
	body := CanonicalDynamicSnapshot(state.KindTunnels, raw)
	if !strings.Contains(body, "tunnel tun6 3.153.0.1 3.156.0.1") {
		t.Fatalf("named student tunnel missing from canonical snapshot: %q", body)
	}
	for _, kernel := range []string{"sit0", "tunl0", "gre0", "gretap0", "erspan0", "ip6tnl0"} {
		if strings.Contains(body, "tunnel "+kernel+" ") {
			t.Fatalf("kernel default %s leaked into canonical snapshot: %q", kernel, body)
		}
	}
	legacyV2 := "twinet-state/v2 tunnels\ntunnel gre0 0.0.0.0 0.0.0.0\n" +
		"tunnel tun6 3.153.0.1 3.156.0.1\n"
	commands := tunnelReplay(legacyV2)
	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "gre0") || !strings.Contains(joined, "tun6") {
		t.Fatalf("legacy tunnel replay was not hygienic: %q", joined)
	}
	runtime := &dynamicRestoreRuntime{}
	device := &model.Device{ID: "as3/ATL", Kind: model.KindRouter, Container: "atl"}
	if err := resetDynamicState(context.Background(), runtime, device, state.KindTunnels); err != nil {
		t.Fatal(err)
	}
	if got := runtime.joined(); len(got) != 1 ||
		!strings.Contains(got[0], "gre0|gretap0|erspan0") {
		t.Fatalf("tunnel reset does not protect kernel defaults: %q", got)
	}
}

func TestRestoreCanonicalDynamicStateClearsStaleFactsBeforeReplay(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as10/SFO_host", ASN: 10, Kind: model.KindHost, Container: "sfo-host"}
	if _, err := store.Put(state.Snapshot{
		Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
		Content: []byte(CanonicalDynamicSnapshot(state.KindAddrs, `2: host inet 10.107.0.2/24 scope global host
---
default via 10.107.0.1 dev host
---
`)),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &dynamicRestoreRuntime{}
	restored, err := Restore(context.Background(), runtime, device, "lab", store)
	if err != nil || !restored {
		t.Fatalf("restore = %v, %v", restored, err)
	}
	got := runtime.joined()
	if len(got) != 3 || !strings.Contains(got[0], "ip addr flush") ||
		!strings.Contains(got[1], "ip addr replace 10.107.0.2/24 dev host") ||
		!strings.Contains(got[2], "ip route replace default via 10.107.0.1 dev host") {
		t.Fatalf("dynamic restore order = %q", got)
	}
}

func TestRestoreDynamicStateStopsAtFirstRejectedCommand(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as10/SFO_host", ASN: 10, Kind: model.KindHost, Container: "sfo-host"}
	if _, err := store.Put(state.Snapshot{
		Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
		Content: []byte(CanonicalDynamicSnapshot(state.KindAddrs, `2: host inet 10.107.0.2/24 scope global host
---
default via 10.107.0.1 dev host
---
`)),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &dynamicRestoreRuntime{fail: "ip addr replace"}
	_, err = Restore(context.Background(), runtime, device, "lab", store)
	if err == nil || !strings.Contains(err.Error(), "ip addr replace") {
		t.Fatalf("rejected address replay = %v", err)
	}
	for _, command := range runtime.joined() {
		if strings.Contains(command, "ip route replace") {
			t.Fatalf("restore ran after its first rejected command: %q", runtime.joined())
		}
	}
}

func TestRouterDynamicStateRestoresBeforeFRRConfiguration(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "atl"}
	for _, snapshot := range []state.Snapshot{
		{
			Lab: "lab", Device: device.ID, Kind: state.KindAddrs,
			Content: []byte(CanonicalDynamicSnapshot(state.KindAddrs, `2: eth0 inet 3.101.0.2/24 scope global eth0
---
default via 3.101.0.1 dev eth0
---
`)),
		},
		{Lab: "lab", Device: device.ID, Kind: state.KindFRR, Content: []byte("router bgp 3\n")},
	} {
		if _, err := store.Put(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &dynamicRestoreRuntime{}
	if _, err := Restore(context.Background(), runtime, device, "lab", store); err != nil {
		t.Fatal(err)
	}
	commands := runtime.joined()
	reset, address, ready, load := commandIndex(commands, "ip addr flush"),
		commandIndex(commands, "ip addr replace"), commandIndex(commands, "vtysh -c show version"),
		commandIndex(commands, "vtysh -f /etc/twinet/restore.conf")
	if reset < 0 || address < 0 || ready < 0 || load < 0 || !(reset < address && address < ready && ready < load) {
		t.Fatalf("router restore order = %q", commands)
	}
}

func TestFRRRestoreWaitRetriesTransientZebraFailure(t *testing.T) {
	device := &model.Device{ID: "as7/BOS", Kind: model.KindRouter, Container: "bos"}
	runtime := &frrReadinessRuntime{remainingFailures: 2}
	if err := waitForFRRRestoreReady(context.Background(), runtime, device); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 3 {
		t.Fatalf("FRR readiness calls = %d, want 3", runtime.calls)
	}
}

func TestRouterCaptureIncludesCanonicalDynamicRoutes(t *testing.T) {
	device := &model.Device{ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "atl"}
	runtime := &readFailingRuntime{exec: func(command []string) (rt.ExecResult, error) {
		joined := strings.Join(command, " ")
		switch {
		case strings.HasPrefix(joined, "vtysh "):
			return rt.ExecResult{Stdout: "router bgp 3\n"}, nil
		case strings.Contains(joined, "ip -o addr show"):
			return rt.ExecResult{Stdout: "2: eth0 inet 3.101.0.2/24 scope global eth0\n---\n" +
				"198.51.100.0/24 via 3.101.0.1 dev eth0 proto static src 3.101.0.2\n---\n" +
				"2001:db8:3::/64 via 2001:db8:3::1 dev eth0 metric 20\n---\n"}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}}
	snapshots, err := Capture(context.Background(), runtime, device, "lab", "topology")
	if err != nil {
		t.Fatal(err)
	}
	var addrs string
	for _, snapshot := range snapshots {
		if snapshot.Kind == state.KindAddrs {
			addrs = string(snapshot.Content)
		}
	}
	if !strings.Contains(addrs, "route inet 198.51.100.0/24 via 3.101.0.1 dev eth0") ||
		!strings.Contains(addrs, "route inet6 2001:db8:3::/64 via 2001:db8:3::1 dev eth0 metric 20") {
		t.Fatalf("router dynamic routes were not captured canonically:\n%s", addrs)
	}
}

type dynamicRestoreRuntime struct {
	rt.Runtime
	commands []string
	fail     string
	copies   []string
}

func (r *dynamicRestoreRuntime) Exec(_ context.Context, _ string, cmd rt.ExecCmd) (rt.ExecResult, error) {
	command := strings.Join(cmd.Cmd, " ")
	r.commands = append(r.commands, command)
	if r.fail != "" && strings.Contains(command, r.fail) {
		return rt.ExecResult{ExitCode: 17, Stderr: "rejected dynamic fact"}, nil
	}
	return rt.ExecResult{}, nil
}

func (r *dynamicRestoreRuntime) joined() []string {
	return append([]string(nil), r.commands...)
}

func (r *dynamicRestoreRuntime) CopyTo(_ context.Context, _ string, path string, _ int64, _ []byte) error {
	r.copies = append(r.copies, path)
	return nil
}

func commandIndex(commands []string, needle string) int {
	for i, command := range commands {
		if strings.Contains(command, needle) {
			return i
		}
	}
	return -1
}

type frrReadinessRuntime struct {
	rt.Runtime
	remainingFailures int
	calls             int
}

func (r *frrReadinessRuntime) Exec(_ context.Context, _ string, _ rt.ExecCmd) (rt.ExecResult, error) {
	r.calls++
	if r.remainingFailures > 0 {
		r.remainingFailures--
		return rt.ExecResult{ExitCode: 13, Stderr: "Failure to communicate[13] to zebra"}, nil
	}
	return rt.ExecResult{}, nil
}
