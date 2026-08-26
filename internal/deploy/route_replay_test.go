package deploy

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// A snapshot of a converged router, in the kernel's own spelling.
//
// This is `ip -o route show` output as FRR leaves it: OSPF and BGP install
// through nexthop objects by default, so the routes carry the kernel-assigned
// `nhid <N>` and the multipath ones are printed on one line with a literal
// backslash where the newline was. iproute2 accepts neither back --
// "Nexthop specification and nexthop id are mutually exclusive" and
// `either "to" is duplicate, or " nexthop" is a garbage` -- so a snapshot
// taken verbatim could not be replayed into the container it came from, and
// every deployment after the first destroy failed on its first restore.
const capturedRouterRoutes = `2: lo    inet 9.151.0.1/24 scope global lo
2: port_CHI    inet 9.0.2.1/24 scope global port_CHI
---
1.0.0.0/8 nhid 124 via 179.3.9.1 dev ext_3_SFO proto ospf metric 20 
9.0.1.0/24 dev port_NYC proto kernel scope link src 9.0.1.1 
9.0.11.0/24 nhid 140 proto ospf metric 20 \	nexthop via 9.0.2.2 dev port_CHI weight 1 \	nexthop via 9.0.3.2 dev port_SFO weight 1 
---
10:201:1::/48 dev tun6 metric 1024 pref medium
---
---
`

// The same facts as they were already written to /var/lib/twinet/state by the
// build that shipped this format. Fixing capture alone would leave every
// existing lab unable to deploy, and the only escape -- deleting the state
// directory -- destroys the work it was protecting.
const legacyRouterSnapshot = `twinet-state/v2 addrs
addr inet lo 9.151.0.1/24
addr inet port_CHI 9.0.2.1/24
route inet 1.0.0.0/8 nhid 124 via 179.3.9.1 dev ext_3_SFO metric 20
route inet 9.0.1.0/24 dev port_NYC scope link
route inet 9.0.11.0/24 nhid 140 metric 20 \ nexthop via 9.0.2.2 dev port_CHI weight 1 \ nexthop via 9.0.3.2 dev port_SFO weight 1
route inet6 10:201:1::/48 dev tun6 metric 1024
`

const legacyTunnelSnapshot = `twinet-state/v2 tunnels
route inet6 10:201:1::/48 dev tun6 metric 1024
tunnel tun6 3.153.0.1 3.156.0.1
`

// rejectsCommand reports why iproute2 would refuse a replayed command, or ""
// when it would take it. The two forms are the ones a real kernel rejected.
func rejectsCommand(command string) string {
	fields := strings.Fields(command)
	hasNhid, hasSpec := false, false
	for _, field := range fields {
		switch field {
		case "nhid":
			hasNhid = true
		case "via", "dev", "nexthop":
			hasSpec = true
		}
	}
	switch {
	case strings.Contains(command, `\`):
		return `a literal backslash: either "to" is duplicate, or "\" is a garbage`
	case hasNhid && hasSpec:
		return "nexthop specification and nexthop id are mutually exclusive"
	case hasNhid:
		return "a nexthop-group id this container does not have"
	}
	return ""
}

func TestCapturedNexthopObjectRoutesBecomeCommandsIprouteAccepts(t *testing.T) {
	commands := addrReplay(capturedRouterRoutes)
	if len(commands) == 0 {
		t.Fatal("a captured router produced no replay commands at all")
	}
	for _, command := range commands {
		if why := rejectsCommand(command); why != "" {
			t.Errorf("replay would be rejected -- %s:\n  %s", why, command)
		}
	}
	joined := strings.Join(commands, "\n")
	// The reviewer's first case: a single-path route installed through a
	// nexthop object. The via/dev beside the id already say everything.
	if !strings.Contains(joined, "ip route replace 1.0.0.0/8 via 179.3.9.1 dev ext_3_SFO metric 20") {
		t.Errorf("the single-path nexthop-object route lost its meaning:\n%s", joined)
	}
	// The second: a multipath route, which must come back as one command.
	if !strings.Contains(joined, "ip route replace 9.0.11.0/24 metric 20 "+
		"nexthop via 9.0.2.2 dev port_CHI weight 1 nexthop via 9.0.3.2 dev port_SFO weight 1") {
		t.Errorf("the ECMP route did not come back as one valid command:\n%s", joined)
	}
	// The third: a route over a tunnel the student built.
	if !strings.Contains(joined, "ip -6 route replace 10:201:1::/48 dev tun6 metric 1024") {
		t.Errorf("the tunnel route was lost:\n%s", joined)
	}
}

// The capture is the input to the replay, so the two have to agree about what
// a route is. This is the whole contract in one test: read a device, write the
// snapshot, replay it, and check that nothing the kernel owns survived and
// nothing the student owns was dropped.
func TestCaptureCanonicaliseReplayContract(t *testing.T) {
	device := &model.Device{ID: "as9/MSP", ASN: 9, Kind: model.KindRouter, Container: "msp"}
	runtime := &readFailingRuntime{exec: func(command []string) (rt.ExecResult, error) {
		joined := strings.Join(command, " ")
		switch {
		case strings.HasPrefix(joined, "vtysh "):
			return rt.ExecResult{Stdout: "router bgp 9\n"}, nil
		case strings.Contains(joined, "ip -o addr show"):
			return rt.ExecResult{Stdout: capturedRouterRoutes}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}}
	snapshots, err := Capture(context.Background(), runtime, device, "cos461", "topology")
	if err != nil {
		t.Fatal(err)
	}
	var body string
	for _, snapshot := range snapshots {
		if snapshot.Kind == state.KindAddrs {
			body = string(snapshot.Content)
		}
	}
	if body == "" {
		t.Fatal("nothing was captured")
	}
	for _, unwanted := range []string{"nhid", `\`, "proto ", "pref ", "linkdown"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("the kernel's %q survived into the snapshot:\n%s", unwanted, body)
		}
	}
	for _, wanted := range []string{
		"route inet 1.0.0.0/8 via 179.3.9.1 dev ext_3_SFO metric 20",
		"route inet 9.0.11.0/24 metric 20 nexthop via 9.0.2.2 dev port_CHI weight 1 " +
			"nexthop via 9.0.3.2 dev port_SFO weight 1",
		"route inet 9.0.1.0/24 dev port_NYC scope link src 9.0.1.1",
		"route inet6 10:201:1::/48 dev tun6 metric 1024",
	} {
		if !strings.Contains(body, wanted) {
			t.Errorf("the snapshot lost %q:\n%s", wanted, body)
		}
	}
	// A snapshot is content-addressed, so canonicalising one twice has to give
	// the same bytes or every capture would look like a change.
	if again := CanonicalDynamicSnapshot(state.KindAddrs, body); again != body {
		t.Fatalf("canonical state is not idempotent:\n%s\n---\n%s", body, again)
	}
	for _, command := range addrReplay(body) {
		if why := rejectsCommand(command); why != "" {
			t.Errorf("replay would be rejected -- %s:\n  %s", why, command)
		}
	}
}

// Snapshots outlive the code that wrote them. The state already on every node
// is in the kernel's spelling, and a fix that only cleaned up future captures
// would leave those labs permanently undeployable unless an operator deleted
// the very work the snapshots exist to protect.
func TestLegacySnapshotIsSanitisedOnTheWayOut(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as9/MSP", ASN: 9, Kind: model.KindRouter, Container: "msp"}
	for _, snapshot := range []state.Snapshot{
		{Lab: "cos461", AS: 9, Device: device.ID, Kind: state.KindAddrs,
			Content: []byte(legacyRouterSnapshot)},
		{Lab: "cos461", AS: 9, Device: device.ID, Kind: state.KindTunnels,
			Content: []byte(legacyTunnelSnapshot)},
	} {
		if _, err := store.Put(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &dynamicRestoreRuntime{}
	restored, err := Restore(context.Background(), runtime, device, "cos461", store)
	if err != nil {
		t.Fatalf("a lab with saved state could not be redeployed: %v", err)
	}
	if !restored {
		t.Fatal("nothing was restored from a snapshot that has work in it")
	}
	commands := runtime.joined()
	for _, command := range commands {
		if !strings.Contains(command, "ip route replace") &&
			!strings.Contains(command, "ip -6 route replace") {
			continue
		}
		if why := rejectsCommand(command); why != "" {
			t.Errorf("a legacy snapshot still replays a rejected command -- %s:\n  %s", why, command)
		}
	}
	joined := strings.Join(commands, "\n")
	for _, wanted := range []string{
		"ip route replace 1.0.0.0/8 via 179.3.9.1 dev ext_3_SFO metric 20",
		"ip route replace 9.0.11.0/24 metric 20 nexthop via 9.0.2.2 dev port_CHI weight 1 " +
			"nexthop via 9.0.3.2 dev port_SFO weight 1",
		"ip -6 route replace 10:201:1::/48 dev tun6 metric 1024",
		"ip tunnel add tun6 mode sit remote 3.153.0.1 local 3.156.0.1",
	} {
		if !strings.Contains(joined, wanted) {
			t.Errorf("a legacy snapshot lost %q:\n%s", wanted, joined)
		}
	}
}

// The snapshot is a sorted set of facts, and "route ... dev tun6" sorts before
// "tunnel tun6 ...". Replaying it in stored order asked the kernel for a route
// on a device that did not exist yet -- "Cannot find device \"tun6\"" -- and
// one rejected command fails the restore, the device, and the deployment.
func TestTunnelsAndLinksExistBeforeAnythingNamesThem(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as3/ATL", ASN: 3, Kind: model.KindRouter, Container: "atl"}
	for _, snapshot := range []state.Snapshot{
		{Lab: "cos461", AS: 3, Device: device.ID, Kind: state.KindTunnels,
			Content: []byte(legacyTunnelSnapshot)},
		{Lab: "cos461", AS: 3, Device: device.ID, Kind: state.KindAddrs,
			Content: []byte(CanonicalDynamicSnapshot(state.KindAddrs,
				"2: ATL-L2.10@ATL-L2    inet 3.101.0.2/24 scope global ATL-L2.10\n"+
					"3: tun6    inet6 2001:db8::1/64 scope global tun6\n"+
					"---\n3.108.0.0/16 via 3.101.0.1 dev ATL-L2.10 metric 20\n"+
					"---\n10:201:1::/48 dev tun6 metric 1024 pref medium\n"+
					"---\n7: ATL-L2.10@ATL-L2: <UP> mtu 1500 qdisc noqueue state UP\\    "+
					"link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    "+
					"vlan protocol 802.1Q id 10 <REORDER_HDR> addrgenmode eui64\n"+
					"---\n"))},
	} {
		if _, err := store.Put(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &dynamicRestoreRuntime{}
	if _, err := Restore(context.Background(), runtime, device, "cos461", store); err != nil {
		t.Fatal(err)
	}
	commands := runtime.joined()
	order := map[string]int{}
	for _, needle := range []string{
		"ip tunnel add tun6", "ip link set tun6 up", "ip addr flush",
		"ip link add link ATL-L2 name ATL-L2.10 type vlan id 10",
		"ip addr replace 3.101.0.2/24 dev ATL-L2.10",
		"ip route replace 3.108.0.0/16 via 3.101.0.1 dev ATL-L2.10",
		"ip -6 route replace 10:201:1::/48 dev tun6",
	} {
		index := commandIndex(commands, needle)
		if index < 0 {
			t.Fatalf("restore never ran %q:\n%s", needle, strings.Join(commands, "\n"))
		}
		order[needle] = index
	}
	// The tunnel exists and is up before the address flush that follows it,
	// and long before any route names it.
	if order["ip tunnel add tun6"] > order["ip link set tun6 up"] ||
		order["ip link set tun6 up"] > order["ip addr flush"] {
		t.Errorf("tunnels are not created and brought up first:\n%s", strings.Join(commands, "\n"))
	}
	// The VLAN sub-interface exists before the address on it and the route
	// through it.
	if order["ip link add link ATL-L2 name ATL-L2.10 type vlan id 10"] >
		order["ip addr replace 3.101.0.2/24 dev ATL-L2.10"] ||
		order["ip addr replace 3.101.0.2/24 dev ATL-L2.10"] >
			order["ip route replace 3.108.0.0/16 via 3.101.0.1 dev ATL-L2.10"] {
		t.Errorf("a VLAN sub-interface is named before it is created:\n%s", strings.Join(commands, "\n"))
	}
	// And the route over the tunnel comes after the tunnel.
	if order["ip -6 route replace 10:201:1::/48 dev tun6"] < order["ip tunnel add tun6"] {
		t.Errorf("a route was replayed onto a tunnel that did not exist yet:\n%s",
			strings.Join(commands, "\n"))
	}
}

// Dropping a rejected command instead of failing would be the opposite fix:
// the device would come back believably wrong and nobody would be told.
func TestRestoreStillFailsOnTheFirstGenuinelyInvalidCommand(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	device := &model.Device{ID: "as9/MSP", ASN: 9, Kind: model.KindRouter, Container: "msp"}
	if _, err := store.Put(state.Snapshot{
		Lab: "cos461", AS: 9, Device: device.ID, Kind: state.KindAddrs,
		Content: []byte(legacyRouterSnapshot),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &dynamicRestoreRuntime{fail: "ip route replace 1.0.0.0/8"}
	if _, err := Restore(context.Background(), runtime, device, "cos461", store); err == nil ||
		!strings.Contains(err.Error(), "ip route replace 1.0.0.0/8") {
		t.Fatalf("a rejected command did not fail the restore: %v", err)
	}
	for _, command := range runtime.joined() {
		if strings.Contains(command, "9.0.11.0/24") {
			t.Fatalf("restore carried on after a rejected command:\n%s",
				strings.Join(runtime.joined(), "\n"))
		}
	}
}

// A route the kernel resolved only through a nexthop object it did not
// describe cannot be reconstructed by any command. Emitting one anyway names a
// destination and nothing else, which fails the whole restore.
func TestARouteThatNoCommandCouldAskForIsDroppedRatherThanFailed(t *testing.T) {
	if got := canonicalRoute("9.0.20.0/24 nhid 90 proto bgp metric 20"); got != "" {
		t.Fatalf("an unreconstructable route was kept as %q", got)
	}
	if got := canonicalRoute("9.0.21.0/24 nhid 91 via 9.0.1.2 dev port_NYC metric 20"); got !=
		"9.0.21.0/24 via 9.0.1.2 dev port_NYC metric 20" {
		t.Fatalf("a describable nexthop-object route was not recovered: %q", got)
	}
}

func TestCanonicalRoutePreservesWhatARouteMeans(t *testing.T) {
	for _, c := range []struct {
		what string
		line string
		want string
	}{
		{"an interface route keeps its scope and source",
			"9.0.1.0/24 dev port_NYC proto kernel scope link src 9.0.1.1",
			"9.0.1.0/24 dev port_NYC scope link src 9.0.1.1"},
		{"a default route keeps its gateway and metric",
			"default via 10.107.0.1 dev host proto dhcp src 10.107.0.2 metric 100",
			"default via 10.107.0.1 dev host metric 100 src 10.107.0.2"},
		{"a route in another table keeps the table",
			"9.0.30.0/24 via 9.0.1.2 dev port_NYC table 100 metric 20",
			"9.0.30.0/24 via 9.0.1.2 dev port_NYC metric 20 table 100"},
		{"an onlink route keeps onlink",
			"9.0.13.0/24 via 9.0.1.2 dev port_NYC metric 20 onlink",
			"9.0.13.0/24 via 9.0.1.2 dev port_NYC metric 20 onlink"},
		{"a locked mtu stays locked",
			"9.0.14.0/24 via 9.0.1.2 dev port_NYC mtu lock 1400",
			"9.0.14.0/24 via 9.0.1.2 dev port_NYC mtu lock 1400"},
		{"an MPLS encapsulation is kept whole",
			"9.0.15.0/24 encap mpls 100/200 via 9.0.1.2 dev port_NYC proto bgp metric 20",
			"9.0.15.0/24 via 9.0.1.2 dev port_NYC encap mpls 100/200 metric 20"},
		{"a blackhole route needs no nexthop",
			"blackhole 9.9.9.0/24", "blackhole 9.9.9.0/24"},
		{"an unreachable route keeps its metric",
			"unreachable 9.9.8.0/24 metric 5", "unreachable 9.9.8.0/24 metric 5"},
		{"a prohibit route survives",
			"prohibit 9.9.7.0/24", "prohibit 9.9.7.0/24"},
		{"an IPv6 route loses only its preference",
			"2001:db8:3::/64 via 2001:db8:1::2 dev tun6 metric 1024 pref medium",
			"2001:db8:3::/64 via 2001:db8:1::2 dev tun6 metric 1024"},
		{"an IPv6 nexthop given in the other family keeps its family",
			"9.0.16.0/24 via inet6 fe80::1 dev port_NYC metric 20",
			"9.0.16.0/24 via inet6 fe80::1 dev port_NYC metric 20"},
		{"a single path printed as a nexthop becomes a plain route",
			"9.0.17.0/24 metric 20 nexthop via 9.0.1.2 dev port_NYC weight 1",
			"9.0.17.0/24 via 9.0.1.2 dev port_NYC metric 20"},
		{"weights survive on a real multipath route",
			"9.0.18.0/24 metric 20 nexthop via 9.0.1.2 dev port_NYC weight 3 " +
				"nexthop via 9.0.2.2 dev port_CHI weight 1",
			"9.0.18.0/24 metric 20 nexthop via 9.0.1.2 dev port_NYC weight 3 " +
				"nexthop via 9.0.2.2 dev port_CHI weight 1"},
		{"a dead path's link state is not student state",
			"9.0.19.0/24 metric 20 nexthop via 9.0.1.2 dev port_NYC weight 1 dead linkdown " +
				"nexthop via 9.0.2.2 dev port_CHI weight 1",
			"9.0.19.0/24 metric 20 nexthop via 9.0.1.2 dev port_NYC weight 1 " +
				"nexthop via 9.0.2.2 dev port_CHI weight 1"},
		{"a line that is not a route is not one", "Kernel IP routing table", ""},
	} {
		t.Run(c.what, func(t *testing.T) {
			got := canonicalRoute(c.line)
			if got != c.want {
				t.Fatalf("canonicalRoute(%q)\n = %q\nwant %q", c.line, got, c.want)
			}
			if got == "" {
				return
			}
			if again := canonicalRoute(got); again != got {
				t.Fatalf("canonical route is not idempotent: %q -> %q", got, again)
			}
		})
	}
}

// The same route printed by `ip -o`, by plain `ip route show`, and by
// `ip -details` has to reduce to the same fact, or a capture taken one way
// would look like a change from one taken the other.
func TestTheSameRoutePrintedThreeWaysIsOneFact(t *testing.T) {
	oneline := "9.0.11.0/24 nhid 140 proto ospf metric 20 \\\tnexthop via 9.0.2.2 dev port_CHI " +
		"weight 1 \\\tnexthop via 9.0.3.2 dev port_SFO weight 1 "
	wrapped := "9.0.11.0/24 nhid 140 proto ospf metric 20 \n" +
		"\tnexthop via 9.0.2.2 dev port_CHI weight 1 \n" +
		"\tnexthop via 9.0.3.2 dev port_SFO weight 1 \n"
	reordered := "9.0.11.0/24 nhid 140 proto ospf metric 20 \n" +
		"\tnexthop via 9.0.3.2 dev port_SFO weight 1 \n" +
		"\tnexthop via 9.0.2.2 dev port_CHI weight 1 \n"
	want := "9.0.11.0/24 metric 20 nexthop via 9.0.2.2 dev port_CHI weight 1 " +
		"nexthop via 9.0.3.2 dev port_SFO weight 1"
	for what, raw := range map[string]string{
		"ip -o": oneline, "ip route show": wrapped, "a kernel that reordered the paths": reordered,
	} {
		entries := routeEntries(raw)
		if len(entries) != 1 {
			t.Fatalf("%s: multipath route split into %d entries: %q", what, len(entries), entries)
		}
		if got := canonicalRoute(entries[0]); got != want {
			t.Errorf("%s:\n got %q\nwant %q", what, got, want)
		}
	}
}

func TestVLANAndVRFObjectsAreCapturedFromDetailedOutput(t *testing.T) {
	raw := "2: ATL-L2.10@ATL-L2    inet 3.101.0.2/24 scope global ATL-L2.10\n---\n---\n---\n" +
		"7: ATL-L2.10@ATL-L2: <UP> mtu 1500 qdisc noqueue state UP mode DEFAULT qlen 1000\\    " +
		"link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    " +
		"vlan protocol 802.1Q id 10 <REORDER_HDR> addrgenmode eui64 numtxqueues 1\n---\n" +
		"9: vrf-blue: <NOARP,MASTER,UP> mtu 65575 qdisc noqueue state UP\\    " +
		"link/ether 8a:6e:40:c9:75:8d brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    " +
		"vrf table 10 addrgenmode eui64 numtxqueues 1\n"
	body := CanonicalDynamicSnapshot(state.KindAddrs, raw)
	if !strings.Contains(body, "link vlan ATL-L2.10 ATL-L2 10") {
		t.Errorf("the VLAN sub-interface was not captured as an object:\n%s", body)
	}
	if !strings.Contains(body, "link vrf vrf-blue 10") {
		t.Errorf("the VRF was not captured as an object:\n%s", body)
	}
	if again := CanonicalDynamicSnapshot(state.KindAddrs, body); again != body {
		t.Fatalf("link facts are not idempotent:\n%s\n---\n%s", body, again)
	}
	// A veth whose parent lives in another namespace prints the peer's index
	// there, which names nothing this device could stack a VLAN onto.
	peer := CanonicalDynamicSnapshot(state.KindAddrs,
		"---\n---\n---\n8: eth0@if12: <UP> mtu 1500\\    vlan protocol 802.1Q id 20\n")
	if strings.Contains(peer, "link vlan") {
		t.Errorf("a cross-namespace peer index was mistaken for a VLAN parent:\n%s", peer)
	}
}

// The capture has to read the VLAN id and the VRF table, which only `ip -d`
// prints. Without them the object cannot be recreated, and the addresses and
// routes on it cannot be replayed either.
// The kernel derives one fe80::/64 route per interface from that interface's
// link-local address, and does so again on the replacement container. They
// cannot be replayed faithfully -- every interface shares the one prefix, so
// each `ip -6 route replace` overwrites the last -- and they are not student
// state, so they are not captured.
func TestTheKernelsOwnLinkLocalRoutesAreNotStudentState(t *testing.T) {
	if got := canonicalRoute("fe80::/64 dev port_NYC proto kernel metric 256 pref medium"); got != "" {
		t.Fatalf("a kernel link-local route was captured as %q", got)
	}
	// A route a student put on the link-local prefix is theirs.
	if got := canonicalRoute("fe80::/64 via 2001:db8::1 dev tun6 metric 100"); got !=
		"fe80::/64 via 2001:db8::1 dev tun6 metric 100" {
		t.Fatalf("a deliberate link-local route was discarded: %q", got)
	}
	if got := canonicalRoute("2001:db8:1::/64 dev tun6 proto kernel metric 256 pref medium"); got !=
		"2001:db8:1::/64 dev tun6 metric 256" {
		t.Fatalf("a connected IPv6 route was mistaken for kernel plumbing: %q", got)
	}
}

func TestAddressCaptureReadsLinkDetail(t *testing.T) {
	if !strings.Contains(addrCapture, "ip -d -o link show type vlan") ||
		!strings.Contains(addrCapture, "ip -d -o link show type vrf") {
		t.Error("the address capture does not read the netdevs its routes name in detail")
	}
	if strings.Count(addrCapture, "|| exit $?") != 5 {
		t.Error("a failed read in the address capture is indistinguishable from an empty device")
	}
}
