package nos

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/runtime"
	"github.com/HongyuHe/twinet/internal/state"
)

// birdOSPFNeighbors is what `birdc -r show ospf neighbors` prints on a BIRD 2
// router with two point-to-point interior adjacencies. The banner, the
// per-instance heading and the column header are all part of the real output.
const birdOSPFNeighbors = `BIRD 2.0.12 ready.
ospf4:
Router ID       Pri          State      DTime   Interface  Router IP
3.151.0.2         1     Full/PtP       00:36   int_CHI    3.201.0.2
3.151.0.3         1     Full/PtP       00:31   int_HOU    3.201.1.2
3.151.0.4         1     ExStart/PtP    00:29   int_NYC    3.201.2.2
`

func TestBirdOSPFNeighborColumnsAreAssignedCorrectly(t *testing.T) {
	peers := parseBirdOSPFNeighbors(birdOSPFNeighbors)
	want := []netstate.OSPFPeer{
		{RouterID: "3.151.0.2", State: "Full/PtP", Interface: "int_CHI", Address: "3.201.0.2", DeadTimerMsec: 36000},
		{RouterID: "3.151.0.3", State: "Full/PtP", Interface: "int_HOU", Address: "3.201.1.2", DeadTimerMsec: 31000},
		{RouterID: "3.151.0.4", State: "ExStart/PtP", Interface: "int_NYC", Address: "3.201.2.2", DeadTimerMsec: 29000},
	}
	if !reflect.DeepEqual(peers, want) {
		t.Fatalf("BIRD OSPF neighbours = %#v, want %#v", peers, want)
	}
	for _, peer := range peers {
		if !peer.Known(netstate.FieldDeadTimer) {
			t.Errorf("%s reported an unknown dead timer it does publish", peer.RouterID)
		}
	}
}

func TestBirdOSPFNeighborsWithoutRouterIPColumn(t *testing.T) {
	peers := parseBirdOSPFNeighbors("Router ID       Pri          State      DTime   Interface\n" +
		"3.151.0.2         1     Full/DR        --      int_CHI\n")
	if len(peers) != 1 {
		t.Fatalf("neighbours = %#v", peers)
	}
	if peers[0].State != "Full/DR" || peers[0].Interface != "int_CHI" || peers[0].Address != "" {
		t.Fatalf("neighbour = %#v", peers[0])
	}
	if peers[0].Known(netstate.FieldDeadTimer) {
		t.Fatalf("an unreadable dead timer was reported as observed: %#v", peers[0])
	}
}

func TestBirdOSPFReadsThroughTheProvider(t *testing.T) {
	var asked [][]string
	peers, err := readBirdOSPF(context.Background(), &model.Device{ID: "as3/ATL"},
		netstate.ExecFunc(func(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
			asked = append(asked, command)
			return runtime.ExecResult{Stdout: birdOSPFNeighbors}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 3 || peers[0].State != "Full/PtP" {
		t.Fatalf("peers = %#v", peers)
	}
	for _, command := range asked {
		if command[0] != "birdc" {
			t.Fatalf("BIRD OSPF was read with %q", command)
		}
	}
}

// birdProtocolsAll is a realistic `birdc -r show protocols all` transcript for
// a router with one established external session, one that is still trying,
// and the non-BGP protocols BIRD always reports.
const birdProtocolsAll = `BIRD 2.0.12 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     2026-08-26 06:00:00
direct4    Direct     ---        up     2026-08-26 06:00:00
kernel4    Kernel     master4    up     2026-08-26 06:00:00
own4       Static     master4    up     2026-08-26 06:00:00
ospf4      OSPF       master4    up     2026-08-26 06:00:01  Running
ebgp_ext_2_ALL BGP    ---        up     2026-08-26 06:00:12  Established
  BGP state:          Established
    Neighbor address: 179.1.2.2
    Neighbor AS:      2
    Local AS:         3
    Neighbor ID:      2.151.0.1
    Local capabilities
      Multiprotocol
        AF announced: ipv4
      Route refresh
    Neighbor capabilities
      Multiprotocol
        AF announced: ipv4
      Route refresh
    Session:          external AS4
    Source address:   179.1.2.1
    Hold timer:       171.649/180
    Keepalive timer:  36.211/60
  Channel ipv4
    State:          UP
    Table:          master4
    Preference:     100
    Input filter:   import_ebgp_ext_2_ALL
    Output filter:  export_ebgp_ext_2_ALL
    Routes:         5 imported, 0 filtered, 3 exported, 5 preferred
    Route change stats:     received   rejected   filtered    ignored   accepted
      Import updates:              7          0          2          0          5
      Import withdraws:            0          0        ---          0          0
      Export updates:             12          4          5        ---          3
      Export withdraws:            2        ---        ---        ---          1
ebgp_ext_4_DEN BGP    ---        start  2026-08-26 06:00:05  Active        Socket: Connection refused
  BGP state:          Active
    Neighbor address: 179.1.4.2
    Neighbor AS:      4
    Local AS:         3
  Channel ipv4
    State:          DOWN
    Table:          master4
`

func TestBirdBGPSessionCountersAreNormalized(t *testing.T) {
	sessions := readBirdBGPSessions(birdProtocolsAll)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %#v, want the two BGP protocols only", sessions)
	}

	up := sessions[0]
	if up.Neighbor != "179.1.2.2" || up.RemoteAS != 2 || up.State != "Established" {
		t.Fatalf("established session = %#v", up)
	}
	if up.PrefixesIn != 5 || up.PrefixesOut != 3 {
		t.Errorf("prefixes = %d in / %d out, want 5/3", up.PrefixesIn, up.PrefixesOut)
	}
	if up.UpdatesReceived != 7 || up.UpdatesSent != 3 {
		t.Errorf("updates = %d received / %d sent, want 7/3", up.UpdatesReceived, up.UpdatesSent)
	}
	for _, field := range []netstate.Field{
		netstate.FieldPrefixesIn, netstate.FieldPrefixesOut,
		netstate.FieldUpdatesReceived, netstate.FieldUpdatesSent,
	} {
		if !up.Known(field) {
			t.Errorf("%s was reported unknown on a session that publishes it", field)
		}
	}

	// A session with no channel counters must say so rather than report the
	// zeros that make a check conclude "the session carries nothing".
	down := sessions[1]
	if down.Neighbor != "179.1.4.2" || down.RemoteAS != 4 || down.State != "Active" {
		t.Fatalf("connecting session = %#v", down)
	}
	for _, field := range []netstate.Field{
		netstate.FieldPrefixesIn, netstate.FieldPrefixesOut,
		netstate.FieldUpdatesReceived, netstate.FieldUpdatesSent,
	} {
		if down.Known(field) {
			t.Errorf("%s was reported as observed on a session BIRD published no counters for", field)
		}
	}
}

func TestBirdBGPStateUsesTheFSMNotTheProtocolColumn(t *testing.T) {
	// A protocol whose generic state is "start" is not established, whatever
	// the up/down column suggests.
	sessions := readBirdBGPSessions("ebgp_x BGP  ---  start  2026-08-26 06:00:05  Connect\n")
	if len(sessions) != 1 || sessions[0].State != "Connect" {
		t.Fatalf("sessions = %#v, want a single Connect session", sessions)
	}
	sessions = readBirdBGPSessions("ebgp_x BGP  ---  up  2026-08-26 06:00:05\n")
	if len(sessions) != 1 || sessions[0].State != "Established" {
		t.Fatalf("sessions = %#v, want Established from the protocol column", sessions)
	}
}

// birdRouteAll exercises the attribute lines a BIRD 2 RIB actually prints,
// including the community spelling and the resolved/attribute next hops.
const birdRouteAll = `BIRD 2.0.12 ready.
Table master4:
2.0.0.0/8            unicast [ebgp_ext_2_ALL 06:00:14.331 from 179.1.2.2] * (100) [AS2i]
	via 179.1.2.2 on ext_2_ALL
	Type: BGP univ
	BGP.origin: IGP
	BGP.as_path: 2
	BGP.next_hop: 179.1.2.2
	BGP.local_pref: 200
	BGP.community: (1,20) (1,30)
	BGP.large_community: (3, 100, 200)
                     unicast [ibgp_CHI 06:00:16.002 from 3.151.0.2] (100/10) [AS2i]
	via 3.201.0.2 on int_CHI
	Type: BGP univ
	BGP.origin: Incomplete
	BGP.as_path: 2 2 2
	BGP.local_pref: 100
3.0.0.0/8            unreachable [own4 06:00:00.100] * (200)
	Type: static univ
`

func TestBirdRIBNormalizesCommunitiesAndNextHops(t *testing.T) {
	paths := readBirdRIB(birdRouteAll)
	if len(paths) != 3 {
		t.Fatalf("paths = %#v, want two for 2.0.0.0/8 and one static", paths)
	}

	best := paths[0]
	if best.Prefix != "2.0.0.0/8" || !best.Best || best.Source != "external" {
		t.Fatalf("best path = %#v", best)
	}
	if best.Peer != "179.1.2.2" {
		t.Errorf("peer = %q, want the address the path was learned from", best.Peer)
	}
	if best.Origin != "IGP" {
		t.Errorf("origin = %q, want IGP", best.Origin)
	}
	if best.ASPath != "2" || len(best.ASNs) != 1 || best.ASNs[0] != 2 {
		t.Errorf("as path = %q / %v", best.ASPath, best.ASNs)
	}
	if best.LocalPref != 200 {
		t.Errorf("local pref = %d, want 200", best.LocalPref)
	}
	wantCommunities := []string{"1:20", "1:30", "3:100:200"}
	if !reflect.DeepEqual(best.Communities, wantCommunities) {
		t.Errorf("communities = %v, want %v", best.Communities, wantCommunities)
	}
	if len(best.NextHops) != 1 || best.NextHops[0].Address != "179.1.2.2" ||
		best.NextHops[0].Device != "ext_2_ALL" {
		t.Errorf("next hops = %#v", best.NextHops)
	}

	alternate := paths[1]
	if alternate.Prefix != "2.0.0.0/8" || alternate.Best {
		t.Fatalf("alternate path = %#v", alternate)
	}
	if alternate.Source != "internal" || alternate.Peer != "3.151.0.2" {
		t.Errorf("alternate source/peer = %q/%q", alternate.Source, alternate.Peer)
	}
	if alternate.Origin != "incomplete" {
		t.Errorf("alternate origin = %q", alternate.Origin)
	}

	local := paths[2]
	if local.Prefix != "3.0.0.0/8" || local.Source != "local" {
		t.Errorf("static origin = %#v", local)
	}
}

func TestBirdPolicyBindsFiltersToPeers(t *testing.T) {
	const config = `filter import_ebgp_ext_2_ALL {
  bgp_local_pref = 200;
  accept;
}
filter export_ebgp_ext_2_ALL {
  accept;
}
filter unused_filter {
  reject;
}
protocol bgp ebgp_ext_2_ALL {
  local as 3;
  neighbor 179.1.2.2 as 2;
  ipv4 { import filter import_ebgp_ext_2_ALL; export filter export_ebgp_ext_2_ALL; };
}
`
	facts := parseBirdPolicy(config)
	want := []netstate.PolicyFact{
		{Name: "import_ebgp_ext_2_ALL", Peer: "179.1.2.2", Direction: "import"},
		{Name: "export_ebgp_ext_2_ALL", Peer: "179.1.2.2", Direction: "export"},
		{Name: "unused_filter"},
	}
	if !reflect.DeepEqual(facts, want) {
		t.Fatalf("policy facts = %#v, want %#v", facts, want)
	}
}

func TestBirdStateCommandsNeverInvokeFRR(t *testing.T) {
	device := &model.Device{ID: "as3/ATL", Kind: model.KindRouter, NOS: "bird"}
	commands := birdProvider{}.StateCommands(device, netstate.All)
	if len(commands) == 0 {
		t.Fatal("BIRD declared no state commands")
	}
	for _, command := range commands {
		for _, word := range command {
			if word == "vtysh" || word == "frr" {
				t.Fatalf("BIRD state command %q reaches an FRR binary", command)
			}
		}
	}
}

// Every command the BIRD provider can emit, audited in one place.
//
// Each of these paths ran an FRR binary at some point in this system's life:
// save ran `vtysh -c "show running-config"`, submission loading ran FRR's
// exact-reload tool, and the eBGP liveness witness ran `vtysh -c "clear bgp
// ... soft in"`. None of them exist inside a BIRD container, so each was a
// grading infrastructure error at best -- and, in the refresh's case, a
// counter that never moved and a verdict that the session carried nothing.
func TestNoFRRBinaryReachesABIRDDevice(t *testing.T) {
	device := &model.Device{
		ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter, ASN: 3, NOS: "bird",
		Container: "twinet-as3-ATL",
	}
	provider := birdProvider{}

	var emitted [][]string
	emitted = append(emitted, provider.StateCommands(device, netstate.All)...)
	emitted = append(emitted, provider.RefreshBGP(device, []string{"179.1.2.2"})...)
	applied, err := provider.Apply(RenderRequest{Device: device, Platform: "router id 3.151.0.1;\n"})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range applied {
		emitted = append(emitted, command.Args)
	}

	record := netstate.ExecFunc(func(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
		emitted = append(emitted, command)
		return runtime.ExecResult{Stdout: "BIRD 2.0.12 ready.\nDaemon is up and running\n"}, nil
	})
	if _, err := provider.CaptureConfig(context.Background(), device, record); err != nil {
		t.Fatal(err)
	}
	restore := BIRDStartWaitForTest(50 * time.Millisecond)
	defer restore()
	if err := provider.LoadConfig(context.Background(), device, record,
		"router id 3.151.0.1;\n", LoadOptions{RequireDaemons: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Save(context.Background(), device, record, "cos461", "hash"); err != nil {
		t.Fatal(err)
	}

	if len(emitted) < 8 {
		t.Fatalf("only %d commands were audited; the audit is not exercising the provider", len(emitted))
	}
	for _, command := range emitted {
		joined := strings.Join(command, " ")
		for _, forbidden := range []string{"vtysh", "frr-reload.py", "frrinit.sh", "/etc/frr"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("BIRD emitted %q, which reaches FRR (%q)", joined, forbidden)
			}
		}
	}
}

// The rendered file paths and the archive identity must agree, or a save and a
// restore disagree about where BIRD's configuration lives.
func TestBIRDConfigFileMatchesWhatItRenders(t *testing.T) {
	provider := birdProvider{}
	file := provider.ConfigFile()
	if file.NOS != "bird" || file.Kind != state.KindBIRD || file.Extension != ".conf" {
		t.Fatalf("BIRD config identity = %#v", file)
	}
	rendered, err := provider.Render(RenderRequest{
		Device:   &model.Device{ID: "as3/ATL", Kind: model.KindRouter, NOS: "bird"},
		Platform: "router id 3.151.0.1;\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rendered.Files[file.Path]; !ok {
		t.Fatalf("BIRD renders %v but declares its configuration at %s",
			sortedFileNames(rendered.Files), file.Path)
	}
}

func sortedFileNames(files map[string]FileSpec) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Linux records which daemon installed a route, and BIRD is one daemon for
// every protocol. A check that asks whether a path came from OSPF or from a
// hand-installed route -- which the ECMP question does -- would read every
// BIRD route as neither and fail a correct submission.
func TestBIRDAttributesKernelRoutesToTheProtocolThatProducedThem(t *testing.T) {
	const routes = `BIRD 2.0.12 ready.
Table master4:
3.201.1.0/24         unicast [ospf4 06:00:03.100] * I (150/10) [3.151.0.2]
	via 3.201.0.2 on int_CHI
	Type: OSPF univ
2.0.0.0/8            unicast [ebgp_ext_1_ALL 06:00:14.331] * (100) [AS2i]
	via 179.1.2.2 on ext_1_ALL
	Type: BGP univ
9.9.9.0/24           unicast [own4 06:00:00.100] * (200)
	Type: static univ
`
	kernel := []netstate.Route{
		{Prefix: "3.201.1.0/24", Protocol: "bird"},
		{Prefix: "2.0.0.0/8", Protocol: "bird"},
		{Prefix: "9.9.9.0/24", Protocol: "bird"},
		// A route the student installed by hand carries its own protocol and
		// must keep it: it is the whole point of the distinction.
		{Prefix: "8.8.8.0/24", Protocol: "static"},
		// A connected route belongs to the kernel, not to BIRD.
		{Prefix: "3.201.0.0/24", Protocol: "kernel"},
		// Installed by BIRD and no longer held by it: honest rather than
		// attributed to a protocol nobody can name.
		{Prefix: "7.7.7.0/24", Protocol: "bird"},
	}
	birdAttributeKernelRoutes(kernel, birdRouteProtocols(routes))

	want := map[string]string{
		"3.201.1.0/24": "ospf", "2.0.0.0/8": "bgp", "9.9.9.0/24": "static",
		"8.8.8.0/24": "static", "3.201.0.0/24": "kernel", "7.7.7.0/24": "",
	}
	for _, route := range kernel {
		if route.Protocol != want[route.Prefix] {
			t.Errorf("%s attributed to %q, want %q", route.Prefix, route.Protocol, want[route.Prefix])
		}
	}
}
