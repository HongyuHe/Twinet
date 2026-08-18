package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// switchSaying builds a one-switch AS whose Open vSwitch answers from a table
// keyed by the command that was run.
func switchSaying(replies map[string]string) *Env {
	sw := &model.Device{Name: "S1", ASN: 3, Kind: model.KindSwitch, L2Domain: "DC"}
	as := &model.AS{ASN: 3, Devices: []*model.Device{sw}}
	top := &model.Topology{ASes: map[int]*model.AS{3: as}}
	return &Env{
		Topology: top,
		AS:       3,
		Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
			key := strings.Join(cmd, " ")
			if out, ok := replies[key]; ok {
				return rt.ExecResult{Stdout: out}, nil
			}
			return rt.ExecResult{ExitCode: 1, Stderr: "no such command: " + key}, nil
		},
	}
}

const twoVLANPorts = `name,tag
port_A,10
port_P,20
br0,[]
`

// A switch is read whatever it calls its bridge.
//
// Only `br0` was ever asked for, and `ovs-ofctl show br0` failing meant the
// switch was skipped without a word -- so a submission that did its switching
// on a bridge by any other name had nothing read at all, and could forward
// between VLANs as it liked. The broadcast probe does not find a rule aimed at
// one flow, so that was full marks.
func TestASwitchIsReadWhateverItsBridgeIsCalled(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br": "dcfabric\n",
		"ovs-ofctl show dcfabric": " 1(port_A): addr:aa\n 2(port_P): addr:bb\n" +
			" LOCAL(dcfabric): addr:cc\n",
		"ovs-ofctl dump-flows dcfabric": " cookie=0x0, priority=200,in_port=1,tcp," +
			"tp_dst=443, actions=output:2\n cookie=0x0, priority=0, actions=NORMAL\n",
	})
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a rule carrying frames from VLAN 10 to VLAN 20 was not read, because it " +
			"was not on a bridge called br0")
	}
	if !strings.Contains(got[0], "port_A") || !strings.Contains(got[0], "port_P") {
		t.Fatalf("the report does not name the two ports: %q", got[0])
	}
}

// Port numbers belong to the bridge that used them.
//
// Two bridges each number their ports from one, so resolving a number against
// the wrong bridge's table names a port that had nothing to do with the flow --
// and a report naming the wrong port is worse than none.
func TestPortNumbersAreResolvedAgainstTheirOwnBridge(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br":        "br0\nbr1\n",
		"ovs-ofctl show br0":       " 1(trunk): addr:aa\n",
		"ovs-ofctl dump-flows br0": " cookie=0x0, priority=0, actions=NORMAL\n",
		"ovs-ofctl show br1":       " 1(port_A): addr:bb\n 2(port_P): addr:cc\n",
		"ovs-ofctl dump-flows br1": " cookie=0x0, in_port=1, actions=output:2\n",
		"ovs-vsctl --columns=name,type,options --format=csv list interface": "name,type,options\n",
	})
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) != 1 {
		t.Fatalf("want one crossing read from br1, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "from port_A (VLAN 10) out of port_P (VLAN 20)") {
		t.Fatalf("the flow's ports were resolved against the wrong bridge: %q", got[0])
	}
}

// A way across that no single flow describes.
//
// Bridges are joined by patch ports: what goes out of one arrives on its peer.
// A frame can leave a VLAN 10 port, cross into a second bridge and come back
// out in VLAN 20 without any one flow naming ports in two VLANs, so reading
// flows one at a time finds nothing to object to.
func TestAWayAcrossThroughASecondBridgeIsFound(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br":  "br0\nbr1\n",
		"ovs-ofctl show br0": " 1(port_A): addr:aa\n 2(port_P): addr:bb\n 3(p0): addr:cc\n",
		"ovs-ofctl dump-flows br0": " cookie=0x0, in_port=1, actions=output:3\n" +
			" cookie=0x0, in_port=3, actions=output:2\n",
		"ovs-ofctl show br1":       " 1(p1): addr:dd\n",
		"ovs-ofctl dump-flows br1": " cookie=0x0, priority=0, actions=NORMAL\n",
		"ovs-vsctl --columns=name,type,options --format=csv list interface": "name,type,options\n" +
			`p0,patch,"{peer=p1}"` + "\n" + `p1,patch,"{peer=p0}"` + "\n",
	})
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("frames can go from VLAN 10 out through a second bridge and back into " +
			"VLAN 20, and nothing said so")
	}
	if !strings.Contains(strings.Join(got, "\n"), "another bridge") {
		t.Fatalf("the report does not say how the frames get across: %v", got)
	}
}

// A switch that keeps its VLANs apart is left alone.
//
// The reference answer has one bridge, tagged access ports and a single
// NORMAL flow, and reads nothing across. A check that objected to that would
// take the mark from every correct submission, which is the same defect the
// other way round.
func TestASwitchThatKeepsItsVLANsApartIsNotComplainedAbout(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br":  "br0\n",
		"ovs-ofctl show br0": " 1(port_A): addr:aa\n 2(port_P): addr:bb\n 3(trunk): addr:cc\n",
		"ovs-ofctl dump-flows br0": " cookie=0x0, duration=1s, table=0, n_packets=3, " +
			"priority=0 actions=NORMAL\n",
		"ovs-vsctl --columns=name,type,options --format=csv list interface": "name,type,options\n",
	})
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) != 0 {
		t.Fatalf("a correct switch was reported as forwarding across VLANs: %v", got)
	}
}

// A switch that cannot be read is said to be unread.
//
// Failing to reach Open vSwitch used to skip the switch in silence, and a
// check that reports "no way across" having looked at nothing is the defect
// this whole exercise keeps finding.
func TestASwitchThatCannotBeReadIsNotReadAsClean(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
	})
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a switch whose bridges could not be listed was passed as keeping its " +
			"VLANs apart")
	}
	if !strings.Contains(got[0], "could not be asked") {
		t.Fatalf("the report does not say the switch went unread: %q", got[0])
	}
}

// The peer of a patch port is read from where it is written.
//
// Options hold commas of their own, so counting comma-separated fields finds
// the wrong thing as soon as a port has more than one option set.
func TestAPatchPortsPeerIsFoundAmongOtherOptions(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,type,options --format=csv list interface": "name,type,options\n" +
			`p0,patch,"{key=1, peer=p1, tos=2}"` + "\n",
	})
	sw := env.Topology.ASes[3].Devices[0]
	peers := ovsPatchPeers(context.Background(), env, sw)
	if peers["p0"] != "p1" {
		t.Fatalf("peer of p0 read as %q, want p1", peers["p0"])
	}
	if _, ok := peers["name"]; ok {
		t.Fatal("the header row was read as a port")
	}
}
