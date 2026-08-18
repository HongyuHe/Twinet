package grade

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// flowTable builds the answers of a switch whose one bridge has these flows.
func flowTable(flows string) *Env {
	return switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br": "br0\n",
		"ovs-ofctl show br0": " 1(port_A): addr:aa\n 2(port_P): addr:bb\n" +
			" LOCAL(br0): addr:cc\n",
		"ovs-ofctl dump-flows br0": flows,
	})
}

// The flow that scored full marks: nothing is output anywhere, the frame is
// simply retagged and told it came in on the other port, and the switch's own
// forwarding takes it from there.
//
// Reading an action list for output ports finds none here. An action list is a
// program, and this one hands NORMAL a frame that is in VLAN 20 and claims to
// have arrived on a VLAN 20 port.
func TestRetaggingBeforeNormalIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,udp,in_port=1,tp_dst=55555 " +
		"actions=load:4->NXM_OF_IN_PORT[],mod_vlan_vid:20,NORMAL\n" +
		" cookie=0x0, priority=0 actions=NORMAL\n")
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a frame retagged into VLAN 20 and handed to NORMAL was read as harmless")
	}
	if !strings.Contains(got[0], "VLAN 20") || !strings.Contains(got[0], "port_A") {
		t.Fatalf("the report does not say what crosses where: %q", got[0])
	}
}

// Retagging alone is enough; the input port need not be touched.
func TestRetaggingAloneIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,in_port=1 actions=mod_vlan_vid:20,NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) == 0 {
		t.Fatal("mod_vlan_vid before NORMAL was read as harmless")
	}
}

// So is claiming to have arrived somewhere else, with the tag left alone.
func TestPretendingToArriveElsewhereIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,in_port=1 " +
		"actions=set_field:2->in_port,NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) == 0 {
		t.Fatal("rewriting in_port before NORMAL was read as harmless")
	}
}

// A rewrite that resubmits rather than saying NORMAL itself is delivered by
// whichever later flow does say it, so it crosses just the same.
func TestRewritingThenResubmittingIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,in_port=1 " +
		"actions=mod_vlan_vid:20,resubmit(,0)\n cookie=0x0, priority=0 actions=NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) == 0 {
		t.Fatal("a rewrite handed back to the tables was read as harmless")
	}
}

// The register forms carry the present bit above the id, so 4116 is VLAN 20.
func TestTheRegisterFormOfARetagIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,in_port=1 " +
		"actions=set_field:4116->vlan_vid,NORMAL\n")
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("set_field on vlan_vid before NORMAL was read as harmless")
	}
	if !strings.Contains(got[0], "VLAN 20") {
		t.Fatalf("4116 was not read as VLAN 20: %q", got[0])
	}
}

// The fairness guard. A correct switch's whole table is one flow that forwards
// by VLAN and rewrites nothing, and that must cost nothing.
func TestPlainNormalForwardingIsNotComplainedAbout(t *testing.T) {
	env := flowTable(" cookie=0x0, duration=931.2s, table=0, n_packets=4423, " +
		"n_bytes=418, priority=0 actions=NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) != 0 {
		t.Fatalf("a correct switch was complained about: %v", got)
	}
}

// Nor may a rewrite that keeps the frame where it was: retagging a VLAN 10
// frame as 10 is pointless, not a crossing.
func TestARetagToTheSameVLANIsNotComplainedAbout(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100,in_port=1 actions=mod_vlan_vid:10,NORMAL\n" +
		" cookie=0x0, priority=100,dl_vlan=20 actions=mod_vlan_vid:20,NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) != 0 {
		t.Fatalf("a rewrite that changes nothing was complained about: %v", got)
	}
}

// A rewrite whose result cannot be worked out is reported rather than passed
// over: which VLAN such a frame is delivered in is not something a grader can
// vouch for.
func TestAnUnreadableRewriteIsNotReadAsClean(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=100 actions=push_vlan:0x8100,NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) == 0 {
		t.Fatal("a rewrite whose result is unknown was read as harmless")
	}
}

// The word "all" inside a longer action is not the flood action. Expanding on
// it would report every port of the switch and take marks off a submission
// that forwards nothing of the sort.
func TestTheLettersAllInsideAnActionAreNotFlooding(t *testing.T) {
	byNum := map[string]string{"1": "port_A", "2": "port_P"}
	got := ovsActionPorts("note:00.11.wall,ct(table=0)", byNum, nil, map[string]bool{})
	if len(got) != 0 {
		t.Fatalf("an action containing the letters all was read as flooding: %v", got)
	}
	if p := ovsActionPorts("strip_vlan,flood", byNum, nil, map[string]bool{}); len(p) != 2 {
		t.Fatalf("flood did not reach both ports: %v", p)
	}
}

// Actions are split at the commas that separate them, not the ones inside a
// bracketed argument.
func TestActionsAreSplitAtTheirOwnCommas(t *testing.T) {
	got := ovsSplitActions("load:4->NXM_OF_IN_PORT[],resubmit(,10),NORMAL")
	if len(got) != 3 || got[2] != "NORMAL" {
		t.Fatalf("actions were split wrongly: %q", got)
	}
}

// The match ends at a space before `actions=`, not at a comma. A flow whose
// only match is its input port therefore has `in_port=1 actions=output:2` as
// one comma-separated field, and reading the port out of that gave a port
// nobody had heard of -- so the flow counted as one that never said where its
// frames came from, and carrying them straight into the other VLAN cost
// nothing.
func TestAFlowMatchingOnlyItsInputPortIsRead(t *testing.T) {
	env := flowTable(" cookie=0x0, duration=5.0s, table=0, n_packets=0, n_bytes=0, " +
		"in_port=1 actions=output:2\n")
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a flow whose only match was its input port was read as harmless")
	}
	if !strings.Contains(got[0], "port_A (VLAN 10)") || !strings.Contains(got[0], "port_P (VLAN 20)") {
		t.Fatalf("the report does not name both ends: %q", got[0])
	}
}

// Ports are printed in quotes when they are printed by name, and a quoted name
// matches neither the number table nor the VLAN table.
func TestPortsPrintedByNameAreRead(t *testing.T) {
	env := flowTable(" cookie=0x0, table=0, in_port=\"port_A\" actions=output:\"port_P\"\n")
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a flow printed with port names was read as harmless")
	}
	if !strings.Contains(got[0], "port_A (VLAN 10)") {
		t.Fatalf("the quoted name was not resolved: %q", got[0])
	}
}

// A destination that is not a port this can name is not a destination this can
// vouch for. `output:NXM_NX_REG0[]` sends the frame wherever an earlier flow
// put the register, and a reader looking for a port number finds a token that
// is not one.
func TestAnOutputThisCannotNameIsNotReadAsClean(t *testing.T) {
	env := flowTable(" cookie=0x0, in_port=1 actions=output:NXM_NX_REG0[]\n")
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("an output to a register was read as harmless")
	}
	if !strings.Contains(got[0], "could not be read") {
		t.Fatalf("the report does not say it could not be read: %q", got[0])
	}
}

// Sending a frame back out of the port it arrived on stays in its VLAN, so it
// must not be reported.
func TestOutputBackToTheIngressPortIsNotComplainedAbout(t *testing.T) {
	env := flowTable(" cookie=0x0, in_port=1 actions=output:in_port\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) != 0 {
		t.Fatalf("sending a frame back where it came from was complained about: %v", got)
	}
}

// A flow that installs other flows means the table does not yet say what the
// switch will do.
func TestLearnedFlowsAreNotReadAsClean(t *testing.T) {
	env := flowTable(" cookie=0x0, priority=10 actions=learn(table=0," +
		"NXM_OF_VLAN_TCI[0..11],output:NXM_OF_IN_PORT[]),NORMAL\n")
	if got := crossVLANLeaks(context.Background(), env, "DC"); len(got) == 0 {
		t.Fatal("a flow that installs flows was read as harmless")
	}
}

// A bridge under a controller does not forward by its table alone: the
// controller is a program of the student's own and the table shows none of it.
func TestABridgeUnderAControllerIsNotReadAsClean(t *testing.T) {
	env := switchSaying(map[string]string{
		"ovs-vsctl --columns=name,tag --format=csv list port": twoVLANPorts,
		"ovs-vsctl list-br":            "br0\n",
		"ovs-vsctl get-controller br0": "tcp:10.0.0.9:6653\n",
		"ovs-ofctl show br0":           " 1(port_A): addr:aa\n 2(port_P): addr:bb\n",
		"ovs-ofctl dump-flows br0":     " cookie=0x0, priority=0 actions=NORMAL\n",
	})
	got := crossVLANLeaks(context.Background(), env, "DC")
	if len(got) == 0 {
		t.Fatal("a bridge run by a controller was read as forwarding only what its table says")
	}
	if !strings.Contains(got[0], "controller") {
		t.Fatalf("the report does not name the controller: %q", got[0])
	}
}

// crossVLANLeaks is crossVLANForwarding with an inventory covering every
// address, so no rule is excused for carrying nothing this lab addresses.
func crossVLANLeaks(ctx context.Context, env *Env, domain string) []string {
	leaks, _ := crossVLANForwarding(ctx, env, domain, []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	return leaks
}
