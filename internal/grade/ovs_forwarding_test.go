package grade

import (
	"slices"
	"testing"
	"time"
)

// A flow whose action is a group names no port at all. Reading only the flow
// table saw nothing to complain about, and a group carrying a frame from one
// VLAN straight into another scored full marks.
func TestAGroupIsFollowedToThePortsItSendsFramesOutOf(t *testing.T) {
	byNum := map[string]string{"1": "port_A_CHA", "2": "port_P_CHA"}
	groups := ovsGroupBuckets(`NXST_GROUP_DESC reply (xid=0x2):
 group_id=461,type=all,bucket=actions=mod_dl_dst:02:58:da:e6:4a:5f,output:2
`)
	if _, ok := groups["461"]; !ok {
		t.Fatalf("group 461 not read out of the dump: %v", groups)
	}
	in, outs := ovsFlowPorts(
		" cookie=0x0, table=0, udp,in_port=1,nw_dst=3.200.1.12,tp_dst=54321 actions=group:461",
		byNum, groups)
	if in != "port_A_CHA" {
		t.Errorf("ingress port = %q, want port_A_CHA", in)
	}
	if !slices.Contains(outs, "port_P_CHA") {
		t.Errorf("ports the frame can leave by = %v, want it to include port_P_CHA", outs)
	}
}

// `type=all` on the group line is the group's type, not an instruction to
// flood: reading it as one would fail every switch that has a group.
func TestAGroupsTypeIsNotReadAsFlooding(t *testing.T) {
	byNum := map[string]string{"1": "port_A_CHA", "2": "port_P_CHA", "3": "trunk"}
	groups := ovsGroupBuckets(
		" group_id=7,type=all,bucket=actions=output:1\n")
	_, outs := ovsFlowPorts("in_port=1 actions=group:7", byNum, groups)
	if slices.Contains(outs, "port_P_CHA") || slices.Contains(outs, "trunk") {
		t.Errorf("a group of type=all reached %v; it sends frames out of port 1 only", outs)
	}
}

// A group that points at itself, or at one that points back, must not spin.
func TestGroupsThatPointAtEachOtherTerminate(t *testing.T) {
	byNum := map[string]string{"2": "port_P_CHA"}
	groups := ovsGroupBuckets(
		" group_id=1,type=all,bucket=actions=group:2\n" +
			" group_id=2,type=all,bucket=actions=group:1,bucket=actions=output:2\n")
	done := make(chan []string, 1)
	go func() {
		_, outs := ovsFlowPorts("in_port=1 actions=group:1", byNum, groups)
		done <- outs
	}()
	select {
	case outs := <-done:
		if !slices.Contains(outs, "port_P_CHA") {
			t.Errorf("ports = %v, want port_P_CHA through the chain of groups", outs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("following the groups did not terminate")
	}
}

// A mirror leaves the flow table exactly as a correct switch would have it and
// still copies every frame of one VLAN onto a port in another.
func TestAMirrorAcrossVLANsIsNamed(t *testing.T) {
	ports := "_uuid,name\n" +
		"1111aaaa-0000-0000-0000-000000000001,port_A_CHA\n" +
		"2222bbbb-0000-0000-0000-000000000002,port_P_CHA\n"
	mirrors := "select_src_port,select_dst_port,select_all,output_port\n" +
		"1111aaaa-0000-0000-0000-000000000001,[],false,2222bbbb-0000-0000-0000-000000000002\n"
	byUUID := map[string]string{}
	for _, rec := range ovsCSV(ports) {
		if len(rec) >= 2 {
			byUUID[rec[0]] = rec[1]
		}
	}
	rec := ovsCSV(mirrors)[1]
	from := ovsPortNames(rec[0], byUUID)
	to := ovsPortNames(rec[3], byUUID)
	if !slices.Contains(from, "port_A_CHA") || !slices.Contains(to, "port_P_CHA") {
		t.Fatalf("mirror read as %v -> %v, want port_A_CHA -> port_P_CHA", from, to)
	}
}

// A set of several ports is printed quoted, with the commas inside the quotes.
func TestASetOfMirroredPortsIsReadWhole(t *testing.T) {
	byUUID := map[string]string{
		"1111aaaa-0000-0000-0000-000000000001": "port_A_CHA",
		"3333cccc-0000-0000-0000-000000000003": "port_A_EUH",
	}
	rows := ovsCSV("select_src_port\n" +
		"\"[1111aaaa-0000-0000-0000-000000000001, 3333cccc-0000-0000-0000-000000000003]\"\n")
	if len(rows) < 2 {
		t.Fatalf("read %d rows, want 2", len(rows))
	}
	got := ovsPortNames(rows[1][0], byUUID)
	if len(got) != 2 {
		t.Errorf("ports = %v, want both of them", got)
	}
}
