package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// The reset between two submissions has to leave the device in the state a
// student starts from, and the loopback carries an address the student is asked
// to configure.
//
// It was skipped, and restarting FRR does not flush kernel addresses, so every
// submission inherited the previous one's loopback -- and the reference's, on
// the first run of a class. That is marks for addressing nobody did, plus an
// OSPF and iBGP fabric that comes up because the addresses the exercise asks
// for are already there.
func TestTheResetFlushesTheLoopback(t *testing.T) {
	d := &model.Device{
		ID: "as3/ATL", ASN: 3, Kind: model.KindRouter,
		Ifaces: []*model.Iface{
			{Name: "lo", Owner: model.OwnerStudent},
			{Name: "port_BOS", Owner: model.OwnerStudent},
		},
	}
	var ran []string
	first := true
	exec := func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		ran = append(ran, strings.Join(cmd, " "))
		if first {
			// The reset itself, which ends in `exit 0`.
			first = false
			return rt.ExecResult{}, nil
		}
		// The read-back that confirms it worked.
		return rt.ExecResult{ExitCode: 1, Stdout: probeReply(nil)}, nil
	}
	if err := wipeDeviceState(context.Background(), exec, d); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(ran, "\n")
	if !strings.Contains(all, "ip addr flush dev lo scope global") {
		t.Errorf("the reset does not flush the loopback, so the next submission is "+
			"marked on the previous one's addressing.\nWhat it ran:\n%s", all)
	}
	if !strings.Contains(all, "ip addr flush dev port_BOS scope global") {
		t.Errorf("the reset does not flush a student-owned interface:\n%s", all)
	}
}
