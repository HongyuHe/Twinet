package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// loadFRRConfig has to notice a submission FRR would not accept.
//
// FRR's start script succeeds even when a daemon reads the file, rejects a
// line and exits. The check used to be `vtysh -c "show version"`, which answers
// as long as any one daemon is up -- so a submission whose OSPF configuration
// was rejected loaded "successfully" with ospfd dead. Its author was then
// marked on a network whose routers could not learn a route, with nothing in
// the report saying why, and their neighbours were marked down with them.
func TestASubmissionThatKillsADaemonDoesNotLoad(t *testing.T) {
	dead := "ospfd"
	exec := func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		body := strings.Join(cmd, " ")
		switch {
		case strings.Contains(body, "pidof"):
			return rt.ExecResult{Stdout: dead + " "}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}

	err := loadFRRConfig(context.Background(), exec, d, "router ospf\n network 3.0.0.0/8 area 0\n")
	if err == nil {
		t.Fatal("a submission that left ospfd dead loaded successfully. It will be " +
			"graded on a network that cannot learn a route, and so will its neighbours.")
	}
	if !strings.Contains(err.Error(), dead) {
		t.Errorf("the failure does not name the daemon that died, so its author cannot "+
			"tell what they got wrong: %v", err)
	}
}

func TestASubmissionFRRAcceptsLoads(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		return rt.ExecResult{}, nil
	}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}
	if err := loadFRRConfig(context.Background(), exec, d, "router ospf\n"); err != nil {
		t.Fatalf("a submission every daemon accepted was rejected: %v", err)
	}
}

// The daemons checked are the ones the platform actually enables, so enabling a
// new one does not quietly go unchecked.
func TestTheDaemonsCheckedAreTheOnesEnabled(t *testing.T) {
	if len(render.EnabledDaemons()) == 0 {
		t.Fatal("no daemons are enabled, so the check is vacuous")
	}
	for _, want := range []string{"zebra", "bgpd", "ospfd"} {
		found := false
		for _, d := range render.EnabledDaemons() {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not among the daemons checked, and the routing assignment "+
				"cannot be graded without it", want)
		}
	}
}
