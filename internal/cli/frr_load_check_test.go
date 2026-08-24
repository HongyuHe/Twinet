package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/render"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// loadFRRConfig has to notice a submission FRR would not accept.
//
// A generic `vtysh -c "show version"` answers as long as any one daemon is up.
// Each daemon therefore has to answer through its own vty socket.
func TestASubmissionThatKillsADaemonDoesNotLoad(t *testing.T) {
	dead := "ospfd"
	exec := func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
		body := strings.Join(cmd, " ")
		switch {
		case strings.Contains(body, "vtysh -d"):
			return rt.ExecResult{Stdout: dead + " "}, nil
		default:
			return rt.ExecResult{}, nil
		}
	}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}

	// The real budget gives a loaded node time to start FRR; here the daemon
	// is never coming back, and the test is about the verdict, not the wait.
	restore := frrStartWait
	frrStartWait = 100 * time.Millisecond
	defer func() { frrStartWait = restore }()

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
	var commands []string
	exec := func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
		commands = append(commands, strings.Join(command, " "))
		return rt.ExecResult{}, nil
	}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}
	if err := loadFRRConfig(context.Background(), exec, d, "router ospf\n"); err != nil {
		t.Fatalf("a submission every daemon accepted was rejected: %v", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "frr-reload.py --reload") {
		t.Fatal("submission loader did not use exact in-place FRR reload")
	}
	if strings.Contains(joined, "frrinit.sh") || strings.Contains(joined, "pidof") {
		t.Fatalf("submission loader crossed the split-control boundary:\n%s", joined)
	}
}

func TestPlatformBaselineDoesNotRequireUnconfiguredRoutingDaemons(t *testing.T) {
	exec := func(_ context.Context, _ string, _ []string) (rt.ExecResult, error) {
		// The student baseline has no OSPF/BGP configuration yet, so the
		// platform reset may legitimately leave routing daemons absent.
		return rt.ExecResult{Stdout: "zebra bgpd ospfd ospf6d ldpd "}, nil
	}
	d := &model.Device{ID: "as3/ATL", Name: "ATL", Kind: model.KindRouter}
	if err := loadPlatformFRRConfig(context.Background(), exec, d, "frr defaults traditional\n"); err != nil {
		t.Fatalf("empty platform baseline was treated as a malformed submission: %v", err)
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
