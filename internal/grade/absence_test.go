package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// twoRouterAS builds the smallest topology the absence checks will accept.
func twoRouterAS() *model.Topology {
	top := &model.Topology{ASes: map[int]*model.AS{}}
	as := &model.AS{ASN: 3}
	for _, n := range []string{"ZURI", "GENE"} {
		d := &model.Device{Name: n, ASN: 3, Kind: model.KindRouter}
		as.Routers = append(as.Routers, d)
		as.Devices = append(as.Devices, d)
	}
	top.ASes[3] = as
	return top
}

// execFunc turns a per-router reply table into an Exec.
//
// A router absent from the table answers with a non-zero exit code, which is
// what vtysh does when FRR is not running: the container is reachable, so this
// is not an infrastructure failure and the central tracker will not catch it.
func execFunc(reply map[string]string) func(context.Context, string, []string) (rt.ExecResult, error) {
	return func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		name := deviceID
		if i := strings.LastIndexByte(deviceID, '/'); i >= 0 {
			name = deviceID[i+1:]
		}
		out, ok := reply[name]
		if !ok {
			return rt.ExecResult{ExitCode: 1, Stderr: "Exiting: failed to connect to any daemons."}, nil
		}
		// A router that answers answers every question. The checks read tables
		// as well as configuration, and a fixture that returns the running
		// configuration to `show ip bgp json` makes a check look broken when it
		// is the fixture that is silent.
		body := strings.Join(cmd, " ")
		switch {
		case strings.Contains(body, "bgp json"), strings.Contains(body, "bgp ipv4 unicast json"):
			return rt.ExecResult{Stdout: `{"routes":{}}`}, nil
		case strings.Contains(body, "show ip route"):
			return rt.ExecResult{Stdout: "{}"}, nil
		case strings.Contains(body, "rpki prefix-table"):
			return rt.ExecResult{Stdout: "RPKI/RTR prefix table\n"}, nil
		}
		return rt.ExecResult{ExitCode: 0, Stdout: out}, nil
	}
}

// A question phrased as a prohibition is answered by what the grader does not
// find. If it could not read a router, what it did not find includes everything
// on that router.
//
// These checks used to skip the unreadable router and pass, so a submission
// whose FRR was not running scored full marks on every such question -- and the
// mark was identical to a correct answer's, so nobody had cause to look.
func TestAProhibitionIsNotSatisfiedByAnUnreadableRouter(t *testing.T) {
	clean := "router ospf\n network 3.0.0.0/8 area 0\n!\n"

	cases := []struct {
		name  string
		check func(context.Context, *Env) Result
	}{
		{"config.no_forbidden_ospf", checkNoForbiddenOSPF},
		{"rpki.notfound_preserved", checkRPKINotFoundPreserved},
	}

	for _, c := range cases {
		// Both routers answer: the configurations are clean, so the
		// prohibition holds and the check must pass.
		env := &Env{Topology: twoRouterAS(), AS: 3,
			Exec: execFunc(map[string]string{
				"ZURI": clean + "rpki\n rpki cache 5.0.0.1 3323 preference 1\n!\n",
				"GENE": clean + "rpki\n rpki cache 5.0.0.1 3323 preference 1\n!\n",
			})}
		if got := c.check(context.Background(), env); got.Score < 1 {
			t.Fatalf("%s: a clean submission scored %.2f: %s",
				c.name, got.Score, got.Evidence.Detail)
		}

		// One router does not answer. Nothing can be concluded about it, so
		// full marks would be awarded for a router the grader never saw.
		env = &Env{Topology: twoRouterAS(), AS: 3,
			Exec: execFunc(map[string]string{
				"ZURI": clean + "rpki\n rpki cache 5.0.0.1 3323 preference 1\n!\n",
			})}
		got := c.check(context.Background(), env)
		if got.Score >= 1 {
			t.Errorf("%s: full marks with GENE unreadable", c.name)
		}
		if !strings.Contains(got.Evidence.Detail, "GENE") {
			t.Errorf("%s: the report does not name the router it could not read: %q",
				c.name, got.Evidence.Detail)
		}
	}
}

// The converse: a router that does answer, and is in breach, must still be
// caught. A fix that fails everything is not a fix.
func TestAProhibitionStillCatchesABreach(t *testing.T) {
	env := &Env{Topology: twoRouterAS(), AS: 3,
		Exec: execFunc(map[string]string{
			"ZURI": "router ospf\n network 3.0.0.0/8 area 0\n!\n",
			"GENE": "router ospf\n network 3.0.0.0/8 area 0\n network 179.3.4.0/24 area 0\n!\n",
		})}
	got := checkNoForbiddenOSPF(context.Background(), env)
	if got.Score != 0 {
		t.Fatalf("an inter-AS subnet advertised into OSPF scored %.2f", got.Score)
	}
	if !strings.Contains(got.Evidence.Detail, "179.3.4.0/24") {
		t.Errorf("the offending statement is not in the report: %q", got.Evidence.Detail)
	}
}
