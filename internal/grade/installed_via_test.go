package grade

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// A static route may name the interface it leaves by instead of a next-hop
// address, and then the routing table carries no address for it at all:
//
//	"nexthops": [{"fib": true, "directlyConnected": true,
//	              "interfaceName": "ext_1_ALL", "active": true}]
//
// The forwarding half of policy.traffic_engineering exists precisely to notice
// `ip route 2.0.0.0/8 <the slow link>`, which overrides every BGP preference
// the other halves read. It compared the next-hop address against the slow
// neighbours, so the interface form was matched against the empty string and
// skipped: traffic left over exactly the link the question asks it to avoid,
// and the check reported the forwarding correct and awarded the mark in full.
func TestAStaticRouteOutTheSlowInterfaceIsSeen(t *testing.T) {
	const routes = `{
	  "2.0.0.0/8": [{"protocol":"static","selected":true,
	    "nexthops":[{"fib":true,"directlyConnected":true,"interfaceName":"ext_1_ALL","active":true}]}],
	  "4.0.0.0/8": [{"protocol":"bgp","selected":true,
	    "nexthops":[{"fib":true,"ip":"3.0.2.2","interfaceName":"port_CHI"}]}]
	}`
	const bgp = `{"routes":{
	  "2.0.0.0/8":[{"nexthops":[{"ip":"179.1.3.2"}]}],
	  "4.0.0.0/8":[{"nexthops":[{"ip":"179.1.3.2"}]}]
	}}`
	env := fakeRouteEnv(map[string]string{
		"show ip route json": routes,
		"show ip bgp json":   bgp,
	})

	slowIf := map[string]map[string]bool{"MSP": {"ext_1_ALL": true}}
	via, unreadable := installedVia(context.Background(), env,
		[]string{"179.1.1.2"}, slowIf, []string{"179.1.3.2"})
	if unreadable != "" {
		t.Fatalf("the table was not read: %s", unreadable)
	}
	if len(via) != 1 || !strings.Contains(via[0], "2.0.0.0/8") {
		t.Fatalf("a destination sent out the slow interface was not reported: %v", via)
	}
}

// And the fix must not fire on a route that does not leave by the slow link.
// Deducting for "installed over the slow provider" when the traffic goes the
// fast way would fail a correct submission for a reason that is not true --
// which is why the fix reads the interface rather than the protocol. A static
// route pointed at the fast neighbour is not this question's failure.
func TestAStaticRouteOutTheFastInterfaceIsNotReported(t *testing.T) {
	const routes = `{
	  "2.0.0.0/8": [{"protocol":"static","selected":true,
	    "nexthops":[{"fib":true,"directlyConnected":true,"interfaceName":"ext_2_ALL","active":true}]}]
	}`
	const bgp = `{"routes":{"2.0.0.0/8":[{"nexthops":[{"ip":"179.1.3.2"}]}]}}`
	env := fakeRouteEnv(map[string]string{
		"show ip route json": routes,
		"show ip bgp json":   bgp,
	})

	slowIf := map[string]map[string]bool{"MSP": {"ext_1_ALL": true}}
	via, unreadable := installedVia(context.Background(), env,
		[]string{"179.1.1.2"}, slowIf, []string{"179.1.3.2"})
	if unreadable != "" {
		t.Fatalf("the table was not read: %s", unreadable)
	}
	if len(via) != 0 {
		t.Fatalf("traffic that does not leave by the slow link was reported as if it did: %v", via)
	}
}

func fakeRouteEnv(replies map[string]string) *Env {
	return &Env{
		Topology: &model.Topology{ASes: map[int]*model.AS{
			3: {ASN: 3, Routers: []*model.Device{{Name: "MSP", ASN: 3}}},
		}},
		AS: 3,
		Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) == 3 && cmd[0] == "vtysh" {
				if out, ok := replies[cmd[2]]; ok {
					return rt.ExecResult{Stdout: out}, nil
				}
			}
			return rt.ExecResult{ExitCode: 1, Stderr: "no such command"}, nil
		},
	}
}
