package cli

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

// The agent's network is derived from the lab rather than configured, because
// an operator cannot keep a firewall in step with a placement. These pin what
// it derives, and what it refuses.

func labWithNodes(addrs ...string) *model.Topology {
	lab := &model.Lab{}
	for i, a := range addrs {
		lab.Placement.Nodes = append(lab.Placement.Nodes,
			model.NodeSpec{Name: "node-" + string(rune('0'+i)), Addr: a})
	}
	return &model.Topology{Lab: lab, Devices: map[string]*model.Device{}}
}

func TestTheAgentMayReachTheNodeAgentsAndNothingElseByDefault(t *testing.T) {
	got, _, err := agentEgress(labWithNodes("127.0.0.1:7200", "127.0.0.2:7200"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range got {
		out = append(out, e.String())
	}
	want := "127.0.0.1:7200,127.0.0.2:7200"
	if strings.Join(out, ",") != want {
		t.Errorf("the agent would have been allowed %v, wanted %s", out, want)
	}
}

func TestExtraEgressIsExplicitAndValidated(t *testing.T) {
	got, _, err := agentEgress(labWithNodes("127.0.0.1:7200"), []string{"127.0.0.9:443"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("an explicitly allowed endpoint was dropped: %v", got)
	}
	for _, bad := range []string{"127.0.0.1", "127.0.0.1:notaport", "127.0.0.1:0"} {
		if _, _, err := agentEgress(labWithNodes("127.0.0.1:7200"), []string{bad}); err == nil {
			t.Errorf("%q was accepted as an endpoint; a firewall built from it would "+
				"have been wrong in a way nobody would notice", bad)
		}
	}
}

func TestAnEndpointAppearsOnceHoweverOftenItIsNamed(t *testing.T) {
	got, _, err := agentEgress(labWithNodes("127.0.0.1:7200", "127.0.0.1:7200"),
		[]string{"127.0.0.1:7200"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("the same endpoint was allowed %d times: %v", len(got), got)
	}
}

// A name the agent needs is resolved before it starts, so blocking DNS costs it
// nothing and gives it no channel.
func TestNamedEndpointsAreResolvedForTheNamespace(t *testing.T) {
	_, names, err := agentEgress(labWithNodes("localhost:7200"), nil)
	if err != nil {
		t.Skipf("this machine cannot resolve localhost: %v", err)
	}
	if names["localhost"] == "" {
		t.Errorf("the agent was given no way to resolve a name its manifest uses: %v", names)
	}
}
