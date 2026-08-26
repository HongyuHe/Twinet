package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// The refusal has to reach the person running the deployment.
//
// A device whose network namespace could not be proven continuous is running,
// its inventory matches, and its audited health says it is fine -- the audit
// deliberately does not look at addressing a student owns. The only thing
// wrong with it is that its saved state is being withheld from the store,
// which is visible in no other field of this response. A field the node writes
// and the controller cannot read looks exactly like a node with nothing to
// report, so both sides are pinned to the name.
func TestUnprovenNamespacesCrossTheProtocolBoundaryByName(t *testing.T) {
	unproven := map[string]string{
		"as3/ATL": "the saved address it was last seen with is not in it (addr inet lo 3.156.0.1/24)",
		"as9/SW1": "the saved switch port it was last seen with is not in it (port p1 tag=10 trunks= mode=)",
	}
	for _, phase := range []string{"apply", "prepare", "commit"} {
		resp := ApplyResponse{Node: "node-0", Phase: phase}
		attachUnprovenNamespaces(&resp, unproven)
		raw, err := json.Marshal(resp)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"unproven_namespaces"`) {
			t.Fatalf("the %s response does not carry unproven_namespaces: %s", phase, raw)
		}
		var wire struct {
			Unproven map[string]string `json:"unproven_namespaces"`
		}
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatalf("%s response: %v", phase, err)
		}
		if len(wire.Unproven) != 2 || !strings.Contains(wire.Unproven["as3/ATL"], "3.156.0.1/24") {
			t.Fatalf("%s response carried %v, want the devices and their reasons", phase, wire.Unproven)
		}
	}
}

// Nothing unresolved is not the same as a field full of empty values. A
// response that always carried the key would make every summary print a
// heading for a problem nobody has, and an older agent that does not send it
// at all must be read as "said nothing", not as "everything is fine" -- the
// controller reports what it was told, and it was told nothing.
func TestAResponseWithNothingUnresolvedDoesNotCarryTheField(t *testing.T) {
	resp := ApplyResponse{Node: "node-0"}
	attachUnprovenNamespaces(&resp, nil)
	attachUnprovenNamespaces(&resp, map[string]string{})
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unproven_namespaces") {
		t.Fatalf("a clean response carried the field anyway: %s", raw)
	}
	var legacy ApplyResponse
	if err := json.Unmarshal([]byte(`{"node":"node-0","steps":0}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if len(legacy.UnprovenNamespaces) != 0 {
		t.Fatalf("a response from an older agent was read as reporting %v",
			legacy.UnprovenNamespaces)
	}
}
