package agent

import (
	"encoding/json"
	"testing"
)

func TestBGPPeerStateFindsNestedFRRSummaryState(t *testing.T) {
	var summary any
	if err := json.Unmarshal([]byte(`{"ipv4Unicast":{"peers":{"192.0.2.2":{"state":"Established"}}}}`), &summary); err != nil {
		t.Fatal(err)
	}
	if got := bgpPeerState(summary, "192.0.2.2"); got != "Established" {
		t.Fatalf("BGP peer state = %q", got)
	}
	if got := bgpPeerState(summary, "192.0.2.3"); got != "" {
		t.Fatalf("unexpected BGP peer state = %q", got)
	}
}
