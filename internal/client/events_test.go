package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HongyuHe/twinet/internal/agent"
)

func TestCorrelationPropagatesToAgentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Twinet-Correlation-ID"); got != "controller-test-1" {
			t.Errorf("correlation header = %q, want controller-test-1", got)
		}
		_ = json.NewEncoder(w).Encode(agent.StatusResponse{Node: "node-0"})
	}))
	defer server.Close()
	node := NewNode("node-0", server.URL, "token")
	if _, err := node.Status(WithCorrelation(context.Background(), "controller-test-1")); err != nil {
		t.Fatal(err)
	}
}

func TestMergeEventsIsDeterministicAcrossNodes(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	merged := MergeEvents([]NodeResult[agent.EventsResponse]{
		{Node: "node-b", Value: agent.EventsResponse{Events: []agent.Event{
			{Timestamp: at, Node: "node-b", Lab: "lab", Sequence: 1},
		}}},
		{Node: "node-a", Value: agent.EventsResponse{Events: []agent.Event{
			{Timestamp: at, Node: "node-a", Lab: "lab-z", Sequence: 2},
			{Timestamp: at, Node: "node-a", Lab: "lab-a", Sequence: 3},
		}}},
	})
	if len(merged) != 3 || merged[0].Node != "node-a" || merged[0].Lab != "lab-a" ||
		merged[2].Node != "node-b" {
		t.Fatalf("merged events are not stable: %#v", merged)
	}
}
