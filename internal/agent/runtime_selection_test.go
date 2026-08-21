package agent

import (
	"strings"
	"testing"
)

func TestAgentRejectsUnavailableRuntimeBeforeConnectingOrMutating(t *testing.T) {
	_, err := New(Config{Node: "node-0", Runtime: "unavailable-runtime"})
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("agent unavailable runtime error = %v", err)
	}
}
