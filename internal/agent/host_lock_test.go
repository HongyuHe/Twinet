package agent

import (
	"strings"
	"testing"
)

func TestOnlyOneAgentMayOwnAHostNetworkNamespace(t *testing.T) {
	path := t.TempDir() + "/agent.lock"
	first, err := acquireHostAgentLock(path, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	if _, err := acquireHostAgentLock(path, "node-shadow", "10.0.1.1:7300",
		"twinet-shadow"); err == nil {
		t.Fatal("a second agent acquired the same host-network lock")
	} else {
		for _, want := range []string{"another Twinet agent", "node-0", "10.0.1.1:7200"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("lock refusal does not contain %q: %v", want, err)
			}
		}
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireHostAgentLock(path, "node-0", "10.0.1.1:7200", "twinet-node-0")
	if err != nil {
		t.Fatalf("lock was not released with the first agent: %v", err)
	}
	_ = second.Close()
}
