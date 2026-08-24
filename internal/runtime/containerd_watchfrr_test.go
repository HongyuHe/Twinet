package runtime

import (
	"strings"
	"testing"
)

func TestWatchFRRRestartsWithTwoPassPolicyBinding(t *testing.T) {
	command := watchFRRCommand("traditional", []frrDaemon{
		{name: "zebra"},
		{name: "bgpd"},
		{name: "ospfd"},
	})
	joined := strings.Join(command, " ")
	for _, want := range []string{
		"/usr/lib/frr/watchfrr",
		"-F traditional",
		"zebra bgpd ospfd",
		"daemon=%s",
		`/usr/lib/frr/watchfrr.sh restart "$daemon"`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("watchfrr command %q does not contain %q", joined, want)
		}
	}
	for _, flag := range []string{"-r", "-s"} {
		index := -1
		for i, arg := range command {
			if arg == flag {
				index = i
				break
			}
		}
		if index < 0 || index+1 >= len(command) {
			t.Fatalf("watchfrr command has no %s action: %q", flag, joined)
		}
		if got := strings.Count(command[index+1], "vtysh --no-fork -b"); got != 2 {
			t.Fatalf("watchfrr %s policy binding passes = %d, want 2: %q",
				flag, got, command[index+1])
		}
		if got := strings.Count(command[index+1], "%s"); got != 1 {
			t.Fatalf("watchfrr %s substitutions = %d, want 1: %q",
				flag, got, command[index+1])
		}
	}
}
