package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestCaptureCommandsRetainsGlobalLoopbacks(t *testing.T) {
	exec := func(_ context.Context, _ string, args []string) (execResult, error) {
		if len(args) != 3 {
			t.Fatalf("capture args = %#v", args)
		}
		script := args[2]
		if strings.Contains(script, `$2!="lo"`) {
			t.Fatal("capture still excludes every loopback address")
		}
		if got := strings.Count(script, "addr show scope global"); got != 2 {
			t.Fatalf("global-scope address collectors = %d, want 2", got)
		}
		return execResult{Stdout: strings.Join([]string{
			"ip addr replace 3.156.0.1/24 dev lo",
			"ip -6 addr replace 3:ffff::1/128 dev lo",
			"",
		}, "\n")}, nil
	}

	got, err := captureCommands(context.Background(), exec, &model.Device{ID: "as3/ATL"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip addr replace 3.156.0.1/24 dev lo",
		"ip -6 addr replace 3:ffff::1/128 dev lo",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("capture omitted %q:\n%s", want, got)
		}
	}
}
