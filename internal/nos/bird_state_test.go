package nos

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func TestBirdStaticHijackNormalizesAsLocalOrigin(t *testing.T) {
	state, err := readBirdBGP(context.Background(), &model.Device{ID: "as1/ALL"},
		netstate.ExecFunc(func(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
			if len(command) > 0 && command[len(command)-1] == "all" {
				return runtime.ExecResult{Stdout: "10.128.0.0/9 unicast [hijack4 00:00:01] * (200)\n"}, nil
			}
			return runtime.ExecResult{}, nil
		}), netstate.QueryBGPRIB)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Paths) != 1 || state.Paths[0].Source != "local" {
		t.Fatalf("BIRD static origin = %#v", state.Paths)
	}
}
