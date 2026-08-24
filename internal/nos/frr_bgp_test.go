package nos

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func TestFRRNetworkOriginWithUnspecifiedPeerNormalizesAsLocal(t *testing.T) {
	const table = `{"routes":{"10.128.0.0/9":[{
		"valid":true,
		"bestpath":true,
		"pathFrom":"external",
		"peerId":"(unspec)",
		"path":"",
		"origin":"IGP",
		"nexthops":[{"ip":"0.0.0.0"}]
	}]}}`
	state, err := readFRRBGP(context.Background(), &model.Device{ID: "as1/ALL"},
		netstate.ExecFunc(func(context.Context, string, []string) (runtime.ExecResult, error) {
			return runtime.ExecResult{Stdout: table}, nil
		}), netstate.QueryBGPRIB)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Paths) != 1 || state.Paths[0].Source != "local" {
		t.Fatalf("FRR network origin = %#v", state.Paths)
	}
}
