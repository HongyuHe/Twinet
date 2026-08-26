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

func TestBirdRetainsAlternativePathsForOnePrefix(t *testing.T) {
	const routes = `3.0.0.0/8            unicast [ebgp_ext_2_ALL 03:26:22.455] * (100) [AS3i]
	via 179.1.2.2 on ext_2_ALL
	Type: BGP univ
	BGP.as_path: 2 3
	BGP.local_pref: 200
                     unicast [ebgp_ext_3_MSP 03:26:22.780] (100) [AS3i]
	via 179.1.3.2 on ext_3_MSP
	Type: BGP univ
	BGP.as_path: 3 3 3 3
	BGP.local_pref: 250
`
	state, err := readBirdBGP(context.Background(), &model.Device{ID: "as1/ALL"},
		netstate.ExecFunc(func(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
			if len(command) > 0 && command[len(command)-1] == "all" {
				return runtime.ExecResult{Stdout: routes}, nil
			}
			return runtime.ExecResult{}, nil
		}), netstate.QueryBGPRIB)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Paths) != 2 {
		t.Fatalf("BIRD paths = %#v, want both paths for 3.0.0.0/8", state.Paths)
	}
	for i, want := range []struct {
		path string
		hop  string
		best bool
	}{
		{path: "2 3", hop: "179.1.2.2", best: true},
		{path: "3 3 3 3", hop: "179.1.3.2"},
	} {
		got := state.Paths[i]
		if got.Prefix != "3.0.0.0/8" || got.ASPath != want.path ||
			len(got.NextHops) != 1 || got.NextHops[0].Address != want.hop ||
			got.Best != want.best {
			t.Errorf("path %d = %#v, want prefix/path/hop/best %q/%q/%q/%v",
				i, got, "3.0.0.0/8", want.path, want.hop, want.best)
		}
	}
}
