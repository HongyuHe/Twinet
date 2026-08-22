package grade

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestKernelForwardsManyUsesOneAgentSideBatch(t *testing.T) {
	calls := 0
	env := &Env{Exec: func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
		calls++
		if len(command) < 5 || command[0] != "sh" || command[1] != "-c" {
			t.Fatalf("want one shell batch, got %v", command)
		}
		return rt.ExecResult{Stdout: "@ 0\n192.0.2.2 via 192.0.2.1 dev eth0 src 192.0.2.3\n@ 1\n198.51.100.2 dev eth1 src 198.51.100.1\n"}, nil
	}}
	got, err := env.kernelForwardsMany(context.Background(), "as3/MSP",
		[]string{"192.0.2.2", "198.51.100.2"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !got["192.0.2.2"].ok || !got["198.51.100.2"].ok {
		t.Fatalf("calls=%d results=%#v", calls, got)
	}
}

func TestResolveNextHopsBatchedDeduplicatesPerRouter(t *testing.T) {
	router := &model.Device{ID: "as3/MSP", Name: "MSP", ASN: 3, Kind: model.KindRouter}
	env := &Env{
		Topology: &model.Topology{
			Devices: map[string]*model.Device{router.ID: router},
			ASes:    map[int]*model.AS{3: {ASN: 3, Routers: []*model.Device{router}}},
		},
		AS: 3,
		Exec: func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
			return rt.ExecResult{Stdout: "@ 0\n192.0.2.2 via 192.0.2.1 dev eth0\n"}, nil
		},
	}
	results, errs := resolveNextHopsBatched(context.Background(), env, []nextHopUse{
		{router: "MSP", prefix: "10.0.0.0/8", nh: "192.0.2.2"},
		{router: "MSP", prefix: "11.0.0.0/8", nh: "192.0.2.2"},
	})
	if errs["MSP"] != nil || !results["MSP"]["192.0.2.2"].ok {
		t.Fatalf("results=%#v errs=%#v", results, errs)
	}
}
