package grade

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

func TestUnreachedOutsideShadowsBatchWithLegacySourceAddress(t *testing.T) {
	router := &model.Device{ID: "as3/R", Name: "R", ASN: 3, Kind: model.KindRouter,
		Ifaces: []*model.Iface{{Name: "lo", Addr4: "3.153.0.1/32"}}}
	host := &model.Device{ID: "as1/H", Name: "H", ASN: 1, Kind: model.KindHost,
		Ifaces: []*model.Iface{{Name: "eth0", Addr4: "1.0.0.2/24"}}}
	var batched, legacy atomic.Int64
	env := &Env{
		Topology: &model.Topology{ASes: map[int]*model.AS{
			1: {ASN: 1, Devices: []*model.Device{host}},
			3: {ASN: 3, Devices: []*model.Device{router}, Routers: []*model.Device{router}},
		}},
		AS: 3, ShadowBatches: true,
		Exec: func(_ context.Context, _ string, command []string) (rt.ExecResult, error) {
			if len(command) == 3 && command[0] == "sh" {
				batched.Add(1)
				if !strings.Contains(command[2], "-I '3.153.0.1'") {
					t.Fatalf("batch did not preserve legacy source address: %q", command[2])
				}
				return rt.ExecResult{Stdout: "@ 0 0\n"}, nil
			}
			if len(command) > 0 && command[0] == "ping" {
				legacy.Add(1)
				return rt.ExecResult{}, nil
			}
			t.Fatalf("unexpected command %v", command)
			return rt.ExecResult{}, nil
		},
	}
	failed, err := unreachedOutside(context.Background(), env, []*model.Device{router})
	if err != nil || len(failed) != 0 || batched.Load() != 1 || legacy.Load() != 1 {
		t.Fatalf("failed=%v err=%v batch=%d legacy=%d", failed, err, batched.Load(), legacy.Load())
	}
}
