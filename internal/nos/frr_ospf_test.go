package nos

import (
	"context"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
	"github.com/HongyuHe/twinet/internal/runtime"
)

func TestReadFRROSPFHandlesCurrentNeighborsWrapper(t *testing.T) {
	raw := `{"neighbors":{"3.151.0.1":[{"nbrState":"Full/DR","address":"3.0.2.1","ifaceName":"port_MSP:3.0.2.2"}]}}`
	got, err := readFRROSPF(context.Background(), &model.Device{ID: "as3/CHI"},
		netstate.ExecFunc(func(context.Context, string, []string) (runtime.ExecResult, error) {
			return runtime.ExecResult{Stdout: raw}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].State != "Full/DR" || got[0].RouterID != "3.151.0.1" {
		t.Fatalf("wrapped OSPF neighbors parsed as %+v", got)
	}
}

func TestBirdStartupDoesNotMatchItsOwnExecShell(t *testing.T) {
	cmds, err := (birdProvider{}).Apply(RenderRequest{Device: &model.Device{ID: "as1/ALL"}})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Join(cmds[0].Args, " ")
	if !strings.Contains(body, `comm= | awk '$2 == "bird"`) {
		t.Fatalf("BIRD startup still uses a self-matching process scan: %q", body)
	}
}
