package netstate

import (
	"context"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/runtime"
)

type kernelExecutor struct{}

func (kernelExecutor) Exec(_ context.Context, _ string, command []string) (runtime.ExecResult, error) {
	switch {
	case len(command) >= 3 && command[0] == "ip" && command[2] == "address":
		return runtime.ExecResult{Stdout: `[{"ifname":"eth0","operstate":"UP","flags":["BROADCAST","UP"],"mtu":1450,"addr_info":[{"family":"inet","local":"192.0.2.1","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8::1","prefixlen":64,"scope":"global"}]}]`}, nil
	case len(command) >= 3 && command[0] == "ip" && command[2] == "route":
		return runtime.ExecResult{Stdout: `[{"dst":"198.51.100.0/24","gateway":"192.0.2.2","dev":"eth0","protocol":"bgp","table":"main"}]`}, nil
	case len(command) == 3 && command[0] == "sysctl" && command[2] == "net.ipv4.ip_forward":
		return runtime.ExecResult{Stdout: "1\n"}, nil
	case len(command) == 3 && command[0] == "sysctl" && command[2] == "net.ipv6.conf.all.forwarding":
		return runtime.ExecResult{Stdout: "1\n"}, nil
	default:
		return runtime.ExecResult{ExitCode: 1, Stderr: "unexpected command"}, nil
	}
}

func TestKernelStateIsVendorNeutral(t *testing.T) {
	device := &model.Device{ID: "as1/R", Kind: model.KindRouter}
	state, err := ReadKernel(context.Background(), device, kernelExecutor{}, QueryInterfaces|QueryKernel)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Interfaces) != 1 || len(state.Interfaces[0].Addresses) != 2 {
		t.Fatalf("interfaces = %#v, want one dual-stack interface", state.Interfaces)
	}
	if !state.Kernel.Forwarding.IPv4 || !state.Kernel.Forwarding.IPv6 {
		t.Fatalf("forwarding = %#v, want both families enabled", state.Kernel.Forwarding)
	}
	if len(state.Kernel.Routes) != 1 || state.Kernel.Routes[0].Protocol != "bgp" {
		t.Fatalf("routes = %#v, want normalized BGP route", state.Kernel.Routes)
	}
}
