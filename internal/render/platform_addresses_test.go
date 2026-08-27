package render

import (
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
)

func TestPlatformRepairAppliesOnlyPlatformOwnedRouterAddresses(t *testing.T) {
	router := &model.Device{
		ID: "as9/HOU", Name: "HOU", Kind: model.KindRouter, ASN: 9, RouterID: 8,
	}
	router.Ifaces = []*model.Iface{
		{Device: router, Name: "lo", Addr4: "9.158.0.1/24", Owner: model.OwnerStudent},
		{
			Device: router, Name: "measurement", Addr4: "9.0.199.1/24",
			Role: model.RoleService, Owner: model.OwnerPlatform,
		},
		{
			Device: router, Name: "port_CHI", Addr4: "9.0.6.2/24",
			Role: model.RoleIntraAS, Owner: model.OwnerStudent,
		},
	}
	topology := &model.Topology{
		Devices: map[string]*model.Device{router.ID: router},
		ASes: map[int]*model.AS{
			9: {
				ASN: 9, Role: model.RoleStudent, Routers: []*model.Device{router},
				Devices: []*model.Device{router},
			},
		},
	}

	commands, err := New(topology, ModePlatform).Commands(router)
	if err != nil {
		t.Fatal(err)
	}
	var rendered strings.Builder
	for _, command := range commands {
		rendered.WriteString(strings.Join(command.Args, " "))
		rendered.WriteByte('\n')
	}
	body := rendered.String()
	if !strings.Contains(body, "ip addr replace 9.0.199.1/24 dev measurement") {
		t.Fatalf("platform-owned service address has no idempotent repair command:\n%s", body)
	}
	for _, studentAddress := range []string{"9.158.0.1/24", "9.0.6.2/24"} {
		if strings.Contains(body, "ip addr replace "+studentAddress) {
			t.Fatalf("platform repair overwrites student address %s:\n%s", studentAddress, body)
		}
	}
}
