package expand

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/HongyuHe/twinet/internal/manifest"
	"github.com/HongyuHe/twinet/internal/model"
)

func TestMixedSubstrateExpansionCarriesTypedContracts(t *testing.T) {
	loaded, err := manifest.Load("../../examples/mixed-substrate")
	if err != nil {
		t.Fatal(err)
	}

	if err := loaded.Validate().Err(); err != nil {
		t.Fatal(err)
	}
	result, err := Expand(loaded.Lab)
	if err != nil {
		t.Fatal(err)
	}
	p4, ok := result.Topology.Device("as1/P4")
	if !ok || p4.Kind != model.KindP4 || p4.P4 == nil || p4.P4.Table != "IngressImpl.ipv4_lpm" {
		t.Fatalf("P4 contract did not survive expansion: %#v", p4)
	}
	controller, ok := result.Topology.Device("svc/of")
	if !ok || controller.Kind != model.KindController || controller.OpenFlow == nil || controller.OpenFlow.Port != 6653 {
		t.Fatalf("OpenFlow controller did not survive expansion: %#v", controller)
	}
	switchDevice, ok := result.Topology.Device("as1/FAB_S1")
	if !ok || switchDevice.OpenFlowController != controller.ID {
		t.Fatalf("OVS switch did not receive controller binding: %#v", switchDevice)
	}
	controlLinks := 0
	for _, iface := range switchDevice.Ifaces {
		if iface.Role == model.RoleOpenFlowControl {
			controlLinks++
		}
	}
	if controlLinks != 1 {
		t.Fatalf("switch has %d OpenFlow control links, want one", controlLinks)
	}
	for _, routerID := range []string{"as1/R1", "as1/R2"} {
		router, ok := result.Topology.Device(routerID)
		if !ok {
			t.Fatalf("mixed substrate router %s is absent", routerID)
		}
		if containsCapability(router.Capabilities, "SYS_ADMIN") {
			t.Fatalf("%s has SYS_ADMIN; FRR must use the private control sidecar", routerID)
		}
	}
}

// O12 keeps the student/evaluated-agent router shell out of CAP_SYS_ADMIN.
// The FRR control sidecar is the only place that capability is allowed, so
// this scans every bundled manifest after inheritance/expansion rather than
// trusting a handful of literal kinds.router declarations.
func TestBundledRouterShellsNeverReceiveSysAdmin(t *testing.T) {
	manifests, err := filepath.Glob("../../examples/*")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("no bundled example manifests found")
	}
	for _, path := range manifests {
		loaded, err := manifest.Load(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := loaded.Validate().Err(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		result, err := Expand(loaded.Lab)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, d := range result.Topology.Devices {
			if d.Kind != model.KindRouter {
				continue
			}
			if containsCapability(d.Capabilities, "SYS_ADMIN") {
				t.Errorf("%s: router shell %s has SYS_ADMIN; FRR must use the private control sidecar", path, d.ID)
			}
		}
	}
}

// O12's capability boundary is not router-only: one accidentally privileged
// host, switch, service, controller, or P4 device is still a host escape
// surface. Scan fully inherited bundled devices rather than only literal YAML
// kind defaults.
func TestBundledExpandedDevicesUseOnlyMinimalCapabilities(t *testing.T) {
	manifests, err := filepath.Glob("../../examples/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range manifests {
		loaded, err := manifest.Load(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if err := loaded.Validate().Err(); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		result, err := Expand(loaded.Lab)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, device := range result.Topology.Devices {
			for _, capability := range device.Capabilities {
				normalized := strings.TrimPrefix(strings.ToUpper(capability), "CAP_")
				switch normalized {
				case "NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE", "SYS_NICE":
				default:
					t.Errorf("%s: %s receives non-minimal capability %q", path, device.ID, capability)
				}
				if normalized == "SYS_ADMIN" {
					t.Errorf("%s: %s receives SYS_ADMIN", path, device.ID)
				}
			}
		}
	}
}

func containsCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}
