package netx

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestMultiplexNamesArePairStableAndBounded(t *testing.T) {
	brAB, vxAB, err := MultiplexOverlayNames("cos461", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}

	brBA, vxBA, err := MultiplexOverlayNames("cos461", "node-b", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if brAB != brBA || vxAB != vxBA {
		t.Fatalf("node-pair names differ by endpoint order: %s/%s vs %s/%s", brAB, vxAB, brBA, vxBA)
	}
	if len(brAB) > 15 || len(vxAB) > 15 {
		t.Fatalf("multiplex names exceed IFNAMSIZ: %q / %q", brAB, vxAB)
	}
	other, _, err := MultiplexOverlayNames("cos461", "node-a", "node-c")
	if err != nil {
		t.Fatal(err)
	}
	if other == brAB {
		t.Fatalf("different pairs got the same deterministic bridge name %q", other)
	}
	key, err := newPairKey("cos461", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if pairDeviceName("twbp", key, 0) == pairDeviceName("twbp", key, 1) {
		t.Fatal("name collision retry salt did not produce a distinct bridge candidate")
	}
}

func TestAssignMultiplexPortsIsStableAndPairUnique(t *testing.T) {
	pairs := [][2]string{{"node-a", "node-b"}, {"node-a", "node-c"}, {"node-b", "node-c"}}
	first, err := AssignMultiplexPorts("cos461", pairs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssignMultiplexPorts("cos461", [][2]string{
		{"node-b", "node-c"}, {"node-a", "node-b"}, {"node-a", "node-c"},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, pair := range pairs {
		id, err := MultiplexPairID(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		port := first[id]
		if port < multiplexPortFirst || port > multiplexPortLast {
			t.Fatalf("pair %q got out-of-range port %d", id, port)
		}
		if seen[port] {
			t.Fatalf("multiple pairs received UDP port %d: %#v", port, first)
		}
		seen[port] = true
		if second[id] != port {
			t.Fatalf("pair %q port changed from %d to %d with input order", id, port, second[id])
		}
	}
}

func TestTwoLabsNeverShareOverlayPairIdentity(t *testing.T) {
	leftBridge, leftVXLAN, err := MultiplexOverlayNames("lab-a", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	rightBridge, rightVXLAN, err := MultiplexOverlayNames("lab-b", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if leftBridge == rightBridge || leftVXLAN == rightVXLAN {
		t.Fatalf("two labs share a multiplex overlay identity: %s/%s and %s/%s",
			leftBridge, leftVXLAN, rightBridge, rightVXLAN)
	}
	left, err := newPairKey("lab-a", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	right, err := newPairKey("lab-b", "node-a", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if left.identity() == right.identity() || left.lab == right.lab {
		t.Fatalf("lab ownership is absent from the overlay isolation key: %#v %#v", left, right)
	}
}

func TestMultiplexAliasCarriesFullOwnerIdentity(t *testing.T) {
	key, err := newPairKey("cos461-g3", "node-b", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := key.alias()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := pairKeyFromAlias(alias)
	if !ok || got != key {
		t.Fatalf("pair alias did not round trip: %q -> %#v", alias, got)
	}
	if owner := ownerFromAlias(alias); owner != "cos461-g3" {
		t.Fatalf("ownerFromAlias(%q) = %q, want lab", alias, owner)
	}
}

func TestAssignOverlayVLANsIsDeterministicAndResolvesCollisions(t *testing.T) {
	// These two VNIs share the same first 12-bit candidate.
	first, err := AssignOverlayVLANs([]uint32{4095, 1, 8190})
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssignOverlayVLANs([]uint32{8190, 1, 4095})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint16]bool{}
	for vni, vlan := range first {
		if vlan == 0 || vlan > maxVLANID {
			t.Fatalf("VNI %d got invalid VLAN %d", vni, vlan)
		}
		if seen[vlan] {
			t.Fatalf("two VNIs received VLAN %d: %#v", vlan, first)
		}
		seen[vlan] = true
		if second[vni] != vlan {
			t.Fatalf("VNI %d changed from VLAN %d to %d with input order", vni, vlan, second[vni])
		}
	}
	if _, err := AssignOverlayVLANs([]uint32{0}); err == nil {
		t.Fatal("zero VNI was accepted")
	}
	tooMany := make([]uint32, maxVLANID+1)
	for i := range tooMany {
		tooMany[i] = uint32(i + 1)
	}
	if _, err := AssignOverlayVLANs(tooMany); err == nil {
		t.Fatalf("%d links were accepted despite the %d VLAN bound", len(tooMany), maxVLANID)
	}
}

func TestMultiplexVXLANObservationRequiresExternalMode(t *testing.T) {
	vx := &netlink.Vxlan{
		LinkAttrs:    netlink.LinkAttrs{Name: "twvp00000000000", MTU: 1500},
		FlowBased:    true,
		SrcAddr:      net.ParseIP("10.0.0.1"),
		Port:         VXLANPort,
		VtepDevIndex: 7,
		Learning:     false,
	}
	if reason := multiplexVXLANReason(vx, net.ParseIP("10.0.0.1"), 7, VXLANPort, 1500); reason != "" {
		t.Fatalf("matching external VXLAN would be rebuilt: %s", reason)
	}
	vx.FlowBased = false
	if reason := multiplexVXLANReason(vx, net.ParseIP("10.0.0.1"), 7, VXLANPort, 1500); reason == "" {
		t.Fatal("fixed-VNI VXLAN was accepted as a shared external tunnel")
	}
}

func TestMultiplexLocksArePairScoped(t *testing.T) {
	key := "lab\x00node-a\x00node-b"
	unlockA := lockMultiplexKeys([]string{key})
	releasedA := false
	defer func() {
		if !releasedA {
			unlockA()
		}
	}()
	acquiredOther := make(chan func(), 1)
	go func() {
		acquiredOther <- lockMultiplexKeys([]string{"lab\x00node-a\x00node-c"})
	}()
	select {
	case unlock := <-acquiredOther:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("independent node pairs were serialized behind one overlay lock")
	}
	acquiredSame := make(chan func(), 1)
	go func() {
		acquiredSame <- lockMultiplexKeys([]string{key})
	}()
	select {
	case unlock := <-acquiredSame:
		unlock()
		t.Fatal("two links on one pair acquired the reconciliation lock concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	unlockA()
	releasedA = true
	select {
	case unlock := <-acquiredSame:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("same-pair lock was not released")
	}
}

func setMultiplexLockOverride(t *testing.T, override func([]string) func()) {
	t.Helper()
	multiplexLockOverrides.Lock()
	previous := multiplexLockOverrides.override
	multiplexLockOverrides.override = override
	multiplexLockOverrides.Unlock()
	t.Cleanup(func() {
		multiplexLockOverrides.Lock()
		multiplexLockOverrides.override = previous
		multiplexLockOverrides.Unlock()
	})
}

func setMultiplexStepHook(t *testing.T, hook func(string) error) {
	t.Helper()
	multiplexStepHooks.Lock()
	previous := multiplexStepHooks.hook
	multiplexStepHooks.hook = hook
	multiplexStepHooks.Unlock()
	t.Cleanup(func() {
		multiplexStepHooks.Lock()
		multiplexStepHooks.hook = previous
		multiplexStepHooks.Unlock()
	})
}

func noMultiplexLock([]string) func() { return func() {} }
