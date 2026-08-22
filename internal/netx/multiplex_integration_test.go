//go:build linux

package netx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	goruntime "runtime"
	"slices"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// This is deliberately root-gated: it exercises the kernel data path rather
// than asserting implementation details. It proves that two VNIs share one
// external VXLAN device while an ARP broadcast from one access VLAN does not
// appear on the other.
func TestMultiplexOverlaySharesTunnelAndIsolatesFrames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	hostA := integrationNS(t, origin, "host-a")
	hostB := integrationNS(t, origin, "host-b")
	clientA1 := integrationNS(t, origin, "client-a1")
	clientA2 := integrationNS(t, origin, "client-a2")
	clientB1 := integrationNS(t, origin, "client-b1")
	clientB2 := integrationNS(t, origin, "client-b2")

	root, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := createUnderlay(root, hostA, hostB, "tmuxua", "tmuxub"); err != nil {
		integrationSupport(t, err)
		t.Fatal(err)
	}
	if err := configureUnderlay(hostA, "tmuxua", "198.18.0.1/24"); err != nil {
		t.Fatal(err)
	}
	if err := configureUnderlay(hostB, "tmuxub", "198.18.0.2/24"); err != nil {
		t.Fatal(err)
	}

	vlans, err := AssignOverlayVLANs([]uint32{5001, 5002})
	if err != nil {
		t.Fatal(err)
	}
	vxlanPort, err := MultiplexOverlayPort("mux-test", "host-a", "host-b")
	if err != nil {
		t.Fatal(err)
	}
	bridgeA := ensureIntegrationOverlay(t, hostA, MultiplexOverlaySpec{
		Lab: "mux-test", LocalNode: "host-a", RemoteNode: "host-b",
		LocalIP: "198.18.0.1", RemoteIP: "198.18.0.2", UnderlayDev: "tmuxua",
		MTU: 1400, VNI: 5001, VLAN: vlans[5001],
	})
	if got := ensureIntegrationOverlay(t, hostA, MultiplexOverlaySpec{
		Lab: "mux-test", LocalNode: "host-a", RemoteNode: "host-b",
		LocalIP: "198.18.0.1", RemoteIP: "198.18.0.2", UnderlayDev: "tmuxua",
		MTU: 1400, VNI: 5002, VLAN: vlans[5002],
	}); got != bridgeA {
		t.Fatalf("two links on host A created different bridges: %q and %q", bridgeA, got)
	}
	bridgeB := ensureIntegrationOverlay(t, hostB, MultiplexOverlaySpec{
		Lab: "mux-test", LocalNode: "host-b", RemoteNode: "host-a",
		LocalIP: "198.18.0.2", RemoteIP: "198.18.0.1", UnderlayDev: "tmuxub",
		MTU: 1400, VNI: 5001, VLAN: vlans[5001],
	})
	if got := ensureIntegrationOverlay(t, hostB, MultiplexOverlaySpec{
		Lab: "mux-test", LocalNode: "host-b", RemoteNode: "host-a",
		LocalIP: "198.18.0.2", RemoteIP: "198.18.0.1", UnderlayDev: "tmuxub",
		MTU: 1400, VNI: 5002, VLAN: vlans[5002],
	}); got != bridgeB {
		t.Fatalf("two links on host B created different bridges: %q and %q", bridgeB, got)
	}
	assertSinglePairDevices(t, hostA, "mux-test", "host-a", "host-b")
	assertSinglePairDevices(t, hostB, "mux-test", "host-a", "host-b")
	assertIntegrationListing(t, hostA)

	macA1 := attachIntegrationEndpoint(t, hostA, clientA1, "tmha1", "tma1", bridgeA, vlans[5001], "10.77.1.1/24")
	attachIntegrationEndpoint(t, hostB, clientA2, "tmha2", "tma2", bridgeB, vlans[5001], "10.77.1.2/24")
	attachIntegrationEndpoint(t, hostA, clientB1, "tmhb1", "tmb1", bridgeA, vlans[5002], "10.77.2.1/24")
	attachIntegrationEndpoint(t, hostB, clientB2, "tmhb2", "tmb2", bridgeB, vlans[5002], "10.77.2.2/24")

	udpReady := make(chan error, 1)
	udpResult := make(chan error, 1)
	go receiveIntegrationUDP(clientA2, "10.77.1.2", 29001, udpReady, udpResult)
	if err := <-udpReady; err != nil {
		t.Fatalf("start same-VNI UDP receiver: %v", err)
	}
	rawReady := make(chan error, 1)
	rawResult := make(chan error, 1)
	go receiveForeignFrame(clientB2, "tmb2", macA1, rawReady, rawResult)
	if err := <-rawReady; err != nil {
		t.Fatalf("start isolated-VLAN frame receiver: %v", err)
	}
	vxlanTXReady, vxlanRXReady := make(chan error, 1), make(chan error, 1)
	vxlanTX, vxlanRX := make(chan bool, 1), make(chan bool, 1)
	go captureVXLANPacket(hostA, "tmuxua", vxlanPort, vxlanTXReady, vxlanTX)
	go captureVXLANPacket(hostB, "tmuxub", vxlanPort, vxlanRXReady, vxlanRX)
	if err := <-vxlanTXReady; err != nil {
		t.Fatalf("start underlay transmitter capture: %v", err)
	}
	if err := <-vxlanRXReady; err != nil {
		t.Fatalf("start underlay receiver capture: %v", err)
	}

	if err := sendIntegrationUDP(clientA1, "10.77.1.2", 29001, []byte("only-vni-5001")); err != nil {
		t.Fatal(err)
	}
	udpErr := <-udpResult
	txSeen, rxSeen := <-vxlanTX, <-vxlanRX
	if udpErr != nil {
		dumpIntegrationState(t, hostA, hostB, clientA1, clientA2)
		t.Fatalf("same-VNI endpoint did not receive UDP: %v (underlay VXLAN tx=%t rx=%t)",
			udpErr, txSeen, rxSeen)
	}
	if !txSeen || !rxSeen {
		t.Fatalf("same-VNI traffic did not traverse both underlays: tx=%t rx=%t", txSeen, rxSeen)
	}
	if err := <-rawResult; err != nil {
		t.Fatalf("frame leaked from VNI 5001 into VNI 5002: %v", err)
	}

}

// This deliberately disables the in-process pair lock. It models independent
// controller/CLI processes racing against the same host namespace, so EEXIST
// recovery rather than the local lock is what makes this pass.
func TestMultiplexEnsureConcurrentRequestsAndPartialRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	hostA := integrationNS(t, origin, "concurrent-host-a")
	hostB := integrationNS(t, origin, "concurrent-host-b")
	root, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := createUnderlay(root, hostA, hostB, "tmuxca", "tmuxcb"); err != nil {
		integrationSupport(t, err)
		t.Fatal(err)
	}
	if err := configureUnderlay(hostA, "tmuxca", "198.19.0.1/24"); err != nil {
		t.Fatal(err)
	}
	if err := configureUnderlay(hostB, "tmuxcb", "198.19.0.2/24"); err != nil {
		t.Fatal(err)
	}

	type request struct {
		scope string
		vni   uint32
	}
	requests := make([]request, 24)
	for i := range requests {
		requests[i] = request{scope: "same-pair", vni: uint32(6100 + i)}
	}
	// The first two are the real-world collision that triggered the live
	// failure: service and peering wires become runnable together for one
	// shared pair. The remaining requests make the race high fan-out.
	requests[0].scope, requests[1].scope = "service", "peering"
	vnis := make([]uint32, len(requests))
	for i, request := range requests {
		vnis[i] = request.vni
	}
	vlans, err := AssignOverlayVLANs(vnis)
	if err != nil {
		t.Fatal(err)
	}
	setMultiplexLockOverride(t, noMultiplexLock)
	var wg sync.WaitGroup
	errs := make(chan error, len(vnis))
	for _, request := range requests {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := hostA.Do(func() error {
				_, err := EnsureMultiplexOverlay(MultiplexOverlaySpec{
					Lab: "mux-concurrent", LocalNode: "host-a", RemoteNode: "host-b",
					LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
					MTU: 1400, VNI: request.vni, VLAN: vlans[request.vni],
				})
				return err
			})
			if err != nil {
				errs <- fmt.Errorf("%s VNI %d: %w", request.scope, request.vni, err)
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent EnsureMultiplexOverlay: %v", err)
		}
	}
	assertMultiplexVNIs(t, hostA, "mux-concurrent", vnis)
	assertPhysicalInventory(t, hostA, "mux-concurrent", len(vnis), 1)

	// One more matching request must be a no-op reconciliation, not a second
	// object or an EEXIST failure.
	if err := hostA.Do(func() error {
		_, err := EnsureMultiplexOverlay(MultiplexOverlaySpec{
			Lab: "mux-concurrent", LocalNode: "host-b", RemoteNode: "host-a",
			LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
			MTU: 1400, VNI: vnis[0], VLAN: vlans[vnis[0]],
		})
		return err
	}); err != nil {
		t.Fatalf("matching reconciliation: %v", err)
	}

	for i, step := range []string{
		"bridge-created", "vxlan-created", "vxlan-attached", "trunk-ready",
		"binding-vlan", "binding-mapped", "binding-fdb",
	} {
		t.Run(step, func(t *testing.T) {
			lab := fmt.Sprintf("mux-partial-%d", i)
			vni := uint32(7000 + i)
			fired := false
			setMultiplexStepHook(t, func(got string) error {
				if !fired && got == step {
					fired = true
					return errors.New("injected interruption")
				}
				return nil
			})
			spec := MultiplexOverlaySpec{
				Lab: lab, LocalNode: "host-a", RemoteNode: "host-b",
				LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
				MTU: 1400, VNI: vni, VLAN: uint16(1000 + i),
			}
			err := hostA.Do(func() error {
				_, err := EnsureMultiplexOverlay(spec)
				return err
			})
			if err == nil || !fired {
				t.Fatalf("step %s did not leave an interrupted partial object: err=%v fired=%t", step, err, fired)
			}
			if err := hostA.Do(func() error {
				_, err := EnsureMultiplexOverlay(spec)
				return err
			}); err != nil {
				t.Fatalf("recover %s partial object: %v", step, err)
			}
			assertMultiplexVNIs(t, hostA, lab, []uint32{vni})
		})
	}

	t.Run("conflicting-owner-selects-salted-name", func(t *testing.T) {
		lab := "mux-conflict-salt"
		_, vxName, err := MultiplexOverlayNames(lab, "host-a", "host-b")
		if err != nil {
			t.Fatal(err)
		}
		if err := hostA.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: vxName}}); err != nil {
				return err
			}
			link, err := h.LinkByName(vxName)
			if err != nil {
				return err
			}
			return h.LinkSetAlias(link, "foreign-owner")
		}); err != nil {
			t.Fatal(err)
		}
		var bridge string
		if err := hostA.Do(func() error {
			var err error
			bridge, err = EnsureMultiplexOverlay(MultiplexOverlaySpec{
				Lab: lab, LocalNode: "host-a", RemoteNode: "host-b",
				LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
				MTU: 1400, VNI: 7501, VLAN: 1201,
			})
			return err
		}); err != nil {
			t.Fatalf("ensure around conflicting owner: %v", err)
		}
		if bridge == "" {
			t.Fatal("ensure returned no bridge")
		}
		if err := hostA.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			link, err := h.LinkByName(vxName)
			if err != nil {
				return err
			}
			if link.Type() != "dummy" || link.Attrs().Alias != "foreign-owner" {
				return fmt.Errorf("conflicting object was adopted or changed: %s %q", link.Type(), link.Attrs().Alias)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("owned-bridge-plus-conflicting-vxlan-fails-closed", func(t *testing.T) {
		lab := "mux-conflict-paired"
		bridgeName, vxName, err := MultiplexOverlayNames(lab, "host-a", "host-b")
		if err != nil {
			t.Fatal(err)
		}
		key, err := newPairKey(lab, "host-a", "host-b")
		if err != nil {
			t.Fatal(err)
		}
		alias, err := key.alias()
		if err != nil {
			t.Fatal(err)
		}
		if err := hostA.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			if err := h.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}); err != nil {
				return err
			}
			bridge, err := h.LinkByName(bridgeName)
			if err != nil {
				return err
			}
			if err := h.LinkSetAlias(bridge, alias); err != nil {
				return err
			}
			if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: vxName}}); err != nil {
				return err
			}
			vx, err := h.LinkByName(vxName)
			if err != nil {
				return err
			}
			return h.LinkSetAlias(vx, "foreign-owner")
		}); err != nil {
			t.Fatal(err)
		}
		err = hostA.Do(func() error {
			_, err := EnsureMultiplexOverlay(MultiplexOverlaySpec{
				Lab: lab, LocalNode: "host-a", RemoteNode: "host-b",
				LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
				MTU: 1400, VNI: 7502, VLAN: 1202,
			})
			return err
		})
		if err == nil {
			t.Fatal("ensure adopted a conflicting VXLAN beside an owned bridge")
		}
	})

	t.Run("active-standard-port-survives-port-allocation-upgrade", func(t *testing.T) {
		const lab = "mux-legacy-port"
		spec := MultiplexOverlaySpec{
			Lab: lab, LocalNode: "host-a", RemoteNode: "host-b",
			LocalIP: "198.19.0.1", RemoteIP: "198.19.0.2", UnderlayDev: "tmuxca",
			MTU: 1400, Port: VXLANPort, VNI: 7601, VLAN: 1301,
		}
		if err := hostA.Do(func() error {
			_, err := EnsureMultiplexOverlay(spec)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		spec.Port = 0 // New topology-wide allocator would choose another port.
		if err := hostA.Do(func() error {
			_, err := EnsureMultiplexOverlay(spec)
			return err
		}); err != nil {
			t.Fatalf("active legacy-port reconciliation: %v", err)
		}
		_, vxName, err := MultiplexOverlayNames(lab, "host-a", "host-b")
		if err != nil {
			t.Fatal(err)
		}
		if err := hostA.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			link, err := h.LinkByName(vxName)
			if err != nil {
				return err
			}
			vx, ok := link.(*netlink.Vxlan)
			if !ok || vx.Port != VXLANPort {
				return fmt.Errorf("legacy active trunk port = %#v, want %d", link, VXLANPort)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMultiplexUpgradeLegacyNoChangeAndRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and CAP_NET_ADMIN")
	}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	origin, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	hostA := integrationNS(t, origin, "upgrade-host-a")
	hostB := integrationNS(t, origin, "upgrade-host-b")
	root, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := createUnderlay(root, hostA, hostB, "tmuxla", "tmuxlb"); err != nil {
		integrationSupport(t, err)
		t.Fatal(err)
	}
	if err := configureUnderlay(hostA, "tmuxla", "198.20.0.1/24"); err != nil {
		t.Fatal(err)
	}
	if err := configureUnderlay(hostB, "tmuxlb", "198.20.0.2/24"); err != nil {
		t.Fatal(err)
	}
	const lab = "mux-upgrade"
	vnis := []uint32{8001, 8002}
	vlans, err := AssignOverlayVLANs(vnis)
	if err != nil {
		t.Fatal(err)
	}
	for i, vni := range vnis {
		ensureLegacyUpgradeSide(t, hostA, lab, "198.20.0.1", "198.20.0.2", "tmuxla",
			fmt.Sprintf("tmula%d", i), vni)
		ensureLegacyUpgradeSide(t, hostB, lab, "198.20.0.2", "198.20.0.1", "tmuxlb",
			fmt.Sprintf("tmulb%d", i), vni)
	}
	for i, vni := range vnis {
		upgradeLegacySide(t, hostA, lab, "host-a", "host-b", "198.20.0.1", "198.20.0.2",
			"tmuxla", fmt.Sprintf("tmula%d", i), vni, vlans[vni])
		upgradeLegacySide(t, hostB, lab, "host-b", "host-a", "198.20.0.2", "198.20.0.1",
			"tmuxlb", fmt.Sprintf("tmulb%d", i), vni, vlans[vni])
	}
	assertMultiplexVNIs(t, hostA, lab, vnis)
	assertMultiplexVNIs(t, hostB, lab, vnis)
	assertLegacyGone(t, hostA, vnis)
	assertLegacyGone(t, hostB, vnis)

	// Re-applying the exact desired state must reuse the trunk and mappings.
	for i, vni := range vnis {
		upgradeLegacySide(t, hostA, lab, "host-a", "host-b", "198.20.0.1", "198.20.0.2",
			"tmuxla", fmt.Sprintf("tmula%d", i), vni, vlans[vni])
		upgradeLegacySide(t, hostB, lab, "host-b", "host-a", "198.20.0.2", "198.20.0.1",
			"tmuxlb", fmt.Sprintf("tmulb%d", i), vni, vlans[vni])
	}
	assertMultiplexVNIs(t, hostA, lab, vnis)
	assertMultiplexVNIs(t, hostB, lab, vnis)

	// Model a forward apply that added a new cross-node wire, then roll it
	// back to the previous topology. Existing trunks and their old VNIs must
	// survive; only the forward binding and its access port may disappear.
	const forwardVNI = 8003
	forwardVLAN := uint16(1203)
	for _, side := range []struct {
		ns                                                   *NS
		localNode, remoteNode, local, remote, underlay, port string
	}{
		{hostA, "host-a", "host-b", "198.20.0.1", "198.20.0.2", "tmuxla", "tmulfa"},
		{hostB, "host-b", "host-a", "198.20.0.2", "198.20.0.1", "tmuxlb", "tmulfb"},
	} {
		if err := side.ns.Do(func() error {
			bridge, err := EnsureMultiplexOverlay(MultiplexOverlaySpec{
				Lab: lab, LocalNode: side.localNode, RemoteNode: side.remoteNode,
				LocalIP: side.local, RemoteIP: side.remote, UnderlayDev: side.underlay,
				MTU: 1400, VNI: forwardVNI, VLAN: forwardVLAN,
			})
			if err != nil {
				return err
			}
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: side.port}}); err != nil {
				return err
			}
			return AttachToMultiplexOverlay(side.port, bridge, forwardVLAN)
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, side := range []struct {
		ns   *NS
		port string
	}{
		{hostA, "tmulfa"}, {hostB, "tmulfb"},
	} {
		if err := side.ns.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			port, err := h.LinkByName(side.port)
			if err != nil {
				return err
			}
			if err := h.LinkDel(port); err != nil {
				return err
			}
			return RemoveOverlay(forwardVNI)
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertMultiplexVNIs(t, hostA, lab, vnis)
	assertMultiplexVNIs(t, hostB, lab, vnis)
}

func ensureLegacyUpgradeSide(t *testing.T, ns *NS, lab, local, remote, underlay, port string, vni uint32) {
	t.Helper()
	if err := ns.Do(func() error {
		bridge, err := EnsureOverlay(OverlaySpec{
			Lab: lab, VNI: vni, LocalIP: local, RemoteIP: remote, UnderlayDev: underlay, MTU: 1400,
		})
		if err != nil {
			return err
		}
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: port}}); err != nil {
			return err
		}
		return AttachToBridgeByName(port, bridge)
	}); err != nil {
		t.Fatal(err)
	}
}

func upgradeLegacySide(t *testing.T, ns *NS, lab, localNode, remoteNode, local, remote, underlay,
	port string, vni uint32, vlan uint16) {
	t.Helper()
	if err := ns.Do(func() error {
		bridge, err := EnsureMultiplexOverlay(MultiplexOverlaySpec{
			Lab: lab, LocalNode: localNode, RemoteNode: remoteNode,
			LocalIP: local, RemoteIP: remote, UnderlayDev: underlay, MTU: 1400,
			VNI: vni, VLAN: vlan,
		})
		if err != nil {
			return err
		}
		if err := AttachToMultiplexOverlay(port, bridge, vlan); err != nil {
			return err
		}
		return RemoveLegacyOverlayForLab(vni, lab)
	}); err != nil {
		t.Fatal(err)
	}
}

func assertLegacyGone(t *testing.T, ns *NS, vnis []uint32) {
	t.Helper()
	if err := ns.Do(func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		for _, vni := range vnis {
			for _, name := range []string{VxlanName(vni), BridgeName(vni)} {
				if _, err := h.LinkByName(name); err == nil {
					return fmt.Errorf("legacy object %s remains after migration", name)
				} else if !IsNotFound(err) {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertMultiplexVNIs(t *testing.T, ns *NS, lab string, want []uint32) {
	t.Helper()
	want = append([]uint32(nil), want...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	err := ns.Do(func() error {
		overlays, err := ListMultiplexOverlaysOfLab(lab)
		if err != nil {
			return err
		}

		if len(overlays) != 1 {
			return fmt.Errorf("%s has %d shared overlays, want one: %#v", lab, len(overlays), overlays)
		}
		if !slices.Equal(overlays[0].VNIs, want) {
			return fmt.Errorf("%s VNIs = %v, want %v", lab, overlays[0].VNIs, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertPhysicalInventory(t *testing.T, ns *NS, lab string, bindings, trunks int) {
	t.Helper()
	if err := ns.Do(func() error {
		inventory, err := InspectOverlayInventory(lab)
		if err != nil {
			return err
		}
		if len(inventory.Bindings) != bindings || len(inventory.Trunks) != trunks {
			return fmt.Errorf("%s inventory = %d bindings / %d trunks, want %d / %d",
				lab, len(inventory.Bindings), len(inventory.Trunks), bindings, trunks)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func dumpIntegrationState(t *testing.T, namespaces ...*NS) {
	t.Helper()
	for _, ns := range namespaces {
		err := ns.Do(func() error {
			h, err := netlink.NewHandle()
			if err != nil {
				return err
			}
			defer h.Close()
			links, err := h.LinkList()
			if err != nil {
				return err
			}
			vlans, err := h.BridgeVlanList()
			if err != nil {
				return err
			}
			tunnels, err := h.BridgeVlanTunnelShow()
			if err != nil {
				return err
			}
			for _, link := range links {
				t.Logf("%s link %s type=%s idx=%d master=%d up=%t alias=%q",
					ns.path, link.Attrs().Name, link.Type(), link.Attrs().Index,
					link.Attrs().MasterIndex, link.Attrs().Flags&net.FlagUp != 0, link.Attrs().Alias)
				if stats := link.Attrs().Statistics; stats != nil {
					t.Logf("%s link %s stats=%+v", ns.path, link.Attrs().Name, *stats)
				}
				if addrs, aerr := h.AddrList(link, netlink.FAMILY_V4); aerr == nil && len(addrs) > 0 {
					t.Logf("%s addresses on %s: %v", ns.path, link.Attrs().Name, addrs)
				}
				if routes, rerr := h.RouteList(link, netlink.FAMILY_V4); rerr == nil && len(routes) > 0 {
					t.Logf("%s routes on %s: %v", ns.path, link.Attrs().Name, routes)
				}
				if info := vlans[int32(link.Attrs().Index)]; len(info) > 0 {
					t.Logf("%s VLANs on %s: %v", ns.path, link.Attrs().Name, info)
				}
				if vx, ok := link.(*netlink.Vxlan); ok {
					fdb, ferr := h.NeighList(vx.Attrs().Index, syscall.AF_BRIDGE)
					t.Logf("%s VXLAN %s flow=%t id=%d local=%s port=%d FDB=%v err=%v",
						ns.path, vx.Attrs().Name, vx.FlowBased, vx.VxlanId, vx.SrcAddr, vx.Port, fdb, ferr)
				}
			}
			t.Logf("%s VLAN tunnel mappings: %v", ns.path, tunnels)
			return nil
		})
		if err != nil {
			t.Logf("dump %s: %v", ns.path, err)
		}
	}
}

func integrationNS(t *testing.T, origin netns.NsHandle, label string) *NS {
	t.Helper()
	handle, err := netns.New()
	if err != nil {
		integrationSupport(t, err)
		t.Fatal(err)
	}
	if err := netns.Set(origin); err != nil {
		_ = handle.Close()
		t.Fatalf("restore origin after creating %s: %v", label, err)
	}
	ns := &NS{handle: handle, path: label}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func integrationSupport(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOTSUP) {
		t.Skipf("kernel namespace/VLAN-tunnel support is unavailable: %v", err)
	}
}

func createUnderlay(h *netlink.Handle, left, right *NS, a, b string) error {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a, MTU: 1500}, PeerName: b}
	if err := h.LinkAdd(veth); err != nil {
		return err
	}
	aLink, err := h.LinkByName(a)
	if err != nil {
		return err
	}
	bLink, err := h.LinkByName(b)
	if err != nil {
		return err
	}
	if err := h.LinkSetNsFd(aLink, left.Fd()); err != nil {
		return err
	}
	return h.LinkSetNsFd(bLink, right.Fd())
}

func configureUnderlay(ns *NS, name, cidr string) error {
	h, err := ns.Handle()
	if err != nil {
		return err
	}
	defer h.Close()
	if lo, err := h.LinkByName("lo"); err == nil {
		if err := h.LinkSetUp(lo); err != nil {
			return err
		}
	}
	link, err := h.LinkByName(name)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := h.AddrAdd(link, addr); err != nil && !isExist(err) {
		return err
	}
	return h.LinkSetUp(link)
}

func ensureIntegrationOverlay(t *testing.T, ns *NS, spec MultiplexOverlaySpec) string {
	t.Helper()
	var bridge string
	err := ns.Do(func() error {
		var err error
		bridge, err = EnsureMultiplexOverlay(spec)
		return err
	})
	if err != nil {
		integrationSupport(t, err)
		t.Fatal(err)
	}
	return bridge
}

func assertSinglePairDevices(t *testing.T, ns *NS, lab, first, second string) {
	t.Helper()
	key, err := newPairKey(lab, first, second)
	if err != nil {
		t.Fatal(err)
	}

	alias, err := key.alias()
	if err != nil {
		t.Fatal(err)
	}
	h, err := ns.Handle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	links, err := h.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	bridges, tunnels := 0, 0
	for _, link := range links {
		if link.Attrs().Alias != alias {
			continue
		}
		switch link.(type) {
		case *netlink.Bridge:
			bridges++
		case *netlink.Vxlan:
			tunnels++
		}
	}
	if bridges != 1 || tunnels != 1 {
		t.Fatalf("pair %s/%s has %d bridges and %d VXLANs, want one each", first, second, bridges, tunnels)
	}
}

func assertIntegrationListing(t *testing.T, ns *NS) {
	t.Helper()
	err := ns.Do(func() error {
		overlays, err := ListMultiplexOverlaysOfLab("mux-test")
		if err != nil {
			return err
		}
		if len(overlays) != 1 || len(overlays[0].VNIs) != 2 ||
			overlays[0].VNIs[0] != 5001 || overlays[0].VNIs[1] != 5002 {
			return fmt.Errorf("multiplex listing = %#v, want one pair with VNIs 5001 and 5002", overlays)
		}
		vnis, err := ListOverlaysOfLab("mux-test")
		if err != nil {
			return err
		}
		if len(vnis) != 2 || vnis[0] != 5001 || vnis[1] != 5002 {
			return fmt.Errorf("overlay VNI listing = %v", vnis)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func attachIntegrationEndpoint(t *testing.T, host, client *NS, hostName, clientName, bridge string,
	vlan uint16, cidr string) net.HardwareAddr {
	t.Helper()
	err := host.Do(func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostName, MTU: 1400}, PeerName: clientName}
		if err := h.LinkAdd(veth); err != nil {
			return err
		}
		peer, err := h.LinkByName(clientName)
		if err != nil {
			return err
		}
		if err := h.LinkSetNsFd(peer, client.Fd()); err != nil {
			return err
		}
		return AttachToMultiplexOverlay(hostName, bridge, vlan)
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := client.Handle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if lo, err := h.LinkByName("lo"); err == nil {
		if err := h.LinkSetUp(lo); err != nil {
			t.Fatal(err)
		}
	}
	link, err := h.LinkByName(clientName)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.AddrAdd(link, addr); err != nil && !isExist(err) {
		t.Fatal(err)
	}
	if err := h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	return append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...)
}

func receiveIntegrationUDP(ns *NS, ip string, port int, ready chan<- error, result chan<- error) {
	readySent := false
	err := ns.Do(func() error {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
		if err != nil {
			return err
		}
		defer conn.Close()
		ready <- nil
		readySent = true
		if err := conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return err
		}
		buf := make([]byte, 128)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			result <- err
			return nil
		}
		if got := string(buf[:n]); got != "only-vni-5001" {
			result <- fmt.Errorf("unexpected UDP body %q", got)
			return nil
		}
		result <- nil
		return nil
	})
	if err != nil {
		if !readySent {
			ready <- err
			return
		}
		result <- err
	}
}

func sendIntegrationUDP(ns *NS, ip string, port int, body []byte) error {
	return ns.Do(func() error {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: port})
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write(body)
		return err
	})
}

func captureVXLANPacket(ns *NS, iface string, vxlanPort int, ready chan<- error, result chan<- bool) {
	readySent := false
	err := ns.Do(func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName(iface)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  link.Attrs().Index,
		}); err != nil {
			return err
		}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
			&unix.Timeval{Sec: 3}); err != nil {
			return err
		}
		ready <- nil
		readySent = true
		buf := make([]byte, 2048)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					result <- false
					return nil
				}
				return err
			}
			if isVXLANUDP(buf[:n], vxlanPort) {
				result <- true
				return nil
			}
		}
	})
	if err != nil {
		if !readySent {
			ready <- err
			return
		}
		result <- false
	}
}

func isVXLANUDP(frame []byte, vxlanPort int) bool {
	if len(frame) < 14+20+8 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return false
	}
	ipStart := 14
	ihl := int(frame[ipStart]&0x0f) * 4
	if ihl < 20 || len(frame) < ipStart+ihl+8 || frame[ipStart+9] != unix.IPPROTO_UDP {
		return false
	}
	udpStart := ipStart + ihl
	return binary.BigEndian.Uint16(frame[udpStart:udpStart+2]) == uint16(vxlanPort) ||
		binary.BigEndian.Uint16(frame[udpStart+2:udpStart+4]) == uint16(vxlanPort)
}

func receiveForeignFrame(ns *NS, iface string, foreignMAC net.HardwareAddr, ready chan<- error, result chan<- error) {
	readySent := false
	err := ns.Do(func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName(iface)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: htons(unix.ETH_P_ALL),
			Ifindex:  link.Attrs().Index,
		}); err != nil {
			return err
		}
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
			&unix.Timeval{Sec: 3}); err != nil {
			return err
		}
		ready <- nil
		readySent = true
		buf := make([]byte, 2048)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					result <- nil
					return nil
				}
				return err
			}
			if n >= 12 && bytes.Equal(buf[6:12], foreignMAC) {
				result <- fmt.Errorf("received Ethernet frame from %s", foreignMAC)
				return nil
			}
		}
	})
	if err != nil {
		if !readySent {
			ready <- err
			return
		}
		result <- err
	}
}

func htons(v uint16) uint16 {
	var b [2]byte
	nl.NativeEndian().PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
