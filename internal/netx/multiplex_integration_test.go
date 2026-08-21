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

	if err := sendIntegrationUDP(clientA1, "10.77.1.2", 29001, []byte("only-vni-5001")); err != nil {
		t.Fatal(err)
	}
	if err := <-udpResult; err != nil {
		t.Fatalf("same-VNI endpoint did not receive UDP: %v", err)
	}
	if err := <-rawResult; err != nil {
		t.Fatalf("frame leaked from VNI 5001 into VNI 5002: %v", err)
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
