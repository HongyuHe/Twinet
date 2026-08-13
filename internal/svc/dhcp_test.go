package svc

import (
	"net"
	"net/netip"
	"testing"
)

// discover builds a client request the way busybox's udhcpc does.
func discover(t *testing.T, kind byte, mac net.HardwareAddr, requested netip.Addr) []byte {
	t.Helper()
	p := make([]byte, 240)
	p[0], p[1], p[2] = 1, 1, 6
	copy(p[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(p[28:34], mac)
	p[236], p[237], p[238], p[239] = 99, 130, 83, 99
	p = append(p, 53, 1, kind)
	if requested.IsValid() {
		v := requested.As4()
		p = append(p, 50, 4, v[0], v[1], v[2], v[3])
	}
	return append(p, 255)
}

func optionsOf(t *testing.T, reply []byte) map[byte][]byte {
	t.Helper()
	out := map[byte][]byte{}
	b := reply[240:]
	for i := 0; i < len(b); {
		if b[i] == 255 {
			break
		}
		if b[i] == 0 {
			i++
			continue
		}
		n := int(b[i+1])
		out[b[i]] = b[i+2 : i+2+n]
		i += 2 + n
	}
	return out
}

func testConfig() *DHCPConfig {
	return &DHCPConfig{Subnets: []DHCPSubnet{{
		Subnet: "3.100.0.0/24", First: "3.100.0.200", Last: "3.100.0.240",
		Routers: []string{"3.100.0.1"}, DNS: []string{"198.3.0.2"}, Lease: 600,
	}}}
}

// A lease has to carry an address, a mask, a gateway and a resolver, because
// each of those is something a fault can get wrong and each produces a
// different symptom. A server that answered with an address alone would make
// three of the five DHCP faults unobservable.
func TestALeaseCarriesWhatTheClientNeeds(t *testing.T) {
	s := NewDHCPServer(testConfig())
	mac, _ := net.ParseMAC("02:42:ac:11:00:02")

	reply, _, err := s.handle(discover(t, dhcpDiscover, mac, netip.Addr{}))
	if err != nil || reply == nil {
		t.Fatalf("no answer to a discover: %v", err)
	}
	if reply[0] != 2 {
		t.Fatal("the answer is not a reply")
	}
	yi, _ := netip.AddrFromSlice(reply[16:20])
	if !netip.MustParsePrefix("3.100.0.0/24").Contains(yi) {
		t.Errorf("offered %s, which is not in the subnet", yi)
	}
	opts := optionsOf(t, reply)
	if got := opts[53]; len(got) != 1 || got[0] != dhcpOffer {
		t.Errorf("a discover was answered with message type %v", got)
	}
	for _, c := range []struct {
		code byte
		what string
		want string
	}{
		{1, "the netmask", "255.255.255.0"},
		{3, "the gateway", "3.100.0.1"},
		{6, "the resolver", "198.3.0.2"},
	} {
		v, ok := opts[c.code]
		if !ok || len(v) != 4 {
			t.Errorf("the lease carries no %s, so a fault that changes it has no symptom", c.what)
			continue
		}
		if got := net.IP(v).String(); got != c.want {
			t.Errorf("%s is %s, want %s", c.what, got, c.want)
		}
	}

	// And the same client asking again is given the same address, or every
	// renewal renumbers the network.
	ack, _, err := s.handle(discover(t, dhcpRequest, mac, yi))
	if err != nil || ack == nil {
		t.Fatalf("no answer to a request: %v", err)
	}
	again, _ := netip.AddrFromSlice(ack[16:20])
	if again != yi {
		t.Errorf("the client was offered %s and acknowledged %s", yi, again)
	}
	if got := optionsOf(t, ack)[53]; len(got) != 1 || got[0] != dhcpAck {
		t.Errorf("a request was answered with message type %v", got)
	}
}

// Two clients must not be given the same address.
func TestTwoClientsGetDifferentAddresses(t *testing.T) {
	s := NewDHCPServer(testConfig())
	a, _ := net.ParseMAC("02:42:ac:11:00:02")
	b, _ := net.ParseMAC("02:42:ac:11:00:03")

	ra, _, _ := s.handle(discover(t, dhcpRequest, a, netip.Addr{}))
	rb, _, _ := s.handle(discover(t, dhcpRequest, b, netip.Addr{}))
	if ra == nil || rb == nil {
		t.Fatal("one of the clients was not answered")
	}
	x, _ := netip.AddrFromSlice(ra[16:20])
	y, _ := netip.AddrFromSlice(rb[16:20])
	if x == y {
		t.Errorf("both clients were given %s", x)
	}
}

// A subnet that is not configured must produce silence, not an answer from
// whichever subnet happened to be first. The missing-subnet fault is exactly
// this, and a server that answered anyway would hide it.
func TestAnUnconfiguredSubnetIsNotAnswered(t *testing.T) {
	cfg := testConfig()
	cfg.Subnets = append(cfg.Subnets, DHCPSubnet{
		Subnet: "3.101.0.0/24", First: "3.101.0.200", Last: "3.101.0.240",
		Routers: []string{"3.101.0.1"},
	})
	s := NewDHCPServer(cfg)
	mac, _ := net.ParseMAC("02:42:ac:11:00:04")

	// A relay on a subnet the server does not serve.
	req := discover(t, dhcpDiscover, mac, netip.Addr{})
	copy(req[24:28], []byte{3, 200, 0, 1})
	if reply, _, _ := s.handle(req); reply != nil {
		t.Error("a client on an unserved subnet was answered anyway, so a missing subnet " +
			"has no symptom and the fault about it cannot be observed")
	}
}
