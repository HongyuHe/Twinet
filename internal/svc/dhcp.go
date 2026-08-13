// DHCP: the lab's own address server.
//
// A teaching lab needs one for two reasons. Several of the fault families this
// platform is meant to reproduce are about DHCP -- a server that has stopped, a
// subnet missing from its configuration, a lease handed out with somebody
// else's gateway or resolver -- and none of them can be injected into a network
// that has no DHCP at all. Adding a fault against a service that does not exist
// would produce an episode with no symptom, which is worse than an absent fault
// because it looks like a working one.
//
// It is written here rather than by shipping isc-dhcp-server for the same
// reason the RPKI validator is: the subset a lab needs is small, the
// configuration is derived from the topology so it cannot drift from it, and a
// fault injector can change one option and know exactly what a correct client
// will do with it. A third-party daemon would bring a configuration language,
// a package repository and a set of behaviours nobody here can debug.
package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// DHCPSubnet is one served network.
type DHCPSubnet struct {
	// Subnet is the network in CIDR form; a request whose relay or interface
	// address falls inside it is answered from here.
	Subnet string `json:"subnet"`
	// First and Last bound the pool.
	First string `json:"first"`
	Last  string `json:"last"`
	// Routers and DNS are what the client is told to use. They are separate
	// fields rather than a generic option map because these are the two a
	// wrong answer is invisible in: a client with a plausible address and the
	// wrong gateway looks configured and reaches nothing.
	Routers []string `json:"routers,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	// Lease is how long a client may keep an address.
	Lease int `json:"lease_seconds,omitempty"`
}

// DHCPConfig is what the server serves.
type DHCPConfig struct {
	Subnets []DHCPSubnet `json:"subnets"`
}

// LoadDHCPConfig reads a server's configuration.
func LoadDHCPConfig(path string) (*DHCPConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c DHCPConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// JSON renders a configuration.
func (c *DHCPConfig) JSON() []byte {
	raw, _ := json.MarshalIndent(c, "", "  ")
	return append(raw, '\n')
}

// BuildDHCP derives a server's configuration from the topology.
//
// Every layer-2 domain of every autonomous system that the manifest attaches a
// DHCP service to gets a subnet, with the gateway router's own address as the
// router option and the lab's resolver as the DNS option. Derived rather than
// written by hand so that a lab which gains a datacentre gains a subnet, and so
// that "the gateway the clients are told about" is by construction the gateway
// they actually have -- which is what makes handing out a wrong one a fault
// rather than a typo somebody made in a fixture.
func BuildDHCP(top *model.Topology, r *model.Device) *DHCPConfig {
	c := &DHCPConfig{}
	if r == nil || r.Kind != model.KindRouter {
		return c
	}
	as, ok := top.ASes[r.ASN]
	if !ok {
		return c
	}
	// The subnets this router is itself on, because a DHCP server has to be on
	// the segment it serves: the client's first packet is a broadcast, and a
	// server one hop away never hears it. Running it on the gateway is both
	// what real deployments do and the only arrangement in which the faults
	// about it produce the symptoms they claim.
	mine := map[string]bool{}
	for _, i := range r.Ifaces {
		// Any segment of its own, including the VLAN sub-interfaces of a
		// datacentre. Requiring a link excluded exactly those -- a sub-interface
		// hangs off a trunk rather than off a cable -- so the gateway of a
		// datacentre with two VLANs and six hosts served one point-to-point
		// subnet with one host on it, and the fault about a missing subnet
		// could not be injected anywhere because no router had two.
		if i.Addr4 == "" || (i.Link != nil && i.Link.InterAS) {
			continue
		}
		if p, err := netip.ParsePrefix(i.Addr4); err == nil {
			mine[p.Masked().String()] = true
		}
	}
	seen := map[string]bool{}
	for _, d := range as.Devices {
		if d.Kind != model.KindHost {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Addr4 == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(i.Addr4)
			if err != nil {
				continue
			}
			net := pfx.Masked()
			if seen[net.String()] || !mine[net.String()] {
				continue
			}
			seen[net.String()] = true
			s := DHCPSubnet{Subnet: net.String(), Lease: 600}
			// The pool starts high enough to leave the addresses the manifest
			// planned alone: a lab is deployed with static addressing and DHCP
			// exists here for the exercises and the faults, so the two must not
			// hand out the same address.
			base := net.Addr().As4()
			first := base
			first[3] = 200
			last := base
			last[3] = 240
			s.First = netip.AddrFrom4(first).String()
			s.Last = netip.AddrFrom4(last).String()
			if gw := addrOnSubnet(r, net); gw != "" {
				s.Routers = []string{gw}
			}
			if dns := ResolverFor(top, r.ASN); dns != "" {
				s.DNS = []string{dns}
			}
			c.Subnets = append(c.Subnets, s)
		}
	}
	sort.Slice(c.Subnets, func(i, j int) bool { return c.Subnets[i].Subnet < c.Subnets[j].Subnet })
	return c
}

// addrOnSubnet returns the address a device has on a network, which for the
// router serving it is what its hosts must be told to use as their gateway.
//
// Derived rather than configured, so that "the gateway the clients are told
// about" is by construction the gateway they actually have -- which is what
// makes handing out a wrong one a fault rather than a typo in a fixture.
func addrOnSubnet(d *model.Device, net netip.Prefix) string {
	for _, i := range d.Ifaces {
		if i.Addr4 == "" {
			continue
		}
		if p, err := netip.ParsePrefix(i.Addr4); err == nil && net.Contains(p.Addr()) {
			return p.Addr().String()
		}
	}
	return ""
}

// ---- The server ------------------------------------------------------------

const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
)

// DHCPServer answers DISCOVER and REQUEST on a set of interfaces.
type DHCPServer struct {
	mu     sync.Mutex
	cfg    *DHCPConfig
	leases map[string]netip.Addr // MAC -> address
	taken  map[netip.Addr]string
}

// NewDHCPServer builds a server around a configuration.
func NewDHCPServer(cfg *DHCPConfig) *DHCPServer {
	return &DHCPServer{
		cfg:    cfg,
		leases: map[string]netip.Addr{},
		taken:  map[netip.Addr]string{},
	}
}

// Update replaces the configuration.
//
// Leases already handed out are kept: a configuration change is not a reason to
// give a client a different address, and a fault that changes the gateway must
// change what the *next* renewal says rather than shuffling everything.
func (s *DHCPServer) Update(cfg *DHCPConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

// Serve answers requests on a packet connection until it is closed.
//
// The hint says which segment this connection is bound to. A DISCOVER carries
// no address at all -- that is what the client is asking for -- so on a server
// with several segments there is nothing in the packet to say which one it came
// from, and a single wildcard socket cannot tell. Measured: with one subnet
// configured every client was served, and the moment the gateway served three
// every DISCOVER went unanswered. One socket per interface, bound to the
// device, restores the one piece of information the protocol leaves out.
func (s *DHCPServer) Serve(pc net.PacketConn) error {
	return s.serveOn(pc, "")
}

func (s *DHCPServer) serveOn(pc net.PacketConn, hint string) error {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		reply, sub, err := s.handleOn(buf[:n], hint)
		if err != nil || reply == nil {
			continue
		}
		// Answered to the subnet's own broadcast address rather than to
		// 255.255.255.255.
		//
		// The client has no address yet, so a unicast reply would have to go
		// to an address it does not hold -- but a limited broadcast has no
		// route on a host with several interfaces and none of them default,
		// and the kernel refuses it: "network is unreachable". The directed
		// broadcast of the subnet the lease came from is reachable over the
		// connected route by construction, and every client on that segment
		// hears it.
		dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
		if b := subnetBroadcast(sub); b != nil {
			dst = &net.UDPAddr{IP: b, Port: 68}
		}
		if u, ok := addr.(*net.UDPAddr); ok && !u.IP.Equal(net.IPv4zero) && u.Port == 68 {
			dst = u
		}
		if _, err := pc.WriteTo(reply, dst); err != nil {
			return err
		}
	}
}

// handle builds the reply to one request, or nil when there is nothing to say.
func (s *DHCPServer) handle(pkt []byte) ([]byte, *DHCPSubnet, error) {
	return s.handleOn(pkt, "")
}

func (s *DHCPServer) handleOn(pkt []byte, hint string) ([]byte, *DHCPSubnet, error) {
	if len(pkt) < 240 || pkt[0] != 1 {
		return nil, nil, nil
	}
	// The magic cookie marks where the options begin.
	if pkt[236] != 99 || pkt[237] != 130 || pkt[238] != 83 || pkt[239] != 99 {
		return nil, nil, nil
	}
	msgType, requested, serverID := parseDHCPOptions(pkt[240:])
	if msgType != dhcpDiscover && msgType != dhcpRequest {
		return nil, nil, nil
	}
	mac := net.HardwareAddr(pkt[28 : 28+int(pkt[2])]).String()
	if pkt[2] == 0 {
		mac = net.HardwareAddr(pkt[28:34]).String()
	}
	// giaddr: which subnet the client is on when a relay forwarded it.
	gi, _ := netip.AddrFromSlice(pkt[24:28])
	ci, _ := netip.AddrFromSlice(pkt[12:16])

	s.mu.Lock()
	defer s.mu.Unlock()

	sub := s.subnetFor(gi, ci, requested, hint)
	if sub == nil {
		// No subnet configured for where this client is. That is exactly the
		// "missing subnet" fault, and the honest answer is silence: a server
		// that answers anyway would hide it.
		return nil, nil, nil
	}
	addr, ok := s.leases[mac]
	if !ok || !containsAddr(sub, addr) {
		addr, ok = s.allocate(sub, mac)
		if !ok {
			return nil, nil, nil
		}
	}
	if msgType == dhcpRequest && requested.IsValid() && requested != addr {
		return s.reply(pkt, dhcpNak, sub, addr), sub, nil
	}
	_ = serverID
	kind := byte(dhcpOffer)
	if msgType == dhcpRequest {
		kind = dhcpAck
		s.leases[mac] = addr
		s.taken[addr] = mac
	}
	return s.reply(pkt, kind, sub, addr), sub, nil
}

func (s *DHCPServer) subnetFor(gi, ci, requested netip.Addr, hint string) *DHCPSubnet {
	// The segment the request arrived on, when the caller knows it. This is
	// the only reliable answer: a DISCOVER carries no address of its own.
	if hint != "" {
		for i := range s.cfg.Subnets {
			if s.cfg.Subnets[i].Subnet == hint {
				return &s.cfg.Subnets[i]
			}
		}
		// Bound to a segment that is no longer configured. That is the
		// missing-subnet fault, and the honest answer is silence.
		return nil
	}
	for i := range s.cfg.Subnets {
		sub := &s.cfg.Subnets[i]
		pfx, err := netip.ParsePrefix(sub.Subnet)
		if err != nil {
			continue
		}
		for _, a := range []netip.Addr{gi, ci, requested} {
			if a.IsValid() && !a.IsUnspecified() && pfx.Contains(a) {
				return sub
			}
		}
	}
	// Nothing to go on: a single-subnet server is unambiguous, and a
	// multi-subnet one cannot guess.
	if len(s.cfg.Subnets) == 1 {
		return &s.cfg.Subnets[0]
	}
	return nil
}

func (s *DHCPServer) allocate(sub *DHCPSubnet, mac string) (netip.Addr, bool) {
	first, err1 := netip.ParseAddr(sub.First)
	last, err2 := netip.ParseAddr(sub.Last)
	if err1 != nil || err2 != nil {
		return netip.Addr{}, false
	}
	for a := first; a.Compare(last) <= 0; a = a.Next() {
		if who, taken := s.taken[a]; !taken || who == mac {
			s.leases[mac] = a
			s.taken[a] = mac
			return a, true
		}
	}
	return netip.Addr{}, false
}

func containsAddr(sub *DHCPSubnet, a netip.Addr) bool {
	pfx, err := netip.ParsePrefix(sub.Subnet)
	return err == nil && a.IsValid() && pfx.Contains(a)
}

// reply builds an OFFER, ACK or NAK.
func (s *DHCPServer) reply(req []byte, kind byte, sub *DHCPSubnet, addr netip.Addr) []byte {
	out := make([]byte, 240, 300)
	out[0] = 2 // BOOTREPLY
	out[1], out[2], out[3] = req[1], req[2], req[3]
	copy(out[4:8], req[4:8])     // xid
	copy(out[24:28], req[24:28]) // giaddr
	copy(out[28:44], req[28:44]) // chaddr
	if kind != dhcpNak {
		a := addr.As4()
		copy(out[16:20], a[:]) // yiaddr
	}
	out[236], out[237], out[238], out[239] = 99, 130, 83, 99

	out = append(out, 53, 1, kind)
	if sid := s.serverID(sub); sid.IsValid() {
		v := sid.As4()
		out = append(out, 54, 4, v[0], v[1], v[2], v[3])
	}
	if kind != dhcpNak {
		if pfx, err := netip.ParsePrefix(sub.Subnet); err == nil {
			mask := net.CIDRMask(pfx.Bits(), 32)
			out = append(out, 1, 4, mask[0], mask[1], mask[2], mask[3])
		}
		lease := sub.Lease
		if lease <= 0 {
			lease = 600
		}
		out = append(out, 51, 4, byte(lease>>24), byte(lease>>16), byte(lease>>8), byte(lease))
		out = appendAddrOption(out, 3, sub.Routers)
		out = appendAddrOption(out, 6, sub.DNS)
	}
	out = append(out, 255)
	return out
}

// serverID is the address the client should talk to, which is ours on that
// subnet. Derived from the router option because that is the only address of
// this network the configuration names.
func (s *DHCPServer) serverID(sub *DHCPSubnet) netip.Addr {
	if len(sub.Routers) > 0 {
		if a, err := netip.ParseAddr(sub.Routers[0]); err == nil {
			return a
		}
	}
	return netip.Addr{}
}

func appendAddrOption(out []byte, code byte, addrs []string) []byte {
	var body []byte
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			continue
		}
		v := a.As4()
		body = append(body, v[:]...)
	}
	if len(body) == 0 {
		return out
	}
	out = append(out, code, byte(len(body)))
	return append(out, body...)
}

// parseDHCPOptions returns the message type, the requested address and the
// server identifier a request carried.
func parseDHCPOptions(b []byte) (msgType byte, requested, serverID netip.Addr) {
	for i := 0; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			break
		}
		val := b[i+2 : i+2+n]
		switch code {
		case 53:
			if n == 1 {
				msgType = val[0]
			}
		case 50:
			if n == 4 {
				requested, _ = netip.AddrFromSlice(val)
			}
		case 54:
			if n == 4 {
				serverID, _ = netip.AddrFromSlice(val)
			}
		}
		i += 2 + n
	}
	return
}

// DHCPListen is the port the server listens on.
const DHCPListen = ":67"

// DHCPReload bounds how long a configuration change takes to take effect.
const DHCPReload = 10 * time.Second

// DHCPConfigPath is where a server's configuration lives inside its container.
//
// Named as a constant because a fault injector edits this file and a verifier
// reads it, and a path written out twice is a path that will differ once.
const DHCPConfigPath = "/etc/twinet/dhcp.json"

// DHCPStartCommand starts the server.
//
// Shared between the deployment and the fault that stops it, so that resolving
// puts back exactly what the deployment started -- and so that neither writes
// the path out again where it would become a marker inside the device telling
// an agent that a fault was injected here.
// Whatever is already running is stopped first.
//
// Two servers on one segment answer the same client with different
// configurations, and which one it hears is a race: a client asking for a lease
// during a fault got no address at all, because the copy the deployment started
// and the copy a fault's resolve started were both listening. Starting is
// therefore idempotent, and a fault that restarts the server leaves one.
const DHCPStartCommand = "for p in $(ps -ef | awk '/twinet-dhcpd/ && !/awk/ {print $1}'); " +
	"do kill $p 2>/dev/null || true; done; sleep 1; " +
	"nohup twinet-dhcpd -config " + DHCPConfigPath +
	" >/var/log/twinet-dhcpd.log 2>&1 &"

// SummariseDHCP renders a configuration for a human, which is what a fault's
// evidence quotes.
func SummariseDHCP(c *DHCPConfig) string {
	var b strings.Builder
	for _, s := range c.Subnets {
		fmt.Fprintf(&b, "%s pool %s-%s routers %s dns %s\n",
			s.Subnet, s.First, s.Last,
			strings.Join(s.Routers, ","), strings.Join(s.DNS, ","))
	}
	return b.String()
}

// subnetBroadcast returns the directed broadcast address of a subnet.
func subnetBroadcast(sub *DHCPSubnet) net.IP {
	if sub == nil {
		return nil
	}
	pfx, err := netip.ParsePrefix(sub.Subnet)
	if err != nil || !pfx.Addr().Is4() {
		return nil
	}
	a := pfx.Masked().Addr().As4()
	mask := net.CIDRMask(pfx.Bits(), 32)
	out := make(net.IP, 4)
	for i := range out {
		out[i] = a[i] | ^mask[i]
	}
	return out
}

// ServeSegments answers on one socket per local interface that holds an address
// in a configured subnet.
//
// A DHCP client's first packet is a broadcast carrying no address, so nothing
// in it says which segment it came from. A server with one segment can assume;
// one with several cannot, and a wildcard socket loses the only fact that would
// have told it. Each socket is therefore bound to a device, and what arrives on
// it is by construction from that device's segment.
//
// Returns when every listener has stopped.
func (s *DHCPServer) ServeSegments(port string) error {
	s.mu.Lock()
	subnets := append([]DHCPSubnet(nil), s.cfg.Subnets...)
	s.mu.Unlock()

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	started := 0
	var firstErr error
	var errMu sync.Mutex
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		hint := ""
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			for _, sub := range subnets {
				if pfx, err := netip.ParsePrefix(sub.Subnet); err == nil {
					if ip, ok := netip.AddrFromSlice(ipn.IP.To4()); ok && pfx.Contains(ip) {
						hint = sub.Subnet
					}
				}
			}
		}
		if hint == "" {
			continue
		}
		pc, err := listenOnDevice(ifc.Name, port)
		if err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", ifc.Name, err)
			}
			errMu.Unlock()
			continue
		}
		started++
		wg.Add(1)
		go func(pc net.PacketConn, hint string) {
			defer wg.Done()
			_ = s.serveOn(pc, hint)
		}(pc, hint)
	}
	if started == 0 {
		if firstErr != nil {
			return firstErr
		}
		return fmt.Errorf("no interface holds an address in any configured subnet")
	}
	wg.Wait()
	return nil
}

// listenOnDevice opens a UDP socket that only receives from one interface.
func listenOnDevice(dev, port string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, dev)
				if serr != nil {
					return
				}
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BROADCAST, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", port)
}
