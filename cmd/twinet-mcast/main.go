// Command twinet-mcast joins, sends and listens on IP multicast groups.
//
// It exists because the grader has to answer a question no configuration
// reading can answer: did a packet sent to a group actually reach the host that
// asked for it, and not reach the one that did not. The course's own exercise
// uses smcroute for the join and ping for the traffic, which needs two
// packages, leaves a membership behind after it exits, and reports success from
// an ICMP reply that a unicast route could equally well have produced.
//
// Three modes:
//
//	-recv    join the group and report what arrives
//	-listen  do not join, and report what arrives anyway
//	-send    send to the group
//
// The join is an ordinary UDP socket, because a membership is held by an open
// socket: the process exiting is what leaves the group, so there is no state
// left behind to change the next measurement's answer. The *reading*, though,
// is not done through that socket. A datagram socket cannot tell a packet that
// arrived on the wire from one this host's own stack looped back to it, and the
// difference is the whole question: a host that sends to the group on its own
// segment receives its own packets, so anyone with root here can satisfy "it
// arrived" without a tree existing anywhere. The reader is therefore a packet
// socket, which the kernel tells where each frame came from, and only frames
// that came in off the wire are counted.
//
// What arrives is reported by digest rather than judged here. The grader knows
// what it sent and does the matching; this program's job is to say truthfully
// what it saw.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/HongyuHe/twinet/internal/mcast"
)

func main() {
	var (
		recv    = flag.Bool("recv", false, "join the group and report what arrives")
		listen  = flag.Bool("listen", false, "report what arrives without joining")
		send    = flag.Bool("send", false, "send to the group")
		group   = flag.String("group", "", "multicast group address")
		iface   = flag.String("iface", "", "interface to use")
		port    = flag.Int("port", 24601, "UDP port")
		seconds = flag.Int("seconds", 10, "how long to listen")
		count   = flag.Int("count", 5, "how many packets to send")
		ttl     = flag.Int("ttl", 10, "time to live of sent packets")
		tag     = flag.String("tag", "", "token stamped on sent packets")
		from    = flag.String("from", "", "only count packets carrying this source address")
	)
	flag.Parse()

	if *group == "" {
		fail("a group address is required")
	}
	ip := net.ParseIP(*group)
	if ip == nil || !ip.IsMulticast() {
		fail(fmt.Sprintf("%q is not a multicast address", *group))
	}
	nic, err := net.InterfaceByName(*iface)
	if err != nil {
		fail(fmt.Sprintf("interface %q: %v", *iface, err))
	}
	var src net.IP
	if *from != "" {
		if src = net.ParseIP(*from).To4(); src == nil {
			fail(fmt.Sprintf("%q is not an IPv4 address", *from))
		}
	}

	switch {
	case *send:
		doSend(ip, nic, *port, *count, *ttl, *tag)
	case *recv:
		doReceive(ip, nic, *port, *seconds, src, true)
	case *listen:
		doReceive(ip, nic, *port, *seconds, src, false)
	default:
		fail("one of -send, -recv or -listen is required")
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "twinet-mcast: "+msg)
	os.Exit(2)
}

func doSend(group net.IP, nic *net.Interface, port, count, ttl int, tag string) {
	// Bound to the interface's own address so the packets leave the segment the
	// exercise is about, rather than whichever one the default route picks on a
	// multi-homed host.
	src, err := firstIPv4(nic)
	if err != nil {
		fail(err.Error())
	}
	c, err := net.ListenPacket("udp4", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		fail(fmt.Sprintf("opening a socket on %s: %v", src, err))
	}
	defer func() { _ = c.Close() }()

	p := ipv4.NewPacketConn(c)
	// A time to live of one is the default and never leaves the segment, which
	// is the mistake the exercise warns about; a check that made it would fail
	// every submission for the grader's reason.
	if err := p.SetMulticastTTL(ttl); err != nil {
		fail(fmt.Sprintf("setting the multicast ttl: %v", err))
	}
	if err := p.SetMulticastInterface(nic); err != nil {
		fail(fmt.Sprintf("choosing the outgoing interface: %v", err))
	}
	dst := &net.UDPAddr{IP: group, Port: port}
	for i := 0; i < count; i++ {
		if _, err := p.WriteTo([]byte(mcast.Stamp(tag, i)), nil, dst); err != nil {
			fail(fmt.Sprintf("sending: %v", err))
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("sent %d packet(s) to %s from %s ttl %d\n", count, group, src, ttl)
}

// sighting is one packet seen on the group, and where the kernel says it came
// from.
type sighting struct {
	digest  string
	source  string
	onWire  bool
	pkttype string
}

// doReceive holds the membership, if this is a join, and reports every packet
// for the group that the interface saw.
//
// The membership and the observation are two sockets on purpose. Only the first
// makes the host send an IGMP report, and only the second can say where a
// packet came from.
func doReceive(group net.IP, nic *net.Interface, port, seconds int, from net.IP, join bool) {
	if join {
		// Opened and never read. Holding it is the join; what it would deliver
		// is not evidence of anything, because the kernel hands this host's own
		// transmissions to it as readily as the network's.
		c, err := net.ListenMulticastUDP("udp4", nic, &net.UDPAddr{IP: group, Port: port})
		if err != nil {
			fail(fmt.Sprintf("joining %s on %s: %v", group, nic.Name, err))
		}
		defer func() { _ = c.Close() }()
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		fail(fmt.Sprintf("opening a packet socket on %s: %v", nic.Name, err))
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  nic.Index,
	}); err != nil {
		fail(fmt.Sprintf("binding a packet socket to %s: %v", nic.Name, err))
	}
	// A second at a time, so the deadline is kept without the program having to
	// be woken by traffic that may never come.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		fail(fmt.Sprintf("setting a read timeout: %v", err))
	}

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	buf := make([]byte, 2048)
	var seen []sighting
	elsewhere := 0
	for time.Now().Before(deadline) {
		n, addr, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			fail(fmt.Sprintf("reading from %s: %v", nic.Name, err))
		}
		ll, ok := addr.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		s, dst, payload, ok := parseUDP4(buf[:n], port)
		if !ok || !dst.Equal(group) {
			continue
		}
		if from != nil && !s.Equal(from) {
			elsewhere++
			continue
		}
		seen = append(seen, sighting{
			digest:  mcast.Digest(payload),
			source:  s.String(),
			onWire:  arrived(ll.Pkttype),
			pkttype: pkttypeName(ll.Pkttype),
		})
	}

	wire, loop := 0, 0
	sources := map[string]bool{}
	for _, s := range seen {
		if !s.onWire {
			loop++
			continue
		}
		wire++
		sources[s.source] = true
	}
	var names []string
	for s := range sources {
		names = append(names, s)
	}
	sort.Strings(names)
	fmt.Printf("twinet-mcast joined=%t group=%s iface=%s seconds=%d wire=%d loopback=%d "+
		"elsewhere=%d sources=%s\n",
		join, group, nic.Name, seconds, wire, loop, elsewhere, joinOr(names, "none"))
	for _, s := range seen {
		fmt.Printf("packet %s %s %s\n", s.digest, s.source, s.pkttype)
	}
}

// arrived reports whether the kernel says this frame was received rather than
// sent or looped back by this host.
//
// PACKET_OUTGOING is the copy a packet socket is given of what this host
// transmits, and PACKET_LOOPBACK is the copy the IP stack hands back to itself
// when a multicast socket has loopback enabled -- which it does by default.
// Both are this host talking to itself, and neither says anything about whether
// the network delivered anything.
func arrived(t uint8) bool {
	switch t {
	case unix.PACKET_HOST, unix.PACKET_BROADCAST, unix.PACKET_MULTICAST, unix.PACKET_OTHERHOST:
		return true
	default:
		return false
	}
}

func pkttypeName(t uint8) string {
	switch t {
	case unix.PACKET_HOST:
		return "host"
	case unix.PACKET_BROADCAST:
		return "broadcast"
	case unix.PACKET_MULTICAST:
		return "multicast"
	case unix.PACKET_OTHERHOST:
		return "otherhost"
	case unix.PACKET_OUTGOING:
		return "outgoing"
	case unix.PACKET_LOOPBACK:
		return "loopback"
	default:
		return fmt.Sprintf("pkttype%d", t)
	}
}

// parseUDP4 pulls the source, destination and payload out of an IPv4 UDP
// datagram addressed to the given port.
func parseUDP4(b []byte, port int) (src, dst net.IP, payload []byte, ok bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil, nil, nil, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+8 || b[9] != unix.IPPROTO_UDP {
		return nil, nil, nil, false
	}
	// A fragment other than the first carries no UDP header, and these packets
	// are far too small to be fragmented.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return nil, nil, nil, false
	}
	u := b[ihl:]
	if int(binary.BigEndian.Uint16(u[2:4])) != port {
		return nil, nil, nil, false
	}
	length := int(binary.BigEndian.Uint16(u[4:6]))
	if length < 8 || length > len(u) {
		length = len(u)
	}
	return net.IP(b[12:16]), net.IP(b[16:20]), u[8:length], true
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func joinOr(v []string, empty string) string {
	if len(v) == 0 {
		return empty
	}
	return strings.Join(v, ",")
}

func firstIPv4(nic *net.Interface) (net.IP, error) {
	addrs, err := nic.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addresses of %s: %w", nic.Name, err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4, nil
			}
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", nic.Name)
}
