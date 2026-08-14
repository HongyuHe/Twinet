// Command twinet-mcast joins, sends and listens on IP multicast groups.
//
// It exists because the grader has to answer a question no configuration
// reading can answer: did a packet sent to a group actually reach the host that
// asked for it, and not reach the one that did not. The course's own exercise
// uses smcroute for the join and ping for the traffic, which needs two
// packages, leaves a membership behind after it exits, and reports success from
// an ICMP reply that a unicast route could equally well have produced.
//
// Three modes, one socket each:
//
//	-recv    join the group and report what arrives
//	-listen  do not join, and report what arrives anyway
//	-send    send to the group
//
// The join and the listen are the same socket on purpose. A membership is held
// by an open socket, so the process exiting is what leaves the group: there is
// no state left behind to change the next measurement's answer.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
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

	switch {
	case *send:
		doSend(ip, nic, *port, *count, *ttl)
	case *recv:
		doReceive(ip, nic, *port, *seconds, true)
	case *listen:
		doReceive(ip, nic, *port, *seconds, false)
	default:
		fail("one of -send, -recv or -listen is required")
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "twinet-mcast: "+msg)
	os.Exit(2)
}

func doSend(group net.IP, nic *net.Interface, port, count, ttl int) {
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
		if _, err := p.WriteTo([]byte(fmt.Sprintf("twinet-mcast %d", i)), nil, dst); err != nil {
			fail(fmt.Sprintf("sending: %v", err))
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("sent %d packet(s) to %s from %s ttl %d\n", count, group, src, ttl)
}

func doReceive(group net.IP, nic *net.Interface, port, seconds int, join bool) {
	var (
		c   *net.UDPConn
		err error
	)
	if join {
		// ListenMulticastUDP joins the group on the given interface and holds
		// the membership for as long as the socket is open, which is what makes
		// the host send an IGMP report.
		c, err = net.ListenMulticastUDP("udp4", nic, &net.UDPAddr{IP: group, Port: port})
	} else {
		// The same port, without the join. A host that receives the group here
		// is receiving traffic nobody asked it to receive.
		c, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	}
	if err != nil {
		fail(fmt.Sprintf("listening for %s: %v", group, err))
	}
	defer func() { _ = c.Close() }()

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	if err := c.SetReadDeadline(deadline); err != nil {
		fail(err.Error())
	}
	buf := make([]byte, 2048)
	n := 0
	var from []string
	for time.Now().Before(deadline) {
		got, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if got == 0 {
			continue
		}
		n++
		if s := addr.IP.String(); !contains(from, s) {
			from = append(from, s)
		}
	}
	verb := "joined"
	if !join {
		verb = "did not join"
	}
	if n == 0 {
		fmt.Printf("nothing arrived for %s in %ds (%s)\n", group, seconds, verb)
		return
	}
	fmt.Printf("received %d packet(s) for %s from %s (%s)\n",
		n, group, strings.Join(from, ","), verb)
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
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
