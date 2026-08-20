package grade

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// A class run of eight copies of the reference solution deducted a mark from
// one of them, and the report said:
//
//	a datagram from SFO_host to HOU_host (4.108.0.1) never arrived
//	-- no packet of it reached any interface -- though pings and
//	connections do: something on the path is filtering by protocol
//
// Asked afterwards, that pair carried 300 datagrams out of 300. Whatever takes
// a pair out for a moment, it is not a path that discards the protocol -- and
// three datagrams sent back to back are milliseconds apart, so they are one
// observation of the path and not three. The round is run again before any of
// it is believed, which is the rule finding 116 already established for the
// load-balancing sweep and which this check never got.

// udpLab builds an AS of hosts wired to one router, which is all these probes
// need: they are driven by addresses, not by topology.
func udpLab(hosts ...string) ([]*model.Device, map[string]string) {
	var devs []*model.Device
	addrOf := map[string]string{}
	for i, name := range hosts {
		d := &model.Device{
			ID:   "as4/" + name,
			Name: name,
			Kind: model.KindHost,
			ASN:  4,
		}
		addr := "4.10" + string(rune('0'+i)) + ".0.1"
		addrOf[d.ID] = addr
		devs = append(devs, d)
	}
	return devs, addrOf
}

// udpFabric answers the whole probe protocol -- starting a capture, reading the
// counters, sending, reading the capture back -- for a network in which every
// datagram arrives except those the test says are lost.
type udpFabric struct {
	mu sync.Mutex
	// lose says, for a "src\x00dst" pair, which of that pair's observations
	// lose their datagrams -- the first, the second, or both.
	lose map[string]map[int]bool
	// sends counts how many times each pair has been probed, which is the
	// observation number the fabric answers for.
	sends map[string]int
	// delivered counts datagrams the destination has taken so far.
	delivered map[string]int
	// arrived is what the destination's capture has yet to report.
	arrived map[string]int
	addrOf  map[string]string
	// starts counts captures begun, so a test can show that a healthy sweep
	// is not probed twice.
	starts int
}

func (f *udpFabric) exec(ctx context.Context, dev string, cmd []string) (rt.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	joined := strings.Join(cmd, " ")
	switch {
	case strings.Contains(joined, "tcpdump -i any"):
		f.starts++
		return rt.ExecResult{}, nil

	case len(cmd) >= 2 && cmd[0] == "cat" && cmd[1] == "/proc/net/snmp":
		n := f.delivered[dev]
		return rt.ExecResult{Stdout: "" +
			"Udp: InDatagrams NoPorts InErrors OutDatagrams\n" +
			"Udp: 0 " + itoa(n) + " 0 0\n" +
			"lo: 0 0 0 0 0 0 0 0\n"}, nil

	case strings.Contains(joined, "nc -u"):
		// The sender names its destination, so the fabric can decide whether
		// this pair is having a bad moment.
		// The command carries the source address too, so the destination is
		// read as the address that is followed by the port it is aimed at.
		m := dstOfSend.FindStringSubmatch(joined)
		dst := ""
		for h, a := range f.addrOf {
			if len(m) > 1 && a == m[1] {
				dst = h
			}
		}
		if dst == "" {
			return rt.ExecResult{Stdout: "sent=" + itoa(datagramAttempts)}, nil
		}
		pair := dev + "\x00" + dst
		n := f.sends[pair]
		f.sends[pair]++
		if !f.lose[pair][n] {
			f.delivered[dst] += datagramAttempts
			f.arrived[dst] += datagramAttempts
		}
		return rt.ExecResult{Stdout: "sent=" + itoa(datagramAttempts)}, nil

	case strings.Contains(joined, "EARLY="):
		body := ""
		for range f.arrived[dev] {
			body += "22:51:31.100000 port_X In  IP 4.100.0.1.43931 > 4.101.0.1.33478: UDP, length 7\n"
		}
		f.arrived[dev] = 0
		return rt.ExecResult{Stdout: stillRunning(tapBanner) + "---\n" + body}, nil
	}
	return rt.ExecResult{}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// dstOfSend picks the destination address out of a send: it is the address
// immediately followed by the port the datagram is aimed at.
var dstOfSend = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+) (\d+) 2>&1`)

func newUDPFabric(addrOf map[string]string, hosts int) *udpFabric {
	return &udpFabric{
		lose:      map[string]map[int]bool{},
		sends:     map[string]int{},
		delivered: map[string]int{},
		arrived:   map[string]int{},
		addrOf:    addrOf,
	}
}

// A pair that fails once and carries traffic when asked again is a pair that
// had a bad moment, not a path that discards the protocol.
func TestAPairIsAskedAgainBeforeItIsAccused(t *testing.T) {
	hosts, addrOf := udpLab("SFO_host", "HOU_host")
	f := newUDPFabric(addrOf, len(hosts))
	// Lost in the first pass over the pairs and carried in the second.
	f.lose["as4/SFO_host\x00as4/HOU_host"] = map[int]bool{0: true}

	env := &Env{Exec: f.exec}
	got := unreachableByUDP(context.Background(), env, hosts, addrOf)
	if len(got) != 0 {
		t.Fatalf("accused a pair that carried the datagrams when it was asked again:\n%s",
			strings.Join(got, "\n"))
	}
}

// And a path that really discards the protocol discards the second round too.
func TestAPathThatKeepsDiscardingIsStillReported(t *testing.T) {
	hosts, addrOf := udpLab("SFO_host", "HOU_host")
	f := newUDPFabric(addrOf, len(hosts))
	f.lose["as4/SFO_host\x00as4/HOU_host"] = map[int]bool{0: true, 1: true}

	env := &Env{Exec: f.exec}
	got := unreachableByUDP(context.Background(), env, hosts, addrOf)
	if len(got) != 1 {
		t.Fatalf("want the pair reported once, got %d:\n%s", len(got), strings.Join(got, "\n"))
	}
	if !strings.Contains(got[0], "SFO_host") || !strings.Contains(got[0], "HOU_host") {
		t.Fatalf("the report must name the pair: %q", got[0])
	}
}

// A healthy network is not slowed down by the retry, because there is nothing
// to retry: the second round only happens where the first found something.
func TestAHealthyRoundIsNotRepeated(t *testing.T) {
	hosts, addrOf := udpLab("SFO_host", "HOU_host", "BOS_host")
	f := newUDPFabric(addrOf, len(hosts))

	env := &Env{Exec: f.exec}
	if got := unreachableByUDP(context.Background(), env, hosts, addrOf); len(got) != 0 {
		t.Fatalf("a network that carries everything has nothing to report:\n%s",
			strings.Join(got, "\n"))
	}
	// Two rounds of pairs for three hosts, one capture per destination each.
	if want := 2 * len(hosts); f.starts != want {
		t.Fatalf("a healthy sweep should start %d captures, started %d", want, f.starts)
	}
}
