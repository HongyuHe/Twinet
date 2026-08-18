package grade

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/HongyuHe/twinet/internal/model"
	rt "github.com/HongyuHe/twinet/internal/runtime"
)

// vpnSite is one customer site the checks will probe: the host a ping runs in
// and the address it is aimed at.
type vpnSite struct {
	host string // device ID of the site's host
	addr string // the site's pingable address
}

// vpnLab builds a provider AS that carries the named customers, giving each the
// requested number of sites, and returns the sites it created so a test can
// build an exact reachability matrix and predict every pair the checks probe.
//
// A customer is a VRF: two provider edges bound to the same table are two sites
// of one customer, which is exactly how customerGroups reads the topology.
func vpnLab(providerAS int, sitesPerCustomer map[string]int) (*model.Topology, map[string][]vpnSite) {
	top := &model.Topology{ASes: map[int]*model.AS{}}
	prov := &model.AS{ASN: providerAS, VRFs: map[string]*model.VRFSpec{}}
	top.ASes[providerAS] = prov

	out := map[string][]vpnSite{}
	custAS := providerAS + 1
	octet := 1
	table := 100

	customers := make([]string, 0, len(sitesPerCustomer))
	for c := range sitesPerCustomer {
		customers = append(customers, c)
	}
	sort.Strings(customers)

	for _, cust := range customers {
		prov.VRFs[cust] = &model.VRFSpec{Table: table}
		table++
		for s := 0; s < sitesPerCustomer[cust]; s++ {
			addr := fmt.Sprintf("192.168.%d.1", octet)
			octet++

			host := &model.Device{
				Name: fmt.Sprintf("H%d", custAS), ASN: custAS, Kind: model.KindHost,
			}
			host.Ifaces = []*model.Iface{
				{Name: "lo", Device: host, Addr4: fmt.Sprintf("10.%d.0.1/32", custAS)},
				{Name: "eth0", Device: host, Addr4: addr + "/24"},
			}
			host.ID = model.DeviceID(custAS, host.Name)
			top.ASes[custAS] = &model.AS{ASN: custAS, Devices: []*model.Device{host}}

			// A provider edge interface in this customer's table, wired to the
			// customer AS so customerGroups resolves the site through it.
			ce := &model.Device{ASN: custAS, Kind: model.KindRouter}
			pe := &model.Device{Name: fmt.Sprintf("PE%d", custAS), ASN: providerAS, Kind: model.KindRouter}
			pe.ID = model.DeviceID(providerAS, pe.Name)
			pe.Ifaces = []*model.Iface{{Name: "port_ce", Device: pe, VRF: cust, Peer: &model.Iface{Device: ce}}}
			prov.Routers = append(prov.Routers, pe)
			prov.Devices = append(prov.Devices, pe)

			out[cust] = append(out[cust], vpnSite{host: host.ID, addr: addr})
			custAS++
		}
	}
	return top, out
}

// reachOutcome is what a mocked ping does.
type reachOutcome int

const (
	blocked       reachOutcome = iota // the ping ran and got no reply: a routing decision
	reachable                         // the ping ran and was answered
	transportFail                     // the ping could not be run at all: the machinery failed
)

// pingExec turns a reachability matrix into an Exec that answers ping probes.
//
// The three outcomes are the three cases a check must tell apart: a reply, a
// deliberate drop, and a probe that never executed. Conflating the last two is
// the defect these tests exist to prevent.
func pingExec(matrix func(fromID, toAddr string) reachOutcome) func(context.Context, string, []string) (rt.ExecResult, error) {
	return func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
		if res, ok := transportProbe(deviceID, cmd, matrix); ok {
			return res, nil
		}
		if len(cmd) == 0 || cmd[0] != "ping" {
			// Isolation reads the tables as well as probing, because a leak
			// that only goes one way answers no probe. An empty table is the
			// right answer for a lab whose only subject here is reachability.
			return rt.ExecResult{ExitCode: 0, Stdout: "{}"}, nil
		}
		addr := cmd[len(cmd)-1]
		switch matrix(deviceID, addr) {
		case reachable:
			return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
		case transportFail:
			return rt.ExecResult{}, fmt.Errorf("container %s is not running", deviceID)
		default:
			return rt.ExecResult{ExitCode: 1, Stdout: "3 packets transmitted, 0 received"}, nil
		}
	}
}

// transportProbe answers the connection and datagram probes the VPN checks make
// alongside their pings, from the same reachability matrix.
//
// A lab where the paths carry pings and nothing else is a broken lab, so the
// fake answers all three the same way. It deliberately does not model the
// kernel counters: `/proc/net/snmp` is left unreadable here, which is the case
// the checks must survive by standing on the probe alone.
func transportProbe(deviceID string, cmd []string,
	matrix func(fromID, toAddr string) reachOutcome) (rt.ExecResult, bool) {
	var addr string
	switch {
	case len(cmd) > 2 && cmd[0] == "nc":
		addr = cmd[len(cmd)-2] // nc -v -w 3 -z <addr> <port>
	case len(cmd) == 3 && cmd[0] == "sh" && strings.Contains(cmd[2], "nc -u"):
		// A datagram tells its sender nothing, whatever became of it.
		return rt.ExecResult{ExitCode: 0}, true
	default:
		return rt.ExecResult{}, false
	}
	if matrix(deviceID, addr) == reachable {
		return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, true
	}
	return rt.ExecResult{ExitCode: 1, Stderr: "Connection timed out"}, true
}

// sameCustomer reports whether a source host and a target address belong to one
// customer, which is what a healthy VPN must let through and a leak must not.
func sameCustomer(sites map[string][]vpnSite, fromID, toAddr string) bool {
	for _, group := range sites {
		fromIn, toIn := false, false
		for _, s := range group {
			if s.host == fromID {
				fromIn = true
			}
			if s.addr == toAddr {
				toIn = true
			}
		}
		if fromIn && toIn {
			return true
		}
	}
	return false
}

// The defect this whole change is about: isolation scored as "the ping failed"
// is satisfied perfectly by a network where nothing works at all. A converged
// but completely dead L3VPN must not collect the isolation marks -- that is
// worse than not testing isolation, because the mark sheet then claims it was
// tested and passed.
func TestABrokenVPNDoesNotScoreIsolationMarks(t *testing.T) {
	top, _ := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	// Nothing is reachable: every probe is dropped, none by policy, all because
	// the VPN carries no traffic whatsoever.
	env := &Env{Topology: top, AS: 100,
		Exec: pingExec(func(_, _ string) reachOutcome { return blocked })}

	got := checkVPNIsolation(context.Background(), env)
	if got.Passed() {
		t.Fatalf("a completely broken VPN was awarded full isolation marks: isolation was certified "+
			"on a network where nothing is reachable.\nevidence: %+v", got.Evidence)
	}
	if got.Status == StatusError {
		t.Fatalf("a dead VPN is a student failure, not a grader failure; want fail, got error: %s", got.Err)
	}
}

// A leak from a customer's second site, or on the return path, is still a leak.
// The check must probe every cross-customer site pair in both directions, not
// only the first site in one direction as it once did.
func TestIsolationIsTestedForEverySitePairInBothDirections(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	a, b := sites["bankA"], sites["bankB"]
	// A single leak, from bankA's *second* site to bankB's first: the old
	// first-site, one-direction probe (bankA[0] -> bankB[0]) never sees it.
	leakFrom, leakTo := a[1].host, b[0].addr

	env := &Env{Topology: top, AS: 100,
		Exec: pingExec(func(fromID, toAddr string) reachOutcome {
			if fromID == leakFrom && toAddr == leakTo {
				return reachable
			}
			if sameCustomer(sites, fromID, toAddr) {
				return reachable // a working VPN otherwise
			}
			return blocked
		})}

	got := checkVPNIsolation(context.Background(), env)
	if got.Passed() {
		t.Fatalf("a leak from a customer's second site went uncaught: isolation is only probing the "+
			"first site in one direction.\nevidence: %+v", got.Evidence)
	}
	if obs, _ := got.Evidence.Observed.(string); !strings.Contains(obs, leakFrom) {
		t.Errorf("the report does not attribute the leak to the site it came from (%s): %q", leakFrom, obs)
	}
}

// A probe that could not run is not a blocked path. Reading a transport failure
// as "correctly isolated" turns a platform outage into full marks, which is the
// single worst thing this system can do because the mark looks entirely real.
func TestATransportFailureDuringIsolationIsNotCountedAsCorrectBlocking(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	a, b := sites["bankA"], sites["bankB"]
	deadFrom, deadTo := a[0].host, b[0].addr

	env := &Env{Topology: top, AS: 100, infraSeen: &infraTracker{},
		Exec: pingExec(func(fromID, toAddr string) reachOutcome {
			if fromID == deadFrom && toAddr == deadTo {
				return transportFail
			}
			if sameCustomer(sites, fromID, toAddr) {
				return reachable
			}
			return blocked
		})}

	got := checkVPNIsolation(context.Background(), env)
	if got.Passed() {
		t.Fatalf("a probe that never executed was counted as a correctly blocked path, so a transport "+
			"outage was scored as isolation.\nevidence: %+v", got.Evidence)
	}
	if got.Status != StatusError {
		t.Fatalf("a transport failure must make the question un-gradeable; want error, got %q: %s",
			got.Status, got.Err)
	}
	if env.infraSeen.failure() == nil {
		t.Error("the transport failure was not recorded with the machinery tracker, so the runner would " +
			"not know to quarantine the mark")
	}
}

// A network that is working and correctly isolated must still earn the marks. A
// fix that fails every submission is not a fix.
func TestAWorkingIsolatedVPNStillEarnsTheIsolationMarks(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	env := &Env{Topology: top, AS: 100,
		Exec: pingExec(func(fromID, toAddr string) reachOutcome {
			if sameCustomer(sites, fromID, toAddr) {
				return reachable
			}
			return blocked
		})}

	got := checkVPNIsolation(context.Background(), env)
	if !got.Passed() {
		t.Fatalf("a working, correctly isolated VPN did not earn full isolation marks: %s", describe(got))
	}
}

// A leak that only goes one way answers no probe.
//
// Importing another customer's route target on one edge puts their prefixes in
// this customer's table and leaves theirs alone: packets flow into the other
// bank's network and nothing comes back, so every ping times out and a check
// built on pings reports perfect isolation. The tables have to be read.
func TestAOneWayRouteLeakIsCaughtEvenThoughNoProbeSucceeds(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	victim := sites["bankB"][0].addr

	env := &Env{Topology: top, AS: 100,
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			if res, ok := transportProbe(deviceID, cmd, func(from, to string) reachOutcome {
				if sameCustomer(sites, from, to) {
					return reachable
				}
				return blocked
			}); ok {
				return res, nil
			}
			if len(cmd) > 0 && cmd[0] == "ping" {
				addr := cmd[len(cmd)-1]
				// A working VPN for each customer, and not one cross-customer
				// probe succeeds: the leak is one-directional, so nothing
				// replies over it.
				if sameCustomer(sites, deviceID, addr) {
					return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
				}
				return rt.ExecResult{ExitCode: 1, Stdout: "3 packets transmitted, 0 received"}, nil
			}
			// bankA's table holds a host route to one of bankB's sites.
			if strings.Contains(strings.Join(cmd, " "), "bankA") {
				return rt.ExecResult{ExitCode: 0,
					Stdout: `{"` + victim + `/32":[{"prefix":"` + victim + `/32"}]}`}, nil
			}
			return rt.ExecResult{ExitCode: 0, Stdout: "{}"}, nil
		}}

	got := checkVPNIsolation(context.Background(), env)
	if got.Passed() {
		t.Fatalf("one customer's table holds a route into another's network and the VPN was "+
			"certified isolated, because no probe could succeed over a leak that only goes "+
			"one way.\nevidence: %+v", got.Evidence)
	}
	if obs, _ := got.Evidence.Observed.(string); !strings.Contains(obs, victim) {
		t.Errorf("the report does not say which address leaked (%s): %q", victim, obs)
	}
}

// A route that covers everybody is not a leak.
//
// The first version of this compared a route against the address it was asked
// about, and a router asked for a route to any address answers with the longest
// match -- so the default route every correct submission carries made every one
// of them look like a total leak.
func TestADefaultRouteIsNotACrossCustomerLeak(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	env := &Env{Topology: top, AS: 100,
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			if res, ok := transportProbe(deviceID, cmd, func(from, to string) reachOutcome {
				if sameCustomer(sites, from, to) {
					return reachable
				}
				return blocked
			}); ok {
				return res, nil
			}
			if len(cmd) > 0 && cmd[0] == "ping" {
				addr := cmd[len(cmd)-1]
				if sameCustomer(sites, deviceID, addr) {
					return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
				}
				return rt.ExecResult{ExitCode: 1, Stdout: "3 packets transmitted, 0 received"}, nil
			}
			return rt.ExecResult{ExitCode: 0,
				Stdout: `{"0.0.0.0/0":[{"prefix":"0.0.0.0/0"}]}`}, nil
		}}

	if got := checkVPNIsolation(context.Background(), env); !got.Passed() {
		t.Fatalf("a correctly isolated VPN with a default route lost the isolation marks: %s",
			describe(got))
	}
}

// Reachability is a claim about carrying a customer between its sites, which is
// a round trip. A VPN that forwards one way but black-holes the return path has
// not carried the customer, and a single-direction probe would call it working.
func TestReachabilityIsTestedInBothDirections(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2})
	a := sites["bankA"]
	env := &Env{Topology: top, AS: 100,
		Exec: pingExec(func(fromID, toAddr string) reachOutcome {
			// Forward path works; the return path is black-holed.
			if fromID == a[1].host && toAddr == a[0].addr {
				return blocked
			}
			return reachable
		})}

	got := checkVPNReachability(context.Background(), env)
	if got.Passed() {
		t.Fatalf("a VPN that carries a customer only one way earned full reachability marks: the "+
			"return path was never probed.\nevidence: %s", describe(got))
	}
}

// A bank's branches do not exchange their business over ICMP.
//
// Dropping TCP and UDP at the provider's edges, and leaving ICMP alone, left
// every probe of this question succeeding and the mark at six out of six, on a
// network across which no customer could have opened a single connection.
func TestAVPNThatCarriesOnlyPingsDoesNotEarnFullReachabilityMarks(t *testing.T) {
	top, _ := vpnLab(100, map[string]int{"bankA": 2})
	env := &Env{Topology: top, AS: 100,
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) > 0 && cmd[0] == "ping" {
				return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
			}
			if len(cmd) > 2 && cmd[0] == "nc" {
				return rt.ExecResult{ExitCode: 1, Stderr: "Connection timed out"}, nil
			}
			return rt.ExecResult{ExitCode: 0, Stdout: "{}"}, nil
		}}

	got := checkVPNReachability(context.Background(), env)
	if got.Score >= 1 {
		t.Fatalf("a VPN carrying ICMP and discarding every connection earned full reachability "+
			"marks.\nevidence: %s", describe(got))
	}
}

// hostOf finds the device that owns an address.
func hostOf(sites map[string][]vpnSite, addr string) string {
	for _, group := range sites {
		for _, s := range group {
			if s.addr == addr {
				return s.host
			}
		}
	}
	return ""
}

// snmpWith renders the part of /proc/net/snmp a destination's own record of
// arriving connections is read from, together with the loopback packet count
// read alongside it -- quiet here, since these hosts generate no traffic of
// their own.
func snmpWith(rsts int) string {
	return "Tcp: RtoAlgorithm RtoMin PassiveOpens OutRsts\n" +
		"Tcp: 1 200 0 " + strconv.Itoa(rsts) + "\n" + procNetDevQuiet
}

// procNetDevQuiet is a /proc/net/dev with nothing on the loopback device.
const procNetDevQuiet = "Inter-|   Receive                              |  Transmit\n" +
	" face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n" +
	"    lo:       0       0    0    0    0     0          0         0     0     0\n"

// Isolation asked only of ICMP is isolation of ICMP.
//
// The customers' pings are blocked and their connections are not: the tables
// are joined, and a check built on ping calls them perfectly separated. The
// destinations answer for themselves here -- their kernels count the resets
// they send -- which is what makes this a leak rather than something on the
// path talking.
func TestCustomersThatExchangeConnectionsAreNotIsolated(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	var mu sync.Mutex
	resets := map[string]int{}
	env := &Env{Topology: top, AS: 100,
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) > 0 && cmd[0] == "ping" {
				addr := cmd[len(cmd)-1]
				if sameCustomer(sites, deviceID, addr) {
					return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
				}
				return rt.ExecResult{ExitCode: 1, Stdout: "3 packets transmitted, 0 received"}, nil
			}
			if len(cmd) > 2 && cmd[0] == "nc" {
				// The attempt arrives, and the host it arrives at resets it.
				mu.Lock()
				resets[hostOf(sites, cmd[len(cmd)-2])]++
				mu.Unlock()
				return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, nil
			}
			if len(cmd) >= 2 && cmd[0] == "cat" && cmd[1] == "/proc/net/snmp" {
				mu.Lock()
				defer mu.Unlock()
				return rt.ExecResult{ExitCode: 0, Stdout: snmpWith(resets[deviceID])}, nil
			}
			return rt.ExecResult{ExitCode: 0, Stdout: "{}"}, nil
		}}

	got := checkVPNIsolation(context.Background(), env)
	if got.Passed() {
		t.Fatalf("two customers whose hosts answer one another's connections were certified "+
			"isolated, because only their pings were tried.\nevidence: %s", describe(got))
	}
}

// A provider that says no is still saying no.
//
// Rejecting cross-customer traffic with a reset rather than dropping it in
// silence is isolation, implemented more helpfully: nothing crosses, and the
// sender is told so immediately instead of waiting for a timeout. The reset
// carries the destination's address because whoever wrote it put that address
// there, and reading it as the destination speaking marked a correctly
// separated VPN as leaking -- four of six on the live cluster.
//
// The destinations here record nothing, because nothing reached them.
func TestAProviderThatRejectsCrossCustomerTrafficIsStillIsolating(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	env := &Env{Topology: top, AS: 100,
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) > 0 && cmd[0] == "ping" {
				addr := cmd[len(cmd)-1]
				if sameCustomer(sites, deviceID, addr) {
					return rt.ExecResult{ExitCode: 0, Stdout: "3 packets transmitted, 3 received"}, nil
				}
				return rt.ExecResult{ExitCode: 1, Stdout: "3 packets transmitted, 0 received"}, nil
			}
			if len(cmd) > 2 && cmd[0] == "nc" {
				if sameCustomer(sites, deviceID, cmd[len(cmd)-2]) {
					return rt.ExecResult{ExitCode: 0}, nil
				}
				// The edge forges the refusal; nothing arrives anywhere.
				return rt.ExecResult{ExitCode: 1, Stderr: "Connection refused"}, nil
			}
			if len(cmd) >= 2 && cmd[0] == "cat" && cmd[1] == "/proc/net/snmp" {
				return rt.ExecResult{ExitCode: 0, Stdout: snmpWith(0)}, nil
			}
			return rt.ExecResult{ExitCode: 0, Stdout: "{}"}, nil
		}}

	got := checkVPNIsolation(context.Background(), env)
	if !got.Passed() {
		t.Fatalf("a VPN whose edges reject cross-customer traffic with a reset was marked as "+
			"leaking, though no packet ever crossed.\nevidence: %s", describe(got))
	}
}

// mplsCoreLab builds the smallest AS the LDP check will run over: two routers
// joined by one interior link, each with a loopback LDP can identify it by.
func mplsCoreLab(providerAS int) *model.Topology {
	top := &model.Topology{ASes: map[int]*model.AS{}}
	as := &model.AS{ASN: providerAS}

	r1 := &model.Device{Name: "R1", ASN: providerAS, Kind: model.KindRouter}
	r2 := &model.Device{Name: "R2", ASN: providerAS, Kind: model.KindRouter}
	r1.ID = model.DeviceID(providerAS, "R1")
	r2.ID = model.DeviceID(providerAS, "R2")

	lo1 := &model.Iface{Name: "lo", Device: r1, Addr4: "10.100.0.1/32"}
	lo2 := &model.Iface{Name: "lo", Device: r2, Addr4: "10.100.0.2/32"}
	i1 := &model.Iface{Name: "port_R2", Device: r1}
	i2 := &model.Iface{Name: "port_R1", Device: r2}
	link := &model.Link{InterAS: false, A: i1, B: i2}
	i1.Link, i2.Link = link, link
	i1.Peer, i2.Peer = i2, i1
	r1.Ifaces = []*model.Iface{lo1, i1}
	r2.Ifaces = []*model.Iface{lo2, i2}

	as.Routers = []*model.Device{r1, r2}
	as.Devices = []*model.Device{r1, r2}
	top.ASes[providerAS] = as
	return top
}

// A router whose forwarding table cannot be read has not been shown to install
// labels; concluding it did anyway once let a router that forwarded nothing
// pass. Failure to read the MPLS table is the grader's problem, so the question
// must come back un-gradeable rather than as a silent pass.
func TestAFailureToReadTheMPLSTableIsAnInfrastructureError(t *testing.T) {
	top := mplsCoreLab(100)
	env := &Env{Topology: top, AS: 100, infraSeen: &infraTracker{},
		Exec: func(_ context.Context, deviceID string, cmd []string) (rt.ExecResult, error) {
			name := deviceID
			if i := strings.LastIndexByte(deviceID, '/'); i >= 0 {
				name = deviceID[i+1:]
			}
			command := ""
			if len(cmd) >= 3 && cmd[0] == "vtysh" && cmd[1] == "-c" {
				command = cmd[2]
			}
			switch command {
			case "show mpls ldp neighbor":
				// Both sessions are healthy: nothing here should fail the check.
				if name == "R1" {
					return rt.ExecResult{ExitCode: 0, Stdout: "ipv4 10.100.0.2 OPERATIONAL\n"}, nil
				}
				return rt.ExecResult{ExitCode: 0, Stdout: "ipv4 10.100.0.1 OPERATIONAL\n"}, nil
			case "show mpls ldp discovery":
				if name == "R1" {
					return rt.ExecResult{ExitCode: 0,
						Stdout: "ipv4 10.100.0.2       Link     port_R2                15\n"}, nil
				}
				return rt.ExecResult{ExitCode: 0,
					Stdout: "ipv4 10.100.0.1       Link     port_R1                15\n"}, nil
			case "show mpls table":
				return rt.ExecResult{}, fmt.Errorf("container %s is not running", deviceID)
			}
			return rt.ExecResult{ExitCode: 1}, nil
		}}

	got := checkLDPAdjacencies(context.Background(), env)
	if got.Status != StatusError {
		t.Fatalf("a network whose MPLS table could not be read was graded as if it had been: want error, "+
			"got %q (%s). Reading the forwarding table is the grader's job, and its failure is the "+
			"grader's fault, not a pass.", got.Status, describe(got))
	}
	if env.infraSeen.failure() == nil {
		t.Error("the unreadable MPLS table was not recorded with the machinery tracker")
	}
}

func questionByID(rep *Report, id string) *QuestionResult {
	for i := range rep.Questions {
		if rep.Questions[i].ID == id {
			return &rep.Questions[i]
		}
	}
	return nil
}

// The rubric ties the two halves together: isolation cannot be scored unless
// reachability earned something. This is the whole-run guarantee behind the
// per-check one -- a submission that fails to carry its customers is skipped for
// isolation instead of being handed the marks for blocking traffic it could
// never pass anyway.
func TestABrokenVPNIsSkippedForIsolationWhenGradedThroughTheRubric(t *testing.T) {
	top, sites := vpnLab(100, map[string]int{"bankA": 2, "bankB": 2})
	b := sites["bankB"]
	env := &Env{Topology: top, AS: 100,
		Exec: pingExec(func(fromID, toAddr string) reachOutcome {
			// bankB's return path is black-holed, so reachability (q2) fails;
			// bankA still carries traffic and every cross-customer path is
			// blocked, so isolation run on its own would happily pass. Only the
			// dependency stops q3 from scoring on a network q2 rejected.
			if fromID == b[1].host && toAddr == b[0].addr {
				return blocked
			}
			if sameCustomer(sites, fromID, toAddr) {
				return reachable
			}
			return blocked
		})}

	rubric := &Rubric{
		Metadata: RubricMeta{Name: "test"},
		Questions: []QuestionSpec{
			{ID: "q2", Title: "carry", Points: 2,
				Checks: []CheckSpec{{Check: "vpn.site_reachability", Weight: 1}}},
			{ID: "q3", Title: "isolate", Points: 2, DependsOn: []string{"q2"},
				Checks: []CheckSpec{{Check: "vpn.isolation", Weight: 1}}},
		},
	}

	rep := Run(context.Background(), rubric, env, RunOptions{})
	q2 := questionByID(rep, "q2")
	q3 := questionByID(rep, "q3")
	if q2 == nil || q3 == nil {
		t.Fatalf("the report is missing a question: q2=%v q3=%v", q2, q3)
	}
	if q2.Awarded != 0 {
		t.Fatalf("reachability should have scored nothing on a black-holed return path, got %.2f", q2.Awarded)
	}
	if q3.Awarded != 0 {
		t.Fatalf("isolation was scored %.2f on a VPN that failed reachability; q3 must depend on q2 so a "+
			"broken VPN cannot collect the isolation marks", q3.Awarded)
	}
	if q3.Status != StatusSkipped {
		t.Errorf("isolation should be skipped when reachability earns nothing, got status %q", q3.Status)
	}
}

// The whole-run guarantee above only holds if the shipped rubric actually
// declares the dependency, so assert it directly on the file students are
// graded against.
func TestTheShippedRubricMakesIsolationDependOnReachability(t *testing.T) {
	r, err := LoadRubric("../../examples/advnet/rubric/advnet.yaml")
	if err != nil {
		t.Fatalf("the advnet rubric did not load: %v", err)
	}
	var q3 *QuestionSpec
	for i := range r.Questions {
		if r.Questions[i].ID == "q3" {
			q3 = &r.Questions[i]
		}
	}
	if q3 == nil {
		t.Fatal("the advnet rubric has no q3 (isolation) question")
	}
	found := false
	for _, dep := range q3.DependsOn {
		if dep == "q2" {
			found = true
		}
	}
	if !found {
		t.Errorf("the isolation question does not depend on reachability, so a VPN where nothing is "+
			"reachable would still be graded for isolation. q3.depends_on = %v", q3.DependsOn)
	}
}

// A datagram is invisible to whoever sent it, so the far side's count is the
// whole of the evidence. Without it there is no verdict, and "no gap found"
// was read as "the VPN carries datagrams".
func TestAnUnreadableFarSideIsNotAWorkingVPN(t *testing.T) {
	env := &Env{
		Topology: &model.Topology{ASes: map[int]*model.AS{1: {ASN: 1}}},
		AS:       1,
		Exec: func(_ context.Context, _ string, cmd []string) (rt.ExecResult, error) {
			if len(cmd) > 0 && cmd[0] == "cat" {
				return rt.ExecResult{ExitCode: 1, Stderr: "no such file"}, nil
			}
			return rt.ExecResult{}, nil
		},
	}
	d := directedPair{from: sitePoint{host: "as1/A"}, to: sitePoint{host: "as1/B", addr: "10.0.0.2"}}
	gap, ok := vpnUDPGap(context.Background(), env, d)
	if ok {
		t.Fatal("a pair whose far side was never read was reported as tested")
	}
	if gap != "" {
		t.Fatalf("a gap was reported from an unread counter: %q", gap)
	}
}
