//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// gradeAS grades one autonomous system and returns the awarded mark per
// question.
func gradeAS(t *testing.T, dir string, as int) (map[string]float64, map[string]float64, string) {
	t.Helper()
	// A system that has just been put back to the reference is still settling,
	// and a check that reads a half-converged table scores it short: the
	// baseline came out at 0.83 of 1.00 on a question the reference answers
	// perfectly, and everything measured against that baseline was then
	// meaningless. The baseline waits; the deliberately broken runs do not.
	return gradeASWithin(t, dir, as, "6m", true)
}

// gradeASBroken marks a system that has been broken on purpose.
//
// A short convergence budget, deliberately: a broken system never converges,
// and waiting six minutes for it on top of every check's own wait took grading
// past twelve minutes, at which point the subprocess was killed mid-run.
func gradeASBroken(t *testing.T, dir string, as int) (map[string]float64, map[string]float64, string) {
	t.Helper()
	// A deliberately broken submission may leave a question that cannot be
	// marked at all -- "nothing was delivered, so whether anybody else
	// received it says nothing" is the grader being careful, not the grader
	// failing. Insisting on a clean run here made three honest mutations look
	// like harness errors and hid whether the checks had noticed them.
	return gradeASWithin(t, dir, as, "90s", false)
}

func gradeASWithin(t *testing.T, dir string, as int, converge string, requireClean bool) (
	map[string]float64, map[string]float64, string) {
	t.Helper()
	out := t.TempDir()
	res, err := twinet(t, "grade", "run", "-m", dir, "--as", itoa(as),
		"-o", out, "--converge-timeout", converge)
	// A run that could not mark every question exits non-zero, correctly: a
	// mark nobody can stand behind must not be released quietly. On a
	// deliberately broken submission that is the expected outcome, and the
	// report is still written, so the exit status is not a reason to stop --
	// only a report that is missing or unreadable is.
	if err != nil && requireClean {
		t.Fatalf("grading AS %d: %v\n%s", as, err, res)
	}
	raw, rerr := os.ReadFile(filepath.Join(out, "group"+itoa(as)+".json"))
	if rerr != nil {
		t.Fatalf("no report was written (grade said %v): %v\n%s", err, rerr, res)
	}
	var rep struct {
		NeedsReview bool   `json:"needs_review"`
		Err         string `json:"error"`
		Questions   []struct {
			ID      string  `json:"id"`
			Awarded float64 `json:"awarded"`
			Points  float64 `json:"points"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("the report does not parse: %v", err)
	}
	if requireClean && (rep.NeedsReview || rep.Err != "") {
		t.Fatalf("grading did not complete cleanly: needs_review=%v err=%q", rep.NeedsReview, rep.Err)
	}
	awarded := map[string]float64{}
	points := map[string]float64{}
	for _, q := range rep.Questions {
		awarded[q.ID] = q.Awarded
		points[q.ID] = q.Points
	}
	return awarded, points, string(raw)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// vtysh runs configuration commands on a router of the lab.
func vtysh(t *testing.T, dir, device string, cmds ...string) {
	t.Helper()
	args := []string{"exec", "-m", dir, device, "--", "vtysh"}
	for _, c := range cmds {
		args = append(args, "-c", c)
	}
	if out, err := twinet(t, args...); err != nil {
		t.Fatalf("configuring %s: %v\n%s", device, err, out)
	}
}

// That the reference scores full marks proves the rubric is satisfiable. It
// does not prove the rubric is discriminating: a check that always passes looks
// exactly the same from that direction, and so does one that is measuring
// something other than what its name says.
//
// This is the other direction. Each case breaks one specific thing and asserts
// that the question about that thing loses marks -- and, just as importantly,
// that the other questions do not, because a check that fails whenever anything
// at all is wrong is not measuring what it claims either, and would take marks
// off a student for a mistake they did not make.
//
// Every case restores the reference afterwards, so a failure part way through
// cannot leave the lab in a state that fails everything after it.
func TestABrokenSubmissionLosesTheRightMarks(t *testing.T) {
	dir := labDir(t)
	const as = 3

	solveAS(t, dir, as)
	// Graded twice if the first is short.
	//
	// Re-solving a system restarts FRR on all of its routers, and a table read
	// while OSPF is still flooding scores a question at 0.99 -- which is not
	// the reference failing, it is the reference not having finished. Failing
	// here on that costs a whole run of the suite; grading again after a wait
	// costs ninety seconds.
	baseline, points, _ := gradeAS(t, dir, as)
	short := func(b map[string]float64) string {
		for id, p := range points {
			if b[id] < p {
				return fmt.Sprintf("%s (%.2f of %.2f)", id, b[id], p)
			}
		}
		return ""
	}
	if why := short(baseline); why != "" {
		t.Logf("the reference is short on %s; waiting for it to settle and grading again", why)
		time.Sleep(60 * time.Second)
		baseline, points, _ = gradeAS(t, dir, as)
	}
	if why := short(baseline); why != "" {
		t.Fatalf("the reference does not score full marks on %s; nothing below can be "+
			"attributed to the breakage", why)
	}

	// Remembered by the mutations that make them, so their undo does not have
	// to find them again in a lab they have just changed.
	var counterfeit string
	var blackholed struct{ router, nh string }
	var ecmpBlock struct{ router, addr string }
	var redistributed struct{ faker, prefix string }
	var impostorSubnet struct{ faker, prefix string }
	var customerDrops []string
	var vlanMirror struct{ switchID, from string }
	var ibgpBlackhole struct{ router, peer string }
	var leakedRange string
	var tunnelTCP struct{ gateway, iface string }
	var rangeAllow []string
	var weighted struct{ router, routeMap, prefix string }
	var ecmpTCP struct{ router, from string }
	var udpBlock struct{ router, src, dst string }
	var impostorLink struct{ router, iface, moved string }
	var ixpRewrite struct{ router, routeMap, match, peer string }
	var rpkiNarrow struct{ router, routeMap, seq string }
	var notFoundBlock struct{ host, prefix string }
	var tcpBlock struct{ router, src, dst string }
	var udpPair struct{ router, src string }
	var vlanFlow struct{ switchID string }
	var tcMirror struct{ switchID, from string }
	var forgedLeak struct{ router, routeMap, prefix string }
	var custTCP string
	var starved struct {
		router string
		peers  []string
	}
	var reorigin struct{ router, routeMap, prefix string }
	var slowPrepend struct{ router, routeMap, seq, peer, original string }
	var staticOverride struct{ router, prefix string }
	var ebgpBlackhole struct{ router, peer string }
	var looseROA struct {
		router, anchor, prefix string
		length                 int
	}
	var ixpDeny struct{ router, peer, routeMap string }
	var importMapNames []string
	var roaWithdrawn struct{ router, anchor, prefix string }
	var nativeV6 []nativeV6End
	var hidden struct{ router, peer, origMap string }
	var greEnds []string

	cases := []struct {
		name string
		// question that must lose marks.
		question string
		// alsoAffects names the other questions this mutation is allowed to
		// cost marks on, for a break that is genuinely about several of them
		// at once. Denying every route that arrives from outside is not "work
		// done correctly" for the questions about which routes you accept and
		// re-export; it is the same mistake seen from three sides.
		alsoAffects []string
		// break it.
		apply func(t *testing.T)
		// put back anything solveAS cannot.
		//
		// solveAS re-renders the routing configuration, which undoes a
		// mutation made with vtysh. It does not undo one made with `ip`: a
		// deployment converges towards the manifest and does not remove a route
		// it never added, so a blackhole added on a host outlives the case that
		// added it and every later case is measured against a broken lab.
		undo func(t *testing.T)
	}{
		{
			name:     "an inter-AS subnet advertised into OSPF",
			question: "q1.2",
			apply: func(t *testing.T) {
				vtysh(t, dir, "as3/ATL", "configure terminal", "router ospf",
					"network 179.0.0.0/8 area 0", "end")
			},
		},
		{
			name:     "an iBGP session removed",
			question: "q2.1",
			apply: func(t *testing.T) {
				// Whichever internal neighbour ATL has, taken out of the mesh.
				out, err := twinet(t, "exec", "-m", dir, "as3/ATL", "--",
					"vtysh", "-c", "show running-config")
				if err != nil {
					t.Fatalf("reading the configuration: %v\n%s", err, out)
				}
				peer := firstIBGPPeer(out)
				if peer == "" {
					t.Skip("no iBGP neighbour found to remove")
				}
				vtysh(t, dir, "as3/ATL", "configure terminal", "router bgp 3",
					"no neighbor "+peer, "end")
			},
		},
		{
			name:     "the local-preference policy removed",
			question: "q2.3",
			apply: func(t *testing.T) {
				// Every router of the system, not one chosen in advance.
				//
				// This detached the import policies of as3/ATL, which has only
				// iBGP neighbours and therefore no import policy to detach --
				// so it skipped, every time, while the status ledger claimed
				// this question was covered by a discrimination test. A test
				// that skips is not a test; the mutation has to reach the
				// routers that actually hold the policy.
				n := 0
				for _, dev := range routersOf(t, dir, 3) {
					out, err := twinet(t, "exec", "-m", dir, dev, "--",
						"vtysh", "-c", "show running-config")
					if err != nil {
						t.Fatalf("reading the configuration of %s: %v\n%s", dev, err, out)
					}
					for _, line := range strings.Split(out, "\n") {
						f := strings.Fields(strings.TrimSpace(line))
						if len(f) >= 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
							vtysh(t, dir, dev, "configure terminal", "router bgp 3",
								"no neighbor "+f[1]+" route-map "+f[3]+" in", "end")
							n++
						}
					}
				}
				if n == 0 {
					t.Fatal("no import route-map is bound anywhere in AS 3, so this " +
						"mutation changes nothing and the question it claims to " +
						"exercise is not exercised at all")
				}
			},
		},
		{
			// A mutation the previous check could not see.
			//
			// "Every host reaches every other" probed from one host to the
			// rest, on the reasoning that a hub-and-spoke exercises every path
			// through the backbone. Reachability is neither symmetric nor
			// transitive: a blackhole on one host for another leaves the hub's
			// seven probes all succeeding while the pair it breaks cannot reach
			// each other, and the question kept its full mark.
			name:     "one host pair unreachable in one direction",
			question: "q1.2",
			undo: func(t *testing.T) {
				hosts := hostsOfAS(t, dir, 3)
				if len(hosts) < 3 {
					return
				}
				from, to := hosts[len(hosts)-1], hosts[1]
				if addr := hostAddr(t, dir, to); addr != "" {
					_, _ = twinet(t, "exec", "-m", dir, from, "--",
						"ip", "route", "del", "blackhole", addr+"/32")
				}
			},
			apply: func(t *testing.T) {
				hosts := hostsOfAS(t, dir, 3)
				if len(hosts) < 3 {
					t.Fatalf("AS 3 has %d hosts, so a directed pair cannot be broken", len(hosts))
				}
				// Not the host the old check probed from, so that a check which
				// still probes from there sees nothing wrong.
				from, to := hosts[len(hosts)-1], hosts[1]
				addr := hostAddr(t, dir, to)
				if addr == "" {
					t.Fatalf("%s has no address to blackhole", to)
				}
				t.Logf("blackholing %s (%s) on %s", to, addr, from)
				if out, err := twinet(t, "exec", "-m", dir, from, "--",
					"ip", "route", "replace", "blackhole", addr+"/32"); err != nil {
					t.Fatalf("adding the blackhole: %v\n%s", err, out)
				}
			},
		},
		{
			// The original of that comment.
			//
			// Gao-Rexford was assessed by comparing the *median* local
			// preference of each relationship, which is a statement about most
			// routes and about no particular one. Ranking a single customer
			// prefix below a peer leaves both medians untouched, so the old
			// check passed a routing table that violates the rule it is named
			// after, and the mutation test above -- which detaches every import
			// policy at once -- was too blunt to notice.
			name:     "one customer prefix ranked below a peer",
			question: "q2.3",
			apply: func(t *testing.T) {
				router, nbr, prefix := bestCustomerRoute(t, dir, 3)
				rm := importRouteMap(t, dir, router, nbr)
				if rm == "" {
					t.Fatalf("%s has no import route-map on the session with %s, so this "+
						"mutation has nothing to alter", router, nbr)
				}
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list ONEROUTE seq 5 permit "+prefix,
					"route-map "+rm+" permit 1",
					" match ip address prefix-list ONEROUTE",
					" set local-preference 150",
					"end")
				// A policy change applies to routes that arrive after it; the
				// ones already in the table keep the preference they were given.
				vtysh(t, dir, router, "clear bgp ipv4 unicast "+nbr+" in")
				time.Sleep(8 * time.Second)
			},
		},
		{
			// Somebody else's address space, originated somewhere the check
			// was not looking.
			//
			// "Only your own prefix" read the table of the first router of the
			// system, which is an accident of the template's ordering. A
			// submission originating 203.0.113.0/24 on another router kept the
			// whole mark: the prefix was in the neighbour's table and in the
			// originating router's advertisements, and the grader looked at
			// neither.
			name:     "address space that is not yours, on another router",
			question: "q2.2",
			apply: func(t *testing.T) {
				const foreign = "203.0.113.0/24"
				routers := routersOf(t, dir, 3)
				// Not the first: that is the one the old check read.
				victim := routers[len(routers)-1]
				for _, r := range routers {
					if importRouteMaps(t, dir, r) != nil && r != routers[0] {
						victim = r
						break
					}
				}
				t.Logf("originating %s on %s", foreign, victim)
				vtysh(t, dir, victim, "configure terminal",
					"ip route "+foreign+" Null0",
					"router bgp 3", "address-family ipv4 unicast",
					"network "+foreign, "end")
				time.Sleep(12 * time.Second)
			},
			undo: func(t *testing.T) {
				const foreign = "203.0.113.0/24"
				// Tolerantly: a router that never had the statement answers
				// non-zero, and that is not a failure of the undo.
				for _, r := range routersOf(t, dir, 3) {
					vtyshQuiet(t, dir, r, "configure terminal",
						"router bgp 3", "address-family ipv4 unicast",
						"no network "+foreign, "end")
					vtyshQuiet(t, dir, r, "configure terminal",
						"no ip route "+foreign+" Null0", "end")
				}
			},
		},
		{
			// Correct BGP policy, overridden in the forwarding table.
			//
			// Everything the traffic-engineering check read was BGP: the
			// preferences a policy assigned and the paths it advertised. None
			// of it is the routing table. A static route over the slow link
			// overrides every one of those decisions, and a submission with
			// textbook policy and one `ip route` statement sent its traffic
			// over exactly the link the question asks it to avoid, with the
			// mark awarded in full.
			name:     "a static route over the slow link",
			question: "q2.5",
			apply: func(t *testing.T) {
				router, nbr, prefix := slowProviderRoute(t, dir, 3)
				t.Logf("routing %s over the slow link via %s on %s", prefix, nbr, router)
				vtysh(t, dir, router, "configure terminal",
					"ip route "+prefix+" "+nbr, "end")
				time.Sleep(6 * time.Second)
			},
			undo: func(t *testing.T) {
				router, nbr, prefix := slowProviderRoute(t, dir, 3)
				vtysh(t, dir, router, "configure terminal",
					"no ip route "+prefix+" "+nbr, "end")
			},
		},
		{
			// Kept out of OSPF by a configuration reading, put into it another
			// way.
			//
			// The check read `network` statements under `router ospf`, which
			// finds one way of putting a prefix into the interior and misses
			// every other. `redistribute connected` puts every inter-AS subnet
			// there with no network statement anywhere, and the peering
			// networks appeared as OSPF routes on every other router of the
			// system while the question was marked correct.
			name:     "inter-AS subnets redistributed into OSPF",
			question: "q1.2",
			apply: func(t *testing.T) {
				vtysh(t, dir, "as3/MSP", "configure terminal", "router ospf",
					"redistribute connected", "end")
				time.Sleep(15 * time.Second)
			},
			undo: func(t *testing.T) {
				vtysh(t, dir, "as3/MSP", "configure terminal", "router ospf",
					"no redistribute connected", "end")
			},
		},
		{
			// The same median loophole as q2.3, in the question about
			// engineering traffic around the slow link.
			//
			// The outbound half compared the *median* local preference of the
			// slow provider's routes with the fast provider's. Raising one
			// prefix learned over the slow link above the fast one's
			// preference moves neither median, so traffic for that prefix took
			// the link the question asks the student to avoid and the mark was
			// awarded in full.
			name:     "one prefix routed over the slow link",
			question: "q2.5",
			// Raising a provider's route above a peer's to make traffic take
			// the slow link is also a business-relationship error, and since
			// routes are attributed by the session they arrived on rather
			// than by a rewritable next hop, the relationship question sees
			// it. That is the grader being right twice, not collateral.
			alsoAffects: []string{"q2.3"},
			apply: func(t *testing.T) {
				router, nbr, prefix := slowProviderRoute(t, dir, 3)
				rm := importRouteMap(t, dir, router, nbr)
				if rm == "" {
					t.Fatalf("%s has no import route-map on the session with the slow "+
						"provider %s", router, nbr)
				}
				t.Logf("raising %s learned from the slow provider %s on %s", prefix, nbr, router)
				// The rest of the policy is preserved.
				//
				// A clause that matches and stops replaces the whole import
				// policy for that prefix, including the community the export
				// policy classifies routes by -- so the route stops looking
				// like a provider's and the *export* question fails too. A
				// student who mis-set one preference has not also stopped
				// tagging their routes, and a mutation that breaks two
				// questions cannot show that either check works.
				cfg := []string{"configure terminal",
					"ip prefix-list SLOWONE seq 5 permit " + prefix,
					"route-map " + rm + " permit 1",
					" match ip address prefix-list SLOWONE"}
				if c := communitySetBy(t, dir, router, rm); c != "" {
					cfg = append(cfg, " set community "+c)
				}
				cfg = append(cfg, " set local-preference 150", "end")
				vtysh(t, dir, router, cfg...)
				vtysh(t, dir, router, "clear bgp ipv4 unicast "+nbr+" in")
				time.Sleep(8 * time.Second)
			},
		},
		{
			// The other half of the export rule, which was never checked.
			//
			// "No transit for peers" was assessed by counting leaks and by
			// requiring the AS's own prefix to be advertised. An AS that
			// accepted its customers' routes and told nobody about them leaked
			// nothing and advertised its own prefix, so it passed -- while the
			// customer it is paid to carry was unreachable from the rest of the
			// internet.
			name:     "a customer's prefix withheld from a provider",
			question: "q2.3",
			apply: func(t *testing.T) {
				_, _, prefix := bestCustomerRoute(t, dir, 3)
				// On whichever router holds a provider session, which is not
				// necessarily the one that holds the customer: AS 3's customer
				// sessions and its provider sessions are on different routers,
				// and denying a customer prefix to another customer proves
				// nothing, because a customer may receive everything.
				router, prov := providerSession(t, dir, 3)
				if prov == "" {
					t.Fatal("AS 3 has no provider session, so nothing can be withheld")
				}
				t.Logf("withholding %s from the provider %s on %s", prefix, prov, router)
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list NOCUST seq 5 deny "+prefix,
					"ip prefix-list NOCUST seq 10 permit 0.0.0.0/0 le 32",
					"route-map WITHHOLD permit 10",
					" match ip address prefix-list NOCUST",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  neighbor "+prov+" route-map WITHHOLD out",
					" exit-address-family",
					"end")
				vtysh(t, dir, router, "clear bgp ipv4 unicast "+prov+" out")
				time.Sleep(8 * time.Second)
			},
		},
		{
			// An adjacency somewhere else instead of the one that was asked
			// for.
			//
			// The question counted neighbours in state Full and compared the
			// total with twice the number of interior links. A count does not
			// say which links: making one link's interfaces passive and
			// building a tunnel between the same two routers to carry an
			// adjacency instead kept the total exactly right, and every
			// interior link was reported adjacent while one of them was not.
			name:     "an interior adjacency moved onto a tunnel",
			question: "q1.2",
			undo: func(t *testing.T) {
				for _, r := range greEnds {
					_, _ = twinet(t, "exec", "-m", dir, r, "--", "sh", "-c",
						"ip link set gre1 down 2>/dev/null; ip tunnel del gre1 2>/dev/null; echo ok")
				}
			},
			apply: func(t *testing.T) {
				a, b, aIf, bIf := interiorLinkEnds(t, dir, 3)
				greEnds = []string{a, b}
				aLo, bLo := loopbackOf(t, dir, a), loopbackOf(t, dir, b)
				t.Logf("making %s/%s and %s/%s passive and tunnelling the adjacency instead",
					a, aIf, b, bIf)
				vtysh(t, dir, a, "configure terminal", "router ospf",
					" passive-interface "+aIf, "end")
				vtysh(t, dir, b, "configure terminal", "router ospf",
					" passive-interface "+bIf, "end")
				for _, e := range []struct{ dev, local, remote, addr string }{
					{a, aLo, bLo, "10.66.0.1/30"}, {b, bLo, aLo, "10.66.0.2/30"},
				} {
					if _, err := twinet(t, "exec", "-m", dir, e.dev, "--", "sh", "-c",
						"ip tunnel add gre1 mode gre local "+e.local+" remote "+e.remote+
							" ttl 64; ip addr add "+e.addr+" dev gre1; ip link set gre1 up"); err != nil {
						t.Fatalf("building the tunnel on %s: %v", e.dev, err)
					}
					vtysh(t, dir, e.dev, "configure terminal", "router ospf",
						" network 10.66.0.0/30 area 0", "end")
				}
				time.Sleep(75 * time.Second)
			},
		},
		{
			// A customer's routes made invisible by rewriting their next hop.
			//
			// Routes were attributed to a relationship by their next hop, and
			// an inbound route-map can set that to anything. Rewriting a
			// customer's next hop to an unrelated on-link address hid its
			// routes from the check entirely, so ranking them below a peer's
			// -- the exact violation the question is about -- cost nothing.
			name:     "a customer's next hop rewritten and its routes ranked below a peer's",
			question: "q2.3",
			undo: func(t *testing.T) {
				if hidden.router == "" {
					return
				}
				vtysh(t, dir, hidden.router, "configure terminal",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  neighbor "+hidden.peer+" route-map "+hidden.origMap+" in",
					" exit-address-family",
					"exit",
					"no route-map HIDECUST permit 10",
					"end")
				vtysh(t, dir, hidden.router, "clear ip bgp "+hidden.peer+" in")
				time.Sleep(20 * time.Second)
			},
			apply: func(t *testing.T) {
				router, peer, orig := customerImport(t, dir, 3)
				hidden = struct{ router, peer, origMap string }{router, peer, orig}
				t.Logf("hiding the customer at %s behind a rewritten next hop on %s", peer, router)
				vtysh(t, dir, router, "configure terminal",
					"route-map HIDECUST permit 10",
					" set local-preference 50",
					" set ip next-hop "+bumpLastOctet(peer),
					"router bgp 3",
					" address-family ipv4 unicast",
					"  neighbor "+peer+" route-map HIDECUST in",
					"end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" in")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// Native IPv6, with the tunnel's counters kept moving.
			//
			// The tunnel question was settled by the tunnel's packet counters
			// rising during the test. A counter is a total, and a total can be
			// moved by anything: routing every datacentre prefix natively and
			// pinging a link-local address across the tunnel in a loop earned
			// the whole mark while none of the traffic in question was
			// encapsulated at all.
			name:     "the datacentres routed natively while the tunnel is kept busy",
			question: "q1.4",
			undo: func(t *testing.T) {
				for _, g := range nativeV6 {
					for _, p := range g.prefixes {
						_, _ = twinet(t, "exec", "-m", dir, g.router, "--", "ip", "-6",
							"route", "del", p, "via", g.via, "dev", g.iface, "metric", "100")
					}
					_, _ = twinet(t, "exec", "-m", dir, g.router, "--", "ip", "-6",
						"addr", "del", g.addr, "dev", g.iface)
				}
				time.Sleep(45 * time.Second)
			},
			apply: func(t *testing.T) {
				nativeV6 = nativeV6Path(t, dir, 3)
				if len(nativeV6) != 2 {
					t.Fatal("could not build a native IPv6 path between the two datacentres")
				}
				for _, g := range nativeV6 {
					if out, err := twinet(t, "exec", "-m", dir, g.router, "--", "ip", "-6",
						"addr", "add", g.addr, "dev", g.iface); err != nil {
						t.Fatalf("addressing %s on %s: %v\n%s", g.iface, g.router, err, out)
					}
				}
				for _, g := range nativeV6 {
					for _, p := range g.prefixes {
						if out, err := twinet(t, "exec", "-m", dir, g.router, "--", "ip", "-6",
							"route", "replace", p, "via", g.via, "dev", g.iface,
							"metric", "100"); err != nil {
							t.Fatalf("routing %s natively on %s: %v\n%s", p, g.router, err, out)
						}
					}
					// And keep the tunnel busy, so its counters climb
					// throughout the measurement.
					_, _ = twinet(t, "exec", "-m", dir, g.router, "--", "sh", "-c",
						"setsid timeout 600 ping6 -q -i 0.2 -I "+g.tunnel+
							" ff02::1 >/dev/null 2>&1 & echo started")
				}
				t.Logf("routed the datacentre prefixes natively and set both tunnels pinging")
				time.Sleep(10 * time.Second)
			},
		},
		{
			// A trust anchor of one's own.
			//
			// Whether a ROA was published was read out of `show rpki
			// prefix-table` on a router of the system being marked. A student
			// has root in their own containers: withdraw the genuine ROA, run
			// an RTR server on a host, point the validator session at it, and
			// the prefix table says whatever they like -- so the question
			// about having published was answered by the publication being
			// faked. Publication is a fact about the anchor. This mutation
			// withdraws the real one and leaves the routers untouched: if the
			// mark survives, the check is reading something other than the
			// anchor.
			name:     "the published ROA withdrawn from the trust anchor",
			question: "q2.6",
			undo: func(t *testing.T) {
				if roaWithdrawn.prefix == "" {
					return
				}
				publishROA(t, dir, roaWithdrawn.router, roaWithdrawn.anchor,
					roaWithdrawn.prefix, 3, false)
				time.Sleep(70 * time.Second)
			},
			apply: func(t *testing.T) {
				router, anchor, prefix := roaPublisher(t, dir, 3)
				roaWithdrawn = struct{ router, anchor, prefix string }{router, anchor, prefix}
				t.Logf("withdrawing %s from the trust anchor at %s", prefix, anchor)
				publishROA(t, dir, router, anchor, prefix, 3, true)
				time.Sleep(70 * time.Second)
			},
		},
		{
			// Everything denied, everywhere.
			//
			// "No invalid route is selected" is trivially true of an AS that
			// selected no external route at all. A deny-everything clause
			// ahead of the RPKI one -- which stays present and reachable in
			// the configuration -- left the AS with nothing but its own
			// prefix, and the origin-validation question awarded full marks
			// for refusing something it had never been in a position to
			// accept.
			name:        "every external route denied on the way in",
			question:    "q2.6",
			alsoAffects: []string{"q2.3", "q2.4", "q2.5"},
			undo: func(t *testing.T) {
				for _, dev := range routersOf(t, dir, 3) {
					cmds := []string{"configure terminal"}
					for _, m := range importMapNames {
						cmds = append(cmds, "no route-map "+m+" deny 1")
					}
					cmds = append(cmds,
						"no ip prefix-list DENYALL seq 5 permit 0.0.0.0/0 le 32", "end")
					vtysh(t, dir, dev, cmds...)
					vtysh(t, dir, dev, "clear ip bgp * in")
				}
				time.Sleep(20 * time.Second)
			},
			apply: func(t *testing.T) {
				importMapNames = inboundRouteMaps(t, dir, 3)
				if len(importMapNames) == 0 {
					t.Fatal("AS 3 applies no inbound policy, so there is nothing to put a " +
						"deny in front of")
				}
				t.Logf("denying everything ahead of %v on every router of AS 3", importMapNames)
				for _, dev := range routersOf(t, dir, 3) {
					cmds := []string{"configure terminal",
						"ip prefix-list DENYALL seq 5 permit 0.0.0.0/0 le 32"}
					for _, m := range importMapNames {
						cmds = append(cmds, "route-map "+m+" deny 1",
							" match ip address prefix-list DENYALL")
					}
					cmds = append(cmds, "end")
					vtysh(t, dir, dev, cmds...)
					vtysh(t, dir, dev, "clear ip bgp * in")
				}
				time.Sleep(25 * time.Second)
			},
		},
		{
			// Everything from the exchange denied.
			//
			// The exchange question was decided on refusals: no route whose
			// path crosses this region may be accepted. An inbound policy that
			// denied everything the route server sent accepted no in-region
			// route either, and passed -- a member that hears nothing from the
			// exchange has not written a peering policy, it has switched the
			// exchange off.
			name:     "everything from the exchange denied",
			question: "q2.4",
			undo: func(t *testing.T) {
				if ixpDeny.router == "" {
					return
				}
				vtysh(t, dir, ixpDeny.router, "configure terminal",
					"no route-map "+ixpDeny.routeMap+" deny 4", "end")
				vtysh(t, dir, ixpDeny.router, "clear ip bgp "+ixpDeny.peer+" in")
			},
			apply: func(t *testing.T) {
				router, peer, rmap := ixpImport(t, dir, 3)
				ixpDeny = struct{ router, peer, routeMap string }{router, peer, rmap}
				t.Logf("denying everything %s sends %s, before its AS-path filter", peer, router)
				vtysh(t, dir, router, "configure terminal",
					"route-map "+rmap+" deny 4", "end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" in")
				time.Sleep(15 * time.Second)
			},
		},
		{
			// A subnet redistributed into OSPF instead of advertised into it.
			//
			// "Protocol is ospf" is true of a route somebody redistributed
			// from a static blackhole. Removing a service subnet's genuine
			// advertisement, pointing Null0 at it on a different router and
			// turning on `redistribute static` put the prefix in every table,
			// marked ospf, reaching nowhere -- and the check said all
			// thirty-two subnets were carried while the service was at total
			// loss.
			name:     "a service subnet redistributed into OSPF rather than advertised",
			question: "q1.2",
			undo: func(t *testing.T) {
				if redistributed.prefix == "" {
					return
				}
				vtysh(t, dir, redistributed.faker, "configure terminal",
					"no ip route "+redistributed.prefix+" Null0",
					"router ospf",
					" no redistribute static",
					"end")
			},
			apply: func(t *testing.T) {
				owner, faker, prefix := serviceSubnet(t, dir, 3)
				redistributed = struct{ faker, prefix string }{faker, prefix}
				t.Logf("removing %s from OSPF on %s and redistributing a blackhole for it on %s",
					prefix, owner, faker)
				vtysh(t, dir, owner, "configure terminal",
					"router ospf",
					" no network "+prefix+" area 0",
					"end")
				vtysh(t, dir, faker, "configure terminal",
					"ip route "+prefix+" Null0",
					"router ospf",
					" redistribute static",
					"end")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// An external session held open by a timer.
			//
			// Dropping both directions of the TCP flow leaves the session
			// reported Established until the hold timer expires, which is
			// longer than a grading run.
			name:     "an eBGP session blackholed but still called Established",
			question: "q2.2",
			undo: func(t *testing.T) {
				if ebgpBlackhole.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, ebgpBlackhole.router, "--", "sh", "-c",
					"iptables -D INPUT -p tcp -s "+ebgpBlackhole.peer+" -j DROP; "+
						"iptables -D OUTPUT -p tcp -d "+ebgpBlackhole.peer+" -j DROP")
			},
			apply: func(t *testing.T) {
				router, peer := externalSessionOf(t, dir, as)
				ebgpBlackhole = struct{ router, peer string }{router, peer}
				t.Logf("discarding BGP packets between %s and %s", router, peer)
				out, err := twinet(t, "exec", "-m", dir, router, "--", "sh", "-c",
					"iptables -I INPUT 1 -p tcp -s "+peer+" -j DROP && "+
						"iptables -I OUTPUT 1 -p tcp -d "+peer+" -j DROP")
				if err != nil {
					t.Fatalf("blackholing an external session: %v\n%s", err, out)
				}
			},
		},
		{
			// The ordering agreed with and then ignored.
			//
			// BGP's decision is not the kernel's. A static route for an
			// externally learned prefix sends the traffic wherever it says
			// while the BGP table still shows the right path selected.
			name:     "an external prefix forwarded by a static route instead of BGP",
			question: "q2.3",
			undo: func(t *testing.T) {
				if staticOverride.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, staticOverride.router, "--",
					"ip", "route", "del", staticOverride.prefix)
			},
			apply: func(t *testing.T) {
				router, peer, _, prefix, _ := leakableRoute(t, dir, as)
				staticOverride = struct{ router, prefix string }{router, prefix}
				t.Logf("forwarding %s from %s by hand, via %s", prefix, router, peer)
				out, err := twinet(t, "exec", "-m", dir, router, "--", "ip", "route",
					"replace", prefix, "via", peer, "proto", "static", "metric", "1")
				if err != nil {
					t.Fatalf("installing a static override: %v\n%s", err, out)
				}
			},
		},
		{
			// A prepend that empties the slow link instead of lengthening it.
			//
			// Prepending the neighbour's own number is three hops longer and
			// discarded on arrival as a loop, so the backup link stops
			// carrying anything -- which counting hops read as correct.
			name:     "the slow link prepended with the neighbour's own ASN",
			question: "q2.5",
			undo: func(t *testing.T) {
				if slowPrepend.router == "" {
					return
				}
				vtysh(t, dir, slowPrepend.router, "configure terminal",
					"route-map "+slowPrepend.routeMap+" permit "+slowPrepend.seq,
					" set as-path prepend "+slowPrepend.original,
					"end")
				vtysh(t, dir, slowPrepend.router, "clear ip bgp "+slowPrepend.peer+" out")
			},
			apply: func(t *testing.T) {
				router, rmap, seq, peer, orig, asn := slowPrependClause(t, dir, as)
				slowPrepend = struct{ router, routeMap, seq, peer, original string }{
					router, rmap, seq, peer, orig}
				t.Logf("prepending AS%s instead of AS%d towards %s", asn, as, peer)
				vtysh(t, dir, router, "configure terminal",
					"route-map "+rmap+" permit "+seq,
					" set as-path prepend "+asn+" "+asn+" "+asn,
					"end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" out")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// Somebody else's prefix, re-originated on the way out.
			//
			// A relayed route keeps its origin at the end of the path, and our
			// own prepends go on the front. Rewriting the end makes the
			// neighbour believe this AS originates address space it does not
			// hold, and it never appears as a locally injected route.
			name:     "a transit route re-originated as ours towards a customer",
			question: "q2.2",
			undo: func(t *testing.T) {
				if reorigin.router == "" {
					return
				}
				vtysh(t, dir, reorigin.router, "configure terminal",
					"no route-map "+reorigin.routeMap+" permit 3",
					"no ip prefix-list TWGRADE-STEAL seq 5 permit "+reorigin.prefix,
					"end")
			},
			apply: func(t *testing.T) {
				router, peer, rmap, prefix, origin := leakableRoute(t, dir, as)
				reorigin = struct{ router, routeMap, prefix string }{router, rmap, prefix}
				t.Logf("telling %s that %s originates %s", peer, "AS"+itoa(as), prefix)
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list TWGRADE-STEAL seq 5 permit "+prefix,
					"route-map "+rmap+" permit 3",
					" match ip address prefix-list TWGRADE-STEAL",
					" set as-path exclude "+origin,
					" set as-path prepend "+itoa(as),
					"end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" out")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// A ROA that authorises everything smaller.
			//
			// The maximum length was printed and not read, so a ROA with
			// `maxlen 32` -- which makes a hijack of any piece of the block
			// valid to everybody who checks -- was full credit.
			name:     "a ROA authorising every more-specific inside the block",
			question: "q2.6",
			undo: func(t *testing.T) {
				if looseROA.anchor == "" {
					return
				}
				publishROAWithLength(t, dir, looseROA.router, looseROA.anchor,
					looseROA.prefix, as, looseROA.length)
			},
			apply: func(t *testing.T) {
				router, anchor, prefix := roaPublisher(t, dir, as)
				length := 8
				if _, l, ok := strings.Cut(prefix, "/"); ok {
					if n, err := strconv.Atoi(l); err == nil {
						length = n
					}
				}
				looseROA = struct {
					router, anchor, prefix string
					length                 int
				}{router, anchor, prefix, length}
				t.Logf("publishing %s with maxlen 32 instead of %d", prefix, length)
				publishROAWithLength(t, dir, router, anchor, prefix, as, 32)
			},
		},
		{
			// A leak wearing a customer's number.
			//
			// Whether an advertisement to a peer or a provider was a leak was
			// decided from the AS path in that advertisement, and a path on
			// the way out is the submission's to write.
			name:     "a peer's route leaked with a customer's ASN prepended",
			question: "q2.3",
			undo: func(t *testing.T) {
				if forgedLeak.router == "" {
					return
				}
				vtysh(t, dir, forgedLeak.router, "configure terminal",
					"no route-map "+forgedLeak.routeMap+" permit 5",
					"no ip prefix-list TWGRADE-LEAK-OUT seq 5 permit "+forgedLeak.prefix,
					"end")
			},
			apply: func(t *testing.T) {
				router, peer, rmap, prefix, cust := leakableRoute(t, dir, as)
				forgedLeak = struct{ router, routeMap, prefix string }{router, rmap, prefix}
				t.Logf("leaking %s to %s from %s, wearing AS %s", prefix, peer, router, cust)
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list TWGRADE-LEAK-OUT seq 5 permit "+prefix,
					"route-map "+rmap+" permit 5",
					" match ip address prefix-list TWGRADE-LEAK-OUT",
					" set as-path prepend "+itoa(as)+" "+cust,
					"end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" out")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// A copy the switch's own tables know nothing about.
			//
			// The kernel will copy a frame for anybody who asks, and a `tc`
			// mirror on an access port carries one VLAN's traffic into another
			// with the flow table exactly as it should be.
			name:     "one protocol mirrored across VLANs by a traffic-control rule",
			question: "q1.1",
			undo: func(t *testing.T) {
				if tcMirror.switchID == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, tcMirror.switchID, "--",
					"tc", "qdisc", "del", "dev", tcMirror.from, "clsact")
			},
			apply: func(t *testing.T) {
				sw, from, to := vlanPortPair(t, dir, as)
				tcMirror = struct{ switchID, from string }{sw, from}
				t.Logf("mirroring ICMP from %s to %s on %s", from, to, sw)
				out, err := twinet(t, "exec", "-m", dir, sw, "--", "sh", "-c",
					"tc qdisc add dev "+from+" clsact && "+
						"tc filter add dev "+from+" ingress protocol ip pref 49152 flower "+
						"ip_proto icmp action mirred egress mirror dev "+to)
				if err != nil {
					t.Fatalf("mirroring across VLANs with tc: %v\n%s", err, out)
				}
			},
		},
		{
			// A way across that carries one flow and no broadcast.
			//
			// The isolation probe sends a broadcast, which is what a shared
			// broadcast domain leaks. An OpenFlow entry copying one protocol
			// from a port in one VLAN to a port in another leaks nothing else,
			// and cost nothing.
			name:     "one flow mirrored across VLANs by a forwarding rule",
			question: "q1.1",
			undo: func(t *testing.T) {
				if vlanFlow.switchID == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, vlanFlow.switchID, "--",
					"ovs-ofctl", "del-flows", "br0", "cookie=0x461bad/-1")
			},
			apply: func(t *testing.T) {
				sw, from, to := vlanPortPair(t, dir, as)
				vlanFlow = struct{ switchID string }{sw}
				t.Logf("mirroring one flow from %s to %s on %s", from, to, sw)
				out, err := twinet(t, "exec", "-m", dir, sw, "--", "ovs-ofctl", "add-flow", "br0",
					"cookie=0x461bad,priority=200,in_port="+from+",ip,tcp,tp_dst=443,"+
						"actions=normal,output:"+to)
				if err != nil {
					t.Fatalf("mirroring one flow across VLANs: %v\n%s", err, out)
				}
			},
		},
		{
			// A pair that exchanges everything but datagrams.
			//
			// The matrix was tried with a ping and a connection, so a rule
			// dropping UDP between two hosts left every probe succeeding.
			name:     "two hosts that cannot exchange a datagram",
			question: "q1.2",
			undo: func(t *testing.T) {
				if udpPair.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, udpPair.router, "--", "iptables", "-D",
					"INPUT", "-s", udpPair.src, "-p", "udp", "-j", "DROP")
			},
			apply: func(t *testing.T) {
				dst := "as" + itoa(as) + "/NYC_host"
				src := hostAddr(t, dir, "as"+itoa(as)+"/MSP_host")
				udpPair = struct{ router, src string }{dst, src + "/32"}
				t.Logf("discarding datagrams from %s at %s", src, dst)
				out, err := twinet(t, "exec", "-m", dir, dst, "--", "iptables", "-I", "INPUT",
					"1", "-s", udpPair.src, "-p", "udp", "-j", "DROP")
				if err != nil {
					t.Fatalf("discarding datagrams: %v\n%s", err, out)
				}
			},
		},
		{
			// One port open and the rest of TCP discarded.
			//
			// A fixed probe port is a published answer: a rule resetting that
			// one port and dropping every other connection read as a network
			// in perfect health.
			name:     "one port answering while every other connection is dropped",
			question: "q1.2",
			undo: func(t *testing.T) {
				_, _ = twinet(t, "exec", "-m", dir, "as3/NYC_host", "--", "sh", "-c",
					"iptables -D INPUT -p tcp --dport 9 -j REJECT --reject-with tcp-reset; "+
						"iptables -D INPUT -p tcp --tcp-flags RST RST -j ACCEPT; "+
						"iptables -D INPUT -p tcp -j DROP")
			},
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/NYC_host", "--", "sh", "-c",
					"iptables -A INPUT -p tcp --dport 9 -j REJECT --reject-with tcp-reset && "+
						"iptables -I INPUT 2 -p tcp --tcp-flags RST RST -j ACCEPT && "+
						"iptables -A INPUT -p tcp -j DROP")
				if err != nil {
					t.Fatalf("permitting one port and dropping the rest: %v\n%s", err, out)
				}
			},
		},
		{
			// A pair that can be pinged and not spoken to.
			//
			// Every probe of the internal data plane was ICMP, so a rule
			// discarding TCP between two hosts left every probe succeeding.
			name:     "two hosts that can ping each other and nothing more",
			question: "q1.2",
			undo: func(t *testing.T) {
				if tcpBlock.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, tcpBlock.router, "--", "iptables", "-D",
					"FORWARD", "-s", tcpBlock.src, "-d", tcpBlock.dst, "-p", "tcp", "-j", "DROP")
			},
			apply: func(t *testing.T) {
				src := hostAddr(t, dir, "as"+itoa(as)+"/NYC_host")
				dst := hostAddr(t, dir, "as"+itoa(as)+"/BOS_host")
				tcpBlock = struct{ router, src, dst string }{
					"as" + itoa(as) + "/NYC", src + "/32", dst + "/32"}
				t.Logf("discarding TCP from %s to %s", src, dst)
				out, err := twinet(t, "exec", "-m", dir, tcpBlock.router, "--", "iptables",
					"-I", "FORWARD", "1", "-s", tcpBlock.src, "-d", tcpBlock.dst,
					"-p", "tcp", "-j", "DROP")
				if err != nil {
					t.Fatalf("discarding TCP between two hosts: %v\n%s", err, out)
				}
			},
		},
		{
			// One host that cannot reach the preserved network.
			//
			// Whether an unsigned origin was still reachable was decided by one
			// ping from whichever host the manifest happened to list first, so
			// a blackhole on any other cost nothing.
			name:     "a preserved route blackholed on one host",
			question: "q2.6",
			undo: func(t *testing.T) {
				if notFoundBlock.host == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, notFoundBlock.host, "--",
					"ip", "route", "del", "blackhole", notFoundBlock.prefix)
			},
			apply: func(t *testing.T) {
				prefix := notFoundPrefix(t, dir, as)
				host := "as" + itoa(as) + "/NYC_host"
				notFoundBlock = struct{ host, prefix string }{host, prefix}
				t.Logf("blackholing %s on %s alone", prefix, host)
				out, err := twinet(t, "exec", "-m", dir, host, "--",
					"ip", "route", "add", "blackhole", prefix)
				if err != nil {
					t.Fatalf("blackholing the preserved route: %v\n%s", err, out)
				}
			},
		},
		{
			// A prohibition narrowed until it prohibits one thing.
			//
			// FRR requires every match in a clause to hold, so a deny that
			// matches `rpki invalid` and a prefix list rejects invalid routes
			// on that list and accepts every other one.
			name:     "the RPKI deny narrowed to the one prefix the lab announces",
			question: "q2.6",
			undo: func(t *testing.T) {
				if rpkiNarrow.router == "" {
					return
				}
				vtysh(t, dir, rpkiNarrow.router, "configure terminal",
					"route-map "+rpkiNarrow.routeMap+" deny "+rpkiNarrow.seq,
					" no match ip address prefix-list TWGRADE-ONLY",
					"exit",
					"no ip prefix-list TWGRADE-ONLY seq 5 permit 10.128.0.0/9",
					"end")
			},
			apply: func(t *testing.T) {
				router, rmap, seq := rpkiDenyClause(t, dir, as)
				rpkiNarrow = struct{ router, routeMap, seq string }{router, rmap, seq}
				t.Logf("narrowing %s deny %s on %s to one prefix", rmap, seq, router)
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list TWGRADE-ONLY seq 5 permit 10.128.0.0/9",
					"route-map "+rmap+" deny "+seq,
					" match ip address prefix-list TWGRADE-ONLY",
					"end")
			},
		},
		{
			// An in-region route accepted with its evidence erased.
			//
			// Which routes crossed a system of this region was decided from the
			// AS path the member holds after its own import policy has run, and
			// an import policy can rewrite a path.
			name:     "an in-region announcement accepted with the path rewritten",
			question: "q2.4",
			undo: func(t *testing.T) {
				if ixpRewrite.router == "" {
					return
				}
				vtysh(t, dir, ixpRewrite.router, "configure terminal",
					"no route-map "+ixpRewrite.routeMap+" permit 4",
					"no bgp as-path access-list TWGRADE-VIA permit "+ixpRewrite.match,
					"end")
			},
			apply: func(t *testing.T) {
				router, rmap, peer, hidden, path := ixpInRegionRoute(t, dir, as)
				ixpRewrite = struct{ router, routeMap, match, peer string }{
					router, rmap, "^" + path + "$", peer}
				t.Logf("accepting %s on %s with %s taken out of its path", hidden, router, path)
				vtysh(t, dir, router, "configure terminal",
					"bgp as-path access-list TWGRADE-VIA permit ^"+path+"$",
					"route-map "+rmap+" permit 4",
					" match as-path TWGRADE-VIA",
					" set as-path exclude "+strings.Fields(path)[0],
					" set local-preference 200",
					"end")
				vtysh(t, dir, router, "clear ip bgp "+ixpRewrite.peer+" in")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// An adjacency on something wearing the link's name.
			//
			// The interior adjacencies were tied to the plan by the name of
			// the interface each ran on, and a name is the one part of an
			// interface anyone with root can change.
			name:     "an interior link impersonated by a tunnel with its name",
			question: "q1.2",
			undo: func(t *testing.T) {
				if impostorLink.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, impostorLink.router, "--", "sh", "-c",
					"ip link del "+impostorLink.iface+" 2>/dev/null; "+
						"ip link set "+impostorLink.moved+" down 2>/dev/null; "+
						"ip link set "+impostorLink.moved+" name "+impostorLink.iface+
						" 2>/dev/null; ip link set "+impostorLink.iface+" up")
			},
			apply: func(t *testing.T) {
				router, iface, local, remote := interiorLinkEnd(t, dir, as)
				impostorLink = struct{ router, iface, moved string }{
					router, iface, "underlay0"}
				t.Logf("renaming %s on %s and putting a tunnel in its place", iface, router)
				out, err := twinet(t, "exec", "-m", dir, router, "--", "sh", "-c",
					"ip link set "+iface+" down && ip link set "+iface+" name underlay0 && "+
						"ip link set underlay0 up && ip addr flush dev underlay0 && "+
						"ip addr add "+local+" dev underlay0 && "+
						"ip link add "+iface+" type gretap local "+
						strings.SplitN(local, "/", 2)[0]+" remote "+remote+" && "+
						"ip link set "+iface+" up")
				if err != nil {
					t.Fatalf("substituting a tunnel for the link: %v\n%s", err, out)
				}
				time.Sleep(20 * time.Second)
			},
		},
		{
			// Paths that carry two protocols of three.
			//
			// A filter is written per protocol as easily as per port: dropping
			// UDP between the two loopbacks leaves the pings and the
			// connections working.
			name:     "the prescribed paths dropping datagrams alone",
			question: "q1.3",
			undo: func(t *testing.T) {
				if udpBlock.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, udpBlock.router, "--", "iptables", "-D",
					"OUTPUT", "-p", "udp", "-s", udpBlock.src, "-d", udpBlock.dst, "-j", "DROP")
			},
			apply: func(t *testing.T) {
				a, b := "as3/ATL", "as3/BOS"
				udpBlock = struct{ router, src, dst string }{
					a, loopbackOf(t, dir, a), loopbackOf(t, dir, b)}
				t.Logf("discarding UDP from %s to %s", udpBlock.src, udpBlock.dst)
				out, err := twinet(t, "exec", "-m", dir, a, "--", "iptables", "-I", "OUTPUT",
					"1", "-p", "udp", "-s", udpBlock.src, "-d", udpBlock.dst, "-j", "DROP")
				if err != nil {
					t.Fatalf("discarding datagrams: %v\n%s", err, out)
				}
			},
		},
		{
			// Paths that answer pings and carry nothing else.
			//
			// The equal-cost question was decided from the forwarding tables
			// plus one ICMP probe from end to end. That probe takes one of the
			// three paths -- which one is a hash, and it is the same hash every
			// time -- and it says nothing about any other protocol.
			name:        "the prescribed paths dropping everything but ICMP",
			question:    "q1.3",
			alsoAffects: []string{"q2.1", "q2.2"},
			undo: func(t *testing.T) {
				if ecmpTCP.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, ecmpTCP.router, "--",
					"iptables", "-D", "INPUT", "-p", "tcp", "-s", ecmpTCP.from, "-j", "DROP")
			},
			apply: func(t *testing.T) {
				a, b := "as3/ATL", "as3/BOS"
				src := loopbackOf(t, dir, a)
				ecmpTCP = struct{ router, from string }{b, src}
				t.Logf("discarding TCP from %s at %s", src, b)
				out, err := twinet(t, "exec", "-m", dir, b, "--",
					"iptables", "-I", "INPUT", "1", "-p", "tcp", "-s", src, "-j", "DROP")
				if err != nil {
					t.Fatalf("discarding TCP: %v\n%s", err, out)
				}
			},
		},
		{
			// The ordering arranged by an attribute nobody looked at.
			//
			// Local preference is only the second tie-break in the decision
			// process, so `set weight 65535` on a provider's route puts it
			// ahead of a peer's while every local preference in the table
			// still reads correctly.
			name:     "a provider's route preferred by weight while local preference reads right",
			question: "q2.3",
			undo: func(t *testing.T) {
				if weighted.router == "" {
					return
				}
				vtysh(t, dir, weighted.router, "configure terminal",
					"no route-map "+weighted.routeMap+" permit 15",
					"no ip prefix-list TWGRADE-WEIGHT seq 5 permit "+weighted.prefix,
					"end")
			},
			apply: func(t *testing.T) {
				router, peer, rmap, prefix := providerImport(t, dir, as)
				weighted = struct{ router, routeMap, prefix string }{router, rmap, prefix}
				t.Logf("preferring %s from the provider at %s by weight, on %s",
					prefix, peer, router)
				// A clause on the policy the provider's session already
				// applies, so it takes effect the way a student's would.
				vtysh(t, dir, router, "configure terminal",
					"ip prefix-list TWGRADE-WEIGHT seq 5 permit "+prefix,
					"route-map "+rmap+" permit 15",
					" match ip address prefix-list TWGRADE-WEIGHT",
					" set local-preference 100",
					" set weight 65535",
					"end")
				vtysh(t, dir, router, "clear ip bgp "+peer+" in")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// A route in the table and no packet on the wire.
			//
			// A policy rule sending one destination to another table, with a
			// discard in it, leaves every next hop resolved and every route
			// held in the daemon's own view, while the kernel drops the
			// traffic.
			name:     "an external destination discarded by a policy rule",
			question: "q2.2",
			undo: func(t *testing.T) {
				_, _ = twinet(t, "exec", "-m", dir, "as3/ATL", "--", "sh", "-c",
					"ip rule del pref 100 to 8.0.0.0/8 lookup 123; "+
						"ip route del blackhole 8.0.0.0/8 table 123")
			},
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/ATL", "--", "sh", "-c",
					"ip route add blackhole 8.0.0.0/8 table 123 && "+
						"ip rule add pref 100 to 8.0.0.0/8 lookup 123")
				if err != nil {
					t.Fatalf("diverting a destination into a discard: %v\n%s", err, out)
				}
			},
		},
		{
			// The probe's own port range, permitted and nothing else.
			//
			// A range is a published answer as surely as a single port. This
			// permits the range the grader used to draw from, and discards
			// every other connection and every datagram.
			name:     "only the grader's old port range allowed across the tunnel",
			question: "q1.4",
			undo: func(t *testing.T) {
				for _, r := range rangeAllow {
					_, _ = twinet(t, "exec", "-m", dir, r, "--", "sh", "-c",
						"ip6tables -D FORWARD -p tcp --dport 20000:39999 -j ACCEPT; "+
							"ip6tables -D FORWARD -p tcp --tcp-flags RST RST -j ACCEPT; "+
							"ip6tables -D FORWARD -p tcp -j DROP; "+
							"ip6tables -D FORWARD -p udp -j DROP")
				}
			},
			apply: func(t *testing.T) {
				gw, _ := tunnelGateway(t, dir, as)
				rangeAllow = []string{gw}
				t.Logf("permitting only 20000-39999 across the tunnel on %s", gw)
				out, err := twinet(t, "exec", "-m", dir, gw, "--", "sh", "-c",
					"ip6tables -I FORWARD 1 -p tcp --dport 20000:39999 -j ACCEPT && "+
						"ip6tables -I FORWARD 2 -p tcp --tcp-flags RST RST -j ACCEPT && "+
						"ip6tables -A FORWARD -p tcp -j DROP && "+
						"ip6tables -A FORWARD -p udp -j DROP")
				if err != nil {
					t.Fatalf("permitting one range: %v\n%s", err, out)
				}
			},
		},
		{
			// A tunnel that only carries pings.
			//
			// Every probe of the 6in4 question was ICMPv6, so a rule
			// discarding forwarded TCP on the gateway left every ping
			// answered, the tunnel counters moving, and the point awarded for
			// a tunnel across which no connection could be made.
			name:     "the tunnel carrying pings and no other traffic",
			question: "q1.4",
			undo: func(t *testing.T) {
				if tunnelTCP.gateway == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, tunnelTCP.gateway, "--", "sh", "-c",
					"ip6tables -D FORWARD -i "+tunnelTCP.iface+" -p tcp -j DROP; "+
						"ip6tables -D FORWARD -o "+tunnelTCP.iface+" -p tcp -j DROP")
			},
			apply: func(t *testing.T) {
				gw, iface := tunnelGateway(t, dir, as)
				tunnelTCP = struct{ gateway, iface string }{gw, iface}
				t.Logf("discarding forwarded TCP over %s on %s", iface, gw)
				out, err := twinet(t, "exec", "-m", dir, gw, "--", "sh", "-c",
					"ip6tables -I FORWARD 1 -i "+iface+" -p tcp -j DROP && "+
						"ip6tables -I FORWARD 1 -o "+iface+" -p tcp -j DROP")
				if err != nil {
					t.Fatalf("blocking TCP over the tunnel: %v\n%s", err, out)
				}
			},
		},
		{
			// A prefix in OSPF that no routing table holds.
			//
			// Redistributed with the maximum metric, an inter-AS range is
			// flooded to every router in the area and installed by none of
			// them: LSInfinity means "do not use this", so `show ip route
			// ospf` is empty and a check that reads routing tables sees
			// nothing. The database is where being in OSPF is decided.
			name:     "an inter-AS range flooded into OSPF at infinite metric",
			question: "q1.2",
			undo: func(t *testing.T) {
				vtysh(t, dir, "as3/NYC", "configure terminal",
					"router ospf",
					" no redistribute connected route-map TWGRADE-LEAK",
					"exit",
					"no route-map TWGRADE-LEAK permit 10",
					"no ip prefix-list TWGRADE-LEAK seq 5 permit "+leakedRange,
					"end")
			},
			apply: func(t *testing.T) {
				leakedRange = interASRange(t, dir, as)
				t.Logf("flooding %s into OSPF as an unusable external route", leakedRange)
				vtysh(t, dir, "as3/NYC", "configure terminal",
					"ip prefix-list TWGRADE-LEAK seq 5 permit "+leakedRange,
					"route-map TWGRADE-LEAK permit 10",
					" match ip address prefix-list TWGRADE-LEAK",
					" set metric 16777215",
					"exit",
					"router ospf",
					" redistribute connected route-map TWGRADE-LEAK",
					"end")
				time.Sleep(15 * time.Second)
			},
		},
		{
			// A session held open by a timer.
			//
			// "Established" is a memory. A session whose packets are being
			// discarded stays Established until the hold timer expires, which
			// with the default timers is longer than a grading run, so the
			// mesh scored full marks for a session carrying nothing.
			name:     "an iBGP session blackholed but still called Established",
			question: "q2.1",
			undo: func(t *testing.T) {
				if ibgpBlackhole.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, ibgpBlackhole.router, "--", "sh", "-c",
					"iptables -D INPUT -p tcp -s "+ibgpBlackhole.peer+" -j DROP; "+
						"iptables -D OUTPUT -p tcp -d "+ibgpBlackhole.peer+" -j DROP")
			},
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/NYC", "--",
					"vtysh", "-c", "show running-config")
				if err != nil {
					t.Fatalf("reading the configuration: %v\n%s", err, out)
				}
				peer := firstIBGPPeer(out)
				if peer == "" {
					t.Skip("no iBGP neighbour found to blackhole")
				}
				ibgpBlackhole = struct{ router, peer string }{"as3/NYC", peer}
				t.Logf("discarding BGP packets between as3/NYC and %s", peer)
				out, err = twinet(t, "exec", "-m", dir, "as3/NYC", "--", "sh", "-c",
					"iptables -I INPUT 1 -p tcp -s "+peer+" -j DROP && "+
						"iptables -I OUTPUT 1 -p tcp -d "+peer+" -j DROP")
				if err != nil {
					t.Fatalf("blackholing the session: %v\n%s", err, out)
				}
			},
		},
		{
			// Two VLANs made into one broadcast domain.
			//
			// The isolation check asked only about IP: hosts in one VLAN
			// adjacent, hosts in two separated by the gateway. Mirroring one
			// access port onto another leaves all of that true, because
			// off-subnet traffic goes through the gateway by a routing decision
			// the host makes before any frame exists.
			name:     "one VLAN's frames mirrored onto another",
			question: "q1.1",
			undo: func(t *testing.T) {
				if vlanMirror.switchID == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, vlanMirror.switchID, "--",
					"tc", "qdisc", "del", "dev", vlanMirror.from, "clsact")
			},
			apply: func(t *testing.T) {
				sw, from, to := vlanPortPair(t, dir, as)
				vlanMirror = struct{ switchID, from string }{sw, from}
				t.Logf("mirroring %s onto %s on %s", from, to, sw)
				out, err := twinet(t, "exec", "-m", dir, sw, "--", "sh", "-c",
					"tc qdisc add dev "+from+" clsact && "+
						"tc filter add dev "+from+" ingress protocol all pref 10 "+
						"matchall action mirred egress mirror dev "+to)
				if err != nil {
					t.Fatalf("mirroring one access port onto another: %v\n%s", err, out)
				}
			},
		},
		{
			// Transit promised and not delivered.
			//
			// Everything the transit check asked about was the routes a
			// customer is offered, which is a promise rather than a service.
			// Leaving every session established and every route advertised
			// while dropping the customers' packets in the FORWARD chain cost
			// nothing at all.
			name:     "customers' packets dropped while their routes are advertised",
			question: "q2.3",
			undo: func(t *testing.T) {
				for _, iface := range customerDrops {
					_, _ = twinet(t, "exec", "-m", dir, "as3/SFO", "--",
						"iptables", "-D", "FORWARD", "-i", iface, "-j", "DROP")
				}
			},
			apply: func(t *testing.T) {
				customerDrops = customerIfaces(t, dir, as)
				if len(customerDrops) == 0 {
					t.Skip("AS 3 has no customer-facing interface to block")
				}
				for _, iface := range customerDrops {
					out, err := twinet(t, "exec", "-m", dir, "as3/SFO", "--",
						"iptables", "-I", "FORWARD", "-i", iface, "-j", "DROP")
					if err != nil {
						t.Fatalf("blocking %s: %v\n%s", iface, err, out)
					}
				}
			},
		},
		{
			// A table emptied so that nothing is owed.
			//
			// What a customer was owed came from the table of the router
			// holding its session, and that table is the submission's to
			// empty: denying everything inbound left the router with only its
			// own prefix and the check reporting that everything selected had
			// been passed on.
			name:        "a border router that selects nothing to give its customers",
			question:    "q2.3",
			alsoAffects: []string{"q2.2", "q2.5", "q2.6"},
			undo: func(t *testing.T) {
				if starved.router == "" {
					return
				}
				for _, p := range starved.peers {
					vtysh(t, dir, starved.router, "configure terminal",
						"router bgp "+itoa(as),
						" address-family ipv4 unicast",
						"  no neighbor "+p+" route-map TWGRADE-DENY in",
						"end")
				}
				vtysh(t, dir, starved.router, "configure terminal",
					"no route-map TWGRADE-DENY deny 10", "end")
			},
			apply: func(t *testing.T) {
				router := "as" + itoa(as) + "/SFO"
				peers := bgpPeersOf(t, dir, router)
				if len(peers) == 0 {
					t.Skip("no BGP peers found")
				}
				starved = struct {
					router string
					peers  []string
				}{router, peers}
				t.Logf("denying every inbound announcement on %s", router)
				vtysh(t, dir, router, "configure terminal", "route-map TWGRADE-DENY deny 10", "end")
				for _, p := range peers {
					vtysh(t, dir, router, "configure terminal",
						"router bgp "+itoa(as),
						" address-family ipv4 unicast",
						"  neighbor "+p+" route-map TWGRADE-DENY in",
						"end")
				}
				vtysh(t, dir, router, "clear ip bgp * soft in")
				time.Sleep(25 * time.Second)
			},
		},
		{
			// Transit that carries pings and nothing else.
			//
			// The customer-transit probe was ICMP, so a rule dropping
			// forwarded TCP from one customer left every probe answered.
			name:     "a customer whose connections cannot cross while its pings can",
			question: "q2.3",
			undo: func(t *testing.T) {
				if custTCP != "" {
					_, _ = twinet(t, "exec", "-m", dir, "as3/SFO", "--", "iptables", "-D",
						"FORWARD", "-i", custTCP, "-p", "tcp", "-j", "DROP")
				}
			},
			apply: func(t *testing.T) {
				ifaces := customerIfaces(t, dir, as)
				if len(ifaces) == 0 {
					t.Skip("AS 3 has no customer-facing interface to block")
				}
				custTCP = ifaces[0]
				t.Logf("discarding forwarded TCP arriving on %s", custTCP)
				out, err := twinet(t, "exec", "-m", dir, "as3/SFO", "--", "iptables",
					"-I", "FORWARD", "1", "-i", custTCP, "-p", "tcp", "-j", "DROP")
				if err != nil {
					t.Fatalf("discarding a customer's TCP: %v\n%s", err, out)
				}
			},
		},
		{
			// A hijack dressed as transit.
			//
			// Whether the AS originated a prefix was decided by the AS path
			// being empty. Injecting one through a route-map that prepends an
			// ASN produces a locally sourced route with a path, which read as
			// somebody else's route passing through -- so the check that exists
			// to catch a hijack gave full marks to one.
			name:     "somebody else's prefix announced with a forged AS path",
			question: "q2.2",
			undo: func(t *testing.T) {
				vtysh(t, dir, "as3/NYC", "configure terminal",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  no network 203.0.113.0/24 route-map TWGRADE-HIJACK",
					" exit",
					"exit",
					"no route-map TWGRADE-HIJACK permit 10",
					"end")
			},
			apply: func(t *testing.T) {
				vtysh(t, dir, "as3/NYC", "configure terminal",
					"route-map TWGRADE-HIJACK permit 10",
					" set as-path prepend 65000",
					"exit",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  network 203.0.113.0/24 route-map TWGRADE-HIJACK",
					"end")
				time.Sleep(15 * time.Second)
			},
		},
		{
			// An address the plan does not mention.
			//
			// Reported and scored neither way until two reviewers made the
			// same objection: the question is whether the addressing matches
			// the plan, and a router carrying an address the plan does not
			// mention does not match it. It is also the raw material for
			// impersonation, which is how most of the defects in this grader
			// were built.
			name:     "an unplanned address left on a router",
			question: "q1.2",
			undo: func(t *testing.T) {
				_, _ = twinet(t, "exec", "-m", dir, "as3/NYC", "--",
					"ip", "addr", "del", "192.0.2.123/32", "dev", "lo")
			},
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/NYC", "--",
					"ip", "addr", "add", "192.0.2.123/32", "dev", "lo")
				if err != nil {
					t.Fatalf("adding an unplanned address: %v\n%s", err, out)
				}
			},
		},
		{
			// The same, in a scope the reader used to filter on.
			//
			// A scope the check did not ask about is a place to put an address
			// it will never see, and a link-scoped address is live: the router
			// answers for it.
			name:     "an unplanned address hidden in another scope",
			question: "q1.2",
			undo: func(t *testing.T) {
				_, _ = twinet(t, "exec", "-m", dir, "as3/NYC", "--", "ip", "address", "del",
					"198.51.100.23/32", "dev", "lo", "scope", "link")
			},
			apply: func(t *testing.T) {
				out, err := twinet(t, "exec", "-m", dir, "as3/NYC", "--", "ip", "address", "add",
					"198.51.100.23/32", "dev", "lo", "scope", "link")
				if err != nil {
					t.Fatalf("adding a link-scoped address: %v\n%s", err, out)
				}
			},
		},
		{
			// The right prefix, advertised by the wrong router.
			//
			// A prefix carries no record of where it came from. Taking a
			// service subnet out of OSPF on the router it is attached to and
			// putting the same numbers on a dummy interface elsewhere in the
			// AS left every router holding it as an ordinary intra-area route,
			// which the check read as the subnet being advertised. It was not:
			// the network was dark, and nothing sent a packet to it to find
			// out.
			name:     "a service subnet advertised from a dummy interface on another router",
			question: "q1.2",
			undo: func(t *testing.T) {
				if impostorSubnet.prefix == "" {
					return
				}
				vtysh(t, dir, impostorSubnet.faker, "configure terminal",
					"router ospf",
					" no network "+impostorSubnet.prefix+" area 0",
					"end")
				_, _ = twinet(t, "exec", "-m", dir, impostorSubnet.faker, "--",
					"ip", "link", "del", "twgrade0")
			},
			apply: func(t *testing.T) {
				owner, faker, prefix := serviceSubnet(t, dir, as)
				impostorSubnet = struct{ faker, prefix string }{faker, prefix}
				t.Logf("removing %s from OSPF on %s and advertising it from a dummy on %s",
					prefix, owner, faker)
				vtysh(t, dir, owner, "configure terminal",
					"router ospf",
					" no network "+prefix+" area 0",
					"end")
				out, err := twinet(t, "exec", "-m", dir, faker, "--", "sh", "-c",
					"ip link add twgrade0 type dummy && ip addr add "+
						impostorAddr(prefix)+" dev twgrade0 && ip link set twgrade0 up")
				if err != nil {
					t.Fatalf("putting the subnet on a dummy interface: %v\n%s", err, out)
				}
				vtysh(t, dir, faker, "configure terminal",
					"router ospf",
					" network "+prefix+" area 0",
					"end")
				time.Sleep(25 * time.Second)
			},
		},
		{
			// Installed paths that carry nothing.
			//
			// The equal-cost question is decided from the forwarding tables,
			// which is the only honest way to establish that a path exists --
			// sampling traceroutes can miss a live one. What the tables cannot
			// say is whether anything gets through, and a rule dropping this
			// exact traffic left every prescribed next hop installed, every
			// packet discarded, and the mark untouched.
			name:     "the equal-cost paths installed but dropping every packet",
			question: "q1.3",
			undo: func(t *testing.T) {
				if ecmpBlock.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, ecmpBlock.router, "--", "iptables", "-D",
					"OUTPUT", "-p", "icmp", "-d", ecmpBlock.addr, "-j", "DROP")
			},
			apply: func(t *testing.T) {
				router, addr := ecmpEndpoints(t, dir, 3)
				ecmpBlock = struct{ router, addr string }{router, addr}
				t.Logf("dropping ICMP from %s to %s, the far end of the equal-cost paths",
					router, addr)
				if out, err := twinet(t, "exec", "-m", dir, router, "--", "iptables", "-I",
					"OUTPUT", "1", "-p", "icmp", "-d", addr, "-j", "DROP"); err != nil {
					t.Fatalf("installing the block: %v\n%s", err, out)
				}
				time.Sleep(5 * time.Second)
			},
		},
		{
			// A next hop that is present and discards everything.
			//
			// The check asked whether the router had a route to the next hop.
			// A blackhole is a route: selected, installed, and dropping every
			// packet sent to it. Pointing one router's route to another
			// router's loopback at Null0 left the AS looking correct from
			// every other router while that router forwarded nothing outside
			// the AS, and the whole fault this check is named for is "the
			// route is everywhere and the traffic is dropped".
			name:     "the interior next hop pointed at a blackhole",
			question: "q2.2",
			undo: func(t *testing.T) {
				if blackholed.router == "" {
					return
				}
				vtysh(t, dir, blackholed.router, "configure terminal",
					"no ip route "+blackholed.nh+"/32 Null0", "end")
			},
			apply: func(t *testing.T) {
				router, nh := internalNextHop(t, dir, 3)
				blackholed = struct{ router, nh string }{router, nh}
				t.Logf("blackholing %s, the interior next hop %s forwards through", nh, router)
				vtysh(t, dir, router, "configure terminal",
					"ip route "+nh+"/32 Null0", "end")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// A route you announce yourself is not a route you preserved.
			//
			// The question asks that an origin nobody has signed is still
			// carried rather than filtered away. It was marked by looking for
			// the prefix in every router's table, and a submission that
			// announced the prefix itself -- to Null0, so nothing could ever
			// reach it -- had it in every table and passed. The AS path can be
			// made to say anything; where the route entered cannot.
			name:     "the unsigned prefix announced locally instead of carried",
			question: "q2.6",
			undo: func(t *testing.T) {
				// The prefix the mutation chose, not one looked up again: by
				// the time this runs the only unsigned route left is the
				// counterfeit, and looking for one would find nothing.
				if counterfeit == "" {
					return
				}
				router := routersOf(t, dir, 3)[0]
				vtysh(t, dir, router, "configure terminal",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  no network "+counterfeit,
					" exit-address-family",
					"exit",
					"no ip route "+counterfeit+" Null0",
					"end")
			},
			apply: func(t *testing.T) {
				prefix := notFoundPrefix(t, dir, 3)
				counterfeit = prefix
				router := routersOf(t, dir, 3)[0]
				t.Logf("originating %s on %s, pointed at Null0", prefix, router)
				vtysh(t, dir, router, "configure terminal",
					"ip route "+prefix+" Null0",
					"router bgp 3",
					" address-family ipv4 unicast",
					"  network "+prefix,
					" exit-address-family",
					"end")
				time.Sleep(15 * time.Second)
			},
		},
		{
			// One direction of one layer-2 pair.
			//
			// The same-VLAN half of the VLAN question probed i<j -- one
			// unordered pair, one direction -- while the cross-VLAN half
			// deliberately probed every ordered pair. Reachability is not
			// symmetric and a student's mistake need not be either: a host
			// that drops what it sends to its neighbour, or a switch port
			// filtering one way, leaves the return path working, and whichever
			// way the loop happened to run was the mark.
			name:     "one same-VLAN neighbour unreachable in one direction",
			question: "q1.1",
			undo: func(t *testing.T) {
				src, _, addr := sameVLANPair(t, dir, 3)
				_, _ = twinet(t, "exec", "-m", dir, src, "--", "iptables", "-D", "OUTPUT",
					"-d", addr+"/32", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
			},
			apply: func(t *testing.T) {
				src, dst, addr := sameVLANPair(t, dir, 3)
				t.Logf("dropping new outbound traffic from %s to %s (%s)", src, dst, addr)
				if out, err := twinet(t, "exec", "-m", dir, src, "--", "iptables", "-I", "OUTPUT",
					"1", "-d", addr+"/32", "-m", "conntrack", "--ctstate", "NEW",
					"-j", "DROP"); err != nil {
					t.Fatalf("installing the one-way block: %v\n%s", err, out)
				}
				time.Sleep(3 * time.Second)
			},
		},
		{
			// The opposite error, and the one nothing was looking at.
			//
			// Leaking a provider's route to a peer was marked; withholding it
			// from a paying customer was not, because the export check skips
			// customer sessions on the grounds that a customer may receive
			// anything. "May receive anything" was read as "need receive
			// nothing", so an AS could sell transit, take its customers'
			// routes, and hand back only a fraction of the internet -- and
			// score full marks for business relationships. The denial is
			// symmetric across every customer so that no single-session check
			// can catch it by accident.
			name:     "a provider's route withheld from every customer",
			question: "q2.3",
			apply: func(t *testing.T) {
				router, custs, prefix := customerSessionsOn(t, dir, 3)
				if len(custs) == 0 {
					t.Fatal("AS 3 has no customer session, so nothing can be withheld from one")
				}
				t.Logf("withholding %s from every customer of AS 3 (%v) on %s",
					prefix, custs, router)
				cmds := []string{"configure terminal",
					"ip prefix-list NOPROV seq 5 deny " + prefix,
					"ip prefix-list NOPROV seq 10 permit 0.0.0.0/0 le 32",
					"route-map CUSTOUT permit 10",
					" match ip address prefix-list NOPROV",
					"router bgp 3",
					" address-family ipv4 unicast"}
				for _, c := range custs {
					cmds = append(cmds, "  neighbor "+c+" route-map CUSTOUT out")
				}
				cmds = append(cmds, " exit-address-family", "end")
				vtysh(t, dir, router, cmds...)
				for _, c := range custs {
					vtysh(t, dir, router, "clear bgp ipv4 unicast "+c+" out")
				}
				time.Sleep(8 * time.Second)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveAS(t, dir, as)
			if c.undo != nil {
				defer c.undo(t)
			}
			c.apply(t)

			after, _, report := gradeASBroken(t, dir, as)
			if after[c.question] >= baseline[c.question] {
				t.Errorf("%s still scored %.2f of %.2f after %q; the check does not "+
					"measure what its name says, and a student could skip this work\n%s",
					c.question, after[c.question], points[c.question], c.name, report)
			}
			// Collateral damage is its own failure: a correct student must not
			// lose a mark because something unrelated is wrong.
			for id, p := range points {
				if id == c.question {
					continue
				}
				allowed := false
				for _, a := range c.alsoAffects {
					if a == id {
						allowed = true
					}
				}
				if !allowed && unrelated(id, c.question) && after[id] < baseline[id] {
					t.Errorf("%s fell from %.2f to %.2f of %.2f because of %q, which is "+
						"about %s; a student would lose a mark for work they did correctly",
						id, baseline[id], after[id], p, c.name, c.question)
				}
			}
		})
	}
}

// unrelated reports whether two questions are independent enough that breaking
// one must not affect the other.
//
// Some genuinely are coupled: the data-plane questions depend on routing, so
// removing an iBGP session legitimately breaks reachability too. Those pairs
// are excluded rather than asserted, because asserting them would be asserting
// something false about networks.
func unrelated(id, broken string) bool {
	coupled := map[string][]string{
		// Announcing somebody else's prefix is the subject of two questions at
		// once: the one about originating only your own, and the one about
		// preserving an unsigned origin rather than replacing it.
		"q2.6": {"q2.2"},
		// Everything that needs routes to exist depends on the routing ones.
		"q2.1": {"q2.2", "q2.3", "q2.4", "q2.5", "q2.6", "q1.2", "q1.3"},
		"q2.3": {"q2.4", "q2.5", "q2.6"},
		"q1.2": {"q1.3", "q2.1", "q2.2", "q2.3", "q2.4", "q2.5", "q2.6"},
	}
	for _, c := range coupled[broken] {
		if c == id {
			return false
		}
	}
	return true
}

// notFoundPrefix is a prefix this AS carries whose origin nobody has signed,
// which is what the preservation question is about.
//
// It is read from the router rather than assumed, so the test does not go
// quietly stale if the lab publishes a ROA for it later, and only prefixes
// learned from somewhere else count -- a prefix this AS originates is not one
// it was asked to preserve.
func notFoundPrefix(t *testing.T, dir string, as int) string {
	t.Helper()
	// Waited for, not demanded immediately.
	//
	// The case before this one restores the system, and BGP takes a minute to
	// bring its sessions back and re-learn what the neighbours know. Reading
	// the table the instant the previous case finished found it empty and
	// stopped the run -- a test failing because it asked too early, which is
	// the sort of flake that gets a real failure ignored later.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if p := findNotFoundPrefix(t, dir, as); p != "" {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("AS %d carries no unsigned origin, so there is nothing to preserve", as)
		}
		time.Sleep(10 * time.Second)
	}
}

func findNotFoundPrefix(t *testing.T, dir string, as int) string {
	t.Helper()
	for _, router := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, router, "--", "vtysh",
			"-c", "show bgp ipv4 unicast rpki notfound")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			// "N*> 1.0.0.0/8  179.2.3.1  75  0  2 1 i"
			if len(f) < 7 || !strings.HasPrefix(f[0], "N") || !strings.Contains(f[1], "/") {
				continue
			}
			// The last field is the origin code; anything before it and after
			// the weight is the AS path. An empty path is a route of our own.
			if f[len(f)-2] == f[5] {
				continue
			}
			return f[1]
		}
	}
	return ""
}

// bgpPeersOf lists the BGP neighbour addresses a router holds sessions with.
func bgpPeersOf(t *testing.T, dir, router string) []string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, router, "--", "vtysh", "-c",
		"show ip bgp summary json")
	if err != nil {
		t.Fatalf("reading %s's sessions: %v\n%s", router, err, out)
	}
	var doc struct {
		IPv4Unicast struct {
			Peers map[string]struct{} `json:"peers"`
		} `json:"ipv4Unicast"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil
	}
	var peers []string
	for addr := range doc.IPv4Unicast.Peers {
		peers = append(peers, addr)
	}
	sort.Strings(peers)
	return peers
}

// externalSessionOf finds one router of this AS and an external neighbour it
// holds a session with.
func externalSessionOf(t *testing.T, dir string, as int) (string, string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		cfg, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(cfg, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 4 && f[0] == "neighbor" && f[2] == "remote-as" && f[3] != itoa(as) {
				return r, f[1]
			}
		}
	}
	t.Skip("no external session found")
	return "", ""
}

// slowPrependClause finds the route-map clause that prepends towards the slow
// neighbour, the session it applies to, and that neighbour's AS number.
func slowPrependClause(t *testing.T, dir string, as int) (router, routeMap, seq, peer, orig, asn string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		cfg, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		lines := strings.Split(cfg, "\n")
		applied := map[string]string{} // route-map -> neighbour
		remote := map[string]string{}  // neighbour -> remote AS
		for _, line := range lines {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "out" {
				applied[f[3]] = f[1]
			}
			if len(f) == 3 && f[0] == "neighbor" && f[1] != "" && f[2] != "" &&
				strings.Contains(line, "remote-as") {
				remote[f[1]] = f[2]
			}
		}
		for i, line := range lines {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) != 4 || f[0] != "route-map" || applied[f[1]] == "" {
				continue
			}
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				t2 := strings.TrimSpace(lines[j])
				if v, ok := strings.CutPrefix(t2, "set as-path prepend "); ok {
					p := applied[f[1]]
					if remote[p] == "" {
						continue
					}
					return r, f[1], f[3], p, v, remote[p]
				}
			}
		}
	}
	t.Skip("no prepend towards a neighbour was found")
	return "", "", "", "", "", ""
}

// leakableRoute finds a router with an export policy towards a peer or
// provider, a prefix that neither this AS nor its customers originate, and a
// customer's AS number to hide it behind.
func leakableRoute(t *testing.T, dir string, as int) (router, peer, routeMap, prefix, cust string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		cfg, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var outMaps [][2]string
		for _, line := range strings.Split(cfg, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "out" &&
				!strings.Contains(f[3], "CUSTOMER") && !strings.Contains(f[3], "IXP") {
				outMaps = append(outMaps, [2]string{f[1], f[3]})
			}
		}
		if len(outMaps) == 0 {
			continue
		}
		out, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var doc struct {
			Routes map[string][]struct {
				Path string `json:"path"`
				Best bool   `json:"bestpath"`
			} `json:"routes"`
		}
		if json.Unmarshal([]byte(out), &doc) != nil {
			continue
		}
		for pfx, ps := range doc.Routes {
			for _, p := range ps {
				f := strings.Fields(p.Path)
				// A single-hop path is a neighbour's own space; using one of
				// those makes the case unambiguous.
				if !p.Best || len(f) != 1 || f[0] == itoa(as) {
					continue
				}
				return r, outMaps[0][0], outMaps[0][1], pfx, f[0]
			}
		}
	}
	t.Skip("no exportable-looking route found")
	return "", "", "", "", ""
}

// publishROAWithLength publishes a ROA with an explicit maximum length, which
// is the part of an authorisation that says how much smaller an announcement
// may be and still be covered.
func publishROAWithLength(t *testing.T, dir, router, anchor, prefix string, as, maxLen int) {
	t.Helper()
	body := fmt.Sprintf(`{"prefix":%q,"max_length":%d,"asn":%d}`, prefix, maxLen, as)
	out, err := twinet(t, "exec", "-m", dir, router, "--", "sh", "-c",
		"wget -qO- --post-data="+shellQuoteForTest(body)+
			" --header=Content-Type:application/json http://"+anchor+":8323/roas")
	if err != nil {
		t.Fatalf("publishing to the anchor at %s: %v\n%s", anchor, err, out)
	}
	time.Sleep(10 * time.Second)
}

// rpkiDenyClause finds a route-map clause that denies RPKI-invalid routes and
// is actually applied inbound on a session bringing routes in from outside.
//
// An unattached route-map does not run, so narrowing one costs nothing and
// proves nothing about the check.
func rpkiDenyClause(t *testing.T, dir string, as int) (router, routeMap, seq string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		cfg, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		lines := strings.Split(cfg, "\n")
		applied := map[string]bool{}
		for _, line := range lines {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
				applied[f[3]] = true
			}
		}
		for i, line := range lines {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) != 4 || f[0] != "route-map" || f[2] != "deny" || !applied[f[1]] {
				continue
			}
			for j := i + 1; j < len(lines) && j < i+4; j++ {
				if strings.Contains(lines[j], "match rpki invalid") {
					return r, f[1], f[3]
				}
			}
		}
	}
	t.Skip("no applied RPKI deny clause found")
	return "", "", ""
}

// ixpInRegionRoute finds a route the exchange relays whose path crosses a
// student system of this AS's own region -- the kind the assignment says to
// refuse -- together with the router, the policy applied to the exchange
// session and the exchange's address.
func ixpInRegionRoute(t *testing.T, dir string, as int) (router, routeMap, peer, prefix, path string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		cfg, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(cfg, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) != 5 || f[0] != "neighbor" || f[2] != "route-map" || f[4] != "in" {
				continue
			}
			if !strings.Contains(f[3], "IXP") {
				continue
			}
			out, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c",
				"show ip bgp neighbors "+f[1]+" received-routes json")
			if err != nil {
				continue
			}
			var doc struct {
				ReceivedRoutes map[string][]struct {
					Path string `json:"path"`
				} `json:"receivedRoutes"`
			}
			if json.Unmarshal([]byte(out), &doc) != nil {
				continue
			}
			for pfx, ps := range doc.ReceivedRoutes {
				for _, p := range ps {
					if len(strings.Fields(p.Path)) >= 2 {
						return r, f[3], f[1], pfx, strings.TrimSpace(p.Path)
					}
				}
			}
		}
	}
	t.Skip("the exchange relays no multi-hop route to this AS")
	return "", "", "", "", ""
}

// interiorLinkEnd picks one end of an interior link and returns the router, the
// interface, its address with prefix, and the address of the router on the
// other side.
func interiorLinkEnd(t *testing.T, dir string, as int) (router, iface, local, remote string) {
	t.Helper()
	a, b, aIf, _ := interiorLinkEnds(t, dir, as)
	out, err := twinet(t, "exec", "-m", dir, a, "--", "ip", "-o", "-4", "addr", "show", "dev", aIf)
	if err != nil {
		t.Fatalf("reading %s's address on %s: %v\n%s", a, aIf, err, out)
	}
	for _, f := range strings.Fields(out) {
		if strings.Count(f, ".") == 3 && strings.Contains(f, "/") {
			local = f
			break
		}
	}
	if local == "" {
		t.Skip("no address on the interior link")
	}
	remote = bumpLastOctet(strings.SplitN(local, "/", 2)[0])
	_ = b
	return a, aIf, local, remote
}

// interiorLinkEnds finds one link between two routers of this AS, and the
// interface each of them faces the other on.
func interiorLinkEnds(t *testing.T, dir string, as int) (a, b, aIf, bIf string) {
	t.Helper()
	routers := routersOf(t, dir, as)
	short := func(id string) string { return id[strings.LastIndexByte(id, '/')+1:] }
	// Not a link between the two datacentre gateways.
	//
	// Breaking that one takes the 6in4 question down with it, which is honest
	// collateral but makes the case about two questions instead of one. Any
	// other interior link isolates the adjacency question.
	ifaces := map[string][]string{}
	gateway := map[string]bool{}
	for _, dev := range routers {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "ls", "/sys/class/net")
		if err != nil {
			continue
		}
		ifaces[dev] = strings.Fields(out)
		for _, f := range ifaces[dev] {
			if strings.HasPrefix(f, "tun") {
				gateway[dev] = true
			}
		}
	}
	for _, dev := range routers {
		if gateway[dev] {
			continue
		}
		out := strings.Join(ifaces[dev], " ")
		for _, f := range strings.Fields(out) {
			if !strings.HasPrefix(f, "port_") {
				continue
			}
			peer := strings.TrimPrefix(f, "port_")
			for _, other := range routers {
				if short(other) == peer && !gateway[other] {
					return dev, other, f, "port_" + short(dev)
				}
			}
		}
	}
	t.Fatalf("AS %d has no link between two of its routers", as)
	return "", "", "", ""
}

// providerImport finds a router with a session to a provider, the policy that
// session applies on import, and a prefix that a peer also offers -- which is
// the pair the ordering rule is about.
func providerImport(t *testing.T, dir string, as int) (router, peer, routeMap, prefix string) {
	t.Helper()
	for _, r := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, r, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var doc struct {
			Routes map[string][]struct {
				Path   string `json:"path"`
				PeerID string `json:"peerId"`
			} `json:"routes"`
		}
		if json.Unmarshal([]byte(out), &doc) != nil {
			continue
		}
		maps := importRouteMaps(t, dir, r)
		for pfx, paths := range doc.Routes {
			// Two paths for one prefix, one of them heard directly over a
			// session this router applies a policy to.
			if len(paths) < 2 {
				continue
			}
			for _, p := range paths {
				if p.PeerID == "" || maps[p.PeerID] == "" {
					continue
				}
				if len(strings.Fields(p.Path)) < 2 {
					continue // a route from the neighbour itself, not through it
				}
				return r, p.PeerID, maps[p.PeerID], pfx
			}
		}
	}
	t.Skip("no prefix offered over two relationships was found")
	return "", "", "", ""
}

// customerImport finds a customer session and the route-map applied to it, by
// taking the neighbour whose routes this AS ranks highest.
func customerImport(t *testing.T, dir string, as int) (router, peer, routeMap string) {
	t.Helper()
	r, addr, _ := bestCustomerRoute(t, dir, as)
	maps := importRouteMaps(t, dir, r)
	if maps[addr] == "" {
		t.Fatalf("%s applies no import policy to the customer at %s", r, addr)
	}
	return r, addr, maps[addr]
}

// bumpLastOctet returns a neighbouring address on the same subnet, which is
// on-link and therefore resolvable, and is not the neighbour.
func bumpLastOctet(addr string) string {
	i := strings.LastIndexByte(addr, '.')
	if i < 0 {
		return addr
	}
	n, err := strconv.Atoi(addr[i+1:])
	if err != nil {
		return addr
	}
	return addr[:i+1] + strconv.Itoa(n+1)
}

// nativeV6End is one end of a native IPv6 path built to bypass the tunnel.
type nativeV6End struct {
	router, iface, addr, via, tunnel string
	prefixes                         []string
}

// nativeV6Path finds the two tunnel gateways, the link between them, and the
// datacentre prefixes each currently reaches through the tunnel.
func nativeV6Path(t *testing.T, dir string, as int) []nativeV6End {
	t.Helper()
	type gw struct {
		router, tunnel string
		prefixes       []string
	}
	var gws []gw
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "ip", "-6", "route", "show")
		if err != nil {
			continue
		}
		g := gw{router: dev}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == "dev" && strings.HasPrefix(f[2], "tun") {
				g.tunnel = f[2]
				g.prefixes = append(g.prefixes, f[0])
			}
		}
		if g.tunnel != "" && len(g.prefixes) > 0 {
			gws = append(gws, g)
		}
	}
	if len(gws) != 2 {
		return nil
	}
	// A link between them, named after each other.
	a, b := gws[0], gws[1]
	aName := a.router[strings.LastIndexByte(a.router, '/')+1:]
	bName := b.router[strings.LastIndexByte(b.router, '/')+1:]
	return []nativeV6End{
		{a.router, "port_" + bName, "2001:db8:ff::1/64", "2001:db8:ff::2", a.tunnel, a.prefixes},
		{b.router, "port_" + aName, "2001:db8:ff::2/64", "2001:db8:ff::1", b.tunnel, b.prefixes},
	}
}

// roaPublisher finds the router entitled to publish this AS's ROA, the address
// of the trust anchor it publishes to, and the prefix.
func roaPublisher(t *testing.T, dir string, as int) (router, anchor, prefix string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			// "rpki cache 197.3.0.2 3323 pref 1"
			if len(f) >= 4 && f[0] == "rpki" && f[1] == "cache" {
				return dev, f[2], itoa(as) + ".0.0.0/8"
			}
		}
	}
	t.Fatalf("no router of AS %d is configured with a validator, so the anchor cannot be found", as)
	return "", "", ""
}

// publishROA publishes or withdraws an authorisation at the trust anchor, from
// the router entitled to do it.
func publishROA(t *testing.T, dir, router, anchor, prefix string, as int, withdraw bool) {
	t.Helper()
	body := fmt.Sprintf(`{"prefix":"%s","max_length":8,"asn":%d,"withdraw":%v}`,
		prefix, as, withdraw)
	out, err := twinet(t, "exec", "-m", dir, router, "--", "sh", "-c",
		"wget -qO- --post-data="+shellQuoteForTest(body)+
			" --header=Content-Type:application/json http://"+anchor+":8323/roas")
	if err != nil {
		t.Fatalf("publishing to the anchor at %s: %v\n%s", anchor, err, out)
	}
}

// shellQuoteForTest wraps a string so one level of shell keeps it intact.
func shellQuoteForTest(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// inboundRouteMaps lists every route-map this AS applies to what arrives from
// outside, across all of its routers.
func inboundRouteMaps(t *testing.T, dir string, as int) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
				seen[f[3]] = true
			}
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ixpImport finds the router holding this AS's exchange session, the route
// server's address, and the route-map applied to what it sends.
func ixpImport(t *testing.T, dir string, as int) (router, peer, routeMap string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" &&
				strings.HasPrefix(f[1], "180.") {
				return dev, f[1], f[3]
			}
		}
	}
	t.Fatalf("AS %d has no exchange session with an import policy", as)
	return "", "", ""
}

// serviceSubnet finds a subnet one router advertises into OSPF, another router
// that does not, and the prefix itself.
//
// tunnelGateway finds a datacentre gateway and the tunnel interface it
// terminates, read from the running lab.
func tunnelGateway(t *testing.T, dir string, as int) (string, string) {
	t.Helper()
	out, err := twinet(t, "inspect", "-m", dir)
	if err != nil {
		t.Fatalf("inspecting the lab: %v\n%s", err, out)
	}
	prefix := "as" + itoa(as) + "/"
	var routers []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && strings.HasPrefix(f[0], prefix) && f[1] == "router" {
			routers = append(routers, f[0])
		}
	}
	sort.Strings(routers)
	for _, r := range routers {
		links, err := twinet(t, "exec", "-m", dir, r, "--", "sh", "-c", "ls /sys/class/net")
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(links) {
			if strings.HasPrefix(f, "tun") {
				return r, f
			}
		}
	}
	t.Skip("no tunnel interface found in this AS")
	return "", ""
}

// interASRange finds the subnet of one of this AS's external links, read from
// the router that terminates it.
func interASRange(t *testing.T, dir string, as int) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, "as"+itoa(as)+"/NYC", "--",
		"ip", "-o", "-4", "addr", "show")
	if err != nil {
		t.Fatalf("reading addresses: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[1], "ext_") {
			continue
		}
		for i, tok := range f {
			if tok == "inet" && i+1 < len(f) {
				pfx, err := netip.ParsePrefix(f[i+1])
				if err == nil {
					return pfx.Masked().String()
				}
			}
		}
	}
	t.Skip("no external link found on as3/NYC")
	return ""
}

// vlanPortPair finds a switch with access ports in two different VLANs and
// returns it with one port from each, read from the lab rather than assumed.
func vlanPortPair(t *testing.T, dir string, as int) (sw, from, to string) {
	t.Helper()
	out, err := twinet(t, "inspect", "-m", dir)
	if err != nil {
		t.Fatalf("inspecting the lab: %v\n%s", err, out)
	}
	prefix := "as" + itoa(as) + "/"
	var switches []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && strings.HasPrefix(f[0], prefix) && f[1] == "switch" {
			switches = append(switches, f[0])
		}
	}
	sort.Strings(switches)
	for _, s := range switches {
		ports, err := twinet(t, "exec", "-m", dir, s, "--", "sh", "-c", "ls /sys/class/net")
		if err != nil {
			continue
		}
		// The access ports of the two VLANs are named after the hosts behind
		// them, and this topology names them A_* and P_* by VLAN.
		var a, p string
		for _, f := range strings.Fields(ports) {
			switch {
			case strings.HasPrefix(f, "port_A_") && a == "":
				a = f
			case strings.HasPrefix(f, "port_P_") && p == "":
				p = f
			}
		}
		if a != "" && p != "" {
			return s, a, p
		}
	}
	t.Skip("no switch with access ports in two VLANs")
	return "", "", ""
}

// customerIfaces names the interfaces of as3/SFO that face a customer, read
// from the running lab so the mutation follows the topology rather than a
// memory of it.
func customerIfaces(t *testing.T, dir string, as int) []string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, "as"+itoa(as)+"/SFO", "--",
		"sh", "-c", "ls /sys/class/net")
	if err != nil {
		t.Fatalf("listing interfaces: %v\n%s", err, out)
	}
	var ifaces []string
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "ext_") {
			ifaces = append(ifaces, f)
		}
	}
	sort.Strings(ifaces)
	return ifaces
}

// impostorAddr picks an address inside a prefix that nothing else is using, so
// a dummy interface can claim to be that subnet.
func impostorAddr(prefix string) string {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil || !pfx.Addr().Is4() {
		return prefix
	}
	b := pfx.Masked().Addr().As4()
	host := uint32(1)<<(32-pfx.Bits()) - 2 // the last usable address
	if pfx.Bits() >= 31 {
		host = 0
	}
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) + host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String() +
		"/" + strconv.Itoa(pfx.Bits())
}

// Read from the running configuration, so the mutation follows whatever the
// submission actually advertises rather than a memory of the lab.
func serviceSubnet(t *testing.T, dir string, as int) (owner, faker, prefix string) {
	t.Helper()
	nets := map[string][]string{}
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 4 && f[0] == "network" && f[2] == "area" {
				nets[f[1]] = append(nets[f[1]], dev)
			}
		}
	}
	var prefixes []string
	for p, owners := range nets {
		if len(owners) == 1 {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	if len(prefixes) == 0 {
		t.Fatalf("AS %d has no subnet advertised by exactly one router", as)
	}
	prefix = prefixes[0]
	owner = nets[prefix][0]
	for _, dev := range routersOf(t, dir, as) {
		if dev != owner {
			faker = dev
			break
		}
	}
	if faker == "" {
		t.Fatalf("AS %d has only one router, so nothing else can counterfeit its subnet", as)
	}
	return owner, faker, prefix
}

// ecmpEndpoints returns the two ends of the equal-cost question: the router the
// rubric measures from, and the loopback address it measures to.
//
// Read from the rubric rather than hardcoded, so the mutation follows the lab
// rather than a memory of it.
func ecmpEndpoints(t *testing.T, dir string, as int) (router, addr string) {
	t.Helper()
	from, to := "ATL", "BOS"
	raw, err := os.ReadFile(filepath.Join(dir, "rubric", "cos461.yaml"))
	if err == nil {
		body := string(raw)
		if i := strings.Index(body, "ospf.ecmp_paths"); i >= 0 {
			for _, line := range strings.Split(body[i:], "\n") {
				f := strings.Fields(strings.TrimSpace(line))
				if len(f) == 2 && f[0] == "a:" {
					from = strings.Trim(f[1], `"`)
				}
				if len(f) == 2 && f[0] == "b:" {
					to = strings.Trim(f[1], `"`)
					break
				}
			}
		}
	}
	out, err := twinet(t, "exec", "-m", dir, "as"+itoa(as)+"/"+to, "--",
		"sh", "-c", "ip -4 -o addr show dev lo scope global | awk '{print $4}' | head -1")
	if err != nil {
		t.Fatalf("reading %s's loopback: %v", to, err)
	}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); strings.Count(s, ".") == 3 {
			return "as" + itoa(as) + "/" + from, strings.SplitN(s, "/", 2)[0]
		}
	}
	t.Fatalf("%s has no loopback address", to)
	return "", ""
}

// internalNextHop finds a router of this AS and an address it uses as the next
// hop for routes another of its routers taught it.
//
// Read from the running system rather than assumed, because which router holds
// which external session is the submission's choice.
func internalNextHop(t *testing.T, dir string, as int) (router, nh string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var doc struct {
			Routes map[string][]struct {
				PathFrom string `json:"pathFrom"`
				Nexthops []struct {
					IP string `json:"ip"`
				} `json:"nexthops"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(trimToJSON(out)), &doc); err != nil {
			continue
		}
		for _, entries := range doc.Routes {
			for _, e := range entries {
				if e.PathFrom != "internal" {
					continue
				}
				for _, n := range e.Nexthops {
					if n.IP != "" && n.IP != "0.0.0.0" {
						return dev, n.IP
					}
				}
			}
		}
	}
	t.Fatalf("AS %d carries no route between its own routers, so there is no interior next "+
		"hop to spoil", as)
	return "", ""
}

// firstIBGPPeer finds a neighbour in the router's own AS.
func firstIBGPPeer(cfg string) string {
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 4 && f[0] == "neighbor" && f[2] == "remote-as" && f[3] == "3" {
			return f[1]
		}
	}
	return ""
}

// routersOf lists the routers of an autonomous system, so a mutation can reach
// the ones that actually hold what it is mutating.
func routersOf(t *testing.T, dir string, asn int) []string {
	t.Helper()
	out, err := twinet(t, "inspect", "-m", dir, "--json")
	if err != nil {
		t.Fatalf("inspecting the lab: %v\n%s", err, out)
	}
	var doc struct {
		Devices []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
			ASN  int    `json:"as"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("reading the lab: %v", err)
	}
	var ids []string
	for _, d := range doc.Devices {
		if d.ASN == asn && d.Kind == "router" {
			ids = append(ids, d.ID)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Fatalf("AS %d has no routers", asn)
	}
	return ids
}

// bestCustomerRoute finds a route a system learned from a customer: the
// neighbour whose routes carry the highest local preference is, by the ordering
// the question is about, a customer.
func bestCustomerRoute(t *testing.T, dir string, as int) (router, nbr, prefix string) {
	t.Helper()
	bestPref := -1
	for _, dev := range routersOf(t, dir, as) {
		// Only sessions this router actually holds, and only ones with an
		// import policy to alter. A route that arrived over iBGP carries the
		// next hop of whichever router originated it into the system, which is
		// not a neighbour of this one -- picking one of those found a "customer
		// route" on a router with no customer session on it.
		inMaps := importRouteMaps(t, dir, dev)
		if len(inMaps) == 0 {
			continue
		}
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var tbl struct {
			Routes map[string][]struct {
				LocalPref int `json:"locPrf"`
				Nexthops  []struct {
					IP string `json:"ip"`
				} `json:"nexthops"`
				Path string `json:"path"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(trimToJSON(out)), &tbl); err != nil {
			continue
		}
		for p, entries := range tbl.Routes {
			for _, e := range entries {
				if strings.TrimSpace(e.Path) == "" {
					continue
				}
				for _, nh := range e.Nexthops {
					if inMaps[nh.IP] == "" {
						continue
					}
					if e.LocalPref > bestPref {
						bestPref, router, nbr, prefix = e.LocalPref, dev, nh.IP, p
					}
				}
			}
		}
	}
	if router == "" {
		t.Fatalf("AS %d has no external session with an import policy, so there is no "+
			"customer route to alter", as)
	}
	t.Logf("customer route: %s learned %s from %s at local preference %d",
		router, prefix, nbr, bestPref)
	return router, nbr, prefix
}

// sameVLANPair finds two hosts of a layer-2 domain that sit in the same VLAN,
// and the address of the second.
//
// Membership is established by asking the kernel rather than by reading names:
// a route to a neighbour in the same VLAN is directly connected, and one to a
// different VLAN goes via the gateway. A test that inferred the VLAN from a
// naming convention would keep passing on a lab that renamed its hosts.
func sameVLANPair(t *testing.T, dir string, as int) (src, dst, addr string) {
	t.Helper()
	var l2 []string
	out, err := twinet(t, "inspect", "-m", dir, "--json")
	if err != nil {
		t.Fatalf("inspecting the lab: %v", err)
	}
	var doc struct {
		Devices []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
			AS   int    `json:"as"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(trimToJSON(out)), &doc); err != nil {
		t.Fatalf("decoding the topology: %v", err)
	}
	for _, d := range doc.Devices {
		if d.AS == as && d.Kind == "host" && !strings.HasSuffix(d.ID, "_host") {
			l2 = append(l2, d.ID)
		}
	}
	sort.Strings(l2)
	for _, a := range l2 {
		for _, b := range l2 {
			if a == b {
				continue
			}
			bAddr := hostAddr(t, dir, b)
			if bAddr == "" {
				continue
			}
			route, err := twinet(t, "exec", "-m", dir, a, "--", "ip", "route", "get", bAddr)
			if err != nil || strings.Contains(route, " via ") {
				continue
			}
			return a, b, bAddr
		}
	}
	t.Fatalf("AS %d has no two hosts in one VLAN, so a one-way block cannot be tested", as)
	return "", "", ""
}

// customerSessionsOn finds the router holding this AS's customer sessions and
// lists every one of them, together with a prefix that arrived from somebody
// else -- which is what a customer is owed and what can be withheld from them.
//
// Relationships are read the way the other helpers read them, from the local
// preference the submission itself set: the neighbours whose routes rank
// highest are the customers, and the lowest-ranked route on that router came
// from a provider.
func customerSessionsOn(t *testing.T, dir string, as int) (router string, addrs []string, prefix string) {
	t.Helper()
	bestPref := -1
	byRouter := map[string]map[string]int{}
	worstOn := map[string]struct {
		pref   int
		prefix string
	}{}
	for _, dev := range routersOf(t, dir, as) {
		inMaps := importRouteMaps(t, dir, dev)
		if len(inMaps) == 0 {
			continue
		}
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var tbl struct {
			Routes map[string][]struct {
				LocalPref int `json:"locPrf"`
				Nexthops  []struct {
					IP string `json:"ip"`
				} `json:"nexthops"`
				Path string `json:"path"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(trimToJSON(out)), &tbl); err != nil {
			continue
		}
		worstOn[dev] = struct {
			pref   int
			prefix string
		}{1 << 30, ""}
		for p, entries := range tbl.Routes {
			for _, e := range entries {
				if strings.TrimSpace(e.Path) == "" {
					continue
				}
				if w := worstOn[dev]; e.LocalPref < w.pref {
					worstOn[dev] = struct {
						pref   int
						prefix string
					}{e.LocalPref, p}
				}
				for _, nh := range e.Nexthops {
					if inMaps[nh.IP] == "" {
						continue
					}
					if byRouter[dev] == nil {
						byRouter[dev] = map[string]int{}
					}
					if e.LocalPref > byRouter[dev][nh.IP] {
						byRouter[dev][nh.IP] = e.LocalPref
					}
					if e.LocalPref > bestPref {
						bestPref, router = e.LocalPref, dev
					}
				}
			}
		}
	}
	if router == "" {
		t.Fatalf("AS %d has no external session with an import policy", as)
	}
	for addr, pref := range byRouter[router] {
		if pref == bestPref {
			addrs = append(addrs, addr)
		}
	}
	sort.Strings(addrs)
	prefix = worstOn[router].prefix
	if prefix == "" {
		t.Fatalf("%s has selected no route learned from anybody else", router)
	}
	t.Logf("customer sessions on %s: %v; %s came from a provider at local preference %d",
		router, addrs, prefix, worstOn[router].pref)
	return router, addrs, prefix
}

// importRouteMaps maps each neighbour of a router to the route-map applied on
// the way in, for the neighbours that have one.
func importRouteMaps(t *testing.T, dir, router string) map[string]string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, router, "--", "vtysh", "-c", "show running-config")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 5 && f[0] == "neighbor" && f[2] == "route-map" && f[4] == "in" {
			m[f[1]] = f[3]
		}
	}
	return m
}

// providerSession finds a session whose routes carry the lowest local
// preference anywhere in the system, which by the ordering the question is
// about is a provider, and says which router holds it.
func providerSession(t *testing.T, dir string, as int) (router, addr string) {
	t.Helper()
	worst := 1 << 30
	for _, dev := range routersOf(t, dir, as) {
		sessions := importRouteMaps(t, dir, dev)
		if len(sessions) == 0 {
			continue
		}
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show ip bgp json")
		if err != nil {
			continue
		}
		var tbl struct {
			Routes map[string][]struct {
				LocalPref int `json:"locPrf"`
				Nexthops  []struct {
					IP string `json:"ip"`
				} `json:"nexthops"`
			} `json:"routes"`
		}
		if err := json.Unmarshal([]byte(trimToJSON(out)), &tbl); err != nil {
			continue
		}
		for _, entries := range tbl.Routes {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					if sessions[nh.IP] == "" {
						continue
					}
					if e.LocalPref < worst {
						worst, router, addr = e.LocalPref, dev, nh.IP
					}
				}
			}
		}
	}
	return router, addr
}

// importRouteMap returns the route-map applied on the way in from a neighbour.
func importRouteMap(t *testing.T, dir, router, nbr string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, router, "--", "vtysh", "-c", "show running-config")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 5 && f[0] == "neighbor" && f[1] == nbr && f[2] == "route-map" && f[4] == "in" {
			return f[3]
		}
	}
	return ""
}

// trimToJSON drops anything the command printed before the JSON document.
func trimToJSON(s string) string {
	if i := strings.Index(s, "{"); i > 0 {
		return s[i:]
	}
	return s
}

// hostsOfAS lists the L3 hosts of a system, in the order the grader sees them.
func hostsOfAS(t *testing.T, dir string, asn int) []string {
	t.Helper()
	out, err := twinet(t, "inspect", "-m", dir, "--json")
	if err != nil {
		t.Fatalf("inspecting the lab: %v", err)
	}
	var doc struct {
		Devices []struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			AS       int    `json:"as"`
			L2Domain string `json:"l2_domain"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(trimToJSON(out)), &doc); err != nil {
		t.Fatalf("decoding the topology: %v", err)
	}
	var hosts []string
	for _, d := range doc.Devices {
		// The L3 hosts, which is what the reachability check is about. A
		// layer-2 domain's hosts have names of their own and are graded by
		// the VLAN question instead; the inspect output does not distinguish
		// them, but their names do -- an L3 host is always <ROUTER>_host.
		if d.AS == asn && d.Kind == "host" && strings.HasSuffix(d.ID, "_host") {
			hosts = append(hosts, d.ID)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// hostAddr returns a host's first IPv4 address.
func hostAddr(t *testing.T, dir, device string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--",
		"sh", "-c", "ip -4 -o addr show scope global | awk '{print $4}' | head -1")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); strings.Count(s, ".") == 3 {
			return strings.SplitN(s, "/", 2)[0]
		}
	}
	return ""
}

// slowProviderRoute finds a prefix learned over the deliberately slow external
// link, and the session it arrived on.
//
// The slow link is the one with the large delay the assignment builds question
// 2.5 around; it is found by measuring, because that is the only definition
// that cannot drift from the lab.
func slowProviderRoute(t *testing.T, dir string, as int) (router, nbr, prefix string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		sessions := importRouteMaps(t, dir, dev)
		for addr := range sessions {
			out, err := twinet(t, "exec", "-m", dir, dev, "--",
				"ping", "-c", "2", "-W", "3", "-i", "0.3", addr)
			if err != nil || !strings.Contains(out, "min/avg/max") {
				continue
			}
			// "rtt min/avg/max/mdev = 25.1/25.2/25.3/0.1 ms"
			f := strings.Split(out[strings.Index(out, "= ")+2:], "/")
			if len(f) < 2 {
				continue
			}
			avg, err := strconv.ParseFloat(f[1], 64)
			if err != nil || avg < 20 {
				continue
			}
			// A prefix this neighbour actually sent.
			tbl, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show ip bgp json")
			if err != nil {
				continue
			}
			var doc struct {
				Routes map[string][]struct {
					Nexthops []struct {
						IP string `json:"ip"`
					} `json:"nexthops"`
					Path string `json:"path"`
				} `json:"routes"`
			}
			if err := json.Unmarshal([]byte(trimToJSON(tbl)), &doc); err != nil {
				continue
			}
			var found []string
			for p, entries := range doc.Routes {
				for _, e := range entries {
					if strings.TrimSpace(e.Path) == "" {
						continue
					}
					for _, nh := range e.Nexthops {
						if nh.IP == addr {
							found = append(found, p)
						}
					}
				}
			}
			if len(found) == 0 {
				continue
			}
			sort.Strings(found)
			t.Logf("slow external link: %s -> %s at %.1fms", dev, addr, avg)
			return dev, addr, found[0]
		}
	}
	t.Fatalf("AS %d has no slow external link with routes on it", as)
	return "", "", ""
}

// communitySetBy returns the community a route-map stamps on what it accepts,
// so a test clause can preserve it.
func communitySetBy(t *testing.T, dir, router, rm string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, router, "--", "vtysh", "-c", "show running-config")
	if err != nil {
		return ""
	}
	inMap := false
	last := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "route-map "+rm+" "):
			inMap = true
		case trimmed == "exit":
			inMap = false
		case inMap && strings.HasPrefix(trimmed, "set community "):
			last = strings.TrimPrefix(trimmed, "set community ")
		}
	}
	return last
}

// vtyshQuiet is vtysh for commands whose failure is expected on some devices --
// undoing a statement a router never had, for instance.
func vtyshQuiet(t *testing.T, dir, device string, cmds ...string) {
	t.Helper()
	args := []string{"exec", "-m", dir, device, "--", "vtysh"}
	for _, c := range cmds {
		args = append(args, "-c", c)
	}
	_, _ = twinet(t, args...)
}
