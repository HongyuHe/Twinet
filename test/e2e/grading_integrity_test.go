//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
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

	cases := []struct {
		name string
		// question that must lose marks.
		question string
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
				if unrelated(id, c.question) && after[id] < baseline[id] {
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
