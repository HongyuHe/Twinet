//go:build e2e

package e2e

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// The advanced course's marks had no discrimination test of their own.
//
// Eleven mutations prove that the COS-461 rubric loses the right marks when a
// submission is broken; the MPLS L3VPN rubric had nothing of the kind. Its
// checks are carefully written -- reachability is only half the mark, isolation
// is gated on the VPN actually carrying traffic -- and nothing established that
// any of them fall when the thing they are about is wrong. A rubric that has
// only ever been run against a correct answer has been shown to award marks,
// not to withhold them, and this suite exists because that distinction has been
// wrong six times.
//
// Each case breaks one thing a student plausibly gets wrong, requires the
// question about that thing to lose marks, and puts the provider back.

func advnetLab(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TWINET_ADVNET_LAB")
	if dir == "" {
		dir = "../../examples/advnet"
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no advanced-course lab to grade: %v", err)
	}
	return dir
}

// solveProvider puts the provider back to the reference answer.
func solveProvider(t *testing.T, dir string, as int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		out, err := twinet(t, "deploy", "-m", dir, "--solve", "--only", "as="+itoa(as))
		if err == nil {
			// The tables have to come back before the next case measures them.
			time.Sleep(20 * time.Second)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not restore AS %d, so every later case is measuring a lab "+
				"that is still broken: %v\n%s", as, err, out)
		}
		time.Sleep(15 * time.Second)
	}
}

func TestABrokenVPNLosesTheRightMarks(t *testing.T) {
	if testing.Short() {
		t.Skip("mutates a live lab")
	}
	dir := advnetLab(t)
	const provider = 1

	var ldpPair []ldpEnd
	var impostors []edgeImpostor
	var hiddenBGPD struct{ router string }

	baseline, points, report := gradeAS(t, dir, provider)
	if len(baseline) == 0 {
		t.Fatalf("the provider scored nothing at all, so there is no baseline to fall "+
			"from:\n%s", report)
	}
	for id, p := range points {
		if baseline[id] < p {
			t.Fatalf("the reference answer does not score full marks on %s (%.2f of %.2f), "+
				"so a mutation that lowers it proves nothing:\n%s", id, baseline[id], p, report)
		}
	}
	t.Logf("baseline: %v", baseline)

	cases := []struct {
		name     string
		question string
		apply    func(t *testing.T)
		// undo puts back what re-solving the provider cannot: a queueing
		// discipline is not part of the routing configuration.
		undo func(t *testing.T)
	}{
		{
			// One character of a route target.
			//
			// The two sites of one customer agree on 1:1; changing one end to
			// 1:9 means the far site's routes are exported into a community
			// nobody imports. The customer's branch is cut off from its own
			// head office while every other customer keeps working, which is
			// exactly the failure this exercise is about and is invisible to
			// any check that pings one pair of sites and stops.
			name:     "one site's route target mistyped",
			question: "q2",
			apply: func(t *testing.T) {
				router, vrf, rt := vrfSite(t, dir, provider, 1)
				t.Logf("changing %s's route target for %s from %s to 1:9", router, vrf, rt)
				vtysh(t, dir, router, "configure terminal",
					"router bgp "+itoa(provider)+" vrf "+vrf,
					" address-family ipv4 unicast",
					"  no rt vpn both "+rt,
					"  rt vpn both 1:9",
					" exit-address-family",
					"end")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// The failure the mechanism exists to prevent.
			//
			// Importing the other customer's route target puts two banks in one
			// table. Traffic flows between them in one direction only, which is
			// the case a one-directional probe misses and is no less of a leak.
			name:     "one customer importing another's route target",
			question: "q3",
			apply: func(t *testing.T) {
				router, vrf, _ := vrfSite(t, dir, provider, 1)
				other := otherRouteTarget(t, dir, provider, vrf)
				if other == "" {
					t.Skip("this lab has only one customer, so nothing can leak into another")
				}
				t.Logf("making %s import %s into %s", router, other, vrf)
				vtysh(t, dir, router, "configure terminal",
					"router bgp "+itoa(provider)+" vrf "+vrf,
					" address-family ipv4 unicast",
					"  rt vpn import "+other,
					" exit-address-family",
					"end")
				time.Sleep(25 * time.Second)
			},
		},
		{
			// A targeted session in place of a link adjacency.
			//
			// LDP will bring up a session between two loopbacks routed over
			// whatever path the IGP offers. That is a session with the right
			// peer at the right address, so a submission could take LDP off an
			// interior link entirely, replace it with a targeted session, and
			// keep full marks for label distribution across a link that
			// distributes no labels.
			name:     "an interior link's LDP replaced by a targeted session",
			question: "q1",
			undo: func(t *testing.T) {
				for _, p := range ldpPair {
					vtysh(t, dir, p.router, "configure terminal", "mpls ldp",
						" address-family ipv4",
						"  no neighbor "+p.peerAddr+" targeted", "end")
				}
			},
			apply: func(t *testing.T) {
				ldpPair = ldpLinkEnds(t, dir, provider)
				if len(ldpPair) != 2 {
					t.Fatal("no interior LDP link with two ends was found")
				}
				for _, p := range ldpPair {
					t.Logf("replacing %s's link adjacency on %s with a targeted session to %s",
						p.router, p.iface, p.peerAddr)
					vtysh(t, dir, p.router, "configure terminal", "mpls ldp",
						" address-family ipv4",
						"  no interface "+p.iface,
						"  neighbor "+p.peerAddr+" targeted", "end")
				}
				time.Sleep(25 * time.Second)
			},
		},
		{
			// The provider answering for the customer it is meant to carry.
			//
			// Reachability between a customer's sites was established by
			// pinging. Every packet crosses the provider, and the provider is
			// what is being marked: a rule on each edge answering the far
			// site's address locally, with the real traffic dropped, left all
			// four probes succeeding and the mark untouched.
			name:     "the provider answering for the customer's far site",
			question: "q2",
			undo: func(t *testing.T) {
				for _, i := range impostors {
					_, _ = twinet(t, "exec", "-m", dir, i.router, "--", "sh", "-c",
						"iptables -t nat -D PREROUTING -d "+i.addr+" -p icmp -j REDIRECT; "+
							"iptables -D FORWARD -d "+i.addr+" -j DROP; "+
							"ip addr del "+i.addr+"/32 dev lo; echo ok")
				}
			},
			apply: func(t *testing.T) {
				impostors = edgeImpostors(t, dir, provider)
				if len(impostors) < 2 {
					t.Fatal("could not find two edges to impersonate the far sites from")
				}
				for _, i := range impostors {
					t.Logf("%s will answer for %s", i.router, i.addr)
					if _, err := twinet(t, "exec", "-m", dir, i.router, "--", "sh", "-c",
						"ip addr add "+i.addr+"/32 dev lo; "+
							"iptables -t nat -I PREROUTING 1 -d "+i.addr+" -p icmp -j REDIRECT; "+
							"iptables -I FORWARD 1 -d "+i.addr+" -j DROP; echo ok"); err != nil {
						t.Fatalf("setting up the impostor on %s: %v", i.router, err)
					}
				}
				time.Sleep(8 * time.Second)
			},
		},
		{
			// Label stacks that carry nothing.
			//
			// How the customer is carried is read from the forwarding table,
			// which is the only place that can tell a two-label VPN path from
			// a static route or a leak into the global table -- and it says
			// nothing about whether a packet gets through. Dropping labelled
			// frames on the interior links leaves every stack installed and
			// every packet discarded, and that used to keep full marks for a
			// mechanism carrying nothing.
			name:     "the labelled path dropping every packet",
			question: "q2",
			undo: func(t *testing.T) {
				for _, dev := range routersOf(t, dir, provider) {
					for _, port := range interiorPorts(t, dir, dev) {
						_, _ = twinet(t, "exec", "-m", dir, dev, "--",
							"tc", "qdisc", "del", "dev", port, "clsact")
					}
				}
			},
			apply: func(t *testing.T) {
				dropped := 0
				for _, dev := range routersOf(t, dir, provider) {
					for _, port := range interiorPorts(t, dir, dev) {
						if _, err := twinet(t, "exec", "-m", dir, dev, "--",
							"tc", "qdisc", "add", "dev", port, "clsact"); err != nil {
							t.Fatalf("preparing %s on %s: %v", port, dev, err)
						}
						if _, err := twinet(t, "exec", "-m", dir, dev, "--",
							"tc", "filter", "add", "dev", port, "ingress",
							"protocol", "mpls_uc", "flower", "action", "drop"); err != nil {
							t.Fatalf("dropping labelled frames on %s of %s: %v", port, dev, err)
						}
						dropped++
					}
				}
				if dropped == 0 {
					t.Fatal("no interior link was found, so nothing was dropped and this " +
						"case would prove nothing")
				}
				t.Logf("dropped every labelled frame on %d interior link(s) of AS %d",
					dropped, provider)
				time.Sleep(10 * time.Second)
			},
		},
		{
			// A VPN that carries pings and nothing else.
			//
			// Both VPN questions were asked entirely in ICMP. Dropping TCP and
			// UDP on the provider's routers, and leaving ICMP alone, left every
			// probe succeeding and the lab at six out of six, on a network
			// across which no bank could have opened a connection to its own
			// branch.
			name:     "the provider carrying pings and discarding the rest",
			question: "q2",
			undo: func(t *testing.T) {
				for _, dev := range routersOf(t, dir, provider) {
					_, _ = twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
						"iptables -D FORWARD -p tcp -j DROP; "+
							"iptables -D FORWARD -p udp -j DROP; echo ok")
				}
			},
			apply: func(t *testing.T) {
				devs := routersOf(t, dir, provider)
				if len(devs) == 0 {
					t.Fatal("AS has no routers to filter on, so this case would prove nothing")
				}
				for _, dev := range devs {
					if _, err := twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
						"iptables -I FORWARD 1 -p tcp -j DROP; "+
							"iptables -I FORWARD 1 -p udp -j DROP; echo ok"); err != nil {
						t.Fatalf("filtering by protocol on %s: %v", dev, err)
					}
				}
				t.Logf("dropped every connection and datagram crossing %d router(s) of AS %d, "+
					"leaving ICMP alone", len(devs), provider)
				time.Sleep(3 * time.Second)
			},
		},
		{
			// A core router that speaks BGP is the thing the exercise forbids.
			//
			// The whole point of carrying customer routes in labels is that the
			// core never learns them. A P router with a BGP instance and a
			// neighbour still forwards everything correctly, so nothing about
			// the data plane gives it away: only a check that looks for the
			// instance will.
			name:     "a BGP speaker in the core",
			question: "q1",
			apply: func(t *testing.T) {
				p := coreRouter(t, dir, provider)
				if p == "" {
					t.Skip("this lab has no BGP-free core router to spoil")
				}
				t.Logf("giving the core router %s a BGP instance", p)
				vtysh(t, dir, p, "configure terminal",
					"router bgp "+itoa(provider),
					" bgp router-id 1.155.0.1",
					" neighbor 1.151.0.1 remote-as "+itoa(provider),
					" neighbor 1.151.0.1 update-source lo",
					"end")
				time.Sleep(15 * time.Second)
			},
		},
		{
			// The same speaker, where vtysh is not looking.
			//
			// FRR runs as many instances as it is told to, each in a pathspace
			// with sockets of its own. `vtysh -c 'show bgp summary'` answers
			// only for the default one, so a core router holding an instance,
			// a neighbour and the BGP port in a pathspace reported "BGP
			// instance not found" and kept the mark.
			name:     "a BGP speaker in the core, in a pathspace of its own",
			question: "q1",
			undo: func(t *testing.T) {
				if hiddenBGPD.router == "" {
					return
				}
				_, _ = twinet(t, "exec", "-m", dir, hiddenBGPD.router, "--", "sh", "-c",
					"kill $(cat /var/run/frr/twgrade/bgpd.pid) 2>/dev/null; sleep 2; "+
						"rm -rf /var/run/frr/twgrade /etc/frr/twgrade; echo ok")
			},
			apply: func(t *testing.T) {
				p := coreRouter(t, dir, provider)
				if p == "" {
					t.Skip("this lab has no BGP-free core router to spoil")
				}
				hiddenBGPD = struct{ router string }{p}
				t.Logf("giving the core router %s a BGP instance vtysh does not answer for", p)
				out, err := twinet(t, "exec", "-m", dir, p, "--", "sh", "-c",
					"mkdir -p /var/run/frr/twgrade /etc/frr/twgrade && "+
						"chown -R frr:frr /var/run/frr/twgrade /etc/frr/twgrade && "+
						"/usr/lib/frr/bgpd -N twgrade -d -A 127.0.0.1 && sleep 2 && "+
						"vtysh -N twgrade -c 'configure terminal' "+
						"-c 'router bgp "+itoa(provider)+"' "+
						"-c 'neighbor 1.151.0.1 remote-as "+itoa(provider)+"' "+
						"-c 'neighbor 1.151.0.1 update-source lo' -c end && echo started")
				if err != nil || !strings.Contains(out, "started") {
					t.Fatalf("starting a hidden BGP daemon on %s: %v\n%s", p, err, out)
				}
				// The default socket must still say there is nothing there,
				// or the case is proving something else.
				plain, err := twinet(t, "exec", "-m", dir, p, "--", "vtysh", "-c",
					"show bgp summary")
				if err == nil && !strings.Contains(plain, "instance not found") {
					t.Fatalf("vtysh can see the hidden daemon, so this case is not "+
						"testing what it says:\n%s", plain)
				}
				time.Sleep(10 * time.Second)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveProvider(t, dir, provider)
			if c.undo != nil {
				defer c.undo(t)
			}
			c.apply(t)

			after, _, report := gradeASBroken(t, dir, provider)
			if after[c.question] >= baseline[c.question] {
				t.Errorf("%s still scored %.2f of %.2f after %q; the check does not "+
					"measure what its name says, and a student could skip this work\n%s",
					c.question, after[c.question], points[c.question], c.name, report)
			}
		})
	}
}

// ldpEnd is one end of an interior link running LDP.
type ldpEnd struct{ router, iface, peerAddr string }

// ldpLinkEnds finds one interior link with LDP on both ends, and returns both.
//
// Read from the running configuration and the discovery table, so the mutation
// follows the submission rather than a memory of the lab.
func ldpLinkEnds(t *testing.T, dir string, as int) []ldpEnd {
	t.Helper()
	type disc struct{ iface, id string }
	byRouter := map[string][]disc{}
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh",
			"-c", "show mpls ldp discovery")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == "ipv4" && f[2] == "Link" {
				byRouter[dev] = append(byRouter[dev], disc{f[3], f[1]})
			}
		}
	}
	routers := make([]string, 0, len(byRouter))
	for r := range byRouter {
		routers = append(routers, r)
	}
	sort.Strings(routers)
	// A pair, so both ends of one link are moved: leaving one end on the link
	// would keep a link adjacency and prove nothing.
	for _, a := range routers {
		for _, da := range byRouter[a] {
			for _, b := range routers {
				if b == a {
					continue
				}
				for _, db := range byRouter[b] {
					if db.id == "" || da.id == "" {
						continue
					}
					// b discovered a on its link, and a discovered b on its.
					if aOf, bOf := loopbackOf(t, dir, a), loopbackOf(t, dir, b); aOf == db.id && bOf == da.id {
						return []ldpEnd{{a, da.iface, db.id}, {b, db.iface, da.id}}
					}
				}
			}
		}
	}
	return nil
}

// loopbackOf returns a router's loopback address.
func loopbackOf(t *testing.T, dir, device string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--",
		"sh", "-c", "ip -4 -o addr show dev lo scope global | awk '{print $4}' | head -1")
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

// edgeImpostor is one provider edge and the customer address it will answer for.
type edgeImpostor struct{ router, addr string }

// edgeImpostors pairs each provider edge with the address of the *other* site
// of the customer attached to it, which is what its own site would ping.
func edgeImpostors(t *testing.T, dir string, as int) []edgeImpostor {
	t.Helper()
	type edge struct{ router, vrf, site string }
	var edges []edge
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var vrf string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 5 && f[0] == "router" && f[1] == "bgp" && f[3] == "vrf" {
				vrf = f[4]
				continue
			}
			if vrf != "" && len(f) == 4 && f[0] == "neighbor" && f[2] == "remote-as" {
				edges = append(edges, edge{dev, vrf, f[3]})
				vrf = ""
			}
		}
	}
	var out []edgeImpostor
	for _, e := range edges {
		for _, other := range edges {
			if other.vrf != e.vrf || other.site == e.site {
				continue
			}
			addr := siteHostAddr(t, dir, other.site)
			if addr == "" {
				continue
			}
			out = append(out, edgeImpostor{e.router, addr})
			break
		}
	}
	return out
}

// siteHostAddr is the address of the host at a customer site, by AS number.
func siteHostAddr(t *testing.T, dir, asn string) string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, "as"+asn+"/BR_host", "--",
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

// interiorPorts lists a router's links to other routers, by name.
//
// Read from /sys/class/net rather than parsed out of `ip link`, whose output
// carries the peer index on the same field and needs quoting that does not
// survive being passed through two shells -- which is how the first version of
// this mutation silently dropped nothing at all and reported that the grader
// had missed it.
func interiorPorts(t *testing.T, dir, device string) []string {
	t.Helper()
	out, err := twinet(t, "exec", "-m", dir, device, "--", "ls", "/sys/class/net")
	if err != nil {
		t.Fatalf("listing the interfaces of %s: %v", device, err)
	}
	var ports []string
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "port_") {
			ports = append(ports, f)
		}
	}
	sort.Strings(ports)
	return ports
}

// vrfSite finds a routing table on a provider edge router, and the route target
// it carries, by reading the provider's own configuration rather than assuming
// the lab's names.
//
// skip selects which of the matching routers to return, so a caller can pick
// the second site of a customer instead of the first: changing the route target
// where the customer's routes originate breaks the export, which is a different
// error from breaking the import.
func vrfSite(t *testing.T, dir string, as, skip int) (router, vrf, rt string) {
	t.Helper()
	seen := 0
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var thisVRF string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 5 && f[0] == "router" && f[1] == "bgp" && f[2] == itoa(as) && f[3] == "vrf" {
				thisVRF = f[4]
				continue
			}
			if thisVRF != "" && len(f) == 4 && f[0] == "rt" && f[1] == "vpn" && f[2] == "both" {
				if seen == skip {
					return dev, thisVRF, f[3]
				}
				seen++
				thisVRF = ""
			}
		}
	}
	t.Fatalf("AS %d has no provider edge with a route target to alter", as)
	return "", "", ""
}

// otherRouteTarget is a route target belonging to some other customer.
func otherRouteTarget(t *testing.T, dir string, as int, notVRF string) string {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var thisVRF string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) >= 5 && f[0] == "router" && f[1] == "bgp" && f[3] == "vrf" {
				thisVRF = f[4]
				continue
			}
			if thisVRF != "" && thisVRF != notVRF && len(f) == 4 &&
				f[0] == "rt" && f[1] == "vpn" && f[2] == "both" {
				return f[3]
			}
		}
	}
	return ""
}

// coreRouter finds a router of the provider that runs no BGP at all, which is
// what the BGP-free core means.
func coreRouter(t *testing.T, dir string, as int) string {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		if !strings.Contains(out, "router bgp") {
			return dev
		}
	}
	return ""
}
