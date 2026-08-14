//go:build e2e

package e2e

import (
	"os"
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
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveProvider(t, dir, provider)
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
