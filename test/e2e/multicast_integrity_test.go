//go:build e2e

package e2e

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The multicast course had one discrimination test, and it did not run.
//
// It was guarded on TWINET_MULTICAST_LAB being set, which nothing sets, so a
// suite that reported success had skipped the only thing establishing that the
// multicast rubric can withhold a mark. That is the same defect as a check that
// passes without looking: the report says the subject was examined.
//
// These run against the example lab by default and break one thing each.

func multicastLab(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TWINET_MULTICAST_LAB")
	if dir == "" {
		dir = "../../examples/multicast"
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no multicast lab to grade: %v", err)
	}
	return dir
}

func TestABrokenMulticastTreeLosesTheRightMarks(t *testing.T) {
	if testing.Short() {
		t.Skip("mutates a live lab")
	}
	dir := multicastLab(t)
	const as = 1

	baseline, points, report := gradeAS(t, dir, as)
	if len(baseline) == 0 {
		t.Fatalf("the reference answer scored nothing, so there is no baseline:\n%s", report)
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
			// Two rendezvous points for one group range.
			//
			// Every router has to agree where the shared tree is rooted. One
			// router pointed somewhere else builds a tree of its own, and the
			// receivers behind it hear nothing -- while every other router is
			// configured perfectly, so a check that reads one router's
			// configuration and stops sees a correct answer.
			name:     "one router pointed at a different rendezvous point",
			question: "q2",
			apply: func(t *testing.T) {
				router, rp, group := pimRP(t, dir, as)
				t.Logf("pointing %s at 10.255.255.1 instead of %s for %s", router, rp, group)
				vtysh(t, dir, router, "configure terminal",
					"no ip pim rp "+rp+" "+group,
					"ip pim rp 10.255.255.1 "+group,
					"end")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// PIM off one link of the core.
			//
			// The interface stays up and unicast keeps working over it, so
			// nothing about reachability gives it away: the multicast tree
			// simply cannot be built across that link.
			name:     "PIM removed from one transit link",
			question: "q1",
			apply: func(t *testing.T) {
				router, iface := pimTransitIface(t, dir, as)
				t.Logf("removing PIM from %s on %s", iface, router)
				vtysh(t, dir, router, "configure terminal",
					"interface "+iface,
					" no ip pim",
					"end")
				time.Sleep(20 * time.Second)
			},
		},
		{
			// PIM off the loopbacks.
			//
			// The check reported "PIM is up on every interface of all 6
			// routers" while the set it examined excluded the loopback from
			// itself. The loopback is not a formality: the rendezvous point is
			// addressed by it so that it outlives any one link, and a
			// rendezvous point whose own address does not run PIM cannot
			// register a source.
			name:     "PIM removed from every loopback",
			question: "q1",
			apply: func(t *testing.T) {
				for _, dev := range routersOf(t, dir, as) {
					vtysh(t, dir, dev, "configure terminal",
						"interface lo",
						" no ip pim",
						"end")
				}
				t.Logf("removed PIM from the loopback of every router in AS %d", as)
				time.Sleep(15 * time.Second)
			},
		},
		{
			// IGMP off the interface a receiver is behind.
			//
			// The router never learns that anybody downstream wants the group,
			// so it never joins the tree, and that site receives nothing while
			// every other site is served correctly.
			name:     "IGMP removed from one receiver's link",
			question: "q3",
			apply: func(t *testing.T) {
				router, iface := igmpIface(t, dir, as)
				t.Logf("removing IGMP from %s on %s", iface, router)
				vtysh(t, dir, router, "configure terminal",
					"interface "+iface,
					" no ip igmp",
					"end")
				time.Sleep(25 * time.Second)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveProvider(t, dir, as)
			c.apply(t)

			after, _, report := gradeASBroken(t, dir, as)
			if after[c.question] >= baseline[c.question] {
				t.Errorf("%s still scored %.2f of %.2f after %q; the check does not "+
					"measure what its name says, and a student could skip this work\n%s",
					c.question, after[c.question], points[c.question], c.name, report)
			}
		})
	}
}

// pimRP finds a router that declares a rendezvous point, and what it declares.
func pimRP(t *testing.T, dir string, as int) (router, rp, group string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 5 && f[0] == "ip" && f[1] == "pim" && f[2] == "rp" {
				return dev, f[3], f[4]
			}
		}
	}
	t.Fatalf("no router in AS %d declares a rendezvous point", as)
	return "", "", ""
}

// pimTransitIface finds an interface running PIM that faces another router,
// which is a branch of the tree rather than a receiver's link.
func pimTransitIface(t *testing.T, dir string, as int) (router, iface string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var cur string
		var hasPIM bool
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			switch {
			case len(f) == 2 && f[0] == "interface":
				if cur != "" && hasPIM && strings.HasPrefix(cur, "port_") {
					return dev, cur
				}
				cur, hasPIM = f[1], false
			case len(f) == 3 && f[0] == "ip" && f[1] == "pim" && cur != "":
				hasPIM = false // "ip pim passive" and friends are not a branch
			case len(f) == 2 && f[0] == "ip" && f[1] == "pim" && cur != "":
				hasPIM = true
			}
		}
		if cur != "" && hasPIM && strings.HasPrefix(cur, "port_") {
			return dev, cur
		}
	}
	t.Fatalf("no router in AS %d runs PIM on a link to another router", as)
	return "", ""
}

// igmpIface finds an interface listening for group memberships, which is where
// a receiver sits.
func igmpIface(t *testing.T, dir string, as int) (router, iface string) {
	t.Helper()
	for _, dev := range routersOf(t, dir, as) {
		out, err := twinet(t, "exec", "-m", dir, dev, "--", "vtysh", "-c", "show running-config")
		if err != nil {
			continue
		}
		var cur string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 2 && f[0] == "interface" {
				cur = f[1]
				continue
			}
			if len(f) == 2 && f[0] == "ip" && f[1] == "igmp" && cur != "" {
				return dev, cur
			}
		}
	}
	t.Fatalf("no router in AS %d listens for group memberships", as)
	return "", ""
}
