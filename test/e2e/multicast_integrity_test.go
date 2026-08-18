//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
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
		// undo puts back what re-solving cannot: a mapping added alongside the
		// rendered configuration rather than in place of it.
		undo func(t *testing.T)
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
			// A more specific mapping for the group actually being tested.
			//
			// PIM takes the longest prefix covering a group. The check
			// compared the declared range exactly, so a second mapping for a
			// /32 inside it was ignored -- and it is the one PIM would use.
			// Every router agreed on the wrong rendezvous point while the
			// question said they agreed on the right one.
			name:     "a more specific rendezvous point for the group under test",
			question: "q2",
			apply: func(t *testing.T) {
				_, rp, _ := pimRP(t, dir, as)
				group := testGroup(t, dir, as)
				other := "10.255.255.1"
				if rp != other {
					t.Logf("overriding %s for %s/32 on every router", rp, group)
				}
				for _, dev := range routersOf(t, dir, as) {
					vtysh(t, dir, dev, "configure terminal",
						"ip pim rp "+other+" "+group+"/32", "end")
				}
				time.Sleep(15 * time.Second)
			},
			undo: func(t *testing.T) {
				group := testGroup(t, dir, as)
				for _, dev := range routersOf(t, dir, as) {
					vtysh(t, dir, dev, "configure terminal",
						"no ip pim rp 10.255.255.1 "+group+"/32", "end")
				}
			},
		},
		{
			// Half the range sent somewhere else.
			//
			// PIM takes the most specific mapping for each group separately, so
			// a mapping covering the half of the declared range that the tested
			// address is not in leaves the test alone and takes the rest.
			name:     "half the declared group range rooted elsewhere",
			question: "q2",
			apply: func(t *testing.T) {
				group := testGroup(t, dir, as)
				// The half the tested address is not in.
				half := group[:strings.LastIndexByte(group, '.')] + ".128/25"
				for _, dev := range routersOf(t, dir, as) {
					vtysh(t, dir, dev, "configure terminal",
						"ip pim rp 10.255.255.1 "+half, "end")
				}
				time.Sleep(15 * time.Second)
			},
			undo: func(t *testing.T) {
				group := testGroup(t, dir, as)
				half := group[:strings.LastIndexByte(group, '.')] + ".128/25"
				for _, dev := range routersOf(t, dir, as) {
					vtysh(t, dir, dev, "configure terminal",
						"no ip pim rp 10.255.255.1 "+half, "end")
				}
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
		{
			// The receivers answering the question by talking to themselves.
			//
			// Delivery was measured as "something arrived on the group", and a
			// host that sends to a group on its own segment receives its own
			// packets. Blocking the graded traffic outright on every router and
			// leaving a sender running on every host therefore satisfied the
			// question for every host at once, with nothing delivered anywhere.
			name:     "every host sending to the group on its own segment",
			question: "q3",
			undo: func(t *testing.T) {
				group := testGroup(t, dir, as)
				for _, dev := range routersOf(t, dir, as) {
					_, _ = twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
						"iptables -D FORWARD -d "+group+" -p udp -j DROP; "+
							"iptables -D INPUT -d "+group+" -p udp -j DROP; echo ok")
				}
				for _, h := range hostsOfAS(t, dir, as) {
					_, _ = twinet(t, "exec", "-m", dir, h, "--", "sh", "-c",
						"for p in $(ps -ef | awk '/[t]winet-mcast/ {print $1}'); do "+
							"kill $p 2>/dev/null || true; done; echo ok")
				}
			},
			apply: func(t *testing.T) {
				group := testGroup(t, dir, as)
				for _, dev := range routersOf(t, dir, as) {
					if _, err := twinet(t, "exec", "-m", dir, dev, "--", "sh", "-c",
						"iptables -I FORWARD 1 -d "+group+" -p udp -j DROP; "+
							"iptables -I INPUT 1 -d "+group+" -p udp -j DROP; echo ok"); err != nil {
						t.Fatalf("blocking %s on %s: %v", group, dev, err)
					}
				}
				hosts := hostsOfAS(t, dir, as)
				if len(hosts) < 2 {
					t.Skip("this lab has too few hosts for the decoy to prove anything")
				}
				for _, h := range hosts {
					// Time to live one, so the decoys never leave the segment
					// and cannot be mistaken for traffic that crossed anything.
					if _, err := twinet(t, "exec", "-m", dir, h, "--", "sh", "-c",
						"i=$(ip -o -4 addr show | awk '$2!=\"lo\"{print $2; exit}'); "+
							"nohup sh -c \"while true; do twinet-mcast -send -group "+group+
							" -iface $i -count 200 -ttl 1; done\" >/dev/null 2>&1 & echo ok"); err != nil {
						t.Fatalf("starting the decoy sender on %s: %v", h, err)
					}
				}
				t.Logf("blocked %s in the network and left a sender running on each of %d host(s)",
					group, len(hosts))
				time.Sleep(5 * time.Second)
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer solveProvider(t, dir, as)
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

// testGroup is the group address the exercise sends to, read from the lab.
func testGroup(t *testing.T, dir string, as int) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "templates", "*.yaml"))
	files = append([]string{filepath.Join(dir, "twinet.yaml")}, files...)
	var body string
	for _, f := range files {
		if raw, err := os.ReadFile(f); err == nil {
			body += string(raw) + "\n"
		}
	}
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 2 && (f[0] == "test_group:" || f[0] == "testGroup:") {
			return strings.Trim(f[1], `"`)
		}
	}
	t.Fatal("the lab declares no multicast test group")
	return ""
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

// A host cannot be its own delivery.
//
// A datagram socket reports what the kernel handed it and cannot say where it
// came from, and a host that sends to a group on its own segment gets its own
// packets back. That was the whole exploit: drop every genuine delivery, read
// the tag out of the grader's own command line -- it was sitting in the
// student's process table -- and produce the traffic the network was failing to
// carry. Every site then reported the group arriving, and the exercise awarded
// full marks to a network that delivered nothing.
//
// So the probe is asked directly, on a real kernel in a real container, whether
// it can tell the two apart. The unit tests pin what the check does with the
// answer; this pins that the answer is true.
func TestTheProbeTellsItsOwnTrafficFromTheNetworksOwn(t *testing.T) {
	dir := multicastLab(t)
	const as = 1
	group := testGroup(t, dir, as)
	hosts := hostsOfAS(t, dir, as)
	if len(hosts) < 2 {
		t.Skip("this needs two hosts")
	}
	listener, sender := hosts[0], hosts[1]

	iface := func(h string) string {
		out, err := twinet(t, "exec", "-m", dir, h, "--", "sh", "-c",
			`ip -o -4 addr show | awk '$2!="lo"{print $2; exit}'`)
		if err != nil {
			t.Fatalf("finding %s's interface: %v", h, err)
		}
		return strings.TrimSpace(lastLine(out))
	}
	addr := func(h string) string {
		out, err := twinet(t, "exec", "-m", dir, h, "--", "sh", "-c",
			`ip -o -4 addr show | awk '$2!="lo"{split($4,a,"/"); print a[1]; exit}'`)
		if err != nil {
			t.Fatalf("finding %s's address: %v", h, err)
		}
		return strings.TrimSpace(lastLine(out))
	}

	watch := func(from string) string {
		out := make(chan string, 1)
		go func() {
			o, _ := twinet(t, "exec", "-m", dir, listener, "--", "twinet-mcast", "-recv",
				"-group", group, "-iface", iface(listener), "-from", from, "-seconds", "14")
			out <- o
		}()
		time.Sleep(5 * time.Second)
		return <-out
	}

	// What the host makes for itself, with this run's tag and everything else
	// right, still has to be reported as the host's own.
	forged := make(chan string, 1)
	go func() { forged <- watch(addr(listener)) }()
	time.Sleep(6 * time.Second)
	if _, err := twinet(t, "exec", "-m", dir, listener, "--", "twinet-mcast", "-send",
		"-group", group, "-iface", iface(listener), "-tag", "e2e", "-count", "6",
		"-ttl", "10"); err != nil {
		t.Fatalf("forging traffic on %s: %v", listener, err)
	}
	got := <-forged
	if !strings.Contains(got, "wire=0") {
		t.Errorf("%s counted traffic it generated itself as having arrived on the wire, "+
			"which is how a network that delivers nothing scored full marks:\n%s",
			listener, got)
	}
	if strings.Contains(got, "loopback=0") {
		t.Errorf("%s did not notice its own traffic at all; the report has nothing to "+
			"tell a student who did this by accident:\n%s", listener, got)
	}

	// And the network's own traffic still has to read as having arrived, or the
	// check fails every correct submission for the grader's reason.
	real := make(chan string, 1)
	go func() { real <- watch(addr(sender)) }()
	time.Sleep(6 * time.Second)
	if _, err := twinet(t, "exec", "-m", dir, sender, "--", "twinet-mcast", "-send",
		"-group", group, "-iface", iface(sender), "-tag", "e2e", "-count", "6",
		"-ttl", "10"); err != nil {
		t.Fatalf("sending from %s: %v", sender, err)
	}
	if got := <-real; strings.Contains(got, "wire=0") {
		t.Errorf("%s did not see the traffic %s really sent it:\n%s", listener, sender, got)
	}
}

// lastLine is the last non-empty line of a command's output, which is where a
// shell one-liner's answer is once the runner has had its say.
func lastLine(s string) string {
	var out string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = l
		}
	}
	return out
}
