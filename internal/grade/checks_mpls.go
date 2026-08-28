package grade

import (
	"context"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/nos"
)

// Checks for the advanced-networks course: a BGP-free core and BGP/MPLS L3VPN.
//
// The exercise asks the student to carry two customers' traffic across a
// backbone whose interior routers hold no BGP state at all, and to keep the two
// customers apart. Each of those is a separate claim, and each is checked by
// observing the network rather than by reading the configuration that was
// supposed to produce it -- a distinction that cost this project a good deal of
// time elsewhere and is not repeated here.

func init() {
	Register(&Check{
		Name:     "mpls.bgp_free_core",
		Describe: "the core routers hold no BGP state, and the edges do not peer with them",
		Run:      checkBGPFreeCore,
		Requires: []nos.Feature{nos.FeatureMPLS},
	})
	Register(&Check{
		Name:     "mpls.ldp_adjacencies",
		Describe: "every interior link has an operational LDP session, and labels are installed",
		Run:      checkLDPAdjacencies,
		Requires: []nos.Feature{nos.FeatureMPLS, nos.FeatureLDP},
	})
	Register(&Check{
		Name:     "vpn.site_reachability",
		Describe: "the sites of one customer can reach each other across the provider",
		Run:      checkVPNReachability,
		Requires: []nos.Feature{nos.FeatureMPLS, nos.FeatureVRF},
	})
	Register(&Check{
		Name:     "vpn.label_switched",
		Describe: "the customer's remote sites are reached over a two-label path, not by plain routing",
		Run:      checkVPNLabelSwitched,
		Requires: []nos.Feature{nos.FeatureMPLS, nos.FeatureVRF},
	})
	Register(&Check{
		Name:     "vpn.isolation",
		Describe: "one customer cannot reach another, whatever addresses they use",
		Run:      checkVPNIsolation,
		Requires: []nos.Feature{nos.FeatureMPLS, nos.FeatureVRF},
	})
}

// checkBGPFreeCore asserts the point of the exercise.
//
// A core router that runs BGP will carry the customer routes perfectly well, so
// reachability alone cannot tell a correct answer from one that has simply put
// BGP everywhere. The absence is the answer, so the absence is what is checked
// -- on the core routers themselves and in the edges' neighbour lists, because
// a core router with a BGP process nobody peers with is a different mistake
// from one that is in the mesh.
func checkBGPFreeCore(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("mpls.bgp_free_core", fmt.Errorf("AS %d is not in this lab", env.AS))
	}
	core := coreRouters(as)
	if len(core) == 0 {
		return Errored("mpls.bgp_free_core",
			fmt.Errorf("AS %d declares no core routers, so there is nothing to check; "+
				"set mpls.core in the manifest", env.AS))
	}

	var bad []string
	for _, d := range core {
		out, err := env.Vtysh(ctx, d.Name, "show bgp summary")
		if err != nil {
			return Errored("mpls.bgp_free_core", err)
		}
		// FRR says "BGP instance not found" when no process exists at all,
		// which is the state being asked for.
		//
		// Requiring the word "Neighbor" as well was the mistake: FRR prints a
		// neighbour table only when there are neighbours, so a core router with
		// `router bgp 1` configured and no peers matched neither string and was
		// reported as holding no BGP state. It holds a BGP instance, a routing
		// information base and an identifier, and one line of configuration
		// away from holding the whole table -- which is the thing the exercise
		// says a core router must not do.
		if !strings.Contains(out, "instance not found") {
			bad = append(bad, fmt.Sprintf("%s has a BGP instance", d.Name))
			continue
		}
		// And the configuration, because an instance that exists but has not
		// been read by this command would be missed by it.
		cfg, err := env.Vtysh(ctx, d.Name, "show running-config")
		if err != nil {
			return Errored("mpls.bgp_free_core", err)
		}
		for _, line := range strings.Split(cfg, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "router bgp") {
				bad = append(bad, fmt.Sprintf("%s is configured with %s",
					d.Name, strings.TrimSpace(line)))
				break
			}
		}
		// And what `vtysh` is not connected to.
		//
		// `vtysh` speaks to one set of sockets, and a second BGP daemon does
		// not have to use them: FRR will run as many instances as you like,
		// each in its own pathspace with its own socket, and a daemon that is
		// not FRR at all shares none of its furniture. Either holds sessions,
		// a table and an identifier while `show bgp summary` answers for an
		// instance that does not exist.
		hidden, err := hiddenBGP(ctx, env, d.Name)
		if err != nil {
			return Errored("mpls.bgp_free_core", err)
		}
		bad = append(bad, hidden...)
	}
	// And no edge may name a core router as a neighbour: a session configured
	// towards a router with no BGP sits idle and is easy to miss.
	coreAddrs := map[string]string{}
	for _, d := range core {
		if lo, ok := d.IfaceByName("lo"); ok && lo.Addr4 != "" {
			coreAddrs[addrOnly(lo.Addr4)] = d.Name
		}
	}
	for _, d := range as.Routers {
		if isCore(as, d.Name) {
			continue
		}
		out, err := env.Vtysh(ctx, d.Name, "show bgp summary")
		if err != nil {
			continue
		}
		for addr, name := range coreAddrs {
			if strings.Contains(out, addr) {
				bad = append(bad, fmt.Sprintf("%s peers with the core router %s", d.Name, name))
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		return Fail("mpls.bgp_free_core", Evidence{
			Expected: "the core carries traffic on labels alone, with no BGP anywhere in it",
			Observed: strings.Join(bad, "; "),
			Command:  "vtysh -c 'show bgp summary'",
		})
	}
	return Pass("mpls.bgp_free_core", Evidence{
		Expected: "no BGP on the core",
		Observed: fmt.Sprintf("%d core router(s) hold no BGP state", len(core)),
	})
}

// hiddenBGP reports the BGP a router is running somewhere `vtysh` is not
// looking.
//
// `vtysh` connects to one set of sockets under /var/run/frr, and asking it
// whether a router runs BGP asks only about the daemons that own those
// sockets. FRR will run as many instances as it is told to, each in a
// pathspace of its own with its own sockets, and `vtysh -c 'show bgp summary'`
// answers "BGP instance not found" for a router holding an established session,
// a table and an identifier in one of them. A daemon that is not FRR at all
// shares none of FRR's furniture and is just as invisible.
//
// So the router is asked what it is running rather than what it will admit to:
// its processes, its sockets, and every FRR pathspace either of those reveals.
// None of this fires on a core router as the exercise wants it -- FRR starts
// bgpd there and leaves it unconfigured, which holds nothing, listens on
// nothing and is the state being asked for.
func hiddenBGP(ctx context.Context, env *Env, device string) ([]string, error) {
	id := model.DeviceID(env.AS, device)

	ps, err := env.Probe(ctx, id, []string{"ps", "-eo", "args"})
	if err != nil {
		return nil, err
	}
	if ps.ExitCode != 0 {
		return nil, fmt.Errorf("could not list what %s is running, so whether it runs a "+
			"second BGP daemon cannot be told: %s", device, firstLine(ps.Stderr))
	}
	spaces, out := bgpDaemons(device, ps.Stdout)

	// The sockets of a pathspace, for a daemon whose own name says nothing --
	// a copy of bgpd under another name is still an FRR daemon and still puts
	// its socket where FRR does.
	socks, err := env.Probe(ctx, id, []string{"sh", "-c",
		`for f in /var/run/frr/*/*.vty; do [ -e "$f" ] && echo "$f"; done`})
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(socks.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ns := path.Base(path.Dir(line))
		if !slices.Contains(spaces, ns) {
			spaces = append(spaces, ns)
			out = append(out, fmt.Sprintf("%s runs a second FRR instance in pathspace %q",
				device, ns))
		}
	}

	// What each of them holds, so the report says something a marker can act
	// on rather than only that something is there.
	sort.Strings(spaces)
	for _, ns := range spaces {
		res, err := env.Probe(ctx, id, []string{"vtysh", "-N", ns, "-c", "show bgp summary"})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 || strings.Contains(res.Stdout, "instance not found") {
			continue
		}
		if n := bgpPeerCount(res.Stdout); n > 0 {
			out = append(out, fmt.Sprintf("%s holds %d BGP neighbour(s) in pathspace %q, "+
				"where the default vtysh cannot see them", device, n, ns))
		}
	}

	// And the wire, because a BGP daemon that has been configured opens the
	// BGP port whatever it calls itself. A core router as the exercise wants
	// it has no socket on 179 in any state.
	ss, err := env.Probe(ctx, id, []string{"ss", "-Htan"})
	if err != nil {
		return nil, err
	}
	if ss.ExitCode != 0 {
		return nil, fmt.Errorf("could not read the sockets of %s, so whether it speaks BGP "+
			"cannot be told: %s", device, firstLine(ss.Stderr))
	}
	out = append(out, bgpSockets(device, ss.Stdout)...)
	return out, nil
}

// bgpSpeakers names the programs that speak BGP, by the name they run under.
//
// FRR's own bgpd is the one the exercise expects to be present and idle, so it
// is judged by how it was started rather than by being there at all; the rest
// have no reason to be on a core router in any state.
var bgpSpeakers = map[string]string{
	"bird": "BIRD", "bird6": "BIRD", "gobgpd": "GoBGP", "exabgp": "ExaBGP",
	"openbgpd": "OpenBGPD", "bgpd-openbsd": "OpenBGPD",
}

// bgpDaemons reads a process listing for BGP daemons the grader is not talking
// to, and returns the FRR pathspaces among them.
func bgpDaemons(device, ps string) (spaces, findings []string) {
	defaults := 0
	for _, line := range strings.Split(ps, "\n") {
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		prog := path.Base(args[0])
		if name, ok := bgpSpeakers[prog]; ok {
			findings = append(findings, fmt.Sprintf("%s runs %s, a BGP daemon of its own",
				device, name))
			continue
		}
		if prog != "bgpd" {
			continue
		}
		ns := pathspaceOf(args)
		switch {
		case ns != "":
			spaces = append(spaces, ns)
			findings = append(findings, fmt.Sprintf(
				"%s runs a second BGP daemon in pathspace %q, which vtysh does not answer for",
				device, ns))
		default:
			// The one FRR starts. A second copy of it, started by hand with
			// its own socket, is not that one.
			defaults++
			if defaults > 1 {
				findings = append(findings, fmt.Sprintf(
					"%s runs %d BGP daemons; vtysh answers for one of them", device, defaults))
			}
		}
	}
	return spaces, findings
}

// pathspaceOf reads the FRR pathspace a daemon was started in, by whichever of
// the three spellings started it. A daemon given its own socket directory
// rather than a pathspace is reported under that directory's name, because it
// is the same act.
func pathspaceOf(args []string) string {
	for i, a := range args {
		switch {
		case a == "-N" || a == "--pathspace":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(a, "--pathspace="):
			return strings.TrimPrefix(a, "--pathspace=")
		case a == "--vty_socket":
			if i+1 < len(args) {
				return path.Base(strings.TrimSuffix(args[i+1], "/"))
			}
		case strings.HasPrefix(a, "--vty_socket="):
			return path.Base(strings.TrimSuffix(strings.TrimPrefix(a, "--vty_socket="), "/"))
		}
	}
	return ""
}

// bgpPeerCount reads how many neighbours a summary lists, so the evidence can
// say what was hidden rather than only that something was.
func bgpPeerCount(summary string) int {
	for _, line := range strings.Split(summary, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 4 && f[0] == "Total" && f[1] == "number" && f[2] == "of" {
			n, err := strconv.Atoi(f[len(f)-1])
			if err == nil {
				return n
			}
		}
	}
	return 0
}

// bgpSockets reports every socket on the BGP port, whoever opened it.
//
// This is what catches a BGP speaker that has been renamed: the name it runs
// under is its to choose, and the port its peers connect to is not.
func bgpSockets(device, ss string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(ss, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		state, local, peer := f[0], f[3], f[4]
		var what string
		switch {
		case portOf(local) == "179" && state == "LISTEN":
			what = fmt.Sprintf("%s is listening for BGP connections on %s", device, local)
		case portOf(local) == "179" || portOf(peer) == "179":
			what = fmt.Sprintf("%s holds a BGP connection, %s to %s", device, local, peer)
		default:
			continue
		}
		if !seen[what] {
			seen[what] = true
			out = append(out, what)
		}
	}
	return out
}

// portOf reads the port from an ss address, which is the text after the last
// colon in both `0.0.0.0:179` and `[::]:179`.
func portOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return ""
	}
	return addr[i+1:]
}

// checkLDPAdjacencies confirms label distribution reached the forwarding table.
// An operational LDP session is not the claim. A router can hold every session
// and still install nothing, and a router can install labels the kernel then
// refuses to act on. Both were real failures here. So the session and the
// installed label table are checked together.
func checkLDPAdjacencies(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("mpls.ldp_adjacencies", fmt.Errorf("AS %d is not in this lab", env.AS))
	}
	var problems []string
	checked := 0
	for _, d := range as.Routers {
		want := interiorPeers(as, d)
		if len(want) == 0 {
			continue
		}
		checked++
		out, err := env.Vtysh(ctx, d.Name, "show mpls ldp neighbor")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		// Where the adjacency was discovered, not merely that a session
		// exists.
		//
		// LDP will happily bring up a *targeted* session between two
		// loopbacks, routed over whatever path the IGP offers. That is a
		// session with the right peer at the right address, and the check
		// accepted it -- so a submission could take LDP off the interior link
		// entirely, replace it with a targeted session, and keep full marks
		// for label distribution across a link that distributes no labels.
		// A link adjacency is discovered by hellos on the interface itself,
		// and says so.
		disc, err := env.Vtysh(ctx, d.Name, "show mpls ldp discovery")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		links := ldpLinkAdjacencies(disc)
		for _, p := range want {
			if !strings.Contains(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s has no LDP session with %s", d.Name, p.name))
				continue
			}
			if !operationalWith(out, p.addr) {
				problems = append(problems, fmt.Sprintf("%s's LDP session with %s is not operational",
					d.Name, p.name))
			}
			if id, ok := links[p.iface]; !ok {
				problems = append(problems, fmt.Sprintf(
					"%s has no link LDP adjacency on %s, the interface facing %s: a targeted "+
						"session is not label distribution across that link",
					d.Name, p.iface, p.name))
			} else if id != p.addr {
				problems = append(problems, fmt.Sprintf(
					"%s's link adjacency on %s is with %s, not %s", d.Name, p.iface, id, p.name))
			}
		}
		// Labels must reach the kernel, not merely be negotiated. A table that
		// cannot be read is the grader's failure, not the student's: silently
		// reading the missing output as "labels are present" once let a router
		// that installed nothing pass, so the read is required to succeed.
		tbl, err := env.Vtysh(ctx, d.Name, "show mpls table")
		if err != nil {
			return Errored("mpls.ldp_adjacencies", err)
		}
		if !strings.Contains(tbl, "LDP") {
			problems = append(problems, fmt.Sprintf(
				"%s has negotiated labels but installed none, so it forwards nothing on them", d.Name))
		}
	}
	if checked == 0 {
		return Errored("mpls.ldp_adjacencies",
			fmt.Errorf("no router in AS %d has an interior link, so there is nothing to check", env.AS))
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		return Fail("mpls.ldp_adjacencies", Evidence{
			Expected: "an operational LDP session on every interior link, with labels installed",
			Observed: strings.Join(problems, "; "),
			Command:  "vtysh -c 'show mpls ldp neighbor'; vtysh -c 'show mpls table'",
		})
	}
	return Pass("mpls.ldp_adjacencies", Evidence{
		Expected: "label distribution across the interior",
		Observed: fmt.Sprintf("%d router(s) have every interior session operational with labels installed", checked),
	})
}

// checkVPNReachability asks whether each customer's sites can reach each other.
//
// It sends between hosts of the same customer, from one site to another. That
// is the only claim the exercise makes that a student can be sure of: the
// branches run ordinary eBGP and know nothing about MPLS, so if two sites of a
// bank can reach each other it is because the provider carried them.
//
// Ping, connection and datagram, because a bank's branches exchange none of
// their business over ICMP.
func checkVPNReachability(ctx context.Context, env *Env) Result {
	groups, err := customerGroups(env)
	if err != nil {
		return Errored("vpn.site_reachability", err)
	}
	// What each site received, before and after.
	//
	// A ping proves that something answered, not that the customer's site did.
	// The provider is the system being marked and every packet crosses it: a
	// DNAT rule on each edge, answering the far site's address locally while
	// the real traffic is dropped, left every probe succeeding and the mark
	// untouched. The customer's hosts are not the provider's to configure, and
	// the kernel's count of echo requests delivered to them is not something a
	// rule on the way can arrange.
	var allSites []sitePoint
	for _, sites := range groups {
		allSites = append(allSites, sites...)
	}
	before := receivedEchoesAt(ctx, env, allSites)

	var problems []string
	tried := 0
	sentTo := map[string]int{}
	var carried []directedPair
	for name, sites := range groups {
		if len(sites) < 2 {
			continue
		}
		for i := 0; i < len(sites); i++ {
			for j := i + 1; j < len(sites); j++ {
				// Both directions: a VPN that carries a customer one way but
				// not back is still broken, and a single-direction probe would
				// report it as working.
				for _, d := range directed(sites[i], sites[j]) {
					tried++
					sentTo[d.to.host]++
					reached, err := env.reaches(ctx, d.from.host, d.to.addr)
					if err != nil {
						return Errored("vpn.site_reachability", err)
					}
					if !reached {
						problems = append(problems, fmt.Sprintf(
							"%s cannot reach %s (%s), both sites of %s",
							d.from.host, d.to.host, d.to.addr, name))
						continue
					}
					carried = append(carried, d)
				}
			}
		}
	}
	// The pairs that answer a ping are asked to carry ordinary traffic too.
	pingOnly, pingOnlyPairs, untestedPairs := vpnTransportGaps(ctx, env, carried)
	after := receivedEchoesAt(ctx, env, allSites)
	for _, site := range allSites {
		if sentTo[site.host] == 0 {
			continue
		}
		b, okB := before[site.host]
		a, okA := after[site.host]
		if !okB || !okA {
			continue // the counter could not be read; the probe stands alone
		}
		if a <= b {
			problems = append(problems, fmt.Sprintf(
				"%s answered %d probe(s) it never received, so something on the way is "+
					"replying for it", site.host, sentTo[site.host]))
		}
	}
	if tried == 0 {
		return Errored("vpn.site_reachability",
			fmt.Errorf("no customer in this lab has two sites, so there is nothing to check"))
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		return Fail("vpn.site_reachability", Evidence{
			Expected: "each customer's sites reach each other across the provider",
			Observed: strings.Join(problems, "; "),
			Command:  "ping",
		})
	}
	if len(pingOnly) > 0 {
		// Half: the tables are joined and the pings cross, so the VPN exists,
		// but a link that carries nothing a customer would send is not one they
		// could use.
		return Partial("vpn.site_reachability", 0.5, Evidence{
			Expected: "each customer's sites exchange ordinary traffic, not only pings",
			Observed: fmt.Sprintf("%d of %d site pair(s) carry ICMP and nothing else",
				pingOnlyPairs, tried),
			Detail: strings.Join(truncate(pingOnly, 6), "\n"),
			Hint: "a VPN that answers a ping but drops connections and datagrams is not " +
				"carrying the customer; check for filtering by protocol on the edge",
			Command: "nc; /proc/net/snmp",
		})
	}
	// The pass says every pair carried a connection and a datagram, and that
	// each was seen arriving at the far side. A pair whose far side could not
	// be read was never shown to do either, and passing it said so anyway.
	if len(untestedPairs) > 0 {
		return Errored("vpn.site_reachability", fmt.Errorf(
			"%d site pair(s) could not be read at the far side (%s), so whether the VPN "+
				"carries anything but pings between them is unknown",
			len(untestedPairs), strings.Join(truncate(untestedPairs, 4), "; ")))
	}
	return Pass("vpn.site_reachability", Evidence{
		Expected: "each customer's sites reach each other",
		Observed: fmt.Sprintf("%d site pair(s) reachable by ping, connection and datagram, and "+
			"every site received the traffic addressed to it", tried),
	})
}

// vpnTransportGaps names the site pairs that answer a ping but do not carry
// ordinary traffic.
//
// A VPN carrying ICMP and nothing else is not one a customer could use, and
// ICMP is the easy thing to leave working: dropping TCP and UDP on the
// provider's edges left every probe of this question succeeding and the mark
// untouched, on a network where no bank could have opened a connection to its
// own branch.
//
// Both transports are tried, in the direction the pair names, and arrival is
// read at the destination. The sender's view is not evidence on its own: a
// rule on the path can answer a connection with a reset of its own making, and
// a dropped datagram is indistinguishable from a delivered one to whoever sent
// it. The destination's kernel counts the resets it sent and the datagrams it
// took delivery of for an unbound port, and neither is a number anything on the
// way can raise.
//
// One pair at a time, so that a counter that moves belongs to the probe that
// just ran. Returns the gaps found and how many pairs they fall across.
func vpnTransportGaps(ctx context.Context, env *Env, pairs []directedPair) (
	gaps []string, affected int, untested []string) {

	var out []string
	for _, d := range pairs {
		n := len(out)
		p, okTCP := vpnTCPGap(ctx, env, d)
		if p != "" {
			out = append(out, p)
		}
		q, okUDP := vpnUDPGap(ctx, env, d)
		if q != "" {
			out = append(out, q)
		}
		if len(out) > n {
			affected++
		}
		// A pair whose far side could not be read is not a pair that carries
		// ordinary traffic. Saying nothing about it passed it.
		if !okTCP || !okUDP {
			untested = append(untested, fmt.Sprintf("%s to %s (%s)",
				d.from.host, d.to.host, d.to.addr))
		}
	}
	sort.Strings(out)
	sort.Strings(untested)
	return out, affected, untested
}

// vpnTCPGap attempts one connection across a site pair and reports what did not
// happen.
func vpnTCPGap(ctx context.Context, env *Env, d directedPair) (string, bool) {
	port := probePort()
	tap := startArrivalTap(ctx, env, d.to.host, port)
	before, okB := tcpAnswers(ctx, env, d.to.host)
	res, err := env.Probe(ctx, d.from.host,
		[]string{"nc", "-v", "-w", "3", "-z", d.to.addr, port})
	if err != nil {
		_, _ = tap.seen(ctx, env) // clear the capture off the machine
		return "", false          // the machinery failed, which is not a verdict
	}
	after, okA := tcpAnswers(ctx, env, d.to.host)
	frames, live := tap.seen(ctx, env)
	got := arrival{
		tapped: frames.tcp, tapLive: live,
		counted: offBoxDelta(before, after), counterOK: okB && okA,
	}
	said := strings.ToLower(res.Stderr + res.Stdout)
	answered := res.ExitCode == 0 ||
		strings.Contains(said, "refused") || strings.Contains(said, "reset")
	arrived := got.attributable() && got.arrived()

	switch {
	case answered && got.attributable() && !arrived:
		return fmt.Sprintf("%s got an answer from %s (%s) to a connection %s never saw -- %s: "+
			"something on the path is answering for it", d.from.host, d.to.host, d.to.addr,
			d.to.host, got.why()), true
	case !answered && arrived:
		return fmt.Sprintf("a connection from %s reaches %s (%s) but the answer does not come "+
			"back, though pings do", d.from.host, d.to.host, d.to.addr), true
	case !answered:
		return fmt.Sprintf("%s can ping %s (%s) but no connection to it arrives: the VPN is "+
			"carrying ICMP and discarding the rest", d.from.host, d.to.host, d.to.addr), true
	}
	// It answered, so the only way to know the answer came from the far side
	// is the far side's own record of what reached it.
	return "", got.attributable()
}

// vpnUDPGap sends one datagram across a site pair and reads, at the far side,
// whether it arrived.
func vpnUDPGap(ctx context.Context, env *Env, d directedPair) (string, bool) {
	probe := datagramProbe{dstAddr: d.to.addr, port: probePort()}
	counter := func(ctx context.Context, env *Env, _ string) (counterWitness, bool) {
		return datagramsDelivered(ctx, env, d.to)
	}
	// A datagram that was never sent cannot have been filtered. Reaching a
	// closed port exits zero here and a blocked one times out and also exits
	// zero, so a sender that could not get a single attempt away is not
	// evidence -- and reading that as a datagram that did not arrive accused
	// the VPN of filtering by protocol on no evidence.
	got, sent := probeDatagramArrival(ctx, env, d.from.host, d.to.host, probe, counter)
	got, status := confirmedDatagramArrival(got, sent, func() (arrival, bool) {
		return probeDatagramArrival(ctx, env, d.from.host, d.to.host, probe, counter)
	})
	// A datagram is invisible to whoever sent it, so the far side's own record
	// is the whole of the evidence. Without it there is no verdict either way.
	if status == datagramArrivalUnknown {
		return "", false
	}
	if status == datagramArrivalSeen {
		return "", true
	}
	return fmt.Sprintf("a datagram from %s to %s (%s) never arrived in two attributable "+
		"rounds -- %s -- though pings do: the VPN is filtering by protocol",
		d.from.host, d.to.host, d.to.addr, got.why()), true
}

// receivedEchoesAt reads each site host's count of ICMP echo requests the
// kernel delivered to it.
func receivedEchoesAt(ctx context.Context, env *Env, sites []sitePoint) map[string]int {
	out := map[string]int{}
	seen := map[string]bool{}
	for _, s := range sites {
		if seen[s.host] {
			continue
		}
		seen[s.host] = true
		res, err := env.Probe(ctx, s.host, []string{"cat", "/proc/net/snmp"})
		if err != nil || res.ExitCode != 0 {
			continue
		}
		if n, ok := icmpInEchos(res.Stdout); ok {
			out[s.host] = n
		}
	}
	return out
}

// checkVPNIsolation asks whether the customers are kept apart.
//
// This is the half that a working VPN does not imply. A provider that simply
// put every customer in one table would pass the reachability check completely
// and fail this one, and it is the mistake the exercise is designed to provoke.
func checkVPNIsolation(ctx context.Context, env *Env) Result {
	groups, err := customerGroups(env)
	if err != nil {
		return Errored("vpn.isolation", err)
	}
	if len(groups) < 2 {
		return Errored("vpn.isolation",
			fmt.Errorf("this lab has fewer than two customers, so isolation cannot be tested"))
	}
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	// Isolation is only worth anything over a VPN that actually carries
	// traffic. "The ping was blocked" is equally true of a network where
	// nothing works at all, so certifying isolation without first seeing one
	// customer's own sites reach each other would award full marks to a dead
	// network -- the very failure this exercise is built to provoke, recorded
	// as a success. The rubric also makes this question depend on reachability;
	// this is the same guarantee at the level of the check, so it holds when
	// the check is run on its own.
	carried, intraPairs := 0, 0
	for _, sites := range groups {
		for i := 0; i < len(sites); i++ {
			for j := i + 1; j < len(sites); j++ {
				for _, d := range directed(sites[i], sites[j]) {
					intraPairs++
					reached, err := env.reaches(ctx, d.from.host, d.to.addr)
					if err != nil {
						return Errored("vpn.isolation", err)
					}
					if reached {
						carried++
					}
				}
			}
		}
	}
	if intraPairs > 0 && carried == 0 {
		return Fail("vpn.isolation", Evidence{
			Expected: "a working VPN whose sites reach each other, so that isolating it means something",
			Observed: "no customer's own sites can reach each other at all",
			Detail: "every isolation probe here is blocked because nothing is reachable, not because " +
				"the tables are kept apart, and a dead network must not earn the isolation marks; " +
				"get vpn.site_reachability passing first",
			Command: "ping",
		})
	}

	// Every site of one customer must fail to reach every site of another, in
	// both directions: a table that leaks from only one branch, or only on the
	// return path, is still a leak, and the first-site, one-direction probe
	// this replaced walked straight past it.
	var leaks []string
	tried := 0
	var crossPairs []directedPair
	for x := 0; x < len(names); x++ {
		for y := x + 1; y < len(names); y++ {
			for _, a := range groups[names[x]] {
				for _, b := range groups[names[y]] {
					for _, d := range directed(a, b) {
						tried++
						crossPairs = append(crossPairs, d)
						reached, err := env.reaches(ctx, d.from.host, d.to.addr)
						if err != nil {
							return Errored("vpn.isolation", err)
						}
						if reached {
							leaks = append(leaks, fmt.Sprintf(
								"%s reached %s (%s): %s and %s are sharing a routing table",
								d.from.host, d.to.host, d.to.addr, names[x], names[y]))
						}
					}
				}
			}
		}
	}
	// The same pairs over the transports a ping does not exercise. Isolation
	// asked only of ICMP is isolation of ICMP: a path that discards echo
	// requests between the customers and carries their connections and
	// datagrams reads as perfectly separated tables, while the two banks are
	// exchanging traffic.
	leaks = append(leaks, vpnCrossTalk(ctx, env, crossPairs)...)

	// And the tables themselves, because a probe that needs a reply cannot see
	// a leak that only goes one way.
	//
	// Importing another customer's route target on one edge puts their
	// prefixes in this customer's table. Traffic then flows into the other
	// bank's network, and nothing comes back, because their table has no route
	// to here -- so every ping is lost and a check built on ping reports
	// perfect isolation. One bank able to inject packets into another's
	// network is precisely the failure the mechanism exists to prevent, and it
	// scored full marks. Found by the advanced course's own discrimination
	// suite, which is what that suite is for.
	routeLeaks, err := crossCustomerRoutes(ctx, env, groups, names)
	if err != nil {
		return Errored("vpn.isolation", err)
	}
	leaks = append(leaks, routeLeaks...)

	if len(leaks) > 0 {
		sort.Strings(leaks)
		return Fail("vpn.isolation", Evidence{
			Expected: "customers cannot reach one another, and cannot see one another's routes",
			Observed: strings.Join(truncate(leaks, 6), "; "),
			Command:  "ping; show ip route vrf <table> <prefix>",
		})
	}
	return Pass("vpn.isolation", Evidence{
		Expected: "customers are kept apart, over a VPN that carries their traffic",
		Observed: fmt.Sprintf("%d directed site pair(s) across %d customer(s) mutually "+
			"unreachable by ping, connection and datagram, and no customer's table holds "+
			"a route aimed at another's prefixes alone", tried, len(names)),
	})
}

// vpnCrossTalk names the cross-customer pairs that exchange anything at all.
//
// The ping between them is one protocol of three, and the one a leak is most
// likely to be missing: a path that discards echo requests and carries the rest
// is separated for the purposes of a check built on ping and joined for the
// purposes of the customers. Both other transports are tried, and the evidence
// for each is chosen so that a leak has to be real:
//
//   - a connection counts only when the destination itself answered it, which
//     its kernel records and nothing on the path can forge. A reset carries the
//     destination's address because whoever wrote it put that address on it,
//     and a provider that rejects cross-customer traffic rather than dropping
//     it silently -- which is isolation, done more helpfully -- was read as the
//     two customers talking to each other;
//   - a datagram counts only when the far side's kernel takes delivery of
//     several, so that a single unrelated packet arriving in the window is not
//     read as a breach and does not cost a correct submission its marks.
func vpnCrossTalk(ctx context.Context, env *Env, pairs []directedPair) []string {
	var (
		mu  sync.Mutex
		out []string
	)
	// Serialised by destination: a counter that moved is only attributable to
	// this attempt if no other attempt is aimed at the same host at the time.
	for _, round := range roundsByDestinationOf(pairs, func(d directedPair) string {
		return d.to.host
	}) {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, d := range round {
			wg.Add(1)
			go func(d directedPair) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				w, ok := tryConnection(ctx, env, d.from.host, d.to.host, d.to.addr, probePort())
				if !ok || !w.proves() {
					return
				}
				mu.Lock()
				out = append(out, fmt.Sprintf(
					"a connection from %s to %s (%s) was answered by %s itself: the two "+
						"customers are not separated, whatever happens to their pings",
					d.from.host, d.to.host, d.to.addr, d.to.host))
				mu.Unlock()
			}(d)
		}
		wg.Wait()
	}
	out = append(out, vpnDatagramLeaks(ctx, env, pairs)...)
	sort.Strings(out)
	return out
}

// vpnDatagramLeaks sends datagrams across every cross-customer pair and reads,
// at each destination, whether they arrived.
//
// A datagram is one way, so the sender learns nothing; what the destination
// recorded is the only witness. The pairs are scheduled so that no destination
// is aimed at twice at once, which is what makes a counter that moved
// attributable to the sender that moved it.
//
// This one accuses, so the direction to err in is the other one: a count the
// destination raised by itself, on its own loopback, would name two properly
// separated customers as leaking into each other. Both the loopback subtraction
// and the capture of the exact flow are here for that reason.
func vpnDatagramLeaks(ctx context.Context, env *Env, pairs []directedPair) []string {
	const burst = 3 // several, so one stray packet in the window is not a verdict

	var out []string
	for _, round := range roundsByDestinationOf(pairs, func(d directedPair) string {
		return d.to.host
	}) {
		ports := map[string]string{}
		for _, d := range round {
			ports[d.to.host] = probePort()
		}
		taps := startTaps(ctx, env, ports)
		before := map[string]counterWitness{}
		for _, d := range round {
			if n, ok := datagramsDelivered(ctx, env, d.to); ok {
				before[d.to.host] = n
			}
		}
		var wg sync.WaitGroup
		for _, d := range round {
			wg.Add(1)
			go func(d directedPair) {
				defer wg.Done()
				for i := 0; i < burst; i++ {
					_, _ = env.Probe(ctx, d.from.host, []string{"sh", "-c",
						"echo twinet | nc -u -w 1 " + d.to.addr + " " + ports[d.to.host]})
				}
			}(d)
		}
		wg.Wait()
		seen := readTaps(ctx, env, taps)
		for _, d := range round {
			b, okB := before[d.to.host]
			a, okA := datagramsDelivered(ctx, env, d.to)
			got := arrival{
				tapped: seen[d.to.host].counts.udp, tapLive: seen[d.to.host].live,
				counted: offBoxDelta(b, a), counterOK: okB && okA,
			}
			if !got.arrivedAtLeast(burst) {
				continue
			}
			out = append(out, fmt.Sprintf(
				"datagrams from %s arrived at %s (%s): the two customers are not separated, "+
					"whatever happens to their pings", d.from.host, d.to.host, d.to.addr))
		}
	}
	return out
}

// datagramsDelivered reads a site's count of datagrams the kernel took delivery
// of for a port nothing is bound to, in the family the site is addressed in.
func datagramsDelivered(ctx context.Context, env *Env, s sitePoint) (counterWitness, bool) {
	if strings.Contains(s.addr, ":") {
		return udpNoPorts(ctx, env, s.host)
	}
	return udpNoPortsV4(ctx, env, s.host)
}

// anyCustomerTrafficArrives reports whether at least one customer's site can
// reach another of its own sites.
//
// It is deliberately a low bar: this is not the reachability question, which is
// marked separately and in full. It is the precondition for asking *how*
// traffic is carried, and a VPN across which nothing at all passes cannot
// answer it.
func anyCustomerTrafficArrives(ctx context.Context, env *Env) (bool, error) {
	groups, err := customerGroups(env)
	if err != nil {
		return false, err
	}
	tried := 0
	for _, sites := range groups {
		for i := 0; i < len(sites); i++ {
			for j := 0; j < len(sites); j++ {
				if i == j {
					continue
				}
				tried++
				ok, err := env.reaches(ctx, sites[i].host, sites[j].addr)
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
		}
	}
	if tried == 0 {
		return false, fmt.Errorf("no customer in this lab has two sites, so there is no " +
			"traffic between them to carry")
	}
	return false, nil
}

// crossCustomerRoutes reports every place one customer's routing table holds a
// route to another customer's addresses.
//
// This is the control-plane half of isolation, and it is not redundant with the
// probes above: a leak in one direction delivers packets and receives no reply,
// which is indistinguishable from isolation to anything that pings.
//
// A route counts as a leak when it covers another customer's site and does not
// cover any of this customer's own. That last clause keeps a route that covers
// everybody -- a default route, or an aggregate wide enough to span both
// customers -- from being read as a total leak, without resorting to a list of
// prefixes to forgive: such a route says nothing about where its traffic ends
// up, and reading it as a leak would cost a correct submission its marks.
//
// The price of that exemption is that a route wide enough to cover this
// customer's own sites is not examined here at all, so a leak arranged behind
// one is invisible to this half. That is not a hole, because it is the probes
// above that decide reachability and they do not care how the route was
// spelled: a 16.0.0.0/4 in one table resolving into the other customer's
// network, advertised to the customer, was measured delivering every packet it
// was sent, and was caught -- by the connection and the datagram, the ping
// having been dropped for want of a return path. What this function
// establishes is therefore narrower than "the tables are separate", and the
// evidence says so.
func crossCustomerRoutes(ctx context.Context, env *Env, groups map[string][]sitePoint,
	names []string) ([]string, error) {
	holders, err := vrfHolders(env)
	if err != nil {
		return nil, err
	}
	addrs := map[string][]netip.Addr{}
	for name, sites := range groups {
		for _, s := range sites {
			if a, perr := netip.ParseAddr(s.addr); perr == nil {
				addrs[name] = append(addrs[name], a)
			}
		}
	}
	covers := func(p netip.Prefix, who string) bool {
		for _, a := range addrs[who] {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	var leaks []string
	for _, mine := range names {
		for _, router := range holders[mine] {
			var doc map[string]any
			cmd := fmt.Sprintf("show ip route vrf %s json", mine)
			if err := env.VtyshJSON(ctx, router, cmd, &doc); err != nil {
				// Unreadable is not empty. A verdict of "no leaks" drawn from a
				// table nobody managed to read is the failure this file exists
				// to avoid.
				return nil, fmt.Errorf("%s: table %s could not be read (%w), so what is in "+
					"it cannot be part of a verdict", router, mine, err)
			}
			for prefix := range doc {
				p, perr := netip.ParsePrefix(prefix)
				if perr != nil || covers(p, mine) {
					continue
				}
				for _, theirs := range names {
					if theirs == mine || !covers(p, theirs) {
						continue
					}
					leaks = append(leaks, fmt.Sprintf(
						"%s holds a route to %s in table %s, and those addresses belong to "+
							"%s: the tables are not separate", router, prefix, mine, theirs))
				}
			}
		}
	}
	sort.Strings(leaks)
	return leaks, nil
}

// vrfHolders lists, for each routing table, the provider edges that hold it.
func vrfHolders(env *Env) (map[string][]string, error) {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil, fmt.Errorf("AS %d is not in this lab", env.AS)
	}
	out := map[string][]string{}
	for _, d := range as.Routers {
		seen := map[string]bool{}
		for _, i := range d.Ifaces {
			if i.VRF == "" || seen[i.VRF] {
				continue
			}
			seen[i.VRF] = true
			out[i.VRF] = append(out[i.VRF], d.Name)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out, nil
}

// ---------------------------------------------------------------------------

type sitePoint struct {
	host string // device ID of a host at this site
	addr string // an address reachable at this site
}

// customerGroups collects the customers of the provider under test and the
// sites of each, keyed by the routing table that carries them.
//
// The table is what defines a customer here: two sites belong to the same
// customer exactly when the provider puts them in the same table, which is the
// property the exercise is about. Grouping by anything else -- a name, an AS
// number range -- would let a lab be built where the check and the exercise
// disagree about who is whose.
func customerGroups(env *Env) (map[string][]sitePoint, error) {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil, fmt.Errorf("AS %d is not in this lab", env.AS)
	}
	if len(as.VRFs) == 0 {
		return nil, fmt.Errorf("AS %d declares no routing tables, so it carries no VPN customers", env.AS)
	}

	groups := map[string][]sitePoint{}
	for _, d := range as.Routers {
		for _, i := range d.Ifaces {
			if i.VRF == "" || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			// The site is the AS on the far side of a table-bound port. Its
			// host is what gets pinged, because a host proves the data plane
			// end to end and a router interface only proves the last hop.
			peerAS := i.Peer.Device.ASN
			if h := hostIn(env.Topology, peerAS); h != nil {
				if addr := siteAddr(h); addr != "" {
					groups[i.VRF] = append(groups[i.VRF], sitePoint{host: h.ID, addr: addr})
				}
			}
		}
	}
	for k := range groups {
		sort.Slice(groups[k], func(a, b int) bool { return groups[k][a].host < groups[k][b].host })
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("no customer site could be resolved; the tables exist but no "+
			"interface is bound to one in AS %d", env.AS)
	}
	return groups, nil
}

func coreRouters(as *model.AS) []*model.Device {
	var out []*model.Device
	for _, d := range as.Routers {
		if isCore(as, d.Name) {
			out = append(out, d)
		}
	}
	return out
}

func isCore(as *model.AS, name string) bool { return as.InCore(name) }

type ldpPeer struct{ name, addr, iface string }

// interiorPeers lists the routers this one shares an interior link with, by the
// address LDP identifies them with.
func interiorPeers(as *model.AS, d *model.Device) []ldpPeer {
	var out []ldpPeer
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Link.InterAS || i.Peer == nil || i.Peer.Device == nil {
			continue
		}
		p := i.Peer.Device
		if p.ASN != as.ASN || p.Kind != model.KindRouter {
			continue
		}
		if lo, ok := p.IfaceByName("lo"); ok && lo.Addr4 != "" {
			out = append(out, ldpPeer{name: p.Name, addr: addrOnly(lo.Addr4), iface: i.Name})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

// ldpLinkAdjacencies maps each interface with a *link* LDP adjacency to the
// peer discovered on it.
//
// `show mpls ldp discovery` names the kind in its Type column: "Link" for
// hellos heard on an interface, "Targeted" for a session set up to an address
// over whatever path the IGP has. Only the first is an adjacency on that link.
func ldpLinkAdjacencies(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// "ipv4 1.152.0.1 Link port_R2 15"
		if len(f) < 4 || f[0] == "AF" {
			continue
		}
		if !strings.EqualFold(f[2], "Link") {
			continue
		}
		res[f[3]] = f[1]
	}
	return res
}

// operationalWith reports whether the line mentioning an address says the
// session is up. Presence alone is not enough: a session in any other state is
// listed too, and treating that as success is how a check passes on a network
// that is not working.
func operationalWith(out, addr string) bool {
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, addr) {
			return strings.Contains(ln, "OPERATIONAL")
		}
	}
	return false
}

func hostIn(top *model.Topology, asn int) *model.Device {
	as, ok := top.ASes[asn]
	if !ok {
		return nil
	}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost {
			return d
		}
	}
	return nil
}

// siteAddr is the address a customer site answers on: the first address that
// is not the loopback, because pinging a loopback proves the control plane
// found the route and says nothing about whether traffic crosses.
func siteAddr(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Name == "lo" || i.Addr4 == "" {
			continue
		}
		return addrOnly(i.Addr4)
	}
	return ""
}

func addrOnly(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i >= 0 {
		return cidr[:i]
	}
	return cidr
}

// directedPair is one ordered probe: from a site, to a site's address.
type directedPair struct{ from, to sitePoint }

// directed returns both orderings of a site pair.
//
// A VPN can carry a customer one way but not back, and a leak can appear in one
// direction only, so probing a single ordering reports either as its opposite.
func directed(a, b sitePoint) [2]directedPair {
	return [2]directedPair{{from: a, to: b}, {from: b, to: a}}
}

// reaches reports whether a device can reach an address, keeping a path that is
// blocked distinct from a probe that never ran.
//
// The distinction decides a mark, and in opposite directions on the two VPN
// questions: a probe that could not execute looks like an unreachable site to
// the reachability check and like a correctly blocked one to the isolation
// check, so the same transport outage would cost marks on the first and award
// them on the second. Going through Probe records the transport failure with
// the machinery tracker, so it surfaces as an un-gradeable question rather than
// either verdict being invented from it.
//
// Three echoes, because a single loss on a shaped link would otherwise read as
// a routing failure and cost a student marks for the network's timing; ping
// exits zero if any one of them is answered.
func (e *Env) reaches(ctx context.Context, deviceID, addr string) (bool, error) {
	res, err := e.Probe(ctx, deviceID, []string{"ping", "-c", "3", "-W", "2", addr})
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// checkVPNLabelSwitched asks how the customer's traffic is carried, not merely
// whether it arrives.
//
// Reachability between two sites of one customer is the exercise's own test,
// and it is satisfiable without doing the exercise: a provider that put every
// customer prefix in the global table and let plain iBGP carry it would pass,
// and so would one that wrote static routes. Neither is a VPN, and the
// distinction is the entire subject of the assignment.
//
// So this reads what the forwarding table actually says. A prefix belonging to
// a remote site must be installed in that customer's own routing table, learned
// by BGP, and resolved through a stack of two labels: the transport label that
// gets the packet across the interior, and the VPN label that tells the far
// edge which customer it belongs to. A static route has no labels; a route in
// the global table is not in the VRF; and a single label is a backbone path
// with no VPN on it.
// vpnNexthop is one path the kernel holds for a VPN prefix, with the label
// stack it would push on a packet taking that path.
type vpnNexthop struct {
	IP            string `json:"ip"`
	FIB           bool   `json:"fib"`
	InterfaceName string `json:"interfaceName"`
	Labels        []int  `json:"labels"`
}

// labelDepth reports how many of a prefix's paths the kernel has installed,
// which of them carry fewer than the two labels a VPN route needs, and the
// thinnest stack among them.
//
// It looks at every installed path rather than the best one. A prefix with
// several equal-cost paths gets a nexthop per path, each with its own transport
// label, and the kernel hashes flows across all of them; the deepest stack
// among them describes the best path, not the route. With LDP missing on one
// interior link the two good paths hid the third, which carried the VPN label
// alone -- and flows hashed onto it arrived at the core router bearing a label
// it had never handed out and were dropped, five of nine source addresses
// losing everything, while this reported the prefix as resolving through a
// transport label and a VPN label. A route is label-switched only if all of it
// is.
//
// Two labels is the right floor even where the two edges are neighbours. LDP
// signals implicit-null for a prefix one hop away, so the ingress pushes only
// the VPN label onto the wire -- but the stack the kernel reports still has the
// implicit-null in it, so the depth is two either way and a correct submission
// is not caught by this.
func labelDepth(nhs []vpnNexthop) (installed int, shallow []string, thinnest int) {
	thinnest = -1
	for _, nh := range nhs {
		if !nh.FIB {
			continue
		}
		installed++
		if thinnest < 0 || len(nh.Labels) < thinnest {
			thinnest = len(nh.Labels)
		}
		if len(nh.Labels) >= 2 {
			continue
		}
		via := nh.IP
		if nh.InterfaceName != "" {
			via = nh.InterfaceName
		}
		if via == "" {
			via = "unnamed path"
		}
		shallow = append(shallow, via)
	}
	if thinnest < 0 {
		thinnest = 0
	}
	sort.Strings(shallow)
	return installed, shallow, thinnest
}

func checkVPNLabelSwitched(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || len(as.VRFs) == 0 {
		return Errored("vpn.label_switched",
			fmt.Errorf("AS %d declares no routing tables, so it carries no VPN customers", env.AS))
	}
	// Which prefixes belong to which customer, and which edges serve them.
	type edge struct {
		router string
		vrf    string
		remote []string // prefixes of the customer's other sites
	}
	var edges []edge
	for _, d := range as.Routers {
		byVRF := map[string]bool{}
		for _, i := range d.Ifaces {
			if i.VRF == "" || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			byVRF[i.VRF] = true
		}
		for vrf := range byVRF {
			// Every site of this customer that is not behind this edge.
			mine := map[int]bool{}
			for _, i := range d.Ifaces {
				if i.VRF == vrf && i.Peer != nil && i.Peer.Device != nil {
					mine[i.Peer.Device.ASN] = true
				}
			}
			var remote []string
			for _, other := range as.Routers {
				if other.Name == d.Name {
					continue
				}
				for _, i := range other.Ifaces {
					if i.VRF != vrf || i.Peer == nil || i.Peer.Device == nil {
						continue
					}
					peer := i.Peer.Device.ASN
					if mine[peer] {
						continue
					}
					if b := blockOf(env.Topology, peer); b != "" {
						remote = append(remote, b)
					}
				}
			}
			sort.Strings(remote)
			if len(remote) > 0 {
				edges = append(edges, edge{d.Name, vrf, remote})
			}
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].router != edges[j].router {
			return edges[i].router < edges[j].router
		}
		return edges[i].vrf < edges[j].vrf
	})
	if len(edges) == 0 {
		return Errored("vpn.label_switched",
			fmt.Errorf("no customer in this lab has a site behind another edge, so there is "+
				"nothing for a VPN to carry"))
	}

	var problems []string
	checked, labelled, paths := 0, 0, 0
	for _, e := range edges {
		for _, prefix := range e.remote {
			checked++
			var doc map[string][]struct {
				Protocol string       `json:"protocol"`
				Selected bool         `json:"selected"`
				Nexthops []vpnNexthop `json:"nexthops"`
			}
			cmd := fmt.Sprintf("show ip route vrf %s %s json", e.vrf, prefix)
			if err := env.VtyshJSON(ctx, e.router, cmd, &doc); err != nil {
				problems = append(problems, fmt.Sprintf(
					"%s: %s is not in %s at all", e.router, prefix, e.vrf))
				continue
			}
			entries, ok := doc[prefix]
			if !ok || len(entries) == 0 {
				problems = append(problems, fmt.Sprintf(
					"%s: %s is not in %s", e.router, prefix, e.vrf))
				continue
			}
			best := entries[0]
			for _, x := range entries {
				if x.Selected {
					best = x
				}
			}
			if best.Protocol != "bgp" {
				problems = append(problems, fmt.Sprintf(
					"%s carries %s in %s as a %s route; a VPN route is learned by BGP",
					e.router, prefix, e.vrf, best.Protocol))
				continue
			}
			// Every path the kernel would use, not the best-labelled one.
			installed, shallow, thinnest := labelDepth(best.Nexthops)
			paths += installed
			switch {
			case installed == 0:
				problems = append(problems, fmt.Sprintf(
					"%s has %s in %s but no path installed for it, so nothing is carrying it",
					e.router, prefix, e.vrf))
			case len(shallow) == 0:
				labelled++
			case len(shallow) < installed:
				carry := "carry"
				if len(shallow) == 1 {
					carry = "carries"
				}
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s over %d equal-cost paths and %d of them (%s) %s the "+
						"VPN label alone; a flow hashed onto one of those arrives at the next "+
						"router carrying a label that router never handed out",
					e.router, prefix, e.vrf, installed, len(shallow),
					strings.Join(shallow, ", "), carry))
			case installed > 1:
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s over %d equal-cost paths and not one of them carries "+
						"a transport label; a VPN route needs two -- a transport label across "+
						"the interior and a VPN label the far edge reads",
					e.router, prefix, e.vrf, installed))
			case thinnest == 1:
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s with one label; a VPN route needs two -- a transport "+
						"label across the interior and a VPN label the far edge reads",
					e.router, prefix, e.vrf))
			default:
				problems = append(problems, fmt.Sprintf(
					"%s reaches %s in %s with no label at all, so it is not being carried "+
						"over the label-switched backbone", e.router, prefix, e.vrf))
			}
		}
	}
	// And the labels have to be carrying something.
	//
	// Everything above reads the forwarding table, which is the only place
	// that can distinguish a two-label VPN path from a static route or a leak
	// into the global table -- and it says nothing about whether a packet gets
	// through. Dropping EtherType 0x8847 on the interior links leaves every
	// label stack installed and every labelled packet discarded, and this
	// awarded full marks for a mechanism that carried nothing. The question is
	// how the customer's traffic is carried; if none of it is, there is
	// nothing to answer it about.
	carried, err := anyCustomerTrafficArrives(ctx, env)
	if err != nil {
		return Errored("vpn.label_switched", err)
	}
	if !carried {
		return Errored("vpn.label_switched", fmt.Errorf(
			"no customer's traffic reaches its other site at all, so how it would have been "+
				"carried cannot be assessed; the label stacks are installed and nothing "+
				"crosses them"))
	}

	sort.Strings(problems)
	if len(problems) == 0 {
		return Pass("vpn.label_switched", Evidence{
			Expected: "each customer's remote sites reached over a two-label path",
			Observed: fmt.Sprintf("%d remote prefix(es) across %d edge/table pair(s) resolve "+
				"through a transport label and a VPN label, on every one of the %d path(s) "+
				"installed for them", labelled, len(edges), paths),
			Command: "show ip route vrf <table> <prefix> json",
		})
	}
	return Partial("vpn.label_switched", ratio(labelled, maxInt(checked, 1)), Evidence{
		Expected: "each customer's remote sites reached over a two-label path",
		Observed: fmt.Sprintf("%d of %d remote prefix(es) are label-switched", labelled, checked),
		Detail:   strings.Join(truncate(problems, 6), "\n"),
		Hint: "the customer's routes must be carried as VPNv4 between the edges and resolved " +
			"through the interior's LDP labels; reachability alone can be achieved without a VPN",
		Command: "show ip route vrf <table> <prefix> json; show bgp ipv4 vpn",
	})
}

// blockOf is the address block an AS was allocated, which is what its sites
// advertise.
func blockOf(top *model.Topology, asn int) string {
	if as, ok := top.ASes[asn]; ok {
		return as.Block
	}
	return ""
}
