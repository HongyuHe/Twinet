package grade

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file registers the checks that grade the intra-domain half of the
// assignment: layer-2 isolation, addressing, OSPF, load balancing and tunnels.

func init() {
	Register(&Check{
		Name:     "l3.addressing_matches_plan",
		Describe: "every router interface carries the address the assignment prescribes",
		Run:      checkAddressing,
	})
	Register(&Check{
		Name:     "ospf.full_adjacency",
		Describe: "every OSPF neighbour has reached the Full state",
		Run:      checkOSPFAdjacency,
	})
	Register(&Check{
		Name:     "ospf.subnets_advertised",
		Describe: "every required subnet, including the service subnets, is in OSPF",
		Run:      checkOSPFSubnets,
	})
	Register(&Check{
		Name:     "ospf.ecmp_paths",
		Describe: "traffic between two routers is load-balanced over exactly the prescribed paths",
		Run:      checkECMP,
	})
	Register(&Check{
		Name:     "l2.vlan_isolation",
		Describe: "hosts reach their own VLAN directly and the other VLAN only through the gateway",
		Run:      checkVLANIsolation,
	})
	Register(&Check{
		Name:     "dataplane.internal_reachability",
		Describe: "every host in the AS can reach every other host",
		Run:      checkInternalReachability,
	})
}

// checkAddressing compares each interface against the expected value recorded
// in the model.
//
// This is only possible because the addressing plan is data: the model knows
// what a correct answer looks like, so the grader does not restate it. In the
// platform this replaces, the plan lived in a bash file, the assignment text,
// the DNS generator and the grader independently, and they drifted.
func checkAddressing(ctx context.Context, env *Env) Result {
	type mismatch struct{ Device, Iface, Want, Got string }
	var bad []mismatch
	var missing []string
	checked := 0

	for _, r := range env.Routers() {
		out, err := env.Probe(ctx, r.ID, []string{"ip", "-o", "-4", "addr", "show"})
		if err != nil {
			return Errored("l3.addressing_matches_plan", err)
		}
		have := parseIPAddrOutput(out.Stdout)

		for _, i := range r.Ifaces {
			// Inter-AS addressing is agreed with a neighbour, not prescribed.
			if i.Role == model.RoleInterAS {
				continue
			}
			if i.Addr4 == "" && i.Subnet == "" {
				continue
			}
			checked++
			got := have[i.Name]
			if len(got) == 0 {
				want := i.Addr4
				if !i.Prescribed {
					want = "an address in " + i.Subnet
				}
				missing = append(missing, fmt.Sprintf("%s:%s (expected %s)", r.Name, i.Name, want))
				continue
			}
			if i.Prescribed {
				// The assignment dictates the exact value.
				if !containsStr(got, i.Addr4) {
					bad = append(bad, mismatch{r.Name, i.Name, i.Addr4, strings.Join(got, ", ")})
				}
				continue
			}
			// The student chose; only membership of the mandated prefix is
			// graded. Demanding the reference answer here would fail a correct
			// student, which is worse than not checking at all.
			if i.Subnet != "" && !anyInSubnet(got, i.Subnet) {
				bad = append(bad, mismatch{r.Name, i.Name, "an address in " + i.Subnet, strings.Join(got, ", ")})
			}
		}
	}

	if len(bad) == 0 && len(missing) == 0 {
		return Pass("l3.addressing_matches_plan", Evidence{
			Detail: fmt.Sprintf("all %d required addresses are configured", checked)})
	}
	var detail strings.Builder
	sort.Strings(missing)
	for _, m := range missing {
		fmt.Fprintf(&detail, "not configured: %s\n", m)
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i].Device+bad[i].Iface < bad[j].Device+bad[j].Iface })
	for _, m := range bad {
		fmt.Fprintf(&detail, "%s:%s has %s, expected %s\n", m.Device, m.Iface, m.Got, m.Want)
	}
	wrong := len(bad) + len(missing)
	return Partial("l3.addressing_matches_plan", ratio(checked-wrong, checked), Evidence{
		Expected: fmt.Sprintf("%d addresses", checked),
		Observed: fmt.Sprintf("%d correct", checked-wrong),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "the required addresses are in the assignment's L3 topology figure",
		Command:  "ip -o -4 addr show",
	})
}

// anyInSubnet reports whether any of the configured addresses falls inside the
// mandated prefix.
func anyInSubnet(addrs []string, subnet string) bool {
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return true // an unparseable expectation must not cost a student marks
	}
	for _, a := range addrs {
		pa, err := netip.ParsePrefix(a)
		if err != nil {
			if ip, err2 := netip.ParseAddr(a); err2 == nil && p.Contains(ip) {
				return true
			}
			continue
		}
		if p.Contains(pa.Addr()) {
			return true
		}
	}
	return false
}

// ospfNeighborJSON is the shape of `show ip ospf neighbor json`.
type ospfNeighborJSON struct {
	Neighbors map[string][]struct {
		NbrState  string `json:"nbrState"`
		IfaceName string `json:"ifaceName"`
		Converged string `json:"converged"`
	} `json:"neighbors"`
}

func checkOSPFAdjacency(ctx context.Context, env *Env) Result {
	total, full := 0, 0
	var stuck []string
	for _, r := range env.Routers() {
		var out ospfNeighborJSON
		if err := env.VtyshJSON(ctx, r.Name, "show ip ospf neighbor json", &out); err != nil {
			// A router with OSPF entirely unconfigured is a legitimate student
			// failure, not a grader failure, so it counts as zero adjacencies.
			continue
		}
		for id, ns := range out.Neighbors {
			for _, n := range ns {
				total++
				if strings.HasPrefix(n.NbrState, "Full") {
					full++
				} else {
					stuck = append(stuck, fmt.Sprintf("%s -> %s on %s is %s",
						r.Name, id, n.IfaceName, n.NbrState))
				}
			}
		}
	}

	// The expected number of adjacencies is twice the number of intra-AS links,
	// which the model knows exactly.
	want := 0
	for _, l := range env.Topology.Links {
		if l.InterAS || l.A.Device.ASN != env.AS {
			continue
		}
		if l.A.Device.IsRouter() && l.B.Device.IsRouter() {
			want += 2
		}
	}

	if want > 0 && full == want && len(stuck) == 0 {
		return Pass("ospf.full_adjacency", Evidence{
			Observed: fmt.Sprintf("%d/%d adjacencies Full", full, want)})
	}
	sort.Strings(stuck)
	return Partial("ospf.full_adjacency", ratio(full, want), Evidence{
		Expected: fmt.Sprintf("%d adjacencies in state Full", want),
		Observed: fmt.Sprintf("%d Full of %d seen", full, total),
		Detail:   strings.Join(stuck, "\n"),
		Hint:     "check that OSPF is enabled on every inter-router subnet, on both ends",
		Command:  "show ip ospf neighbor json",
	})
}

// ospfRouteJSON is the shape of `show ip route ospf json`.
type ospfRouteJSON map[string][]struct {
	Protocol  string `json:"protocol"`
	Prefix    string `json:"prefix"`
	Selected  bool   `json:"selected"`
	Installed bool   `json:"installed"`
	Nexthops  []struct {
		InterfaceName string `json:"interfaceName"`
		IP            string `json:"ip"`
	} `json:"nexthops"`
}

func checkOSPFSubnets(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("ospf.subnets_advertised", fmt.Errorf("AS %d has no routers", env.AS))
	}
	// Every subnet inside the AS that a correct configuration must carry.
	want := map[string]string{} // prefix -> why it matters
	for _, l := range env.Topology.Links {
		if l.Subnet == "" || l.InterAS {
			continue
		}
		if l.A.Device.ASN != env.AS && l.B.Device.ASN != env.AS {
			continue
		}
		why := "an internal subnet"
		if l.Kind == model.LinkService {
			why = "a service subnet the assignment requires in OSPF"
		}
		want[l.Subnet] = why
	}
	for _, r := range routers {
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			want[hostRoute(lo.Addr4)] = "a router loopback"
		}
	}

	// A prefix counts only where some router learned it *from* OSPF.
	//
	// This used to accept "ospf or connected" from a single vantage router,
	// which meant every subnet that router was attached to was credited as
	// advertised whether or not the student had put it in OSPF at all. Choosing
	// a vantage far from most subnets narrowed the hole without closing it: its
	// own links still counted, and so did every service subnet reachable
	// directly. Asking every router and requiring at least one to hold the
	// prefix as an OSPF route is what actually distinguishes "flooded through
	// the area" from "plugged into this box".
	seen := map[string]bool{}
	read := 0
	var unreadable []string
	for _, r := range routers {
		var routes ospfRouteJSON
		if err := env.VtyshJSON(ctx, r.Name, "show ip route json", &routes); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		read++
		for prefix, entries := range routes {
			for _, e := range entries {
				if e.Protocol == "ospf" {
					seen[prefix] = true
				}
			}
		}
	}
	if read == 0 {
		return Errored("ospf.subnets_advertised", fmt.Errorf(
			"no router's routing table could be read, so nothing could be assessed: %s",
			strings.Join(truncate(unreadable, 3), "; ")))
	}

	var absent []string
	for p, why := range want {
		if !seen[p] {
			absent = append(absent, fmt.Sprintf("%s (%s)", p, why))
		}
	}
	sort.Strings(absent)

	if len(absent) == 0 {
		return Pass("ospf.subnets_advertised", Evidence{
			Observed: fmt.Sprintf("all %d internal subnets are carried by OSPF, seen across %d routers",
				len(want), read)})
	}
	return Partial("ospf.subnets_advertised", ratio(len(want)-len(absent), len(want)), Evidence{
		Expected: fmt.Sprintf("all %d internal subnets carried by OSPF", len(want)),
		Observed: fmt.Sprintf("%d not learned through OSPF on any router", len(absent)),
		Detail:   strings.Join(absent, "\n"),
		Hint:     "the DNS and measurement subnets must be advertised in OSPF too",
		Command:  "show ip route json",
	})
}

// checkECMP verifies equal-cost multipath between two routers.
//
// It walks the whole prescribed path rather than only inspecting the first hop.
// That matters because two prescribed paths often share their first hop and
// diverge later: ATL-PHY-BOS and ATL-PHY-NYC-BOS both leave ATL via PHY, so a
// first-hop-only check cannot tell whether both exist, and would report two
// paths where the assignment asks for three.
//
// It asserts on the forwarding tables rather than by sampling traceroutes. The
// tables state exactly which next hops are installed, whereas repeated
// traceroutes only sample the hash: they can miss a live path entirely, which
// the legacy platform's own bug list records as an unresolved complaint.
func checkECMP(ctx context.Context, env *Env) Result {
	from := env.ArgString("a", "ATL")
	to := env.ArgString("b", "BOS")
	wantPaths := env.ArgPaths("paths")
	exclusive := env.ArgBool("exclusive", true)

	if len(wantPaths) == 0 {
		return Errored("ospf.ecmp_paths", fmt.Errorf("the rubric supplied no paths to check"))
	}
	dst, ok := env.Device(to)
	if !ok {
		return Errored("ospf.ecmp_paths", fmt.Errorf("no router %q in AS %d", to, env.AS))
	}
	lo, ok := dst.IfaceByName("lo")
	if !ok || lo.Addr4 == "" {
		return Errored("ospf.ecmp_paths", fmt.Errorf("router %s has no loopback address in the plan", to))
	}
	target := hostRoute(lo.Addr4)

	// Cache each router's next hops toward the destination.
	nextHops := map[string]map[string]bool{}
	other := map[string]bool{}
	fetch := func(router string) (map[string]bool, error) {
		if v, ok := nextHops[router]; ok {
			return v, nil
		}
		var routes ospfRouteJSON
		if err := env.VtyshJSON(ctx, router, "show ip route json", &routes); err != nil {
			return nil, err
		}
		set := map[string]bool{}
		for _, e := range routes[target] {
			if !e.Selected && !e.Installed {
				continue
			}
			// The protocol is what the question is about.
			//
			// It was decoded and then ignored, so three static routes over the
			// prescribed interfaces earned full marks for a question that asks
			// for equal-cost paths produced by OSPF costs. Hand-installed
			// routes do not react to a link failing, which is the entire point
			// of the exercise, and the two were indistinguishable in the mark.
			if e.Protocol != "" && e.Protocol != "ospf" {
				other[e.Protocol] = true
				continue
			}
			for _, nh := range e.Nexthops {
				if nh.InterfaceName != "" {
					set[nh.InterfaceName] = true
				}
			}
		}
		nextHops[router] = set
		return set, nil
	}

	if hops, err := fetch(from); err != nil {
		return Errored("ospf.ecmp_paths", err)
	} else if len(hops) == 0 {
		observed := "no route at all"
		if len(other) > 0 {
			observed = fmt.Sprintf("a route learned by %s rather than OSPF",
				strings.Join(sortedKeysOfBool(other), ", "))
		}
		return Fail("ospf.ecmp_paths", Evidence{
			Expected: fmt.Sprintf("%d equal-cost paths from %s to %s, learned by OSPF",
				len(wantPaths), from, to),
			Observed: observed,
			Detail:   fmt.Sprintf("%s has no route to %s (%s)", from, to, target),
			Hint: "the paths have to come from OSPF costs; a hand-installed route does " +
				"not move when a link fails, which is what this question is about",
			Command: "show ip route json",
		})
	}

	// Every hop of every prescribed path must be installed.
	var detail strings.Builder
	present := 0
	for _, path := range wantPaths {
		ok := true
		for i := 0; i+1 < len(path); i++ {
			hops, err := fetch(path[i])
			if err != nil {
				ok = false
				fmt.Fprintf(&detail, "could not read the routing table of %s: %v\n", path[i], err)
				break
			}
			want := "port_" + path[i+1]
			if path[i+1] == to && len(hops) > 0 && !hops[want] {
				// The final hop may be reached over any interface toward the
				// destination; only require the named one when it exists.
				if !hops[want] {
					ok = false
					fmt.Fprintf(&detail, "%s does not forward toward %s (no next hop on %s)\n",
						path[i], path[i+1], want)
					break
				}
			}
			if !hops[want] {
				ok = false
				fmt.Fprintf(&detail, "%s does not forward toward %s (no next hop on %s)\n",
					path[i], path[i+1], want)
				break
			}
		}
		if ok {
			present++
		} else {
			fmt.Fprintf(&detail, "path not installed: %s\n", strings.Join(path, "-"))
		}
	}

	// Exclusivity: at *every* router the prescribed paths pass through, the
	// only next hops toward the destination are the ones those paths use.
	//
	// This used to look at the source alone, so a fourth path that diverges
	// further along -- at PHY, say -- was invisible: the source's next hops
	// were exactly right, and traffic was still taking a route the assignment
	// does not prescribe. The question is which paths carry traffic, and that
	// is decided at each hop, not at the first.
	var extra []string
	if exclusive {
		allowed := map[string][]string{}
		for _, p := range wantPaths {
			for i := 0; i+1 < len(p); i++ {
				allowed[p[i]] = append(allowed[p[i]], "port_"+p[i+1])
			}
		}
		for _, router := range sortedKeysOfStrings(allowed) {
			hops, err := fetch(router)
			if err != nil {
				fmt.Fprintf(&detail, "%s could not be read, so the paths through it could "+
					"not be checked (%v)\n", router, err)
				extra = append(extra, router+": unreadable")
				continue
			}
			ok := map[string]bool{}
			for _, h := range allowed[router] {
				ok[h] = true
			}
			for h := range hops {
				if !ok[h] {
					extra = append(extra, router+" via "+h)
					fmt.Fprintf(&detail, "%s also forwards toward %s over %s, which no "+
						"prescribed path uses\n", router, to, h)
				}
			}
		}
		sort.Strings(extra)
	}

	got := make([]string, 0)
	for h := range nextHops[from] {
		got = append(got, h)
	}
	sort.Strings(got)

	if present == len(wantPaths) && len(extra) == 0 {
		return Pass("ospf.ecmp_paths", Evidence{
			Observed: fmt.Sprintf("all %d prescribed paths installed; %s balances over %s",
				len(wantPaths), from, strings.Join(got, ", "))})
	}
	score := ratio(present, len(wantPaths))
	if len(extra) > 0 {
		// Carrying traffic on a path that should not be used is a real error,
		// not a rounding difference.
		score *= 0.5
	}
	return Partial("ospf.ecmp_paths", score, Evidence{
		Expected: fmt.Sprintf("%d equal-cost paths, and no others", len(wantPaths)),
		Observed: fmt.Sprintf("%d installed; %s balances over %s", present, from, strings.Join(got, ", ")),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "the cost of a path is the sum of its links; make exactly the intended paths equal",
		Command:  "show ip route json",
	})
}

// checkVLANIsolation verifies that hosts in the same VLAN reach each other
// directly while hosts in different VLANs are forced through the gateway.
func checkVLANIsolation(ctx context.Context, env *Env) Result {
	domain := env.ArgString("domain", "")
	hosts := map[int][]*model.Device{} // vlan -> hosts
	var gateway *model.Device

	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("l2.vlan_isolation", fmt.Errorf("AS %d not in the grading lab", env.AS))
	}
	for _, d := range as.Devices {
		if d.Kind != model.KindHost || d.L2Domain == "" {
			continue
		}
		if domain != "" && d.L2Domain != domain {
			continue
		}
		for _, i := range d.Ifaces {
			if i.VLAN > 0 {
				hosts[i.VLAN] = append(hosts[i.VLAN], d)
			}
		}
	}
	for _, r := range as.Routers {
		if r.L2Gateway != "" && (domain == "" || r.L2Gateway == domain) {
			gateway = r
		}
	}
	if len(hosts) < 2 || gateway == nil {
		return Errored("l2.vlan_isolation",
			fmt.Errorf("the lab has %d VLANs and gateway=%v in domain %q", len(hosts), gateway != nil, domain))
	}

	vlans := make([]int, 0, len(hosts))
	for v := range hosts {
		vlans = append(vlans, v)
	}
	sort.Ints(vlans)

	// Every pair, not one per VLAN and one across.
	//
	// This tested hosts[0] against hosts[1] within each VLAN, and one ordered
	// pair across them. In this topology that meant the cross-VLAN question was
	// asked only of two hosts on the same switch, so a trunk that mis-tags the
	// other switch's ports -- which is the mistake the question exists to catch
	// -- was never looked at. Four hosts is twelve ordered pairs, run at once.
	type outcome struct {
		ok     bool
		detail string
	}
	var (
		mu      sync.Mutex
		results []outcome
		wg      sync.WaitGroup
	)
	sem := make(chan struct{}, 8)
	record := func(ok bool, format string, args ...any) {
		mu.Lock()
		results = append(results, outcome{ok, fmt.Sprintf(format, args...)})
		mu.Unlock()
	}

	// Same VLAN: reachable, and directly.
	for _, v := range vlans {
		hs := hosts[v]
		for i := 0; i < len(hs); i++ {
			for j := i + 1; j < len(hs); j++ {
				wg.Add(1)
				go func(v int, src, dst *model.Device) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					hops, err := traceHops(ctx, env, src, dst)
					switch {
					case err != nil:
						record(false, "VLAN %d: %s cannot reach %s (%v)", v, src.Name, dst.Name, err)
					case hops == 1:
						record(true, "")
					default:
						record(false, "VLAN %d: %s %s; hosts in one VLAN must be adjacent",
							v, src.Name, describeReach(dst.Name, hops))
					}
				}(v, hs[i], hs[j])
			}
		}
	}

	// Across VLANs: reachable, but through the gateway, in both directions and
	// for every pair.
	for a := range vlans {
		for b := range vlans {
			if a == b {
				continue
			}
			for _, src := range hosts[vlans[a]] {
				for _, dst := range hosts[vlans[b]] {
					wg.Add(1)
					go func(src, dst *model.Device) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()
						hops, first, err := traceFirstHop(ctx, env, src, dst)
						switch {
						case err != nil:
							record(false, "%s cannot reach %s across VLANs (%v)",
								src.Name, dst.Name, err)
						case hops < 2:
							record(false, "%s %s; different VLANs must be separated at layer 2",
								src.Name, describeReach(dst.Name, hops))
						case first == "":
							// A first hop that did not answer is not a first
							// hop that was the gateway. This fell through to
							// success, so a path through a silent wrong router
							// scored the point.
							record(false, "%s reaches %s across VLANs, but nothing answered "+
								"at the first hop, so it cannot be shown to have gone "+
								"through %s", src.Name, dst.Name, gateway.Name)
						case !deviceHoldsAddr(ctx, env, gateway, first):
							record(false, "%s reaches %s across VLANs, but its first hop is "+
								"%s, which is not %s; traffic between VLANs must be routed "+
								"by the gateway", src.Name, dst.Name, first, gateway.Name)
						default:
							record(true, "")
						}
					}(src, dst)
				}
			}
		}
	}
	wg.Wait()

	var problems []string
	passed, total := 0, len(results)
	for _, r := range results {
		if r.ok {
			passed++
			continue
		}
		problems = append(problems, r.detail)
	}
	sort.Strings(problems)
	var detail strings.Builder
	detail.WriteString(strings.Join(truncate(problems, 8), "\n"))

	if total > 0 && passed == total {
		return Pass("l2.vlan_isolation", Evidence{
			Observed: fmt.Sprintf("%d VLANs isolated correctly, routed via %s", len(vlans), gateway.Name)})
	}
	return Partial("l2.vlan_isolation", ratio(passed, total), Evidence{
		Expected: "same VLAN adjacent, different VLANs via the gateway",
		Observed: fmt.Sprintf("%d of %d relationships correct", passed, total),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "use access ports with a VLAN tag for hosts and a trunk toward the gateway",
	})
}

func checkInternalReachability(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("dataplane.internal_reachability", fmt.Errorf("AS %d not in the lab", env.AS))
	}
	var hosts []*model.Device
	for _, d := range as.Devices {
		if d.Kind == model.KindHost && d.L2Domain == "" {
			hosts = append(hosts, d)
		}
	}
	if len(hosts) < 2 {
		return Errored("dataplane.internal_reachability", fmt.Errorf("AS %d has %d L3 hosts", env.AS, len(hosts)))
	}

	// Every ordered pair, run concurrently.
	//
	// This was a hub-and-spoke from one host, on the reasoning that it
	// exercises every path through the backbone and is linear. It does not:
	// reachability is not symmetric and it is not transitive. A blackhole route
	// on one host for another was measured to leave the hub's seven probes all
	// succeeding while the pair it broke could not reach each other, and the
	// question kept its full mark. Eight hosts is 56 probes; they take about as
	// long as one, because they run at once.
	addrOf := map[string]string{}
	for _, d := range hosts {
		if a := firstAddr(d); a != "" {
			addrOf[d.ID] = a
		}
	}
	type probe struct {
		from, to *model.Device
	}
	var pairs []probe
	for _, a := range hosts {
		for _, b := range hosts {
			if a.ID == b.ID || addrOf[b.ID] == "" {
				continue
			}
			pairs = append(pairs, probe{a, b})
		}
	}
	if len(pairs) == 0 {
		return Errored("dataplane.internal_reachability",
			fmt.Errorf("AS %d has no addressed host to probe", env.AS))
	}

	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, 16)
	for _, p := range pairs {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addr := addrOf[p.to.ID]
			res, err := env.Probe(ctx, p.from.ID,
				[]string{"ping", "-c", "2", "-W", "2", "-i", "0.2", addr})
			if err != nil || res.ExitCode != 0 {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("%s cannot reach %s (%s)",
					p.from.Name, p.to.Name, addr))
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	tried := len(pairs)
	if len(failed) == 0 {
		return Pass("dataplane.internal_reachability", Evidence{
			Observed: fmt.Sprintf("all %d ordered host pairs reach each other", tried)})
	}
	sort.Strings(failed)
	return Partial("dataplane.internal_reachability", ratio(tried-len(failed), tried), Evidence{
		Expected: fmt.Sprintf("%d reachable ordered pairs", tried),
		Observed: fmt.Sprintf("%d unreachable", len(failed)),
		Detail:   strings.Join(truncate(failed, 8), "\n"),
		Hint:     "every internal subnet, including the router-host links, must be advertised in OSPF",
		Command:  "ping",
	})
}

// traceHops counts the hops between two hosts.
func traceHops(ctx context.Context, env *Env, src, dst *model.Device) (int, error) {
	addr := deviceAddr4(ctx, env, dst)
	if addr == "" {
		return 0, fmt.Errorf("%s has no address configured", dst.Name)
	}
	res, err := env.Probe(ctx, src.ID, []string{"traceroute", "-n", "-q", "1", "-w", "2", "-m", "8", addr})
	if err != nil {
		return 0, err
	}
	return countTracerouteHops(res.Stdout, addr), nil
}

// traceFirstHop reports how many hops away a destination is and the address
// that answered first, which is what says *through what* the traffic went.
func traceFirstHop(ctx context.Context, env *Env, src, dst *model.Device) (int, string, error) {
	addr := deviceAddr4(ctx, env, dst)
	if addr == "" {
		return 0, "", fmt.Errorf("%s has no address configured", dst.Name)
	}
	res, err := env.Probe(ctx, src.ID, []string{"traceroute", "-n", "-q", "1", "-w", "2", "-m", "8", addr})
	if err != nil {
		return 0, "", err
	}
	return countTracerouteHops(res.Stdout, addr), firstTracerouteHop(res.Stdout), nil
}

// firstTracerouteHop returns the address that answered at hop 1, or "" if
// nothing did.
func firstTracerouteHop(out string) string {
	for _, line := range strings.Split(out, "\n") {
		m := hopRe.FindStringSubmatch(line)
		if m == nil || m[1] != "1" {
			continue
		}
		if m[2] == "*" {
			return ""
		}
		return m[2]
	}
	return ""
}

// deviceAddr4 returns the address a device actually has, falling back to the
// one the manifest planned.
//
// The assignment lets a group choose their own datacentre addressing, and this
// check pinged and traced towards the planned address: a group that used
// another one was reported unreachable inside their own network, for an answer
// the assignment permits.
func deviceAddr4(ctx context.Context, env *Env, d *model.Device) string {
	res, err := env.Exec(ctx, d.ID, []string{"sh", "-c",
		"ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}'"})
	if err == nil && res.ExitCode == 0 {
		for _, f := range strings.Fields(res.Stdout) {
			if p, err := netip.ParsePrefix(f); err == nil && p.Addr().Is4() {
				return p.Addr().String()
			}
		}
	}
	return firstAddr(d)
}

// deviceHoldsAddr reports whether a device actually holds an address.
func deviceHoldsAddr(ctx context.Context, env *Env, d *model.Device, addr string) bool {
	if d == nil || addr == "" {
		return false
	}
	res, err := env.Exec(ctx, d.ID, []string{"sh", "-c",
		"ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}'"})
	if err == nil && res.ExitCode == 0 {
		for _, f := range strings.Fields(res.Stdout) {
			if p, perr := netip.ParsePrefix(f); perr == nil && p.Addr().String() == addr {
				return true
			}
		}
		// The device answered and does not hold it. The plan is not consulted:
		// this is about where the traffic actually went.
		return false
	}
	return deviceHasAddr(d, addr)
}

// deviceHasAddr reports whether an address belongs to a device.
func deviceHasAddr(d *model.Device, addr string) bool {
	if d == nil {
		return false
	}
	for _, i := range d.Ifaces {
		if i.Addr4 != "" && ipOnly(i.Addr4) == addr {
			return true
		}
		if i.Addr6 != "" && ipOnly(i.Addr6) == addr {
			return true
		}
	}
	return false
}

// describeReach turns a hop count into something that is true.
//
// Zero means the destination never replied, and calling that "0 hops" reads as
// "directly adjacent" -- the exact opposite of what was observed. A student
// told their isolated hosts are adjacent will look for a VLAN misconfiguration
// that is not there.
func describeReach(dst string, hops int) string {
	if hops <= 0 {
		return fmt.Sprintf("cannot reach %s at all", dst)
	}
	if hops == 1 {
		return fmt.Sprintf("reaches %s directly, in 1 hop", dst)
	}
	return fmt.Sprintf("reaches %s in %d hops", dst, hops)
}

var hopRe = regexp.MustCompile(`^\s*(\d+)\s+(\S+)`)

// countTracerouteHops returns the hop number at which the destination replied,
// or zero if it never did.
//
// Callers must treat zero as "no reply", not as "zero hops away". Reporting it
// as a hop count produces a message that says the opposite of what happened --
// two hosts that cannot reach each other at all are described as directly
// adjacent -- and sends whoever reads it looking for the wrong fault.
func countTracerouteHops(out, dst string) int {
	for _, line := range strings.Split(out, "\n") {
		m := hopRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[2] == dst {
			n, _ := strconv.Atoi(m[1])
			return n
		}
	}
	return 0
}

// parseIPAddrOutput turns `ip -o -4 addr show` into interface -> addresses.
func parseIPAddrOutput(out string) map[string][]string {
	res := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":")
		for i := 2; i < len(fields)-1; i++ {
			if fields[i] == "inet" || fields[i] == "inet6" {
				res[iface] = append(res[iface], fields[i+1])
			}
		}
	}
	return res
}

// hostRoute converts an interface address into the /32 the routing table uses
// for a loopback.
func hostRoute(cidr string) string {
	addr := cidr
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		addr = cidr[:i]
	}
	return addr + "/32"
}

func firstAddr(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Addr4 != "" {
			if j := strings.IndexByte(i.Addr4, '/'); j > 0 {
				return i.Addr4[:j]
			}
			return i.Addr4
		}
	}
	return ""
}

func containsStr(hay []string, s string) bool {
	for _, h := range hay {
		if h == s {
			return true
		}
	}
	return false
}

func ratio(got, want int) float64 {
	if want <= 0 {
		return 0
	}
	if got < 0 {
		got = 0
	}
	return float64(got) / float64(want)
}

// sortedKeysOfStrings returns a map's keys in order, so a report reads the same
// way twice.
func sortedKeysOfStrings(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeysOfBool returns a set's members in order.
func sortedKeysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
