package grade

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/HongyuHe/twinet/internal/model"
)

type nextHopUse struct{ router, prefix, nh string }

func init() {
	Register(&Check{
		Name:     "bgp.next_hop_self",
		Describe: "externally learned routes carry a next hop the whole AS can reach",
		Run:      checkNextHopSelf,
	})
}

// checkNextHopSelf verifies that a route learned from outside the AS is usable
// by every router inside it.
//
// This is the classic iBGP trap and the assignment names it. A border router
// re-advertises an eBGP route to its internal peers with the next hop it
// learned -- an address on the external link, which no interior router has a
// route to unless somebody put one there. The session comes up, the route
// appears in every table, and every packet is dropped. `show ip bgp summary` is
// perfectly happy; the marks for reachability are lost somewhere else entirely.
//
// The documentation has listed this check since the beginning. It was never
// implemented, so the question it belongs to awarded full credit for sessions
// being established, which is the one part of the exercise that is easy.
//
// It is checked as a fact about the tables, not as the presence of the words
// `next-hop-self`: route reflectors, a policy that sets the next hop, or
// carrying the external link's subnet in the interior all solve it correctly
// and none of them say those words.
func checkNextHopSelf(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("bgp.next_hop_self", fmt.Errorf("AS %d has no routers", env.AS))
	}

	type bad struct{ router, prefix, nh, why string }
	var unusable []bad
	var unread []string
	checked := 0
	var uses []nextHopUse
	// Which external destinations each router holds, so a router that is
	// missing some of what the rest of the AS has can be named.
	holds := map[string]map[string]bool{}
	readable := 0

	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		readable++
		holds[r.Name] = map[string]bool{}
		// The interior routing table is what decides whether a next hop is
		// usable. Asking for the route to the next hop itself is exactly the
		// lookup the forwarding plane does.
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				// Every external destination this router has, however it
				// arrived: the union across the AS is what each of them ought
				// to hold.
				if strings.TrimSpace(e.Path) != "" {
					holds[r.Name][prefix] = true
				}
				// Only routes the router learned from another router of this
				// AS can have this fault: a route learned directly over the
				// external session has its next hop on a connected subnet.
				if e.PathFrom != "internal" {
					continue
				}
				for _, nh := range e.Nexthops {
					if nh.IP == "" || nh.IP == "0.0.0.0" {
						continue
					}
					checked++
					uses = append(uses, nextHopUse{router: r.Name, prefix: prefix, nh: nh.IP})
				}
			}
		}
	}

	// A reference table contains many prefixes sharing a handful of next
	// hops. Asking the kernel once per path made this check serially issue
	// hundreds of route lookups and regularly exhaust its two-minute budget.
	// One agent-side shell batch per router asks every distinct next hop while
	// retaining the kernel's actual forwarding decision for each.
	resolved, resolveErrs := resolveNextHopsBatched(ctx, env, uses)
	for _, use := range uses {
		if err := resolveErrs[use.router]; err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", use.router, err))
			continue
		}
		result, ok := resolved[use.router][use.nh]
		if !ok {
			unread = append(unread, fmt.Sprintf("%s: no kernel answer for next hop %s", use.router, use.nh))
			continue
		}
		if !result.ok {
			unusable = append(unusable, bad{use.router, use.prefix, use.nh, result.why})
		}
	}

	if len(unread) > 0 && checked == 0 {
		sort.Strings(unread)
		return Errored("bgp.next_hop_self",
			fmt.Errorf("no router's table could be read: %s", strings.Join(unread, "; ")))
	}

	if checked == 0 {
		return Fail("bgp.next_hop_self", Evidence{
			Expected: "externally learned routes carried across the AS by iBGP",
			Observed: "no router holds a route learned from another router of this AS",
			Hint: "the border routers have to re-advertise what they learn outside " +
				"to the rest of the AS",
			Command: "show ip bgp json",
		})
	}
	// A router with none of it.
	//
	// This counted usable next hops across the whole AS and passed when none
	// were unusable, so a router that had lost *every* externally learned
	// route contributed zero to both totals and was indistinguishable from a
	// router with nothing to say. Blackholing one border router's loopback
	// does exactly that: the other routers' next hops still resolve, this one
	// holds no external route at all, and the site behind it cannot reach the
	// internet. The question is whether the AS carries its external routes to
	// its routers, and a router that receives none of them is the answer being
	// no.
	// What the AS as a whole knows, and what each router has of it.
	//
	// This counted usable next hops across the whole AS and passed when none
	// were unusable, so a router that had lost some or all of its externally
	// learned routes contributed nothing to either total and vanished into
	// them. Blackholing one border router's loopback does exactly that: the
	// other routers still resolve their next hops, this one silently loses
	// every destination that was reached through the blackholed router, and
	// the site behind it cannot reach those networks at all. The question is
	// whether the AS carries its external routes to its routers, and a router
	// missing what its neighbours have is that question answered no.
	union := map[string]bool{}
	for _, seen := range holds {
		for p := range seen {
			union[p] = true
		}
	}
	var short []string
	if len(union) > 0 {
		for _, r := range routers {
			seen, ok := holds[r.Name]
			if !ok {
				continue
			}
			var missing []string
			for p := range union {
				if !seen[p] {
					missing = append(missing, p)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				short = append(short, fmt.Sprintf("%s is missing %d of the %d destination(s) "+
					"the rest of the AS holds (%s)", r.Name, len(missing), len(union),
					strings.Join(truncate(missing, 4), ", ")))
			}
		}
	}
	if len(short) > 0 {
		sort.Strings(short)
		return Partial("bgp.next_hop_self", ratio(readable-len(short), maxInt(readable, 1)), Evidence{
			Expected: "every router holding every destination the AS has learned, over a next " +
				"hop it can forward to",
			Observed: fmt.Sprintf("%d of %d router(s) hold less than the AS knows",
				len(short), readable),
			Detail: strings.Join(truncate(short, 6), "\n"),
			Hint: "a router whose iBGP-learned route has become unusable -- an unreachable or " +
				"discarded next hop, or a session that is down -- drops every packet its " +
				"hosts send to that destination, while the rest of the AS is unaffected",
			Command: "show ip bgp json; show ip route <next-hop> json",
		})
	}
	// And then a packet, from each router to the outside.
	//
	// Everything above is a table lookup, and a table is a claim about what a
	// router would do. A policy rule sending one destination to another table
	// with a discard in it leaves every next hop resolved, every route held,
	// and every packet for that destination dropped -- measured, and worth
	// nothing at all before this. The point of carrying external routes is
	// that traffic reaches the networks they name.
	if dark, err := unreachedOutside(ctx, env, routers); err != nil {
		return Errored("bgp.next_hop_self", err)
	} else if len(dark) > 0 {
		return Partial("bgp.next_hop_self", ratio(maxInt(readable-len(dark), 0), maxInt(readable, 1)),
			Evidence{
				Expected: "every router able to send a packet to the networks it has learned",
				Observed: fmt.Sprintf("%d of %d router(s) hold the routes and drop the traffic",
					len(dark), readable),
				Detail: strings.Join(truncate(dark, 6), "\n"),
				Hint: "a route in the table is not a packet leaving the machine; check for " +
					"policy rules, alternate tables and firewall rules on the routers",
				Command: "ping; ip route get",
			})
	}

	if len(unusable) == 0 {
		return Pass("bgp.next_hop_self", Evidence{
			Observed: fmt.Sprintf("all %d internally carried next hop(s) resolve, and every "+
				"router reaches the networks it has learned", checked),
			Command: "show ip bgp json; show ip route <next-hop> json; ping",
		})
	}

	sort.Slice(unusable, func(i, j int) bool {
		if unusable[i].router != unusable[j].router {
			return unusable[i].router < unusable[j].router
		}
		return unusable[i].prefix < unusable[j].prefix
	})
	detail := make([]string, 0, len(unusable))
	for _, b := range unusable {
		detail = append(detail, fmt.Sprintf("%s: %s via %s, and %s has %s",
			b.router, b.prefix, b.nh, b.router, b.why))
	}
	return Fail("bgp.next_hop_self", Evidence{
		Expected: "every next hop carried inside the AS is reachable from the router holding it, " +
			"over a route that forwards",
		Observed: fmt.Sprintf("%d of %d internally carried route(s) point at an address "+
			"their own router cannot reach", len(unusable), checked),
		Detail: strings.Join(truncate(detail, 6), "\n"),
		Hint: "a border router re-advertising an external route keeps the external " +
			"next hop unless told otherwise; the session comes up, the route appears " +
			"everywhere, and the traffic is dropped",
		Command: "show ip bgp json; show ip route <next-hop> json",
	})
}

type nextHopResolution struct {
	ok  bool
	why string
}

// resolveNextHopsBatched asks each router's kernel about every distinct BGP
// next hop in one agent-side execution. It deliberately uses ip route get,
// not a vendor RIB: policy rules and the FIB decide whether packets move.
func resolveNextHopsBatched(ctx context.Context, env *Env, uses []nextHopUse) (
	map[string]map[string]nextHopResolution, map[string]error,
) {
	needs := map[string]map[string]bool{}
	for _, use := range uses {
		if needs[use.router] == nil {
			needs[use.router] = map[string]bool{}
		}
		needs[use.router][use.nh] = true
	}
	out := map[string]map[string]nextHopResolution{}
	errs := map[string]error{}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for router, set := range needs {
		router, set := router, set
		wg.Add(1)
		go func() {
			defer wg.Done()
			device, ok := env.Device(router)
			if !ok {
				mu.Lock()
				errs[router] = fmt.Errorf("router is not in the topology")
				mu.Unlock()
				return
			}
			addrs := make([]string, 0, len(set))
			results := map[string]nextHopResolution{}
			for addr := range set {
				if _, err := netip.ParseAddr(addr); err != nil {
					results[addr] = nextHopResolution{why: "an invalid next-hop address"}
					continue
				}
				addrs = append(addrs, addr)
			}
			sort.Strings(addrs)
			got, err := env.kernelForwardsMany(ctx, device.ID, addrs)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[router] = err
				return
			}
			for addr, result := range got {
				results[addr] = result
			}
			out[router] = results
		}()
	}
	wg.Wait()
	return out, errs
}

// unreachedOutside names the routers that hold external routes and cannot send
// a packet along them.
//
// Every router is tried against a host in every other AS it has a route for.
// The destinations belong to other systems, so nothing the submission does
// makes them answer, and a router that has the route and drops the traffic --
// a policy rule, an alternate table, a firewall -- is the difference between a
// routing table and a network.
func unreachedOutside(ctx context.Context, env *Env, routers []*model.Device) ([]string, error) {
	type target struct {
		asn    int
		addr   string
		device *model.Device
	}
	var targets []target
	for asn, as := range env.Topology.ASes {
		if asn == env.AS {
			continue
		}
		for _, d := range as.Devices {
			if d.Kind != model.KindHost || d.L2Domain != "" {
				continue
			}
			if a := firstAddr(d); a != "" {
				targets = append(targets, target{asn: asn, addr: a, device: d})
				break
			}
		}
	}
	sort.Slice(targets, func(a, b int) bool { return targets[a].asn < targets[b].asn })
	if len(targets) == 0 {
		return nil, nil
	}
	addresses := map[string]string{}
	for _, target := range targets {
		addresses[target.device.ID] = target.addr
	}
	var probes []reachabilityProbe
	for _, r := range routers {
		// From the loopback, always.
		//
		// A router's own choice of source address for a packet leaving over an
		// inter-AS link is that link's numbering, which is advertised nowhere:
		// the probe arrives and the answer has no way back, and a perfectly
		// healthy router reads as unable to reach half the internet. The
		// loopback is inside this AS's own address space, so a reply can find
		// its way home.
		src := ""
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			src = addrOf(lo.Addr4)
		}
		if src == "" {
			continue
		}
		for _, t := range targets {
			// Match the established witness exactly: ping -I is given the
			// loopback address, not merely its interface name. On routers
			// with policy routing the two can select different source rules.
			probes = append(probes, reachabilityProbe{from: r, to: t.device, srcIface: src})
		}
	}
	if len(probes) == 0 {
		return nil, nil
	}
	failed, complete := batchedPingFailures(ctx, env, probes, addresses)
	if env.ShadowBatches {
		legacy := legacyPingFailures(ctx, env, probes, addresses)
		if !complete || !sameStrings(failed, legacy) {
			return nil, fmt.Errorf("batched external-reachability witness differs from legacy witness; "+
				"refusing to change the verdict until they agree (batched=%v legacy=%v)", failed, legacy)
		}
		return summarizeOutsideFailures(legacy, len(targets), routers), nil
	}
	if complete {
		return summarizeOutsideFailures(failed, len(targets), routers), nil
	}
	// A missing source-side marker is a grader problem, not a failed path.
	// The legacy path retains its per-pair error accounting rather than
	// guessing which probe a partial batch omitted.
	return summarizeOutsideFailures(legacyPingFailures(ctx, env, probes, addresses), len(targets), routers), nil
}

func summarizeOutsideFailures(failed []string, targetCount int, routers []*model.Device) []string {
	byRouter := map[string][]string{}
	for _, failure := range failed {
		for _, router := range routers {
			if strings.HasPrefix(failure, router.ID+" ") || strings.HasPrefix(failure, router.ID+" (") ||
				strings.HasPrefix(failure, router.Name+" ") {
				byRouter[router.Name] = append(byRouter[router.Name], failure)
				break
			}
		}
	}
	var out []string
	for _, router := range routers {
		missing := byRouter[router.Name]
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)
		out = append(out, fmt.Sprintf("%s cannot reach %d of %d other system(s) it has routes for: %s",
			router.Name, len(missing), targetCount, strings.Join(truncate(missing, 3), "; ")))
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// kernelForwardsMany runs all route lookups inside one agent-side shell. Each
// address is passed as an argv element after netip validation, never interpolated
// into the script, so a route attribute cannot become shell syntax.
func (e *Env) kernelForwardsMany(ctx context.Context, deviceID string,
	addrs []string,
) (map[string]nextHopResolution, error) {
	out := make(map[string]nextHopResolution, len(addrs))
	if len(addrs) == 0 {
		return out, nil
	}
	for _, addr := range addrs {
		if _, err := netip.ParseAddr(addr); err != nil {
			out[addr] = nextHopResolution{why: "an invalid next-hop address"}
		}
	}
	valid := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if _, bad := out[addr]; !bad {
			valid = append(valid, addr)
		}
	}
	if len(valid) == 0 {
		return out, nil
	}
	const script = `n=0
for addr in "$@"; do
  echo "@ $n"
  ip route get "$addr" 2>&1 | head -1
  n=$((n+1))
done`
	command := []string{"sh", "-c", script, "--"}
	command = append(command, valid...)
	res, err := e.Probe(ctx, deviceID, command)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("batched kernel route lookup exited %d: %s",
			res.ExitCode, firstLine(res.Stderr))
	}

	current := -1
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "@ ") {
			index, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "@ ")))
			if parseErr != nil || index < 0 || index >= len(valid) {
				current = -1
			} else {
				current = index
			}
			continue
		}
		if current < 0 {
			continue
		}
		addr := valid[current]
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "network is unreachable"),
			strings.Contains(lower, "invalid argument"),
			strings.Contains(lower, "not found"):
			out[addr] = nextHopResolution{why: "no route the kernel can use"}
		case strings.Contains(lower, "blackhole"),
			strings.Contains(lower, "unreachable"),
			strings.Contains(lower, "prohibit"):
			out[addr] = nextHopResolution{
				why: "a route the routing daemon installed, which a policy rule sends somewhere that discards it",
			}
		case strings.Contains(lower, " dev "):
			out[addr] = nextHopResolution{ok: true}
		default:
			out[addr] = nextHopResolution{why: "a kernel route with no forwarding device"}
		}
		current = -1
	}
	for _, addr := range valid {
		if _, ok := out[addr]; !ok {
			out[addr] = nextHopResolution{why: "no route the kernel answered for"}
		}
	}
	return out, nil
}
