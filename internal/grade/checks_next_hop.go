package grade

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

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
	// Per router, because a router that carries none of the AS's external
	// routes contributes nothing to a total and disappears into it.
	carriedOn := map[string]int{}
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
					carriedOn[r.Name]++
					ok, why, err := env.resolves(ctx, r.ID, nh.IP)
					if err != nil {
						unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
						continue
					}
					if !ok {
						unusable = append(unusable, bad{r.Name, prefix, nh.IP, why})
					}
				}
			}
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
	if len(unusable) == 0 {
		return Pass("bgp.next_hop_self", Evidence{
			Observed: fmt.Sprintf("all %d internally carried next hop(s) resolve in the "+
				"interior routing table", checked),
			Command: "show ip bgp json; show ip route <next-hop> json",
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

// resolves reports whether a router has a route to an address that would
// actually carry a packet, and if not, why.
//
// "Has a route" was the whole test: any answer that was not "{}" and mentioned
// a prefix counted. A blackhole route is an answer of exactly that shape --
// selected, installed, and discarding everything sent to it -- so a submission
// that pointed the next hop of every externally learned route at Null0 kept
// full marks while that part of the AS could not reach the internet at all.
// The check is named for a fault whose entire symptom is "the route is
// everywhere and the traffic is dropped", which is what this was.
//
// So the entry is parsed: it must be the one the kernel installed, and it must
// have a next hop that forwards -- in the FIB, active, with somewhere to send
// the packet, and not a discard of any of the three kinds FRR can express.
func (e *Env) resolves(ctx context.Context, deviceID, addr string) (bool, string, error) {
	res, err := e.Probe(ctx, deviceID, []string{"vtysh", "-c",
		fmt.Sprintf("show ip route %s json", addr)})
	if err != nil {
		return false, "", fmt.Errorf("asking %s for its route to %s: %w", deviceID, addr, err)
	}
	if res.ExitCode != 0 {
		return false, "", fmt.Errorf("asking %s for its route to %s: exited %d: %s",
			deviceID, addr, res.ExitCode, firstLine(res.Stderr))
	}
	body := strings.TrimSpace(res.Stdout)
	// FRR prints "{}" when it has no route, and a keyed object when it has one.
	if body == "" || body == "{}" {
		return false, "no route at all", nil
	}
	if i := strings.IndexByte(body, '{'); i > 0 {
		body = body[i:]
	}
	var doc map[string][]routeEntryJSON
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return false, "", fmt.Errorf("reading %s's route to %s: %w", deviceID, addr, err)
	}
	discard := ""
	for _, entries := range doc {
		for _, entry := range entries {
			if !entry.Selected && !entry.Installed {
				continue
			}
			for _, nh := range entry.Nexthops {
				switch {
				case nh.Blackhole || nh.Unreachable || nh.Reject:
					discard = fmt.Sprintf("a %s route (%s) that discards it",
						discardKind(nh), entry.Protocol)
				case !nh.Fib || !nh.Active:
					if discard == "" {
						discard = fmt.Sprintf("a %s route that is not in the forwarding table",
							entry.Protocol)
					}
				case nh.IP == "" && nh.InterfaceName == "":
					if discard == "" {
						discard = fmt.Sprintf("a %s route with nowhere to send the packet",
							entry.Protocol)
					}
				default:
					return true, "", nil
				}
			}
		}
	}
	if discard == "" {
		discard = "no route the kernel installed"
	}
	return false, discard, nil
}

// routeEntryJSON is one entry of `show ip route <addr> json`.
type routeEntryJSON struct {
	Prefix    string `json:"prefix"`
	Protocol  string `json:"protocol"`
	Selected  bool   `json:"selected"`
	Installed bool   `json:"installed"`
	Nexthops  []struct {
		Fib           bool   `json:"fib"`
		Active        bool   `json:"active"`
		Blackhole     bool   `json:"blackhole"`
		Unreachable   bool   `json:"unreachable"`
		Reject        bool   `json:"reject"`
		IP            string `json:"ip"`
		InterfaceName string `json:"interfaceName"`
	} `json:"nexthops"`
}

func discardKind(nh struct {
	Fib           bool   `json:"fib"`
	Active        bool   `json:"active"`
	Blackhole     bool   `json:"blackhole"`
	Unreachable   bool   `json:"unreachable"`
	Reject        bool   `json:"reject"`
	IP            string `json:"ip"`
	InterfaceName string `json:"interfaceName"`
}) string {
	switch {
	case nh.Blackhole:
		return "blackhole"
	case nh.Reject:
		return "prohibit"
	default:
		return "unreachable"
	}
}
