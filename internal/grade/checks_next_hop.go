package grade

import (
	"context"
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

	type bad struct{ router, prefix, nh string }
	var unusable []bad
	var unread []string
	checked := 0

	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		// The interior routing table is what decides whether a next hop is
		// usable. Asking for the route to the next hop itself is exactly the
		// lookup the forwarding plane does.
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
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
					ok, err := env.resolves(ctx, r.ID, nh.IP)
					if err != nil {
						unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
						continue
					}
					if !ok {
						unusable = append(unusable, bad{r.Name, prefix, nh.IP})
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
		detail = append(detail, fmt.Sprintf("%s: %s via %s, which it has no route to",
			b.router, b.prefix, b.nh))
	}
	return Fail("bgp.next_hop_self", Evidence{
		Expected: "every next hop carried inside the AS is reachable from the router holding it",
		Observed: fmt.Sprintf("%d of %d internally carried route(s) point at an address "+
			"their own router cannot reach", len(unusable), checked),
		Detail: strings.Join(truncate(detail, 6), "\n"),
		Hint: "a border router re-advertising an external route keeps the external " +
			"next hop unless told otherwise; the session comes up, the route appears " +
			"everywhere, and the traffic is dropped",
		Command: "show ip bgp json; show ip route <next-hop> json",
	})
}

// resolves reports whether a router has a route to an address.
func (e *Env) resolves(ctx context.Context, deviceID, addr string) (bool, error) {
	res, err := e.Probe(ctx, deviceID, []string{"vtysh", "-c",
		fmt.Sprintf("show ip route %s json", addr)})
	if err != nil {
		return false, fmt.Errorf("asking %s for its route to %s: %w", deviceID, addr, err)
	}
	if res.ExitCode != 0 {
		return false, fmt.Errorf("asking %s for its route to %s: exited %d: %s",
			deviceID, addr, res.ExitCode, firstLine(res.Stderr))
	}
	body := strings.TrimSpace(res.Stdout)
	// FRR prints "{}" when it has no route, and a keyed object when it has one.
	return body != "" && body != "{}" && strings.Contains(body, "\"prefix\""), nil
}
