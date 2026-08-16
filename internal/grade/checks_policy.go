package grade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/svc"
)

// This file registers the remaining course checks: 6in4 tunnels, exchange
// community policy, traffic engineering and RPKI.

func init() {
	Register(&Check{
		Name:     "tunnel.sixin4",
		Describe: "IPv6 traffic between the two datacentres traverses a 6in4 tunnel",
		Run:      checkSixIn4,
	})
	Register(&Check{
		Name:     "policy.ixp_communities",
		Describe: "announcements are relayed through the exchange only where intended",
		Run:      checkIXPCommunities,
	})
	Register(&Check{
		Name:     "policy.traffic_engineering",
		Describe: "the high-delay provider and customer are made less attractive, without filtering",
		Run:      checkTrafficEngineering,
	})
	Register(&Check{
		Name:     "rpki.invalid_rejected",
		Describe: "a route whose origin is RPKI-invalid is not selected",
		Run:      checkRPKIInvalidRejected,
	})
	Register(&Check{
		Name:     "rpki.notfound_preserved",
		Describe: "routes with no ROA are still usable, so filtering has not gone too far",
		Run:      checkRPKINotFoundPreserved,
	})
}

// checkSixIn4 verifies both that IPv6 works between the datacentres and that it
// actually goes through a tunnel.
//
// Testing reachability alone would pass a student who configured native IPv6
// routing, which is not what the question asks for; testing only for a tunnel
// device would pass one who built a tunnel that does not carry traffic.
// tunnelCarriesTransport opens a connection each way and says whether the far
// side saw it.
//
// The target is a port nothing is listening on, so the answer is a reset: no
// service has to be arranged anywhere, and the far side's own count of resets
// it has sent records that the connection attempt arrived. A reply forged on
// the path does not move that counter, and a rule that discards forwarded TCP
// while permitting ICMP -- which is what makes a ping-only test worthless --
// stops it moving at all.
func tunnelCarriesTransport(ctx context.Context, env *Env, hosts map[string]*model.Device,
	domains []string) (string, bool) {
	for i := 0; i < 2; i++ {
		src, dst := hosts[domains[i]], hosts[domains[1-i]]
		if src == nil || dst == nil {
			continue
		}
		addr := deviceAddr6(ctx, env, dst)
		if addr == "" {
			continue
		}
		before, okB := tcpResetsSent(ctx, env, dst.ID)
		res, err := env.Probe(ctx, src.ID,
			[]string{"nc", "-6", "-w", "3", "-z", addr, "9"})
		after, okA := tcpResetsSent(ctx, env, dst.ID)
		if !okB || !okA {
			// The counter could not be read, so a refusal is the only
			// evidence there is; a timeout leaves nothing to conclude from.
			if err == nil && res.ExitCode == 0 {
				continue
			}
			continue
		}
		if after > before {
			continue
		}
		return fmt.Sprintf(
			"IPv6 pings cross the tunnel, but a connection from %s to %s at %s never "+
				"arrived: %s answered no TCP at all, so the tunnel carries ICMP and "+
				"nothing else", src.Name, dst.Name, addr, dst.Name), false
	}
	return "", true
}

// tcpResetsSent reads a host's count of TCP resets it has sent, which is the
// kernel's own record of a connection attempt having reached it.
func tcpResetsSent(ctx context.Context, env *Env, device string) (int, bool) {
	res, err := env.Probe(ctx, device, []string{"cat", "/proc/net/snmp"})
	if err != nil || res.ExitCode != 0 {
		return 0, false
	}
	return snmpCounter(res.Stdout, "Tcp:", "OutRsts")
}

func checkSixIn4(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("tunnel.sixin4", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// Find the two gateway routers and one host in each datacentre.
	gateways := map[string]*model.Device{}
	for _, r := range as.Routers {
		if r.L2Gateway != "" {
			gateways[r.L2Gateway] = r
		}
	}
	if len(gateways) < 2 {
		return Errored("tunnel.sixin4", fmt.Errorf("expected two L2 gateways, found %d", len(gateways)))
	}
	// Every host, not one per datacentre.
	//
	// One host in each was tested, in one direction, so a submission that
	// configured one VLAN and not the other, or the forward path and not the
	// return, scored the whole point. The datacentres here hold two and four
	// hosts across two VLANs, and the question is about the datacentres, not
	// about whichever host this check happened to pick.
	hostsIn := map[string][]*model.Device{}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost && d.L2Domain != "" {
			hostsIn[d.L2Domain] = append(hostsIn[d.L2Domain], d)
		}
	}
	hosts := map[string]*model.Device{}
	for dom, ds := range hostsIn {
		sort.Slice(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name })
		hostsIn[dom] = ds
		hosts[dom] = ds[0]
	}

	domains := make([]string, 0, len(gateways))
	for d := range gateways {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	// A configured tunnel must exist on both gateways.
	//
	// Every container carries the kernel's own sit0, so a substring test for
	// "sit" is true before the student has done anything at all. Only a device
	// with both endpoints set counts.
	var missing []string
	tunnels := map[string]string{}
	for _, d := range domains {
		gw := gateways[d]
		out, err := env.Probe(ctx, gw.ID, []string{"sh", "-c", "ip -d tunnel show 2>/dev/null"})
		if err != nil {
			return Errored("tunnel.sixin4", err)
		}
		name := configuredTunnel(out.Stdout)
		if name == "" {
			missing = append(missing, fmt.Sprintf("%s has no configured 6in4 tunnel "+
				"(the kernel's own sit0 does not count: it has no endpoints)", gw.Name))
			continue
		}
		// The endpoints must be the two gateways' own loopbacks, not merely
		// two addresses.
		//
		// Any pair made the check pass, so a tunnel between two interface
		// addresses -- which breaks the moment either link does, and is not
		// what the question asks for -- scored the same as the answer. The
		// loopback is the point: it is reachable by any interior path.
		if why := tunnelEndpointsWrong(out.Stdout, name, gw, gateways, domains, d); why != "" {
			missing = append(missing, fmt.Sprintf("%s: %s", gw.Name, why))
			continue
		}
		tunnels[d] = name
	}

	// And IPv6 must actually get across *through the tunnel*.
	//
	// Native IPv6 routing between the datacentres also makes the ping succeed,
	// and it is not what the question asks for. The tunnel's own counters
	// settle it: if they do not move, the packets went some other way.
	var reach string
	var unreached []string
	reachable, throughTunnel := false, false
	if len(domains) >= 2 {
		src, sok := hosts[domains[0]]
		dst, dok := hosts[domains[1]]
		gw := gateways[domains[0]]
		switch {
		case !sok || !dok:
			reach = "could not find a host in each datacentre"
		default:
			addr := deviceAddr6(ctx, env, dst)
			if addr == "" {
				reach = fmt.Sprintf("%s has no IPv6 address configured", dst.Name)
				break
			}
			// Each gateway resolves its own datacentre's host before anything
			// is measured, and the result of that is discarded.
			//
			// This is not politeness, it is necessary. Measured on this
			// cluster: after the datacentre is reconfigured -- which is what
			// installing a solution does -- the gateway records the host as
			// FAILED, and traffic arriving through the tunnel never clears it.
			// Twenty seconds of forwarded pings left the entry FAILED; a
			// single ping originated by the gateway itself made it REACHABLE
			// and every forwarded packet then went through. So a correct
			// answer scored zero or full marks depending on whether anything
			// had happened to originate a packet from the right router in the
			// preceding few minutes.
			//
			// Neighbour cache state is not part of the student's answer. This
			// removes it from the measurement in the same spirit as waiting
			// for BGP to converge, and it cannot manufacture a pass: the
			// tunnel's own counters must still move and the end-to-end ping
			// from the far datacentre must still succeed.
			for _, d := range domains {
				gw, h := gateways[d], hosts[d]
				if gw == nil || h == nil {
					continue
				}
				if a := deviceAddr6(ctx, env, h); a != "" {
					_, _ = env.Probe(ctx, gw.ID, []string{"ping6", "-c", "2", "-W", "3", a})
				}
			}

			// Reachability across the tunnel is waited for, not sampled once.
			//
			// The first packet has to wait for neighbour discovery, and the
			// solicitation itself crosses the tunnel and comes back. If the
			// tunnel was rebuilt moments earlier -- which is exactly what
			// installing a solution does -- the path is not ready the instant
			// the check asks. Graded immediately after a redeploy a correct
			// answer scored zero; graded a minute later the same configuration
			// scored full marks. Every other check in this rubric waits for the
			// control plane to settle, and this one is no different: the
			// difference between "not configured" and "not yet" is the whole
			// question.
			var before, after int
			deadline := time.Now().Add(45 * time.Second)
			for {
				before = tunnelTx(ctx, env, gw.ID, tunnels[domains[0]])
				res, err := env.Probe(ctx, src.ID,
					[]string{"ping6", "-c", "3", "-W", "5", "-i", "0.3", addr})
				after = tunnelTx(ctx, env, gw.ID, tunnels[domains[0]])
				if err == nil && res.ExitCode == 0 {
					reachable = true
					break
				}
				if time.Now().After(deadline) {
					reach = fmt.Sprintf("%s could not reach %s at %s over IPv6 in %s",
						src.Name, dst.Name, addr, 45*time.Second)
					break
				}
				select {
				case <-ctx.Done():
					reach = "the grading run was cancelled while waiting for IPv6 to come up"
				case <-time.After(3 * time.Second):
					continue
				}
				break
			}
			// The counters say something crossed the tunnel; the routing
			// table says whether *this* traffic did.
			//
			// A counter is a total, and a total can be moved by anything: a
			// submission that routed every datacentre prefix natively and then
			// pinged a link-local address across the tunnel in a loop made the
			// counters climb throughout the test and earned the whole mark
			// while none of the traffic in question was encapsulated at all.
			// What the gateway would do with a packet for that host is not a
			// total, and it is the thing the question asks about.
			nativeFwd := ""
			if reachable && tunnels[domains[0]] != "" {
				if via, ok := forwardsVia(ctx, env, gw.ID, addr, tunnels[domains[0]]); !ok {
					nativeFwd = fmt.Sprintf("%s forwards traffic for %s over %s, not through "+
						"%s: the tunnel's counters moved, but not for this traffic",
						gw.Name, addr, via, tunnels[domains[0]])
				}
			}
			if reachable && tunnels[domains[0]] != "" && after > before && nativeFwd == "" {
				throughTunnel = true
			} else if nativeFwd != "" {
				reach = nativeFwd
			} else if reachable && tunnels[domains[0]] != "" {
				reach = fmt.Sprintf("IPv6 reaches %s, but %s carried no packets during the test, "+
					"so the traffic is being routed natively rather than encapsulated",
					dst.Name, tunnels[domains[0]])
			}
			// Now every host, both ways.
			//
			// The path above is known to work, so no waiting is needed here:
			// what is left is whether the answer covers the whole datacentre
			// or only the corner this check used to look at.
			if throughTunnel {
				unreached = crossDatacentreGaps(ctx, env, hostsIn, domains, gateways, tunnels)
			}
			// And the return path has to be encapsulated too.
			//
			// The counters were read on one gateway only, for one direction,
			// while the result claimed the tunnel carried traffic "in both
			// directions". A forward 6in4 route with a native IPv6 return path
			// scored the whole point -- and half the answer is a tunnel that
			// only works one way, which is not what the question asks for.
			if throughTunnel && len(domains) >= 2 {
				back := gateways[domains[1]]
				bs, bd := hosts[domains[1]], hosts[domains[0]]
				if back != nil && bs != nil && bd != nil && tunnels[domains[1]] != "" {
					if addr := deviceAddr6(ctx, env, bd); addr != "" {
						before := tunnelTx(ctx, env, back.ID, tunnels[domains[1]])
						res, err := env.Probe(ctx, bs.ID,
							[]string{"ping6", "-c", "3", "-W", "5", "-i", "0.3", addr})
						after := tunnelTx(ctx, env, back.ID, tunnels[domains[1]])
						via, encapsulated := forwardsVia(ctx, env, back.ID, addr, tunnels[domains[1]])
						switch {
						case !encapsulated:
							throughTunnel = false
							reach = fmt.Sprintf("%s forwards traffic for %s over %s, not "+
								"through %s, so the return path is not encapsulated",
								back.Name, addr, via, tunnels[domains[1]])
						case err != nil || res.ExitCode != 0:
							throughTunnel = false
							reach = fmt.Sprintf("%s cannot reach %s at %s over IPv6, so the "+
								"tunnel carries traffic one way only", bs.Name, bd.Name, addr)
						case after <= before:
							throughTunnel = false
							reach = fmt.Sprintf("IPv6 reaches %s from %s, but %s carried no "+
								"packets during the test, so the return path is routed "+
								"natively rather than encapsulated",
								bd.Name, bs.Name, tunnels[domains[1]])
						}
					}
				}
			}
		}
	}

	// And whether anything other than a ping crosses it.
	//
	// Every probe above is ICMPv6. A rule on the gateway discarding forwarded
	// TCP left every ping answered, the tunnel counters moving, and the whole
	// point awarded for a tunnel across which no connection could be made. A
	// datacentre that can only be pinged is not reachable in any sense the
	// assignment means.
	if throughTunnel && len(domains) >= 2 {
		if why, ok := tunnelCarriesTransport(ctx, env, hosts, domains); !ok {
			throughTunnel = false
			reach = why
		}
	}

	switch {
	case len(missing) == 0 && reachable && throughTunnel && len(unreached) > 0:
		// The tunnel works and the answer does not cover the datacentres.
		return Partial("tunnel.sixin4", 0.5, Evidence{
			Expected: "every host of each datacentre reaching every host of the other over IPv6",
			Observed: fmt.Sprintf("the tunnel carries traffic, but %d host pair(s) cannot reach "+
				"each other", len(unreached)),
			Detail: strings.Join(truncate(unreached, 6), "\n"),
			Hint: "check both VLANs, both datacentres and both directions -- a route or an " +
				"address configured on one side only works one way",
			Command: "ping6 <the other datacentre's host>",
		})
	case len(missing) == 0 && reachable && throughTunnel:
		return Pass("tunnel.sixin4", Evidence{
			Observed: fmt.Sprintf("IPv6 crosses between %s and %s through %s in both directions, "+
				"for every host of each", domains[0], domains[1], tunnels[domains[0]])})
	case reachable:
		return Partial("tunnel.sixin4", 0.5, Evidence{
			Expected: "IPv6 carried over a 6in4 tunnel",
			Observed: "IPv6 works, but not through a tunnel",
			Detail:   strings.TrimSpace(strings.Join(append(missing, reach), "\n")),
			Hint:     "the question asks for encapsulation, not native IPv6 routing",
		})
	default:
		detail := strings.Join(append(missing, reach), "\n")
		return Fail("tunnel.sixin4", Evidence{
			Expected: "IPv6 reachability between the datacentres over 6in4",
			Observed: "not reachable",
			Detail:   strings.TrimSpace(detail),
			Hint:     "create the tunnel with `ip tunnel add ... mode sit` at both ends, using the loopbacks",
		})
	}
}

// checkIXPCommunities verifies the community-gated relay policy at an exchange.
//
// The exchange only relays an announcement carrying the community N:X, so a
// correct answer both tags its own announcements for out-of-region members and
// refuses announcements arriving from in-region members.
func checkIXPCommunities(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("policy.ixp_communities", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// Find the exchange this AS is attached to, its number, and the address
	// the exchange's route server is reached at. The peer address matters:
	// the mark is for a policy the route server actually sees, not for one
	// written in the configuration and never attached to anything.
	ixp := 0
	var ixpRouter *model.Device
	ixpPeer := ""
	for _, r := range as.Routers {
		for _, i := range r.Ifaces {
			if i.Role == model.RoleIXPLink && i.Peer != nil {
				if addr, asn := routeServerOn(env.Topology, i); addr != "" {
					ixp, ixpRouter, ixpPeer = asn, r, addr
				}
			}
		}
	}
	if ixp == 0 || ixpRouter == nil {
		return Errored("policy.ixp_communities", fmt.Errorf("AS %d is not attached to an exchange", env.AS))
	}

	out, err := env.Vtysh(ctx, ixpRouter.Name, "show running-config")
	if err != nil {
		return Errored("policy.ixp_communities", err)
	}
	cfg := parseFRR(out)
	if !cfg.hasNeighbor(ixpPeer) {
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("a session with the exchange's route server at %s", ixpPeer),
			Observed: "no such neighbour is configured",
			Hint:     "the exchange relays announcements only between its own members",
			Command:  "show running-config",
		})
	}

	// (i) What the exchange actually did with our announcement.
	//
	// Reading the configuration was not enough, and saying so cost a point of
	// nothing: any `set community 140:...` outbound and any `match as-path`
	// inbound passed, so `set community 140:999` -- naming a member that does
	// not exist -- and a route-map matching an empty AS-path list scored full
	// marks for policy that does nothing at all.
	//
	// The route server is the authority here. It holds what we sent it, the
	// communities that survived our outbound policy, and the list of members it
	// relayed the route to. None of that can be produced by configuration that
	// is not attached to the session.
	members := ixpMembers(env.Topology, ixp)
	own := as.Block
	rs, rsOK := routeServerDevice(env.Topology, ixp)
	if !rsOK {
		return Errored("policy.ixp_communities",
			fmt.Errorf("the route server of exchange %d is not in the lab", ixp))
	}

	var seen ixpRoute
	relayErr := readIXPRoute(ctx, env, rs.ID, own, &seen)
	if relayErr != nil {
		return Errored("policy.ixp_communities", relayErr)
	}
	if !seen.present {
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("the exchange to hold %s, learned from AS %d", own, env.AS),
			Observed: "the route server has no route to it from this AS",
			Hint:     "the exchange can only relay an announcement it has been sent",
			Command:  fmt.Sprintf("show bgp ipv4 unicast %s json (on the route server)", own),
		})
	}

	prefix := strconv.Itoa(ixp) + ":"
	var tagged, strangers []string
	for _, c := range seen.communities {
		if !strings.HasPrefix(c, prefix) {
			continue
		}
		asn, err := strconv.Atoi(strings.TrimPrefix(c, prefix))
		if err != nil {
			strangers = append(strangers, c)
			continue
		}
		if !members[asn] {
			strangers = append(strangers, c)
			continue
		}
		tagged = append(tagged, c)
	}
	sort.Strings(tagged)
	tagged = uniq(tagged)
	sort.Strings(strangers)

	// Every member, not any member.
	//
	// Any non-empty set of real member communities passed, so tagging one of
	// five members -- an announcement four of them never receive -- scored the
	// same as tagging all of them. The question is which members should get
	// the route, and "one of them" is a different answer from "all of them".
	var untagged []string
	have := map[string]bool{}
	for _, c := range tagged {
		have[c] = true
	}
	for _, asn := range sortedInts(members) {
		if asn == env.AS {
			continue
		}
		if c := prefix + strconv.Itoa(asn); !have[c] {
			untagged = append(untagged, c)
		}
	}

	// (ii) The in-region filter must be applied to what arrives from the
	// route server, the list it matches on must exist and select something,
	// and -- the part that decides it -- no route whose path crosses an
	// in-region system may actually be in this AS's table via the exchange.
	//
	// The configuration half alone gave the mark for a route-map that matched
	// an empty list, or one attached in the wrong direction. The table is what
	// the question is about.
	inbound := cfg.appliedBody(ixpPeer, "in")
	filters := false
	var emptyList string
	for _, name := range asPathMatches(inbound) {
		if n := cfg.asPathListLen(name); n > 0 {
			filters = true
		} else {
			emptyList = name
		}
	}
	admitted, accepted, aerr := routesViaIXP(ctx, env, ixpRouter.Name, ixpPeer)
	if aerr != nil {
		return Errored("policy.ixp_communities", aerr)
	}
	if len(admitted) > 0 {
		filters = false
	}
	// What the exchange is for.
	//
	// Only the refusals were read, so an inbound policy denying everything the
	// route server sent admitted no in-region route and passed. A member that
	// accepts nothing from the exchange has not written a peering policy; it
	// has switched the exchange off, and the point of the question is the
	// traffic that does cross it.
	ourAddr := ""
	for _, i := range ixpRouter.Ifaces {
		if i.Role == model.RoleIXPLink && i.Addr4 != "" {
			ourAddr = addrOnly(i.Addr4)
		}
	}
	offered := 0
	if ourAddr != "" {
		offered, aerr = routeServerOffersOutOfRegion(ctx, env, rs.ID, ourAddr, ixpInRegion(env))
		if aerr != nil {
			return Errored("policy.ixp_communities", aerr)
		}
	}
	if len(accepted) == 0 && offered > 0 {
		return Fail("policy.ixp_communities", Evidence{
			Expected: "the routes the exchange relays from out-of-region members accepted, " +
				"and the in-region ones refused",
			Observed: fmt.Sprintf("nothing at all was accepted from %s, though the exchange "+
				"is relaying %d route(s) from outside this region", ixpPeer, offered),
			Hint: "an inbound filter that denies everything refuses the in-region routes " +
				"and the rest with them; match the AS path rather than blocking the session",
			Command: fmt.Sprintf("show ip bgp neighbors %s routes", ixpPeer),
		})
	}

	unapplied := ""
	switch {
	case len(tagged) == 0 && len(strangers) > 0:
		unapplied = fmt.Sprintf("the announcement carries %s, which name%s no member of "+
			"exchange %d, so the exchange relayed it to nobody",
			strings.Join(strangers, " "),
			map[bool]string{true: "s", false: ""}[len(strangers) == 1], ixp)
	case len(tagged) == 0 && strings.Contains(out, "set community "+prefix):
		unapplied = fmt.Sprintf("a route-map sets %s<member> but it is not applied outbound to %s",
			prefix, ixpPeer)
	case len(admitted) > 0:
		unapplied = fmt.Sprintf("%d route(s) whose path crosses a system in this region "+
			"were accepted from the exchange anyway: %s",
			len(admitted), strings.Join(truncate(admitted, 4), "; "))
	case !filters && emptyList != "":
		unapplied = fmt.Sprintf("the inbound route-map matches AS-path list %q, which has "+
			"no terms, so it never matches anything", emptyList)
	case !filters && strings.Contains(out, "match as-path"):
		unapplied = fmt.Sprintf("an AS-path filter exists but is not applied inbound from %s", ixpPeer)
	}

	// The exchange relays to exactly the members named. Anything else means the
	// communities are not doing what the question asks.
	relayed := make([]string, 0, len(seen.advertisedTo))
	for _, asn := range seen.advertisedTo {
		relayed = append(relayed, prefix+strconv.Itoa(asn))
	}
	sort.Strings(relayed)
	relayed = uniq(relayed)

	// The exchange relaying it to nobody is the whole failure, however the
	// configuration reads. A route tagged only with values that name no member
	// -- `set community 140:999` is the obvious one -- leaves the announcement
	// sitting in the route server reaching no one, and the earlier version of
	// this check called that full marks because the words were present.
	if len(seen.advertisedTo) == 0 {
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("the exchange to relay %s to the members named in its communities", own),
			Observed: fmt.Sprintf("the exchange holds it but relayed it to no member at all%s",
				map[bool]string{true: "", false: " (communities on it: " + strings.Join(seen.communities, " ") + ")"}[len(seen.communities) == 0]),
			Hint: fmt.Sprintf("the exchange relays to member X only if the announcement carries %s%s, "+
				"and only members of this exchange count", prefix, "X"),
			Detail:  unapplied,
			Command: fmt.Sprintf("show bgp ipv4 unicast %s json (on the route server)", own),
		})
	}

	switch {
	case len(tagged) > 0 && filters && len(untagged) > 0:
		return Partial("policy.ixp_communities", 0.5, Evidence{
			Expected: fmt.Sprintf("the announcement tagged for every member of exchange %d", ixp),
			Observed: fmt.Sprintf("it is tagged %s, so the exchange relays it to %d member(s) "+
				"and not to %d other(s)", strings.Join(tagged, " "), len(seen.advertisedTo),
				len(untagged)),
			Detail:  "not tagged for " + strings.Join(untagged, " "),
			Hint:    "every member of the exchange should receive your prefix; the in-region ones are refused on the way in, not left untagged on the way out",
			Command: fmt.Sprintf("show bgp ipv4 unicast %s json (on the route server)", own),
		})
	case len(tagged) > 0 && filters:
		return Pass("policy.ixp_communities", Evidence{
			Observed: fmt.Sprintf("the exchange holds %s from this AS tagged %s and relayed it "+
				"to %d member(s); arrivals are filtered on AS path",
				own, strings.Join(tagged, " "), len(seen.advertisedTo)),
			Detail:  "relayed to " + strings.Join(relayed, " "),
			Command: fmt.Sprintf("show bgp ipv4 unicast %s json (on the route server)", own),
		})
	case len(tagged) > 0:
		return Partial("policy.ixp_communities", 0.5, Evidence{
			Expected: "communities set for out-of-region members, and in-region announcements refused",
			Observed: fmt.Sprintf("the exchange sees %s but nothing filters arrivals from %s on AS path",
				strings.Join(tagged, " "), ixpPeer),
			Hint:    "part (ii) asks you to deny announcements whose path contains an in-region AS",
			Detail:  unapplied,
			Command: "show running-config",
		})
	default:
		obs := "the exchange sees no member communities on our announcement"
		if unapplied != "" {
			obs = unapplied
		}
		return Fail("policy.ixp_communities", Evidence{
			Expected: fmt.Sprintf("community values of the form %s<member>, on what the exchange receives from us", prefix),
			Observed: obs,
			Hint: fmt.Sprintf("the exchange relays an announcement to member X only if it carries %s%s",
				prefix, "X"),
			Command: fmt.Sprintf("show bgp ipv4 unicast %s json (on the route server)", own),
		})
	}
}

// ixpRoute is what the exchange's route server holds for one prefix.
type ixpRoute struct {
	present      bool
	communities  []string
	advertisedTo []int
}

// readIXPRoute asks the route server what it has, rather than asking the
// student's router what it meant to send.
func readIXPRoute(ctx context.Context, env *Env, rsDevice, prefix string, out *ixpRoute) error {
	_ = env
	var raw struct {
		Prefix       string `json:"prefix"`
		AdvertisedTo map[string]struct {
			Hostname string `json:"hostname"`
		} `json:"advertisedTo"`
		Paths []struct {
			RxedFromRSClient bool `json:"rxedFromRsClient"`
			Community        struct {
				List []string `json:"list"`
			} `json:"community"`
			ASPath struct {
				String string `json:"string"`
			} `json:"aspath"`
		} `json:"paths"`
	}
	res, err := env.Probe(ctx, rsDevice, []string{"vtysh", "-c",
		fmt.Sprintf("show bgp ipv4 unicast %s json", prefix)})
	if err != nil {
		return fmt.Errorf("asking the route server of the exchange about %s: %w", prefix, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("asking the route server of the exchange about %s: exited %d: %s",
			prefix, res.ExitCode, firstLine(res.Stderr))
	}
	body := strings.TrimSpace(res.Stdout)
	if body == "" || strings.HasPrefix(body, "%") {
		return nil
	}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		// An absent prefix prints a human message rather than JSON, which is
		// not a failure to read the route server: it is the route server
		// saying it has no such route.
		return nil //nolint:nilerr // no JSON means no such prefix
	}
	if raw.Prefix == "" || len(raw.Paths) == 0 {
		return nil
	}
	// Only the path this AS sent directly.
	//
	// The route server may hold several paths to the same prefix -- ours, and
	// the same prefix relayed onward by other members, which carry *their*
	// communities. Unioning them meant a system that had stopped announcing
	// altogether could pass on a neighbour's tags. `rxedFromRsClient` with an
	// AS path of exactly this AS is the announcement we made.
	me := strconv.Itoa(env.AS)
	for _, p := range raw.Paths {
		if !p.RxedFromRSClient {
			continue
		}
		if strings.TrimSpace(p.ASPath.String) != me {
			continue
		}
		out.present = true
		out.communities = append(out.communities, p.Community.List...)
	}
	if !out.present {
		return nil
	}
	for _, m := range raw.AdvertisedTo {
		// The route server names each client by hostname, which carries the AS.
		if i := strings.LastIndex(m.Hostname, ".as"); i >= 0 {
			if asn, err := strconv.Atoi(m.Hostname[i+3:]); err == nil {
				out.advertisedTo = append(out.advertisedTo, asn)
			}
		}
	}
	sort.Ints(out.advertisedTo)
	return nil
}

// ixpMembers is the set of AS numbers attached to one exchange.
func ixpMembers(top *model.Topology, ixp int) map[int]bool {
	out := map[int]bool{}
	for _, l := range top.Links {
		for _, side := range []*model.Iface{l.A, l.B} {
			if side == nil || side.Device == nil {
				continue
			}
			if side.Device.ASN != ixp {
				continue
			}
			for _, other := range []*model.Iface{l.A, l.B} {
				if other == nil || other.Device == nil || other.Device.ASN == ixp {
					continue
				}
				out[other.Device.ASN] = true
			}
		}
	}
	// Members reached over a shared segment rather than a point-to-point link.
	for _, l := range top.Links {
		if l.Segment == "" {
			continue
		}
		atIXP := false
		for _, l2 := range top.Links {
			if l2.Segment != l.Segment {
				continue
			}
			for _, side := range []*model.Iface{l2.A, l2.B} {
				if side != nil && side.Device != nil && side.Device.ASN == ixp {
					atIXP = true
				}
			}
		}
		if !atIXP {
			continue
		}
		for _, side := range []*model.Iface{l.A, l.B} {
			if side != nil && side.Device != nil && side.Device.ASN != ixp && side.Device.ASN > 0 {
				out[side.Device.ASN] = true
			}
		}
	}
	return out
}

// routeServerDevice finds the router of an exchange.
func routeServerDevice(top *model.Topology, ixp int) (*model.Device, bool) {
	as, ok := top.ASes[ixp]
	if !ok {
		return nil, false
	}
	for _, d := range as.Routers {
		return d, true
	}
	return nil, false
}

// asPathMatches lists the AS-path access-lists a route-map body matches on.
func asPathMatches(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 3 && f[0] == "match" && f[1] == "as-path" {
			out = append(out, f[2])
		}
	}
	return out
}

// checkTrafficEngineering verifies the answer to the "one of your links is
// slow" question: prefer the fast neighbour outbound, make the slow one less
// attractive inbound, and do it *without* filtering anything.
func checkTrafficEngineering(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return Errored("policy.traffic_engineering", fmt.Errorf("AS %d not in the lab", env.AS))
	}

	// The model knows which links are slow: the delay is in the topology.
	type nb struct {
		router string
		addr   string
		asn    int
		rel    model.Relationship
		delay  string
		slow   bool
	}
	var neighbours []nb
	var maxDelay float64
	for _, r := range as.Routers {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			// What the neighbour is to us. Derived in one place, because the
			// same two lines written out here, in the renderer and in the
			// other checks were all inverted in the same direction -- so the
			// wrong answer was self-consistent and scored full marks.
			rel := i.Link.PeerRelationship(i)
			d := parseMillis(i.Link.Props.Delay)
			if d > maxDelay {
				maxDelay = d
			}
			neighbours = append(neighbours, nb{r.Name, env.PeerAddr(ctx, i), i.Peer.Device.ASN, rel, i.Link.Props.Delay, false})
		}
	}
	if len(neighbours) < 2 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("AS %d has %d external neighbours", env.AS, len(neighbours)))
	}
	for i := range neighbours {
		neighbours[i].slow = parseMillis(neighbours[i].delay) >= maxDelay && maxDelay > 0
	}

	var slow, fast []nb
	for _, n := range neighbours {
		if n.slow {
			slow = append(slow, n)
		} else {
			fast = append(fast, n)
		}
	}
	if len(slow) == 0 || len(fast) == 0 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("the lab has no delay difference between neighbours to discover"))
	}

	var detail strings.Builder
	detail.WriteString("slow neighbours: ")
	for _, n := range slow {
		fmt.Fprintf(&detail, "AS%d via %s (%s) ", n.asn, n.router, n.delay)
	}
	detail.WriteString("\n")

	checks, passed := 0, 0

	// Outbound: within a relationship class, the fast neighbour's routes must
	// carry a higher local preference than the slow one's.
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		// Every route, not the middle one: the best route from the slow
		// neighbour must still be worse than the worst from the fast one.
		_, slowBest, sn := worstLocalPref(ctx, env, s.addr)
		fastWorst, _, fn := worstLocalPref(ctx, env, f.addr)
		sp, fp := slowBest, fastWorst
		switch {
		case sn == 0:
			// Receiving nothing from the slow neighbour used to read as local
			// preference zero, which is lower than anything and so counted as
			// correctly deprioritised. The question explicitly forbids
			// filtering: the slow neighbour has to stay usable as a backup.
			fmt.Fprintf(&detail,
				"outbound: nothing at all is received from the slow %s (AS%d); it must stay "+
					"available as a backup, so deprioritise it rather than filter it\n",
				rel, s.asn)
		case fn == 0:
			fmt.Fprintf(&detail,
				"outbound: nothing at all is received from the fast %s (AS%d), so it cannot "+
					"be preferred over anything\n", rel, f.asn)
		case fp > sp:
			passed++
		default:
			fmt.Fprintf(&detail,
				"outbound: every route from the fast %s (AS%d) must be preferred over every "+
					"route from the slow one (AS%d), but the slow one has a route at local "+
					"preference %d and the fast one has one at %d\n",
				rel, f.asn, s.asn, sp, fp)
		}
	}

	// And what is actually installed, which is the question.
	//
	// Everything above reads BGP: the preferences a policy assigned, the paths
	// it advertised. None of it is the forwarding table. A static route over
	// the slow link overrides every one of those decisions and was invisible
	// here -- a submission with textbook BGP policy and `ip route 2.0.0.0/8
	// <slow neighbour>` sent its traffic over exactly the link the question
	// asks it to avoid, and kept the mark in full.
	//
	// So the installed route is read for every destination that has a path
	// through a fast neighbour. Being in the table is not the failure: the slow
	// link must stay usable as a backup, and the question says so. Being
	// *selected* is.
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var slowAddrs, fastAddrs []string
		for _, n := range neighbours {
			if n.rel != rel {
				continue
			}
			if n.slow {
				slowAddrs = append(slowAddrs, n.addr)
			} else {
				fastAddrs = append(fastAddrs, n.addr)
			}
		}
		if len(slowAddrs) == 0 || len(fastAddrs) == 0 {
			continue
		}
		checks++
		viaSlow, unreadable := installedVia(ctx, env, slowAddrs, fastAddrs)
		switch {
		case unreadable != "":
			fmt.Fprintf(&detail, "forwarding: %s\n", unreadable)
		case len(viaSlow) == 0:
			passed++
		default:
			sort.Strings(viaSlow)
			fmt.Fprintf(&detail,
				"forwarding: %d destination(s) are installed over the slow %s even though a "+
					"path through the fast one exists: %s\n",
				len(viaSlow), rel, strings.Join(truncate(viaSlow, 4), "; "))
		}
	}

	// Inbound: the announcement of our own prefix sent to the slow neighbour
	// should carry a longer AS path than the one sent to the fast neighbour of
	// the same relationship class, so other networks find that route less
	// attractive.
	own := as.Block
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		sLen, sAdv := advertisedOwnPrefix(ctx, env, s.router, s.addr, own)
		fLen, fAdv := advertisedOwnPrefix(ctx, env, f.router, f.addr, own)

		// Filtering is explicitly forbidden here: the slow neighbour must still
		// be able to reach us directly, as a backup.
		if !sAdv {
			fmt.Fprintf(&detail,
				"inbound: %s is not advertised to the slow AS%d at all; the question forbids blocking it\n",
				own, s.asn)
			continue
		}
		if !fAdv {
			fmt.Fprintf(&detail, "inbound: %s is not advertised to AS%d\n", own, f.asn)
			continue
		}
		if sLen > fLen {
			passed++
		} else {
			fmt.Fprintf(&detail,
				"inbound: the path advertised to the slow AS%d is %d long, no longer than the %d sent to AS%d; prepend to make it less attractive\n",
				s.asn, sLen, fLen, f.asn)
		}
	}

	// Nothing may be *additionally* filtered toward the slow neighbour. This is
	// compared against the fast neighbour of the same class rather than by
	// counting deny clauses: the business-relationship policy of the previous
	// question legitimately denies plenty, and conflating the two would punish
	// a correct answer.
	for _, rel := range []model.Relationship{model.RelProvider, model.RelCustomer} {
		var s, f *nb
		for i := range neighbours {
			if neighbours[i].rel != rel {
				continue
			}
			if neighbours[i].slow && s == nil {
				s = &neighbours[i]
			} else if !neighbours[i].slow && f == nil {
				f = &neighbours[i]
			}
		}
		if s == nil || f == nil {
			continue
		}
		checks++
		sSet := advertisedPrefixes(ctx, env, s.router, s.addr)
		fSet := advertisedPrefixes(ctx, env, f.router, f.addr)
		var withheld []string
		for p := range fSet {
			if !sSet[p] {
				withheld = append(withheld, p)
			}
		}
		if len(withheld) == 0 {
			passed++
		} else {
			sort.Strings(withheld)
			fmt.Fprintf(&detail,
				"inbound: %d prefix(es) advertised to AS%d are withheld from the slow AS%d (%s); the question forbids denying advertisements\n",
				len(withheld), f.asn, s.asn, strings.Join(truncate(withheld, 3), ", "))
		}
	}

	if checks == 0 {
		return Errored("policy.traffic_engineering",
			fmt.Errorf("no slow and fast neighbour of the same relationship class to compare"))
	}
	if passed == checks {
		return Pass("policy.traffic_engineering", Evidence{
			Observed: strings.TrimSpace(detail.String())})
	}
	return Partial("policy.traffic_engineering", ratio(passed, checks), Evidence{
		Expected: "prefer the fast neighbour outbound, prepend toward the slow one inbound, deny nothing",
		Observed: fmt.Sprintf("%d of %d correct", passed, checks),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "local preference controls where your traffic leaves; AS-path length is what other networks see",
	})
}

// advertisedOwnPrefix returns the AS-path length of our own prefix as
// advertised to a neighbour, and whether it is advertised at all.
func advertisedOwnPrefix(ctx context.Context, env *Env, router, peer, own string) (int, bool) {
	adv, err := advertisedRoutes(ctx, env, router, peer)
	if err != nil {
		return 0, false
	}
	entries, ok := adv.Table()[own]
	if !ok || len(entries) == 0 {
		return 0, false
	}
	longest := 0
	for _, e := range entries {
		if n := len(strings.Fields(e.Path)); n > longest {
			longest = n
		}
	}
	return longest, true
}

// advertisedPrefixes returns the set of prefixes advertised to a neighbour.
func advertisedPrefixes(ctx context.Context, env *Env, router, peer string) map[string]bool {
	out := map[string]bool{}
	adv, err := advertisedRoutes(ctx, env, router, peer)
	if err != nil {
		return out
	}
	for p := range adv.Table() {
		out[p] = true
	}
	return out
}

// errNoSuchNeighbour distinguishes "this router does not have that session"
// from "the router could not be read". Both used to arrive as a bare error and
// were dropped together, so a session that could not be assessed was indistinguishable
// from one the student never configured.
var errNoSuchNeighbour = errors.New("no such neighbour")

func advertisedRoutes(ctx context.Context, env *Env, router, peer string) (bgpRouteJSON, error) {
	var adv bgpRouteJSON
	out, err := env.Vtysh(ctx, router,
		fmt.Sprintf("show ip bgp neighbors %s advertised-routes json", peer))
	if err != nil {
		return adv, err
	}
	if err := jsonUnmarshalLoose(out, &adv); err != nil {
		return adv, fmt.Errorf("%s: could not read what is advertised to %s: %w", router, peer, err)
	}
	if adv.NoSuchNeighbour() {
		return adv, fmt.Errorf("%s has no BGP session with %s: %w", router, peer, errNoSuchNeighbour)
	}
	if !adv.Decoded() {
		// An unrecognised document must never pass for an empty table: that is
		// exactly how a policy check silently became an unconditional pass.
		return adv, fmt.Errorf("%s: the advertised-routes output for %s was not recognised", router, peer)
	}
	return adv, nil
}

// worstLocalPref returns the lowest local preference on any route learned from
// a neighbour, the highest, and how many routes there were.
//
// It used to be the median, which is a statement about most routes and about no
// particular one -- the same loophole that was closed in the Gao-Rexford check
// and left open here. Setting one prefix learned over the slow provider to a
// preference above the fast one's moves neither median, so the question about
// engineering traffic around the slow link passed while traffic for that prefix
// took it. Comparing the extremes is what makes the claim true of every route.
func worstLocalPref(ctx context.Context, env *Env, peer string) (lo, hi, n int) {
	lo, hi = 1<<30, -1
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for _, entries := range tbl.Table() {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					if nh.IP != peer {
						continue
					}
					n++
					if e.LocalPref < lo {
						lo = e.LocalPref
					}
					if e.LocalPref > hi {
						hi = e.LocalPref
					}
				}
			}
		}
	}
	if n == 0 {
		return 0, 0, 0
	}
	return lo, hi, n
}

// checkRPKIInvalidRejected verifies that a route whose origin is RPKI-invalid
// does not win.
func checkRPKIInvalidRejected(ctx context.Context, env *Env) Result {
	configured, detail := rpkiConfigured(ctx, env)
	if !configured {
		return Fail("rpki.invalid_rejected", Evidence{
			Expected: "an RPKI cache configured and route-maps matching validation state",
			Observed: "no RPKI configuration found",
			Detail:   detail,
			Hint:     "point your routers at the validator and match `rpki invalid` in an import route-map",
			Command:  "show running-config",
		})
	}

	// The clause must deny, and it must be attached to a session that brings
	// routes in from outside.
	//
	// Any occurrence of the words "match rpki invalid" used to count -- in a
	// permit clause, in a route-map nothing applies, in a comment-like
	// fragment. A hard-coded prefix filter plus an unused clause earned full
	// credit for policy that never ran.
	// Every session that brings routes in from outside, not just one.
	//
	// The search stopped at the first protected session, so an AS that guarded
	// one border router and left the rest accepting invalid origins scored the
	// same as one that guarded all of them. An invalid route only has to get in
	// once.
	var protected, exposed []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
		cfg := parseFRR(out)
		peers := cfg.externalNeighbours()
		if len(peers) == 0 {
			continue
		}
		// A router that brings routes in from outside needs its own validator
		// session. Validation state is per router: one with no cache sees
		// every route as not-found, so an invalid origin arriving there is
		// accepted and its invalid table is empty -- which the table check
		// below reads as "nothing invalid was selected". Aggregating the
		// cache across the AS made one connected router vouch for all of them.
		if !strings.Contains(out, "rpki cache ") {
			exposed = append(exposed, r.Name+" (no validator session, so nothing arriving "+
				"here can be invalid)")
			continue
		}
		// Configured is not connected. A router whose cache is declared but
		// unreachable sees every arriving route as not-found, accepts invalid
		// origins, and has an empty invalid table -- which the table half of
		// this check reads as success. Liveness was aggregated across the
		// autonomous system, so one healthy router vouched for all of them.
		if conn, _ := env.Vtysh(ctx, r.Name, "show rpki cache-connection"); !strings.Contains(conn, "Connected") {
			exposed = append(exposed, r.Name+" (its validator session is configured but not "+
				"connected, so nothing arriving here can be invalid)")
			continue
		}
		for _, peer := range peers {
			if denyMatches(cfg.appliedBody(peer, "in"), "rpki invalid") {
				protected = append(protected, r.Name+" "+peer)
				continue
			}
			exposed = append(exposed, r.Name+" "+peer)
		}
	}
	rejects := len(protected) > 0 && len(exposed) == 0
	var unattached []string
	if len(exposed) > 0 {
		sort.Strings(exposed)
		hint := "a route-map that is not attached to a session does not run; check " +
			"`neighbor <addr> route-map <name> in` on every external session"
		score := 0.4
		if len(protected) > 0 {
			score = 0.5
			hint = "some sessions are guarded and some are not; an invalid route only has " +
				"to arrive on one of them"
		}
		return Partial("rpki.invalid_rejected", score, Evidence{
			Expected: "a deny clause matching `rpki invalid`, applied inbound on every " +
				"session that brings routes in from outside",
			Observed: fmt.Sprintf("%d of %d external session(s) accept invalid origins",
				len(exposed), len(exposed)+len(protected)),
			Detail:  strings.Join(truncate(exposed, 6), "\n"),
			Hint:    hint,
			Command: "show running-config",
		})
	}
	if !rejects && len(unattached) > 0 {
		sort.Strings(unattached)
		return Partial("rpki.invalid_rejected", 0.4, Evidence{
			Expected: "a deny clause matching `rpki invalid`, applied inbound on the sessions " +
				"that bring routes in from outside",
			Observed: fmt.Sprintf("%s match on the invalid state, but not in a deny clause "+
				"applied inbound to an external neighbour", strings.Join(unattached, ", ")),
			Hint: "a route-map that is not attached to a session does not run; check " +
				"`neighbor <addr> route-map <name> in`",
			Command: "show running-config",
		})
	}
	if !rejects {
		return Partial("rpki.invalid_rejected", 0.4, Evidence{
			Expected: "invalid-origin routes rejected",
			Observed: "an RPKI cache is configured but nothing matches the invalid state",
			Detail:   detail,
			Hint:     "add a route-map clause that denies routes matching `rpki invalid`",
		})
	}

	// An empty invalid table is exactly what an unreachable validator produces:
	// with no ROAs, every route is "notfound" and nothing is ever invalid. So
	// "no invalid route is selected" on its own is not evidence of anything.
	// Validation must be shown to be running before its silence means anything.
	live, liveDetail := rpkiValidating(ctx, env)
	if !live {
		return Partial("rpki.invalid_rejected", 0.5, Evidence{
			Expected: "a validator session that is up, with ROAs received and applied to the BGP table",
			Observed: liveDetail,
			Detail:   detail,
			Hint: "the route-maps are right, but nothing is validating: with no ROAs every route is " +
				"`notfound`, so no route can be invalid and the policy never fires",
			Command: "show rpki cache-connection",
		})
	}

	// And confirm no invalid route is actually selected. A router whose table
	// could not be read is not evidence that it selects nothing.
	var selected, unread []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show bgp ipv4 unicast rpki invalid")
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if selectedRoute(line) {
				selected = append(selected, strings.TrimSpace(r.Name+": "+line))
			}
		}
	}
	if len(unread) > 0 {
		return Partial("rpki.invalid_rejected", 0.6, Evidence{
			Expected: "no invalid route selected on any router",
			Observed: fmt.Sprintf("%d router(s) could not be asked", len(unread)),
			Detail:   strings.Join(unread, "\n"),
			Hint:     "an unanswered router is not a router with a clean table",
			Command:  "show bgp ipv4 unicast rpki invalid",
		})
	}
	if len(selected) == 0 {
		// Nothing selected means nothing only if there was something to
		// reject. The lab declares a ROA held by one AS for a prefix inside
		// another's space, and for a while nothing announced that prefix: no
		// route anywhere in the lab was ever invalid, so "no invalid route is
		// selected" was true of a router that had done nothing at all. The
		// premise is checked where the student cannot influence it.
		if why := hijackIsAnnounced(ctx, env); why != "" {
			return Errored("rpki.invalid_rejected", fmt.Errorf(
				"this lab is not announcing anything RPKI-invalid, so rejecting it "+
					"cannot be observed and no verdict here would mean anything: %s", why))
		}
		// And something did get in.
		//
		// "No invalid route is selected" is trivially true of an AS that
		// selected no external route at all. A deny-everything clause placed
		// ahead of the RPKI one -- the legitimate clause still present and
		// still reachable in the configuration -- left this AS with nothing
		// in its table but its own prefix, and this check awarded full marks
		// for rejecting an invalid origin it had never been in a position to
		// accept. A rejection means something only against a background of
		// acceptance.
		accepted, aerr := externalRoutesSelected(ctx, env)
		if aerr != nil {
			return Errored("rpki.invalid_rejected", aerr)
		}
		if accepted == 0 {
			return Fail("rpki.invalid_rejected", Evidence{
				Expected: "the invalid origin refused and everything else accepted",
				Observed: "this AS has selected no externally learned route at all, so " +
					"refusing the invalid one shows nothing",
				Hint: "an import policy that denies everything rejects the invalid origin " +
					"and the rest of the internet with it; deny on the validation state, " +
					"not on the prefix",
				Command: "show ip bgp json",
			})
		}
		return Pass("rpki.invalid_rejected", Evidence{
			Observed: fmt.Sprintf("validation is live, %d externally learned route(s) are "+
				"selected, and the lab's invalid announcement is not among them", accepted),
			Detail: liveDetail + "\n" + detail})
	}
	return Partial("rpki.invalid_rejected", 0.6, Evidence{
		Expected: "no invalid route selected",
		Observed: fmt.Sprintf("%d invalid route(s) still chosen", len(selected)),
		Detail:   strings.Join(truncate(selected, 5), "\n"),
	})
}

// externalRoutesSelected counts the destinations this AS learned from outside
// and chose to use.
//
// It is the background any claim about refusing one route has to be read
// against: an AS that accepted nothing has not shown that it refused anything
// in particular.
func externalRoutesSelected(ctx context.Context, env *Env) (int, error) {
	seen := map[string]bool{}
	read := 0
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		read++
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if e.IsBest() && strings.TrimSpace(e.Path) != "" {
					seen[prefix] = true
				}
			}
		}
	}
	if read == 0 {
		return 0, fmt.Errorf("no router's table could be read, so what this AS accepted " +
			"cannot be established")
	}
	return len(seen), nil
}

// checkRPKINotFoundPreserved guards against over-filtering: a student who
// rejects everything without a ROA would break connectivity to every AS that
// has not yet issued one, which the assignment explicitly forbids.
func checkRPKINotFoundPreserved(ctx context.Context, env *Env) Result {
	if configured, detail := rpkiConfigured(ctx, env); !configured {
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "RPKI configured without over-filtering",
			Observed: "no RPKI configuration found",
			Detail:   detail,
		})
	}
	var denies []string
	cfgs, err := runningConfigs(ctx, env)
	if err != nil {
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "every router's configuration readable, with no clause denying not-found routes",
			Observed: "some configurations could not be read",
			Detail:   err.Error(),
			Hint:     "make sure FRR is running on every router before submitting",
			Command:  "show running-config",
		})
	}
	for _, r := range env.Routers() {
		out := cfgs[r.Name]
		lines := strings.Split(out, "\n")
		for i, line := range lines {
			if !strings.Contains(strings.ToLower(line), "match rpki notfound") {
				continue
			}
			// Walk back to the enclosing route-map clause to see whether this
			// match sits under a deny.
			for j := i; j >= 0 && j > i-8; j-- {
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "route-map ") {
					if strings.Contains(t, " deny ") {
						denies = append(denies, fmt.Sprintf("%s: %s", r.Name, t))
					}
					break
				}
			}
		}
	}
	if len(denies) > 0 {
		sort.Strings(denies)
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "not-found routes remain usable",
			Observed: fmt.Sprintf("%d route-map(s) deny them", len(denies)),
			Detail:   strings.Join(denies, "\n"),
			Hint:     "most of the Internet has no ROA; rejecting not-found would cut you off from it",
		})
	}

	// The text search above only catches the obvious spelling. A clause that
	// denies everything, or that permits only what is valid and falls off the
	// end of the route-map, drops every not-found route without the words
	// "match rpki notfound" appearing anywhere -- and used to pass.
	//
	// So the table is read. Every other system whose block has no ROA is a
	// route this AS must still hold; if one is missing, the filtering is too
	// broad whatever it is written as, and the missing prefix is named.
	missing, checked, err := missingNotFoundRoutes(ctx, env)
	if err != nil {
		return Errored("rpki.notfound_preserved", err)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Fail("rpki.notfound_preserved", Evidence{
			Expected: "routes to systems that have published no ROA are still accepted",
			Observed: fmt.Sprintf("%d of %d such prefix(es) are absent from this AS's table",
				len(missing), checked),
			Detail: strings.Join(truncate(missing, 6), "\n"),
			Hint: "most of the Internet has no ROA; a policy that keeps only what is valid " +
				"cuts you off from it, however it is written",
			Command: "show bgp ipv4 unicast rpki notfound",
		})
	}
	if checked == 0 {
		return Pass("rpki.notfound_preserved", Evidence{
			Observed: "no route-map denies not-found routes",
			Detail: "no other system in this lab announces a prefix without a ROA, so " +
				"there was no not-found route to lose"})
	}
	return Pass("rpki.notfound_preserved", Evidence{
		Observed: fmt.Sprintf("all %d prefix(es) without a ROA are still in this AS's table", checked),
		Command:  "show bgp ipv4 unicast rpki notfound"})
}

// missingNotFoundRoutes names the prefixes this AS should hold and does not,
// among those whose origin has published no ROA.
func missingNotFoundRoutes(ctx context.Context, env *Env) ([]string, int, error) {
	covered, err := roaPrefixes(ctx, env)
	if err != nil {
		return nil, 0, err
	}

	// Every router, and the route each of them has selected.
	//
	// One router's table was read, on the reasoning that iBGP carries the AS's
	// view and a prefix filtered at the border is absent from all of them. The
	// reasoning holds for a border filter and for nothing else: an inbound
	// policy on one router's iBGP sessions removes the prefix from that router
	// alone, and the site behind it cannot reach the network -- 100% packet
	// loss and "Destination Net Unreachable" were measured while this check
	// reported all prefixes present and the system scored full marks. A
	// question about what a system preserves is a question about all of it.
	routers := env.Routers()
	if len(routers) == 0 {
		return nil, 0, fmt.Errorf("AS %d has no router to read", env.AS)
	}
	// Present, per router. A router that cannot be read stops the check: this
	// concludes from what it does not find, so an unreadable router is one
	// whose missing routes would also not have been found.
	haveOn := map[string]map[string]bool{}
	// Where the selected route came from, per prefix. A route this AS
	// originated itself is not a route it preserved.
	forged := map[string][]string{}
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: its table could not be read, so whether it still "+
				"holds the routes without a ROA cannot be decided: %w", r.Name, err)
		}
		seen := map[string]bool{}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				// Selected, not merely present: a route the router holds and
				// does not use carries no traffic.
				if !e.IsBest() {
					continue
				}
				seen[prefix] = true
				// Originated here, not learned from anybody.
				//
				// A submission that filtered the real route away and then
				// announced the same prefix itself -- to Null0, with a forged
				// AS path -- had the prefix selected on every router and
				// passed. The AS path can be written to say anything; where
				// the route entered cannot. FRR gives a locally sourced route
				// a next hop of 0.0.0.0.
				if locallySourced(e) {
					forged[prefix] = append(forged[prefix], r.Name)
				}
			}
		}
		haveOn[r.Name] = seen
	}

	var missing []string
	checked := 0
	for asn, as := range env.Topology.ASes {
		if asn == env.AS || as.Block == "" || as.Role == model.RoleIXP {
			continue
		}
		if covered[as.Block] {
			continue
		}
		checked++
		var without []string
		for _, r := range routers {
			if !haveOn[r.Name][as.Block] {
				without = append(without, r.Name)
			}
		}
		if len(without) > 0 {
			sort.Strings(without)
			missing = append(missing, fmt.Sprintf("%s (AS %d) is not selected on %s",
				as.Block, asn, strings.Join(truncate(without, 4), ", ")))
			continue
		}
		if who := forged[as.Block]; len(who) > 0 {
			sort.Strings(who)
			missing = append(missing, fmt.Sprintf(
				"%s (AS %d) is selected, but %s originates it rather than having learned it: "+
					"a route you announce yourself is not the route you were asked to preserve",
				as.Block, asn, strings.Join(truncate(who, 4), ", ")))
			continue
		}
		// And it has to carry traffic.
		//
		// The whole point of not over-filtering an unsigned origin is that the
		// network stays reachable. A route to Null0 is selected on every
		// router and reaches nobody, and so is a route whose next hop does not
		// resolve; both used to pass. The probe is the only thing that can
		// tell a preserved route from a convincing imitation of one.
		src, dst := hostIn(env.Topology, env.AS), hostIn(env.Topology, asn)
		if src == nil || dst == nil {
			continue
		}
		addr := siteAddr(dst)
		if addr == "" {
			continue
		}
		ok, err := env.reaches(ctx, src.ID, addr)
		if err != nil {
			return nil, 0, fmt.Errorf("probing %s from %s: %w", addr, src.ID, err)
		}
		if !ok {
			missing = append(missing, fmt.Sprintf(
				"%s (AS %d) is in every table, but %s cannot reach %s: the route is preserved "+
					"in name only", as.Block, asn, src.Name, addr))
		}
	}
	return missing, checked, nil
}

// locallySourced reports whether a route was originated by this AS rather than
// learned from a neighbour. FRR gives such a route a next hop of 0.0.0.0.
func locallySourced(e bgpRoute) bool {
	hops := e.NextHops()
	if len(hops) == 0 {
		return false
	}
	for _, h := range hops {
		if h != "0.0.0.0" {
			return false
		}
	}
	return true
}

// roaPrefixes is the set of prefixes the validator has a ROA for.
func roaPrefixes(ctx context.Context, env *Env) (map[string]bool, error) {
	out := map[string]bool{}
	for _, r := range env.Routers() {
		text, err := env.Vtysh(ctx, r.Name, "show rpki prefix-table")
		if err != nil {
			continue
		}
		// The table prints the address and the prefix length in separate
		// columns -- "6.0.0.0   8 -   8   6" -- and never as "6.0.0.0/8".
		// Looking for a slash therefore matched nothing at all, so every
		// system appeared to have no ROA and the check quietly became a test
		// that this AS holds a route to every other one.
		for k := range parseROATable(text) {
			out[k] = true
		}
		return out, nil
	}
	return out, nil
}

// rpkiConfigured reports whether any router has an RPKI cache configured.
func rpkiConfigured(ctx context.Context, env *Env) (bool, string) {
	var found []string
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show running-config")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "rpki cache ") {
				found = append(found, r.Name+": "+t)
			}
		}
	}
	if len(found) == 0 {
		return false, "no `rpki cache` statement on any router"
	}
	sort.Strings(found)
	return true, strings.Join(found, "\n")
}

// deviceAddr6 returns the IPv6 address a host actually has, falling back to the
// one the manifest planned.
//
// The assignment lets a group choose their own datacentre addressing. Reading
// it out of the plan marked a group wrong for an answer the assignment permits:
// the check would ping an address nobody had configured and report the
// datacentre unreachable.
func deviceAddr6(ctx context.Context, env *Env, d *model.Device) string {
	res, err := env.Exec(ctx, d.ID, []string{"sh", "-c",
		"ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}'"})
	if err == nil && res.ExitCode == 0 {
		for _, f := range strings.Fields(res.Stdout) {
			if p, err := netip.ParsePrefix(f); err == nil && p.Addr().Is6() {
				return p.Addr().String()
			}
		}
	}
	return firstAddr6(d)
}

func firstAddr6(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Addr6 != "" {
			if j := strings.IndexByte(i.Addr6, '/'); j > 0 {
				return i.Addr6[:j]
			}
			return i.Addr6
		}
	}
	return ""
}

func parseMillis(s string) float64 {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasSuffix(s, "ms"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64)
		return v
	case strings.HasSuffix(s, "s"):
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
		return v * 1000
	}
	return 0
}

func uniq(in []string) []string {
	out := in[:0]
	var prev string
	for i, s := range in {
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

// rpkiValidating reports whether origin validation is actually operating, as
// opposed to merely being configured.
//
// Three things have to hold, and each has been seen to fail on its own: the
// session to the validator is established, ROAs have arrived, and the BGP table
// reflects them. A cache that FRR never connected to leaves all three of the
// per-state tables empty, which reads identically to a network in which every
// route is legitimate.
func rpkiValidating(ctx context.Context, env *Env) (bool, string) {
	var connected, withROAs, validated []string
	for _, r := range env.Routers() {
		if out, err := env.Vtysh(ctx, r.Name, "show rpki cache-connection"); err == nil &&
			strings.Contains(strings.ToLower(out), "connected") {
			connected = append(connected, r.Name)
		}
		if out, err := env.Vtysh(ctx, r.Name, "show rpki prefix-table"); err == nil {
			if n := countROAs(out); n > 0 {
				withROAs = append(withROAs, fmt.Sprintf("%s: %d ROAs", r.Name, n))
			}
		}
		if out, err := env.Vtysh(ctx, r.Name, "show bgp ipv4 unicast rpki valid"); err == nil &&
			strings.Contains(out, "V") && strings.Contains(out, "Displayed") {
			validated = append(validated, r.Name)
		}
	}
	sort.Strings(connected)
	sort.Strings(withROAs)
	switch {
	case len(connected) == 0:
		return false, "no router has an established session with a validator"
	case len(withROAs) == 0:
		return false, fmt.Sprintf("%d router(s) reached a validator but received no ROAs", len(connected))
	case len(validated) == 0:
		return false, fmt.Sprintf("ROAs were received (%s) but no route carries a validation state",
			strings.Join(truncate(withROAs, 3), ", "))
	}
	return true, fmt.Sprintf("%d router(s) connected to a validator, %s, %d with validated routes",
		len(connected), strings.Join(truncate(withROAs, 3), ", "), len(validated))
}

// countROAs counts prefix entries in `show rpki prefix-table` output.
func countROAs(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// "6.0.0.0   8 -   8   6": address, length, "-", maxlen, origin AS.
		if len(f) >= 5 && strings.Count(f[0], ".") == 3 {
			n++
		}
	}
	return n
}

// configuredTunnel returns the name of a 6in4 tunnel with both endpoints set.
//
// `ip -d tunnel show` always lists the kernel's sit0 with "remote any local
// any"; it is not the student's work and matching it awards the mark before
// the exercise is begun.
//
// The encapsulation is checked, not just the endpoints. The question asks for
// IPv6 over IPv4 -- protocol 41, a SIT device, printed by iproute2 as
// "ipv6/ip". A GRE tunnel between the same two addresses also carries the
// traffic and also moves the counters, so accepting any tunnel with two
// endpoints gave the mark for a different answer to a different question.
func configuredTunnel(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "remote ") || !strings.Contains(line, "local ") {
			continue
		}
		fields := strings.Fields(line)
		name := strings.TrimSuffix(fields[0], ":")
		if name == "sit0" || name == "" {
			continue
		}
		if len(fields) < 2 || fields[1] != "ipv6/ip" {
			continue
		}
		if fieldAfter(line, "remote") == "any" || fieldAfter(line, "local") == "any" {
			continue
		}
		return name
	}
	return ""
}

// tunnelTx reads a tunnel's transmitted packet count.
func tunnelTx(ctx context.Context, env *Env, device, iface string) int {
	if iface == "" {
		return -1
	}
	res, err := env.Probe(ctx, device, []string{"sh", "-c",
		"cat /sys/class/net/" + iface + "/statistics/tx_packets 2>/dev/null"})
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(res.Stdout))
	if err != nil {
		return -1
	}
	return n
}

// fieldAfter returns the token following a keyword on a line.
func fieldAfter(line, key string) string {
	f := strings.Fields(line)
	for i, x := range f {
		if x == key && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// inRegionRoutesViaIXP names the routes this AS accepted from the exchange
// whose path crosses a system in its own region.
//
// The question asks for those to be refused: an in-region network should be
// reached directly, not across the exchange. Whether they are refused is a fact
// about the table, and reading the route-map instead gave the mark to a filter
// attached to nothing.
//
// The session is asked, not the next hop. At an exchange with a route server
// the next hop of a relayed route is the *originating member's* address, not
// the route server's, so selecting by next hop finds nothing at all and the
// check passes for everybody -- vacuous in exactly the way it was written to
// stop. `show ip bgp neighbors <rs> routes` is what the router itself
// considers to have come from that session, after policy.
// routeServerOffersOutOfRegion reports how many of the routes the exchange is
// relaying to this AS are ones it ought to accept.
//
// Requiring a member to accept *something* is only fair when something it
// should accept is on offer. At an exchange whose other members are all in
// this AS's own region, refusing everything is the correct answer, and an
// exchange that is relaying nothing at all is the lab's doing rather than the
// submission's.
func routeServerOffersOutOfRegion(ctx context.Context, env *Env, rsDevice, ourAddr string,
	inRegion map[int]bool) (int, error) {
	res, err := env.Probe(ctx, rsDevice, []string{"vtysh", "-c",
		fmt.Sprintf("show ip bgp neighbors %s advertised-routes json", ourAddr)})
	if err != nil {
		return 0, fmt.Errorf("asking the route server what it relays to %s: %w", ourAddr, err)
	}
	var got bgpRouteJSON
	if jerr := jsonUnmarshalLoose(res.Stdout, &got); jerr != nil {
		return 0, fmt.Errorf("reading what the route server relays to %s: %w", ourAddr, jerr)
	}
	n := 0
	for _, entries := range got.Table() {
		for _, e := range entries {
			crosses := false
			for _, f := range strings.Fields(e.Path) {
				if asn, cerr := strconv.Atoi(f); cerr == nil && inRegion[asn] {
					crosses = true
					break
				}
			}
			if !crosses {
				n++
			}
		}
	}
	return n, nil
}

// routesViaIXP splits what this AS accepted from the exchange into the routes
// whose path crosses a system in its own region -- which the exercise says to
// refuse -- and the rest, which it exists to accept.
//
// Both halves matter. Only the first was ever read, so an inbound policy that
// denied everything from the exchange admitted no in-region route and passed:
// a member that hears nothing from the exchange and sends nothing to it has not
// implemented the peering policy, it has switched the exchange off.
// ixpInRegion is the set the exercise names and the reference answer filters
// on: the other *student* systems of this AS's region.
//
// The staff systems are everybody's transit and are reached through the
// exchange like any out-of-region member; counting them as in-region made the
// reference solution fail its own question the moment the exchange began
// delivering routes at all.
func ixpInRegion(env *Env) map[int]bool {
	out := map[int]bool{}
	me, ok := env.Topology.ASes[env.AS]
	if !ok || me.Region == "" {
		return out
	}
	for asn, as := range env.Topology.ASes {
		if asn != env.AS && as.Region == me.Region && as.Role == model.RoleStudent {
			out[asn] = true
		}
	}
	return out
}

func routesViaIXP(ctx context.Context, env *Env, router, ixpPeer string) (in, out []string, err error) {
	if _, ok := env.Topology.ASes[env.AS]; !ok {
		return nil, nil, fmt.Errorf("AS %d not in the lab", env.AS)
	}
	// The same set the exercise names, and the same one the reference answer
	// filters on: the other *student* systems of this region. The staff
	// systems are everybody's transit and are reached through the exchange
	// like any out-of-region member, so counting them as in-region made the
	// reference solution fail its own question the moment the exchange
	// started delivering routes at all.
	inRegion := ixpInRegion(env)
	var got bgpRouteJSON
	body, verr := env.Vtysh(ctx, router,
		fmt.Sprintf("show ip bgp neighbors %s routes json", ixpPeer))
	if verr != nil {
		return nil, nil, fmt.Errorf("reading what %s accepted from the exchange: %w", router, verr)
	}
	if jerr := jsonUnmarshalLoose(body, &got); jerr != nil {
		return nil, nil, fmt.Errorf("reading what %s accepted from the exchange: %w", router, jerr)
	}
	for prefix, entries := range got.Table() {
		for _, e := range entries {
			crosses := false
			for _, f := range strings.Fields(e.Path) {
				if n, cerr := strconv.Atoi(f); cerr == nil && inRegion[n] {
					crosses = true
					break
				}
			}
			if crosses {
				in = append(in, fmt.Sprintf("%s (path %q)", prefix, strings.TrimSpace(e.Path)))
			} else {
				out = append(out, prefix)
			}
		}
	}
	sort.Strings(in)
	sort.Strings(out)
	return uniq(in), uniq(out), nil
}

// tunnelEndpointsWrong reports why a tunnel's endpoints are not the two
// gateways' loopbacks, or "" if they are.
func tunnelEndpointsWrong(out, name string, gw *model.Device,
	gateways map[string]*model.Device, domains []string, self string) string {

	line := lineContaining(out, name+":")
	if line == "" {
		return ""
	}
	local := fieldAfter(line, "local")
	remote := fieldAfter(line, "remote")

	want := ""
	if lo, ok := gw.IfaceByName("lo"); ok {
		want = ipOnly(lo.Addr4)
	}
	if want != "" && local != want {
		return fmt.Sprintf("its tunnel is sourced from %s, not its loopback %s; a tunnel "+
			"anchored to an interface address stops working when that link does", local, want)
	}

	var peer *model.Device
	for _, d := range domains {
		if d != self {
			peer = gateways[d]
		}
	}
	if peer == nil {
		return ""
	}
	wantRemote := ""
	if lo, ok := peer.IfaceByName("lo"); ok {
		wantRemote = ipOnly(lo.Addr4)
	}
	if wantRemote != "" && remote != wantRemote {
		return fmt.Sprintf("its tunnel points at %s, not %s's loopback %s",
			remote, peer.Name, wantRemote)
	}
	return ""
}

// lineContaining returns the first line of output that mentions a string.
func lineContaining(out, want string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// parseROATable reads `show rpki prefix-table` as FRR prints it: the address
// and the prefix length in separate columns, never joined by a slash.
func parseROATable(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.Count(f[0], ".") != 3 {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			continue
		}
		out[f[0]+"/"+f[1]] = true
	}
	return out
}

// hijackIsAnnounced confirms the lab actually carries an RPKI-invalid
// announcement, and returns why it does not when it does not.
//
// It asks the AS that originates it, which is staff-operated: a student can
// neither remove the announcement nor fake it. Asking the student's own routers
// would be circular -- a submission that correctly rejects the hijack has no
// trace of it, which is exactly the state this is distinguishing from a lab
// where the hijack was never announced.
func hijackIsAnnounced(ctx context.Context, env *Env) string {
	hijacker, prefix := svc.HijackOrigin(env.Topology)
	if hijacker == 0 || prefix == "" {
		return "no autonomous system is configured to originate a mis-attributed prefix"
	}
	as, ok := env.Topology.ASes[hijacker]
	if !ok || len(as.Routers) == 0 {
		return fmt.Sprintf("AS %d should originate %s but has no routers", hijacker, prefix)
	}
	var why []string
	for _, r := range as.Routers {
		res, err := env.Probe(ctx, r.ID, []string{"vtysh", "-c", "show bgp ipv4 unicast " + prefix})
		if err != nil {
			why = append(why, fmt.Sprintf("%s: %v", r.ID, err))
			continue
		}
		if res.ExitCode == 0 && strings.Contains(res.Stdout, prefix) {
			return ""
		}
		why = append(why, fmt.Sprintf("%s does not have %s in its table", r.ID, prefix))
	}
	return strings.Join(truncate(why, 3), "; ")
}

// selectedRouteRE matches a route line FRR marks as chosen.
//
// The status field is not just "*>". When origin validation is on, FRR puts
// the validation code first and the line reads "I*> 10.128.0.0/9", and this
// check looked for a "*>" prefix -- on the output of `show bgp ipv4 unicast
// rpki invalid`, where every line carries a validation code by construction.
// So the one thing it existed to notice, an invalid route still being chosen,
// was the one thing it could never match, and the check passed on every
// submission including ones that had configured no validation at all.
var selectedRouteRE = regexp.MustCompile(`^[A-Za-z]*\*?>`)

func selectedRoute(line string) bool {
	return selectedRouteRE.MatchString(strings.TrimSpace(line))
}

// forwardsVia reports whether a device would send a packet for an address out
// of the interface it is supposed to, and names the interface it would use.
//
// This is what the tunnel question is about. A counter says traffic crossed the
// tunnel; it does not say *which* traffic, and a total can be moved by anything
// the submission cares to send.
func forwardsVia(ctx context.Context, env *Env, deviceID, addr, want string) (string, bool) {
	res, err := env.Probe(ctx, deviceID, []string{"ip", "-6", "route", "get", addr})
	if err != nil || res.ExitCode != 0 {
		return "", false
	}
	f := strings.Fields(res.Stdout)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], f[i+1] == want
		}
	}
	return "", false
}

// crossDatacentreGaps names the host pairs that cannot reach each other across
// the two datacentres, in both directions.
//
// The question is about the datacentres. Testing one host in each, one way, let
// a submission that configured one VLAN and not the other -- or the forward
// path and not the return -- score the whole point.
func crossDatacentreGaps(ctx context.Context, env *Env, hostsIn map[string][]*model.Device,
	domains []string, gateways map[string]*model.Device, tunnels map[string]string) []string {

	var gaps []string
	const packets = 2
	for i, from := range domains {
		for j, to := range domains {
			if i == j {
				continue
			}
			for _, src := range hostsIn[from] {
				for _, dst := range hostsIn[to] {
					addr := deviceAddr6(ctx, env, dst)
					if addr == "" {
						gaps = append(gaps, fmt.Sprintf("%s (%s) has no IPv6 address",
							dst.Name, to))
						continue
					}
					// The tunnel counter is bracketed around every pair, not
					// only the first one.
					//
					// Reachability alone was the test here, and it does not
					// distinguish encapsulated traffic from native IPv6: a
					// system with a /128 tunnel route for the one pair the
					// check happened to measure and native IPv6 for the rest
					// scored the whole mark for an answer that does not use the
					// tunnel at all.
					gw, tun := gateways[from], tunnels[from]
					before := -1
					if gw != nil {
						before = tunnelTx(ctx, env, gw.ID, tun)
					}
					res, err := env.Probe(ctx, src.ID,
						[]string{"ping6", "-c", strconv.Itoa(packets), "-W", "4", "-i", "0.3", addr})
					if err != nil {
						gaps = append(gaps, fmt.Sprintf("%s could not be asked to reach %s: %v",
							src.Name, dst.Name, err))
						continue
					}
					if res.ExitCode != 0 {
						gaps = append(gaps, fmt.Sprintf("%s (%s) cannot reach %s (%s) at %s",
							src.Name, from, dst.Name, to, addr))
						continue
					}
					if gw == nil || tun == "" || before < 0 {
						continue
					}
					after := tunnelTx(ctx, env, gw.ID, tun)
					if after < 0 {
						gaps = append(gaps, fmt.Sprintf(
							"%s reaches %s (%s), but %s could not be read on %s, so there is "+
								"no evidence the traffic was encapsulated",
							src.Name, dst.Name, to, tun, gw.Name))
						continue
					}
					if after-before < packets {
						gaps = append(gaps, fmt.Sprintf(
							"%s (%s) reaches %s (%s) at %s, but %s on %s carried %d packet(s) "+
								"while %d were sent, so that traffic is routed natively rather "+
								"than through the tunnel",
							src.Name, from, dst.Name, to, addr, tun, gw.Name,
							after-before, packets))
					}
				}
			}
		}
	}
	sort.Strings(gaps)
	return gaps
}

// sortedInts returns the keys of a set in order.
func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// installedVia names the destinations whose selected route leaves through one
// of the slow addresses, when a path through a fast one is also available.
//
// It reads the routing table rather than BGP, because that is where a static
// route, a policy route or an administrative distance shows up and BGP does
// not. Every router is asked, and a router that cannot be read stops the check:
// concluding "nothing goes the slow way" from the routers that answered is the
// kind of verdict this project keeps having to take back.
func installedVia(ctx context.Context, env *Env, slow, fast []string) (via []string, unreadable string) {
	isSlow := map[string]bool{}
	for _, a := range slow {
		isSlow[a] = true
	}
	isFast := map[string]bool{}
	for _, a := range fast {
		isFast[a] = true
	}
	// What the system as a whole has an alternative path for, so that a
	// destination nobody can reach except over the slow link is not counted
	// against a student who cannot avoid it.
	//
	// System-wide, not per router: the fast session is usually on a different
	// router from the slow one, so a router that holds the slow session sees
	// the fast path only as an iBGP route with an interior next hop. Computing
	// this per router found no alternative anywhere and the check passed a
	// static route straight over the slow link.
	alt := map[string]bool{}
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				for _, nh := range e.Nexthops {
					if isFast[nh.IP] {
						alt[prefix] = true
					}
				}
			}
		}
	}
	for _, r := range env.Routers() {
		var routes map[string][]struct {
			Protocol string `json:"protocol"`
			Selected bool   `json:"selected"`
			Nexthops []struct {
				IP  string `json:"ip"`
				FIB bool   `json:"fib"`
			} `json:"nexthops"`
		}
		if err := env.VtyshJSON(ctx, r.Name, "show ip route json", &routes); err != nil {
			return nil, fmt.Sprintf("%s: its routing table could not be read (%v), so where "+
				"its traffic actually goes could not be established", r.Name, err)
		}
		for prefix, entries := range routes {
			if !alt[prefix] {
				continue
			}
			for _, e := range entries {
				if !e.Selected {
					continue
				}
				for _, nh := range e.Nexthops {
					if !isSlow[nh.IP] {
						continue
					}
					via = append(via, fmt.Sprintf("%s on %s (%s)", prefix, r.Name, e.Protocol))
					break
				}
			}
		}
	}
	return via, ""
}
