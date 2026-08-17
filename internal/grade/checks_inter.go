package grade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file registers the checks that grade the inter-domain half of the
// assignment: iBGP, eBGP, business relationships, exchange policy and RPKI.

func init() {
	Register(&Check{
		Name:     "bgp.ibgp_full_mesh",
		Describe: "a BGP session exists between every pair of routers, sourced from loopbacks",
		Run:      checkIBGPFullMesh,
	})
	Register(&Check{
		Name:     "bgp.ebgp_established",
		Describe: "every external BGP session with a neighbour is established",
		Run:      checkEBGPEstablished,
	})
	Register(&Check{
		Name:     "bgp.own_prefix_only",
		Describe: "the AS originates exactly its own prefix and nothing else",
		Run:      checkOwnPrefix,
	})
	Register(&Check{
		Name:     "policy.gao_rexford",
		Describe: "routes from a customer are preferred over a peer's, and a peer's over a provider's",
		Run:      checkGaoRexford,
	})
	Register(&Check{
		Name:     "policy.no_transit_for_peers",
		Describe: "routes learned from a peer or provider are not re-exported to a peer or provider",
		Run:      checkNoTransit,
	})
	Register(&Check{
		Name:     "policy.transit_for_customers",
		Describe: "a customer receives every route this AS selected, which is the transit it pays for",
		Run:      checkTransitForCustomers,
	})
	Register(&Check{
		Name:     "config.no_forbidden_ospf",
		Describe: "inter-AS subnets are kept out of OSPF, as the assignment requires",
		Run:      checkNoForbiddenOSPF,
	})
}

// bgpSummaryJSON is the shape of `show ip bgp summary json`.
type bgpSummaryJSON struct {
	IPv4Unicast struct {
		RouterID string `json:"routerId"`
		AS       int    `json:"as"`
		Peers    map[string]struct {
			RemoteAs      int    `json:"remoteAs"`
			State         string `json:"state"`
			PfxRcd        int    `json:"pfxRcd"`
			PfxSnt        int    `json:"pfxSnt"`
			PeerUptimeMs  int64  `json:"peerUptimeMsec"`
			ConnectionsEs int    `json:"connectionsEstablished"`
			MsgRcvd       int64  `json:"msgRcvd"`
			MsgSent       int64  `json:"msgSent"`
		} `json:"peers"`
	} `json:"ipv4Unicast"`
}

// summary fetches a router's BGP summary, tolerating a router with no BGP.
func bgpSummary(ctx context.Context, env *Env, router string) (bgpSummaryJSON, error) {
	var out bgpSummaryJSON
	err := env.VtyshJSON(ctx, router, "show ip bgp summary json", &out)
	return out, err
}

// bgpUpdatesReceived reads, per router and per neighbour, how many UPDATE
// messages have arrived on that session.
//
// Not the total of all messages. A firewall permitting keepalives and route
// refreshes by packet length, and discarding everything else, left the totals
// climbing on a session across which no route could pass: the refresh the
// grader asked for was itself the traffic it then counted. An UPDATE is what a
// session exists to carry, and answering a refresh with one is what a live
// session does.
func bgpUpdatesReceived(ctx context.Context, env *Env, routers []*model.Device) map[string]map[string]int {
	out := map[string]map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range routers {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			res, err := env.Probe(ctx, r.ID, []string{"vtysh", "-c", "show bgp neighbors json"})
			if err != nil || res.ExitCode != 0 {
				return
			}
			var doc map[string]struct {
				MessageStats struct {
					UpdatesRecv int `json:"updatesRecv"`
				} `json:"messageStats"`
			}
			if json.Unmarshal([]byte(res.Stdout), &doc) != nil {
				return
			}
			byPeer := map[string]int{}
			for addr, n := range doc {
				byPeer[addr] = n.MessageStats.UpdatesRecv
			}
			mu.Lock()
			out[r.Name] = byPeer
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
}

// bgpSummaries reads every router's BGP summary at once.
func bgpSummaries(ctx context.Context, env *Env, routers []*model.Device) map[string]bgpSummaryJSON {
	out := map[string]bgpSummaryJSON{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range routers {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			sum, err := bgpSummary(ctx, env, r.Name)
			if err != nil {
				return
			}
			mu.Lock()
			out[r.Name] = sum
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
}

// refreshIBGP asks every router to re-send its table to every other, so that
// each session has to carry a message while the check is watching.
func refreshIBGP(ctx context.Context, env *Env, routers []*model.Device, loopback map[string]string) {
	var wg sync.WaitGroup
	for _, r := range routers {
		var cmds []string
		for _, other := range routers {
			if other == r || loopback[other.Name] == "" {
				continue
			}
			cmds = append(cmds, "clear bgp "+loopback[other.Name]+" soft in")
		}
		if len(cmds) == 0 {
			continue
		}
		wg.Add(1)
		go func(r *model.Device, cmds []string) {
			defer wg.Done()
			args := []string{"vtysh"}
			for _, c := range cmds {
				args = append(args, "-c", c)
			}
			_, _ = env.Probe(ctx, model.DeviceID(env.AS, r.Name), args)
		}(r, cmds)
	}
	wg.Wait()
	// Long enough for a refresh and the answer to it to cross a link that may
	// be on another machine, and short enough not to matter.
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

func checkIBGPFullMesh(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) < 2 {
		return Errored("bgp.ibgp_full_mesh", fmt.Errorf("AS %d has %d routers", env.AS, len(routers)))
	}
	// The expected peer address of each router is its loopback: the assignment
	// is explicit that iBGP must be sourced from loopbacks so a session does
	// not drop when one physical interface goes down.
	loopback := map[string]string{}
	for _, r := range routers {
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			loopback[r.Name] = addrOf(lo.Addr4)
		}
	}

	want := len(routers) * (len(routers) - 1)
	established := 0
	var problems []string

	// "Established" is a memory, not an observation.
	//
	// A session whose packets are being discarded stays Established until the
	// hold timer expires -- three minutes with the default timers, longer than
	// a grading run. A reviewer blackholed an iBGP session in both directions
	// immediately after a keepalive, confirmed ten packets dropped each way,
	// and the mesh scored full marks for a session that was carrying nothing.
	//
	// So each router is asked to send something now. A route refresh is a real
	// message that must cross the connection, and the peer's own received
	// count records its arrival; it also makes the peer answer, so the counts
	// move in both directions. It disturbs nothing: the peer re-sends routes
	// the receiver already has.
	before := bgpUpdatesReceived(ctx, env, routers)
	refreshIBGP(ctx, env, routers, loopback)
	updates := bgpUpdatesReceived(ctx, env, routers)
	after := bgpSummaries(ctx, env, routers)

	for _, r := range routers {
		sum, ok := after[r.Name]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: its BGP summary could not be read", r.Name))
			continue
		}
		for _, other := range routers {
			if other == r {
				continue
			}
			addr := loopback[other.Name]
			if addr == "" {
				continue
			}
			p, ok := sum.IPv4Unicast.Peers[addr]
			was, had := before[r.Name][addr]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s has no session with %s (%s)", r.Name, other.Name, addr))
			case p.RemoteAs != env.AS:
				problems = append(problems, fmt.Sprintf("%s -> %s is configured as AS %d, not %d",
					r.Name, other.Name, p.RemoteAs, env.AS))
			case !strings.EqualFold(p.State, "Established"):
				problems = append(problems, fmt.Sprintf("%s -> %s is %s", r.Name, other.Name, p.State))
			case had && updates[r.Name][addr] <= was:
				problems = append(problems, fmt.Sprintf(
					"%s -> %s says Established, but no route arrived from %s while it was "+
						"asked to send its table: the session is held open by a timer that "+
						"has not expired yet, and carries nothing", r.Name, other.Name,
					other.Name))
			default:
				established++
			}
		}
	}

	if established == want && len(problems) == 0 {
		return Pass("bgp.ibgp_full_mesh", Evidence{
			Observed: fmt.Sprintf("%d of %d iBGP sessions established", established, want)})
	}
	sort.Strings(problems)
	return Partial("bgp.ibgp_full_mesh", ratio(established, want), Evidence{
		Expected: fmt.Sprintf("%d iBGP sessions on loopbacks", want),
		Observed: fmt.Sprintf("%d established", established),
		Detail:   strings.Join(problems, "\n"),
		Hint:     "peer with each router's loopback and set update-source lo on both ends",
		Command:  "show ip bgp summary json",
	})
}

// refreshExternal asks each router to re-send its table to every external
// neighbour it has, so each session has to carry a message while the check is
// watching. It disturbs nothing: the peer re-sends routes the receiver already
// has.
func refreshExternal(ctx context.Context, env *Env, byRouter map[string][]string) {
	var wg sync.WaitGroup
	for router, peers := range byRouter {
		if len(peers) == 0 {
			continue
		}
		wg.Add(1)
		go func(router string, peers []string) {
			defer wg.Done()
			args := []string{"vtysh"}
			for _, p := range peers {
				args = append(args, "-c", "clear bgp "+p+" soft in")
			}
			_, _ = env.Probe(ctx, model.DeviceID(env.AS, router), args)
		}(router, peers)
	}
	wg.Wait()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
}

func checkEBGPEstablished(ctx context.Context, env *Env) Result {
	// The model knows exactly which external sessions should exist.
	type want struct {
		router, peerAddr string
		peerAS           int
		// Who the neighbour actually is, and what they should see us as.
		peerDevice string
		ourAddr    string
	}
	var wanted []want
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Role != model.RoleInterAS && i.Role != model.RoleIXPLink {
				continue
			}
			if i.Peer == nil || i.Peer.Addr4 == "" {
				continue
			}
			w := want{router: r.Name, peerAddr: env.PeerAddr(ctx, i), peerAS: i.Peer.Device.ASN}
			w.peerDevice = i.Peer.Device.ID
			if i.Addr4 != "" {
				w.ourAddr = addrOnly(i.Addr4)
			}
			wanted = append(wanted, w)
		}
	}
	if len(wanted) == 0 {
		return Errored("bgp.ebgp_established", fmt.Errorf("AS %d has no external links in the lab", env.AS))
	}

	// "Established" is a memory here too.
	//
	// A session whose packets are being discarded stays Established until the
	// hold timer expires, which is longer than a grading run: dropping both
	// directions of the TCP flow left every external session reported up and
	// carrying nothing. Each router is asked to send a route refresh first --
	// a real message that has to cross the connection and be answered -- and
	// the counts are compared either side of it.
	before := bgpUpdatesReceived(ctx, env, env.Routers())
	peersOf := map[string][]string{}
	for _, w := range wanted {
		peersOf[w.router] = append(peersOf[w.router], w.peerAddr)
	}
	refreshExternal(ctx, env, peersOf)
	afterUpdates := bgpUpdatesReceived(ctx, env, env.Routers())

	byRouter := map[string]bgpSummaryJSON{}
	up := 0
	var problems []string
	for _, w := range wanted {
		sum, ok := byRouter[w.router]
		if !ok {
			var err error
			sum, err = bgpSummary(ctx, env, w.router)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", w.router, err))
				continue
			}
			byRouter[w.router] = sum
		}
		p, ok := sum.IPv4Unicast.Peers[w.peerAddr]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s has no session with AS %d at %s",
				w.router, w.peerAS, w.peerAddr))
		case !strings.EqualFold(p.State, "Established"):
			problems = append(problems, fmt.Sprintf("%s -> AS %d (%s) is %s",
				w.router, w.peerAS, w.peerAddr, p.State))
		default:
			// And the neighbour has to agree.
			//
			// This read the session out of the submission's own router: an
			// address, a state and a remote AS number, all of them things the
			// submission controls. Taking the real link down, routing the
			// neighbour's address to a host of one's own and running a
			// four-message BGP speaker there that claims to be AS 4 produced
			// "Established, remote AS 4" and full marks for a session with a
			// system that was never contacted. The neighbour belongs to
			// somebody else, and asking it is the one thing a submission
			// cannot arrange.
			if why := peerAgrees(ctx, env, w.peerDevice, w.ourAddr, env.AS); why != "" {
				problems = append(problems, fmt.Sprintf(
					"%s reports a session with AS %d at %s, but %s", w.router, w.peerAS,
					w.peerAddr, why))
				continue
			}
			if was, had := before[w.router][w.peerAddr]; had &&
				afterUpdates[w.router][w.peerAddr] <= was {
				problems = append(problems, fmt.Sprintf(
					"%s -> AS %d (%s) says Established, but no route arrived from it while it "+
						"was asked to send its table: the session is held open by a timer that "+
						"has not expired yet, and carries nothing", w.router, w.peerAS, w.peerAddr))
				continue
			}
			up++
		}
	}

	if up == len(wanted) {
		return Pass("bgp.ebgp_established", Evidence{
			Observed: fmt.Sprintf("all %d eBGP sessions established", up)})
	}
	sort.Strings(problems)
	return Partial("bgp.ebgp_established", ratio(up, len(wanted)), Evidence{
		Expected: fmt.Sprintf("%d eBGP sessions", len(wanted)),
		Observed: fmt.Sprintf("%d established", up),
		Detail:   strings.Join(problems, "\n"),
		Hint:     "agree the addresses with your neighbour, and remember next-hop-self",
		Command:  "show ip bgp summary json",
	})
}

// peerAgrees asks the device on the other side of a link whether it has an
// established session with this AS at the address we think we are using, and
// says what is wrong if not.
//
// An empty answer means agreement. A neighbour that cannot be read is reported
// as such rather than assumed to agree: the whole point is that this is the
// half of the evidence the submission does not control.
func peerAgrees(ctx context.Context, env *Env, peerDevice, ourAddr string, ourAS int) string {
	if peerDevice == "" || ourAddr == "" {
		return ""
	}
	res, err := env.Probe(ctx, peerDevice, []string{"vtysh", "-c", "show ip bgp summary json"})
	if err != nil {
		return fmt.Sprintf("%s could not be asked whether it sees one (%v)", peerDevice, err)
	}
	var sum bgpSummaryJSON
	if jerr := jsonUnmarshalLoose(res.Stdout, &sum); jerr != nil {
		return fmt.Sprintf("%s's own view could not be read (%v)", peerDevice, jerr)
	}
	p, ok := sum.IPv4Unicast.Peers[ourAddr]
	switch {
	case !ok:
		return fmt.Sprintf("%s has no session with %s at all, so the session is with "+
			"something else answering at that address", peerDevice, ourAddr)
	case p.RemoteAs != ourAS:
		return fmt.Sprintf("%s sees %s as AS %d, not AS %d", peerDevice, ourAddr, p.RemoteAs, ourAS)
	case !strings.EqualFold(p.State, "Established"):
		return fmt.Sprintf("%s sees that session as %s", peerDevice, p.State)
	}
	return ""
}

func bgpTable(ctx context.Context, env *Env, router string) (bgpRouteJSON, error) {
	var out bgpRouteJSON
	err := env.VtyshJSON(ctx, router, "show ip bgp json", &out)
	return out, err
}

func checkOwnPrefix(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || as.Block == "" {
		return Errored("bgp.own_prefix_only", fmt.Errorf("AS %d has no prefix in the plan", env.AS))
	}
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("bgp.own_prefix_only", fmt.Errorf("AS %d has no routers", env.AS))
	}
	// Every router, and what each of them actually sends.
	//
	// This read the table of routers[0] alone. A system originating somebody
	// else's address space on one router and hiding it from the first with an
	// outbound route-map kept the whole mark: the prefix was in the neighbour's
	// table and in the originating router's advertisements, and the grader
	// looked at neither. Which router happens to be first is an accident of the
	// template's ordering, and no property of a system is a property of one of
	// its routers.
	originated := map[string]bool{}
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			return Errored("bgp.own_prefix_only", err)
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if e.Originated() {
					originated[prefix] = true
				}
			}
		}
	}

	// And what leaves the system, which is what the neighbours see and what the
	// question is really about. A prefix originated and withheld is a mistake;
	// a prefix advertised is a claim on somebody's address space.
	advertised := map[string]string{}
	var disowned []string
	for _, sess := range externalSessions(ctx, env) {
		adv, err := advertisedRoutes(ctx, env, sess.Router, sess.Addr)
		if err != nil {
			if errors.Is(err, errNoSuchNeighbour) {
				continue
			}
			return Errored("bgp.own_prefix_only", fmt.Errorf(
				"%s: what it advertises to %s could not be read, so whether this system "+
					"announces address space that is not its own cannot be decided: %w",
				sess.Router, sess.Addr, err))
		}
		for prefix, entries := range adv.Table() {
			for _, e := range entries {
				// Our own prefix, sent with somebody else's origin.
				//
				// The path this AS sends for its own address space must end
				// with this AS: that is what originating a prefix means. `set
				// as-path exclude all` and a prepend of a number that is not
				// ours produced an announcement every neighbour treated as
				// AS 65000's, rejected as invalid, and routed around -- while
				// the table on this side still showed the prefix locally
				// injected and the question was marked from that.
				if prefix == as.Block {
					if p := strings.TrimSpace(e.Path); p != "" && originASN(p) != env.AS {
						disowned = append(disowned, fmt.Sprintf(
							"%s tells %s that %s comes from AS %d, not from this AS (path %q)",
							sess.Router, sess.Addr, prefix, originASN(p), p))
					}
					continue
				}
				// Claiming to be the origin of somebody else's prefix.
				//
				// A route this AS relays keeps the origin at the end of its
				// path, and our own prepends go on the front. Rewriting the
				// end -- `set as-path exclude` and a prepend, or a
				// wholesale replacement -- makes the neighbour believe this AS
				// originates address space it does not hold, which is a hijack
				// with a different spelling. It never appears as a locally
				// injected route here, so nothing above notices it.
				if prefix != as.Block && originASN(e.Path) == env.AS {
					originated[prefix] = true
					advertised[prefix] = fmt.Sprintf(
						"%s tells %s that this AS originates it (path %q)",
						sess.Router, sess.Addr, strings.TrimSpace(e.Path))
					continue
				}
				// The advertised view carries no peer, so origination is
				// decided from the tables above; an empty path here still
				// means the same thing and catches a prefix that only appears
				// on the way out.
				if !originated[prefix] && !e.Originated() {
					continue // somebody else's route, passing through
				}
				originated[prefix] = true
				if prefix != as.Block {
					advertised[prefix] = fmt.Sprintf("%s advertises it to %s",
						sess.Router, sess.Addr)
				}
			}
		}
	}

	if len(disowned) > 0 {
		sort.Strings(disowned)
		return Partial("bgp.own_prefix_only", 0.5, Evidence{
			Expected: fmt.Sprintf("%s announced as originating in AS %d", as.Block, env.AS),
			Observed: fmt.Sprintf("%d neighbour(s) are told it comes from somewhere else",
				len(disowned)),
			Detail: strings.Join(truncate(disowned, 6), "\n"),
			Hint: "the path you send for your own address space has to end with your own " +
				"AS number; anything else is an announcement your neighbours will treat as " +
				"somebody else's, and route around",
			Command: "show ip bgp neighbors <addr> advertised-routes json",
		})
	}

	hasOwn := originated[as.Block]
	var extra []string
	for p := range originated {
		if p == as.Block {
			continue
		}
		if where, ok := advertised[p]; ok {
			extra = append(extra, fmt.Sprintf("%s (%s)", p, where))
			continue
		}
		extra = append(extra, p)
	}
	sort.Strings(extra)

	switch {
	case hasOwn && len(extra) == 0:
		return Pass("bgp.own_prefix_only", Evidence{Observed: "originates " + as.Block})
	case !hasOwn:
		return Fail("bgp.own_prefix_only", Evidence{
			Expected: as.Block, Observed: "not originated",
			Detail:  fmt.Sprintf("%s does not appear as a locally originated route", as.Block),
			Hint:    "advertise your /8 with `network " + as.Block + "` under the IPv4 address family",
			Command: "show ip bgp json",
		})
	default:
		return Partial("bgp.own_prefix_only", 0.5, Evidence{
			Expected: "only " + as.Block,
			Observed: fmt.Sprintf("also originates %s", strings.Join(extra, ", ")),
			Detail:   "advertising address space that is not yours is what the hijack exercise is about",
			Command:  "show ip bgp json",
		})
	}
}

// originASN is the AS at the end of a path, which is the one claiming to have
// originated the prefix. Prepends go on the front, so the end is the claim.
func originASN(path string) int {
	f := strings.Fields(strings.TrimSpace(path))
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[len(f)-1])
	if err != nil {
		return 0
	}
	return n
}

// checkGaoRexford verifies the local-preference ordering that implements the
// business relationships: customer over peer over provider.
//
// It reads the ordering out of the routing table rather than pattern-matching
// the configuration, so any correct implementation passes and a configuration
// that merely looks right does not.
// overriddenByStatic names the externally learned prefixes a router forwards
// by some route other than the BGP one.
//
// A ranking that does not decide where packets go is not a ranking. Anything
// installed above BGP -- a static route, a kernel route, a policy table --
// takes the traffic wherever it says, whatever the BGP table shows.
func overriddenByStatic(ctx context.Context, env *Env, routers []*model.Device) []string {
	var (
		mu  sync.Mutex
		out []string
		wg  sync.WaitGroup
	)
	for _, r := range routers {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			tbl, err := bgpTable(ctx, env, r.Name)
			if err != nil {
				return
			}
			external := map[string]bool{}
			for prefix, entries := range tbl.Table() {
				for _, e := range entries {
					if e.IsBest() && strings.TrimSpace(e.Path) != "" {
						external[prefix] = true
					}
				}
			}
			if len(external) == 0 {
				return
			}
			// A rule the routing daemon cannot see.
			//
			// `ip rule add to X lookup 100` with a route in table 100 sends
			// that destination wherever it says, and zebra's main table --
			// which is all a routing daemon reports -- still shows the route
			// BGP chose. The kernel consults the rules first. A router has
			// three of them when nobody has interfered; anything else is a
			// decision being made somewhere the routing protocol has no say.
			if res, err := env.Probe(ctx, r.ID, []string{"ip", "rule", "show"}); err == nil &&
				res.ExitCode == 0 {
				for _, line := range strings.Split(res.Stdout, "\n") {
					t := strings.TrimSpace(line)
					if t == "" || strings.HasSuffix(t, "lookup local") ||
						strings.HasSuffix(t, "lookup main") ||
						strings.HasSuffix(t, "lookup default") {
						continue
					}
					mu.Lock()
					out = append(out, fmt.Sprintf(
						"%s has a policy rule the routing protocols know nothing about: %s",
						r.Name, t))
					mu.Unlock()
				}
			}

			var routes ospfRouteJSON
			if err := env.VtyshJSON(ctx, r.Name, "show ip route json", &routes); err != nil {
				return
			}
			for prefix, entries := range routes {
				if !external[prefix] {
					continue
				}
				for _, e := range entries {
					if !e.Selected && !e.Installed {
						continue
					}
					switch e.Protocol {
					case "bgp", "connected", "":
					default:
						mu.Lock()
						out = append(out, fmt.Sprintf(
							"%s forwards %s by a %s route, not the one BGP chose",
							r.Name, prefix, e.Protocol))
						mu.Unlock()
					}
				}
			}
		}(r)
	}
	wg.Wait()
	sort.Strings(out)
	return uniq(out)
}

// relRank orders the business relationships by how much a route from one is
// worth: a customer pays to be carried, a peer costs nothing, a provider is
// billed for.
func relRank(rel model.Relationship) int {
	switch rel {
	case model.RelCustomer:
		return 3
	case model.RelPeer:
		return 2
	case model.RelProvider:
		return 1
	}
	return 0
}

func checkGaoRexford(ctx context.Context, env *Env) Result {
	routers := env.Routers()
	if len(routers) == 0 {
		return Errored("policy.gao_rexford", fmt.Errorf("AS %d has no routers", env.AS))
	}

	// Which neighbour address corresponds to which relationship.
	//
	// Taken from externalSessions rather than rebuilt here, because rebuilding
	// it here left the exchange out: a session with a route server is not a
	// point-to-point inter-AS link, so every peer reached across an IXP was
	// invisible to this check. An AS whose only peers are exchange members --
	// which is most of them, and all of the ones the assignment cares about --
	// was marked on customer-versus-provider alone.
	relOf := map[string]model.Relationship{}
	relOfASN := map[int]model.Relationship{}
	for _, sess := range externalSessions(ctx, env) {
		relOf[sess.Addr] = sess.Rel
		if sess.ASN != 0 {
			relOfASN[sess.ASN] = sess.Rel
		}
	}
	if len(relOf) == 0 {
		return Errored("policy.gao_rexford", fmt.Errorf("AS %d has no external neighbours", env.AS))
	}

	// Every route, not a summary of them.
	//
	// This used to compare the median local preference of each relationship,
	// which is a statement about most routes and about no particular one: an AS
	// that set local-preference 200 on nine customer prefixes and left the
	// tenth at the default passed, and so did one that ranked a whole peer
	// correctly on average while preferring one of its routes over a
	// customer's. Gao-Rexford is a rule about every route, so every route is
	// where it is checked -- the worst customer route must still beat the best
	// peer route, and the worst peer route the best provider route.
	type observed struct {
		pref   int
		prefix string
		via    string
		router string
	}
	seen := map[model.Relationship][]observed{}
	// And which path each router actually chose.
	//
	// Local preference is what a student configures; which route wins is what
	// the rule is for, and they are not the same thing. Local preference is
	// only the second tie-break in the decision process, so `set weight 65535`
	// on a provider's route puts it ahead of a peer's while every local
	// preference in the table still reads correctly -- measured, and worth
	// full marks before this. Whatever attribute is used to arrange it, a
	// provider's route selected while a peer offers the same prefix is the
	// ordering broken.
	var misranked []string
	for _, r := range routers {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for prefix, entries := range tbl.Table() {
			var chosen, available model.Relationship
			chosenOK := false
			for _, e := range entries {
				if rel, via, ok := learnedFromRelationship(e, relOf); ok {
					seen[rel] = append(seen[rel], observed{e.LocalPref, prefix, via, r.Name})
				}
				// Which relationship the route entered this AS through, which
				// is a different question from which session this router
				// happened to hear it on. A route another router of the AS
				// learned from a peer arrives here over iBGP, where the
				// session says nothing about its origin -- and the whole
				// comparison is between routes that mostly arrive that way.
				// The neighbour at the head of the AS path is the answer.
				rel := sourceRelationship(e, env.AS, relOf, relOfASN)
				if rel == "" {
					continue
				}
				if relRank(rel) > relRank(available) {
					available = rel
				}
				if e.IsBest() {
					chosen, chosenOK = rel, true
				}
			}
			if chosenOK && relRank(available) > relRank(chosen) {
				misranked = append(misranked, fmt.Sprintf(
					"%s sends %s to a %s while a %s offers the same prefix",
					r.Name, prefix, chosen, available))
			}
		}
	}
	sort.Strings(misranked)

	worst := func(rel model.Relationship) (observed, bool) {
		v := seen[rel]
		if len(v) == 0 {
			return observed{}, false
		}
		out := v[0]
		for _, o := range v[1:] {
			if o.pref < out.pref {
				out = o
			}
		}
		return out, true
	}
	best := func(rel model.Relationship) (observed, bool) {
		v := seen[rel]
		if len(v) == 0 {
			return observed{}, false
		}
		out := v[0]
		for _, o := range v[1:] {
			if o.pref > out.pref {
				out = o
			}
		}
		return out, true
	}

	custLo, hasCust := worst(model.RelCustomer)
	peerLo, hasPeer := worst(model.RelPeer)
	provLo, hasProv := worst(model.RelProvider)
	custHi, _ := best(model.RelCustomer)
	peerHi, _ := best(model.RelPeer)
	provHi, _ := best(model.RelProvider)

	span := func(lo, hi observed, ok bool, n int) string {
		if !ok {
			return "none"
		}
		if lo.pref == hi.pref {
			return fmt.Sprintf("%d (%d route(s))", lo.pref, n)
		}
		return fmt.Sprintf("%d..%d (%d route(s))", lo.pref, hi.pref, n)
	}
	var detail strings.Builder
	fmt.Fprintf(&detail, "observed local preference: customer=%s peer=%s provider=%s\n",
		span(custLo, custHi, hasCust, len(seen[model.RelCustomer])),
		span(peerLo, peerHi, hasPeer, len(seen[model.RelPeer])),
		span(provLo, provHi, hasProv, len(seen[model.RelProvider])))

	checks, passed := 0, 0
	compare := func(hiRel, loRel model.Relationship, hiOK, loOK bool,
		hiWorst, loBest observed) {

		if !hiOK || !loOK {
			return
		}
		checks++
		if hiWorst.pref > loBest.pref {
			passed++
			return
		}
		fmt.Fprintf(&detail,
			"every route from a %s must be preferred over every route from a %s, but "+
				"%s carries local preference %d on %s (via %s) while %s carries %d on %s (via %s)\n",
			hiRel, loRel,
			hiWorst.router, hiWorst.pref, hiWorst.prefix, hiWorst.via,
			loBest.router, loBest.pref, loBest.prefix, loBest.via)
	}
	compare(model.RelCustomer, model.RelPeer, hasCust, hasPeer, custLo, peerHi)
	compare(model.RelPeer, model.RelProvider, hasPeer, hasProv, peerLo, provHi)
	compare(model.RelCustomer, model.RelProvider, hasCust, hasProv, custLo, provHi)

	// And that the ranking is what decides where packets go.
	//
	// Everything above is BGP's decision. The kernel's is what forwards, and
	// they are not the same: `ip route replace 4.0.0.0/8 via <provider>` sends
	// the traffic to a provider while BGP's table still shows the peer path
	// selected at a higher local preference. The ordering was arranged, agreed
	// with, and then ignored, for full marks.
	checks++
	if over := overriddenByStatic(ctx, env, routers); len(over) == 0 {
		passed++
	} else {
		fmt.Fprintf(&detail, "%d externally learned prefix(es) are forwarded by something "+
			"other than BGP, so the ordering does not decide where traffic goes:\n%s\n",
			len(over), strings.Join(truncate(over, 5), "\n"))
	}

	// The ordering as it came out, which is the point of arranging it.
	checks++
	if len(misranked) == 0 {
		passed++
	} else {
		fmt.Fprintf(&detail, "%d prefix(es) are sent to a worse relationship than one that "+
			"offers them:\n%s\n", len(misranked), strings.Join(truncate(misranked, 5), "\n"))
	}

	// Every relationship this AS actually has must be represented.
	//
	// Only the classes that happened to be visible were compared, so an AS
	// whose provider routes had all been filtered away was marked on
	// customer-versus-peer alone and passed -- the ordering it was asked about
	// was never observed. What relationships exist is in the topology, so it
	// does not have to be inferred from what survived.
	var absent []string
	for rel, present := range map[model.Relationship]bool{
		model.RelCustomer: hasCust, model.RelPeer: hasPeer, model.RelProvider: hasProv,
	} {
		if present {
			continue
		}
		for _, r := range relOf {
			if r == rel {
				absent = append(absent, string(rel))
				break
			}
		}
	}
	if len(absent) > 0 {
		sort.Strings(absent)
		return Partial("policy.gao_rexford", ratio(passed, maxInt(checks, 1))*0.5, Evidence{
			Expected: "customer routes preferred over peers', and peers' over providers'",
			Observed: fmt.Sprintf("this AS has %s neighbour(s), but no route from them is in "+
				"its table, so the ordering they are part of could not be observed",
				strings.Join(absent, " and ")),
			Detail: detail.String(),
			Hint: "a relationship whose routes are all filtered away cannot be shown to be " +
				"ranked correctly; accept them and rank them",
			Command: "show ip bgp json",
		})
	}
	if checks == 0 {
		return Errored("policy.gao_rexford",
			fmt.Errorf("no routes were learned from enough distinct relationships to compare"))
	}
	if passed == checks {
		return Pass("policy.gao_rexford", Evidence{
			Observed: strings.TrimSpace(detail.String())})
	}
	return Partial("policy.gao_rexford", ratio(passed, checks), Evidence{
		Expected: "local preference customer > peer > provider, for every route",
		Observed: fmt.Sprintf("%d of %d orderings correct", passed, checks),
		Detail:   strings.TrimRight(detail.String(), "\n"),
		Hint:     "set local-preference on import, per relationship, with a route-map",
		Command:  "show ip bgp json",
	})
}

// checkNoTransit verifies the export half of the business relationships: a
// route learned from a peer or a provider must not be handed to another peer or
// provider, or the AS is providing free transit.
func checkNoTransit(ctx context.Context, env *Env) Result {
	relOf := map[string]model.Relationship{}
	relOfASN := map[int]model.Relationship{}
	// What each neighbour is to us. Derived in one place, because the same two
	// lines written out here, in the renderer and in the other checks were all
	// inverted in the same direction -- so the wrong answer was self-consistent
	// and scored full marks. The exchange is included: its members are peers.
	for _, s := range externalSessions(ctx, env) {
		relOf[s.Addr] = s.Rel
		if s.ASN != 0 {
			relOfASN[s.ASN] = s.Rel
		}
	}

	// What this AS is supposed to be announcing about itself.
	own := ""
	if as, ok := env.Topology.ASes[env.AS]; ok {
		own = as.Block
	}
	announced := 0

	// Each router is asked about its own sessions, and only its own.
	//
	// Every router used to be asked about every inter-AS address in the AS, so
	// most reads came back "no such neighbour" -- one router does not hold
	// another's session -- and landed in the same bucket as a read that failed
	// because the router could not be reached. Both were dropped, so a session
	// that could not be assessed cost nothing, and an AS whose routers were
	// mostly unreadable passed on the strength of the one that answered.
	type session struct {
		router string
		addr   string
		rel    model.Relationship
	}
	var sessions []session
	for _, s := range externalSessions(ctx, env) {
		if s.Rel == model.RelCustomer {
			continue // a customer may receive everything
		}
		sessions = append(sessions, session{s.Router, s.Addr, s.Rel})
	}

	// What this AS learned from its customers and selected. Gao-Rexford's
	// export rule has two halves -- advertise your own prefixes and your
	// customers' to everybody, and nothing else to a peer or a provider -- and
	// only the second half was ever checked. An AS that accepted its customer's
	// routes, used them, and told nobody else about them scored full marks
	// while leaving that customer unreachable from the rest of the internet,
	// which is the single most consequential thing a transit AS can get wrong.
	custPrefixes := map[string]string{}
	var unreadableTables []string
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			// A table that could not be read is a customer's routes that
			// might be in it. Since what may be exported is now decided by
			// what was learned from customers, not reading one would turn
			// missing knowledge into an accusation.
			unreadableTables = append(unreadableTables, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if !e.IsBest() {
					continue
				}
				// By the session it arrived on, not the next hop it carries:
				// an inbound route-map can rewrite the second, and a customer
				// whose routes are invisible here is a customer whose routes
				// nobody is required to pass on.
				if rel, via, ok := learnedFromRelationship(e, relOf); ok && rel == model.RelCustomer {
					custPrefixes[prefix] = fmt.Sprintf("learned from a customer at %s", via)
				}
			}
		}
	}

	// For each non-customer neighbour, look at what we advertise to them.
	var leaks []string
	var withheld []string
	var silent []string
	var unreadable []string
	checked := 0
	for _, sess := range sessions {
		name, addr, rel := sess.router, sess.addr, sess.rel
		adv, err := advertisedRoutes(ctx, env, name, addr)
		if err != nil {
			if errors.Is(err, errNoSuchNeighbour) {
				// The student did not configure the session. That is a
				// finding about them, and it is assessed: nothing of ours
				// crosses a session that does not exist.
				checked++
				silent = append(silent, fmt.Sprintf(
					"%s has no BGP session with the %s at %s, so nothing of yours reaches it",
					name, rel, addr))
				continue
			}
			// An unreadable document is ours, and is recorded so it cannot
			// masquerade as a pass.
			unreadable = append(unreadable, err.Error())
			continue
		}
		checked++
		sawOwn := false
		for prefix, entries := range adv.Table() {
			if own != "" && prefix == own {
				announced++
				sawOwn = true
			}
			for _, e := range entries {
				// A route we originate may go anywhere, and so may a
				// customer's.
				//
				// Our own prefix is named, not inferred from an empty path:
				// the traffic-engineering question asks for `set as-path
				// prepend <own> <own> <own>` towards the slow provider, so the
				// advertisement of our own address space leaves carrying a
				// path, and reading only the path called the correct answer a
				// leak.
				if e.Originated() || (own != "" && prefix == own) {
					continue
				}
				if _, ours := custPrefixes[prefix]; ours {
					continue
				}
				// Anything else came from a peer or a provider, and exporting
				// it here is a leak.
				//
				// Which it came from is decided by the session it arrived on,
				// recorded above, and not by the path in the advertisement. A
				// path on the way out is the submission's to write: prepending
				// a customer's ASN in front of a peer's route -- `set as-path
				// prepend 3 3 3 7` -- made a leak read as a customer's route
				// being passed on, which is exactly what the rule permits, and
				// the whole question kept its marks.
				src := sourceRelationship(e, env.AS, relOf, relOfASN)
				from := "which is neither yours nor a customer's"
				if src != "" {
					from = "learned from a " + string(src)
				}
				leaks = append(leaks, fmt.Sprintf(
					"%s advertises %s (%s, sent with path %q) to a %s at %s",
					name, prefix, from, strings.TrimSpace(e.Path), rel, addr))
			}
		}
		if !sawOwn {
			silent = append(silent, fmt.Sprintf("%s advertises nothing of its own to the %s at %s",
				name, rel, addr))
		}
		// The other half of the export rule.
		//
		// A customer's routes must reach the rest of the internet through you;
		// that is what they are paying for. Withholding them is not a safe
		// error, it is the transit service not being provided.
		for prefix, why := range custPrefixes {
			if _, ok := adv.Table()[prefix]; ok {
				continue
			}
			// A route whose own next hop is this neighbour is not withheld
			// from them, it is simply not sent back where it came from.
			withheld = append(withheld, fmt.Sprintf(
				"%s does not advertise %s (%s) to the %s at %s",
				name, prefix, why, rel, addr))
		}
	}
	// A session that could not be read has not been assessed, and a check that
	// reports "no leaks" while some of the sessions it is about were never read
	// is reporting on a question it did not finish asking.
	if len(unreadableTables) > 0 {
		sort.Strings(unreadableTables)
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"%d router table(s) could not be read, and what may be exported is decided by "+
				"what was learned from customers, so nothing can be concluded: %s",
			len(unreadableTables), strings.Join(truncate(unreadableTables, 3), "; ")))
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"%d of %d non-customer session(s) could not be read, so no verdict covers them: %s",
			len(unreadable), len(sessions), strings.Join(truncate(unreadable, 3), "; ")))
	}
	if checked == 0 {
		return Errored("policy.no_transit_for_peers", fmt.Errorf(
			"this AS has no session with a peer or a provider, so the question of what "+
				"may cross one cannot be assessed"))
	}
	// Advertising nothing is not the same as advertising correctly.
	//
	// This check counted leaks and passed when it found none, so a deny-all
	// export policy scored full marks: no advertisements, therefore no leaked
	// advertisements. That is a badly wrong answer -- the AS is invisible to
	// the internet -- receiving the same mark as a correct Gao-Rexford export.
	// The question is what may cross the session, and a session carrying
	// nothing has not answered it.
	if announced == 0 {
		return Fail("policy.no_transit_for_peers", Evidence{
			Expected: "your own prefix advertised to peers and providers, and nothing learned from them",
			Observed: fmt.Sprintf("nothing at all is advertised to any of the %d non-customer neighbours", checked),
			Hint: "an export policy that denies everything leaks nothing, but it also means " +
				"nobody outside your AS can reach you",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	// Reaching one neighbour is not reaching the internet.
	//
	// This counted advertisements in total, so a policy that announced the
	// prefix to a single provider and denied every other peer and provider
	// passed with full marks -- an AS almost nobody can reach, marked the same
	// as one that is correctly connected. Each session is now asked separately.
	if len(silent) > 0 && len(leaks) == 0 {
		sort.Strings(silent)
		return Partial("policy.no_transit_for_peers", 0.5, Evidence{
			Expected: "your own prefix advertised to every peer and provider, and nothing learned from them",
			Observed: fmt.Sprintf("nothing leaks, but %d of %d non-customer sessions carry "+
				"nothing of your own", len(silent), checked),
			Detail: strings.Join(truncate(silent, 5), "\n"),
			Hint: "an export policy that denies everything leaks nothing, but the networks " +
				"behind those sessions cannot reach you at all",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	if len(leaks) == 0 && len(withheld) > 0 {
		sort.Strings(withheld)
		return Partial("policy.no_transit_for_peers", 0.5, Evidence{
			Expected: "your own and your customers' prefixes advertised to every peer and " +
				"provider, and nothing learned from one",
			Observed: fmt.Sprintf("nothing leaks, but %d customer route advertisement(s) are "+
				"missing", len(withheld)),
			Detail: strings.Join(truncate(withheld, 5), "\n"),
			Hint: "a customer pays you to carry their prefixes to the rest of the internet; " +
				"an export policy that sends only your own leaves them unreachable",
			Command: "show ip bgp neighbors <addr> advertised-routes",
		})
	}
	if len(leaks) == 0 {
		return Pass("policy.no_transit_for_peers", Evidence{
			Observed: fmt.Sprintf("no leaks across %d neighbour views; own and customer "+
				"prefixes advertised to all of them", checked)})
	}
	sort.Strings(leaks)
	if len(leaks) > 12 {
		leaks = append(leaks[:12], fmt.Sprintf("... and %d more", len(leaks)-12))
	}
	return Fail("policy.no_transit_for_peers", Evidence{
		Expected: "only your own and your customers' routes go to peers and providers",
		Observed: fmt.Sprintf("%d leaked advertisement(s)", len(leaks)),
		Detail:   strings.Join(leaks, "\n"),
		Hint:     "tag routes with a community on import and match it when exporting",
		Command:  "show ip bgp neighbors <addr> advertised-routes json",
	})
}

// checkTransitForCustomers verifies the half of Gao-Rexford's export rule that
// says what a customer is owed: everything.
//
// A customer pays for reachability to the whole internet, so every route this
// AS has selected is meant to reach them -- its own, its other customers', its
// peers' and its providers'. The no-transit check deliberately skips customer
// sessions because a customer may receive anything, and nothing then looked at
// them at all: an AS could deny its providers' routes to every customer, leave
// them able to reach nobody outside this AS, and still score full marks for
// business relationships. That is the transit service not being delivered,
// which is a worse error than leaking, and it was unassessed.
//
// The requirement is per session and per route rather than in aggregate,
// because withholding the internet from one of two customers is not half an
// error to that customer.
func checkTransitForCustomers(ctx context.Context, env *Env) Result {
	const name = "policy.transit_for_customers"
	var customers []externalSession
	for _, s := range externalSessions(ctx, env) {
		if s.Rel == model.RelCustomer {
			customers = append(customers, s)
		}
	}
	if len(customers) == 0 {
		// A stub AS sells transit to nobody. The property is not true or
		// false here, it does not arise, and the question's other checks
		// carry its marks.
		return NotApplicable(name, fmt.Sprintf(
			"AS %d has no customers, so it owes nobody transit", env.AS))
	}

	// What the AS as a whole has learned from outside.
	//
	// What a customer is owed was taken from the table of the router holding
	// its session, and that table is the submission's to empty: denying
	// everything inbound on every session left one router holding only this
	// AS's own prefix, advertising exactly that to its customers, and the
	// check reporting that every selected route had been passed on. Nothing
	// had been selected. A customer buys the internet, and the internet is
	// what the AS knows, not what one of its routers has been left with.
	own := ""
	if as, ok := env.Topology.ASes[env.AS]; ok {
		own = as.Block
	}
	asWide := map[string]string{} // prefix -> the path the AS has for it
	for _, r := range env.Routers() {
		tbl, err := bgpTable(ctx, env, r.Name)
		if err != nil {
			continue
		}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if e.IsBest() && strings.TrimSpace(e.Path) != "" {
					asWide[prefix] = strings.TrimSpace(e.Path)
				}
			}
		}
	}

	var missing []string
	var silent []string
	var dropped []string
	var unreadable []string
	checked := 0
	for _, sess := range customers {
		// What this router selected is what this router has to give. Asking a
		// different router's table would excuse a session on a router that had
		// learned nothing, and blame one whose neighbour is simply elsewhere.
		tbl, err := bgpTable(ctx, env, sess.Router)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", sess.Router, err))
			continue
		}
		owed := map[string]string{}
		for prefix, entries := range tbl.Table() {
			for _, e := range entries {
				if !e.IsBest() {
					continue
				}
				// A route this customer taught us is not owed back to them,
				// and a route already through their AS would be a loop. Both
				// are correct to withhold, so neither is counted.
				if sess.ASN != 0 && pathContainsASN(e.Path, sess.ASN) {
					continue
				}
				if learnedFrom(e, sess.Addr) {
					continue
				}
				owed[prefix] = strings.TrimSpace(e.Path)
			}
		}
		adv, err := advertisedRoutes(ctx, env, sess.Router, sess.Addr)
		if err != nil {
			if errors.Is(err, errNoSuchNeighbour) {
				checked++
				silent = append(silent, fmt.Sprintf(
					"%s has no BGP session with the customer at %s, so they get no transit at all",
					sess.Router, sess.Addr))
				continue
			}
			unreadable = append(unreadable, fmt.Sprintf("%s -> %s: %v", sess.Router, sess.Addr, err))
			continue
		}
		checked++
		sent := adv.Table()
		var absent []string
		for prefix := range owed {
			if _, ok := sent[prefix]; !ok {
				absent = append(absent, prefix)
			}
		}
		if len(owed) == 0 {
			// Nothing selected is nothing to pass on, and that is a finding
			// about the import side rather than the export side.
			silent = append(silent, fmt.Sprintf(
				"%s has selected no routes at all, so the customer at %s receives nothing",
				sess.Router, sess.Addr))
			continue
		}
		if len(absent) > 0 {
			sort.Strings(absent)
			missing = append(missing, fmt.Sprintf(
				"%s withholds %d of %d selected route(s) from the customer at %s: %s",
				sess.Router, len(absent), len(owed), sess.Addr,
				strings.Join(truncate(absent, 6), ", ")))
		}
		// And what the router never selected in the first place.
		var short []string
		for p, path := range asWide {
			if _, has := owed[p]; has || p == own {
				continue
			}
			// A route this customer taught us is not owed back to them.
			if sess.ASN != 0 && pathContainsASN(path, sess.ASN) {
				continue
			}
			short = append(short, p)
		}
		if len(short) > 0 {
			sort.Strings(short)
			missing = append(missing, fmt.Sprintf(
				"%s holds %d fewer destination(s) than the rest of this AS has learned, so the "+
					"customer at %s receives less than the internet: %s",
				sess.Router, len(short), sess.Addr, strings.Join(truncate(short, 4), ", ")))
		}

		// And then the transit itself.
		//
		// Everything above is the routes a customer is offered, which is a
		// promise rather than a service. A reviewer left every session
		// established and every route advertised and dropped the customers'
		// packets in the FORWARD chain: the mark did not move, because nothing
		// had ever asked whether a packet sent by a customer arrives anywhere.
		// The probe is launched from the customer's own router, which the
		// submission does not configure, so it genuinely enters this AS over
		// this session; the destination is in a third AS and counts what it
		// received, so an answer forged along the way does not read as
		// delivery.
		if why, ok := carriesCustomerTraffic(ctx, env, sess, owed); !ok && why != "" {
			dropped = append(dropped, why)
		}
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return Errored(name, fmt.Errorf(
			"%d of %d customer session(s) could not be read, so no verdict covers them: %s",
			len(unreadable), len(customers), strings.Join(truncate(unreadable, 3), "; ")))
	}
	if checked == 0 {
		return Errored(name, fmt.Errorf("none of the %d customer session(s) could be assessed",
			len(customers)))
	}
	if len(missing) == 0 && len(silent) == 0 && len(dropped) == 0 {
		return Pass(name, Evidence{Observed: fmt.Sprintf(
			"every selected route is advertised to all %d customer session(s), and traffic "+
				"sent from a customer arrives at a destination beyond this AS", checked)})
	}
	detail := append(append(append([]string{}, missing...), silent...), dropped...)
	sort.Strings(detail)
	// Withholding some of the internet from a customer and withholding all of
	// it are different sizes of the same error, and the score says so.
	bad := len(missing) + len(silent) + len(dropped)
	return Partial(name, ratio(maxInt(checked-bad, 0), checked), Evidence{
		Expected: "every route this AS selected, advertised to every customer, and their " +
			"traffic carried",
		Observed: fmt.Sprintf("%d of %d customer session(s) do not carry the full table "+
			"or do not forward", bad, checked),
		Detail: strings.Join(truncate(detail, 6), "\n"),
		Hint: "a customer buys reachability to the whole internet from you; an export " +
			"policy towards them should permit everything you have selected, and their " +
			"packets have to cross you",
		Command: "show ip bgp neighbors <addr> advertised-routes; ping",
	})
}

// carriesCustomerTraffic sends one packet through the AS on a customer's
// behalf and says whether it arrived.
//
// The probe leaves the customer's own router, so it enters this AS over the
// session being marked rather than by some other route in. The destination is
// a host in a third AS, which counts the echo requests delivered to it: a
// submission that answered on the destination's behalf, or rewrote the address
// on the way, does not move that counter.
//
// A "false" with no reason is not a finding: it means the customer's own
// routing does not point at this AS for anything, which is a fact about the
// customer and not about the submission.
func carriesCustomerTraffic(ctx context.Context, env *Env, sess externalSession,
	owed map[string]string) (string, bool) {
	if sess.PeerDevice == "" || sess.PeerIface == "" {
		return "", false
	}
	cands := transitTargets(env, sess, owed)
	for _, cand := range cands {
		// Does the customer already send this destination our way? Then the
		// probe needs no help: the traffic is the customer's own.
		res, err := env.Probe(ctx, sess.PeerDevice, []string{"ip", "route", "get", cand.Addr})
		if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, " dev "+sess.PeerIface) {
			continue
		}
		return transitProbe(ctx, env, sess, cand, "")
	}
	// Nothing is routed this way, which is a fact about the customer -- they
	// may prefer another provider -- and not an answer about the submission. A
	// session nobody happens to use is still a session that has to work, so the
	// traffic is put onto it: one host route on the customer's own router,
	// pointed at our address on this link, and a source address of theirs that
	// the rest of the internet has a route back to. Without the second part the
	// packet carries the link's own numbering, which is advertised nowhere, and
	// the first router that applies a reverse-path check drops it -- measured,
	// before this was understood, as a correct AS failing to carry anything.
	via := sessionAddrOf(ctx, env, sess)
	src := routableAddrOn(ctx, env, sess)
	if via == "" || src == "" || len(cands) == 0 {
		return "", false
	}
	cand := cands[0]
	route := []string{cand.Addr + "/32", "via", via, "dev", sess.PeerIface}
	if res, err := env.Probe(ctx, sess.PeerDevice,
		append([]string{"ip", "route", "replace"}, route...)); err != nil || res.ExitCode != 0 {
		return "", false
	}
	defer func() {
		_, _ = env.Probe(context.WithoutCancel(ctx), sess.PeerDevice,
			append([]string{"ip", "route", "del"}, route...))
	}()
	return transitProbe(ctx, env, sess, cand, src)
}

// transitProbe sends the packets and reads the destination's own counter.
func transitProbe(ctx context.Context, env *Env, sess externalSession, cand transitTarget,
	src string) (string, bool) {
	before, okB := echoesDeliveredTo(ctx, env, cand.Host)
	args := []string{"ping", "-c", "2", "-W", "2", "-i", "0.2"}
	if src != "" {
		args = append(args, "-I", src)
	}
	args = append(args, cand.Addr)
	ping, err := env.Probe(ctx, sess.PeerDevice, args)
	arrived := err == nil && ping.ExitCode == 0
	after, okA := echoesDeliveredTo(ctx, env, cand.Host)
	switch {
	case okB && okA && after > before:
	case arrived && (!okB || !okA):
		// The counter could not be read; the reply stands on its own.
	default:
		return fmt.Sprintf(
			"the customer at %s is offered %s but its traffic does not cross this AS: "+
				"a packet from %s to %s in AS %d was not delivered",
			sess.Addr, cand.Prefix, sess.PeerDevice, cand.Addr, cand.ASN), false
	}

	// And something other than a ping.
	//
	// Transit that carries ICMP and discards the rest is not transit. A rule
	// dropping forwarded TCP arriving from one customer left every probe
	// answered and the question at full marks, while no connection from that
	// customer could cross this AS. The destination counts the resets it sends,
	// so being refused is the far side speaking and silence is the packets
	// being swallowed on the way.
	rstBefore, okR := tcpResetsSent(ctx, env, cand.Host)
	conn := []string{"nc", "-v", "-w", "3", "-z"}
	if src != "" {
		conn = append(conn, "-s", src)
	}
	conn = append(conn, cand.Addr, probePort())
	res, cerr := env.Probe(ctx, sess.PeerDevice, conn)
	rstAfter, okR2 := tcpResetsSent(ctx, env, cand.Host)
	said := ""
	if cerr == nil {
		said = strings.ToLower(res.Stderr + res.Stdout)
	}
	switch {
	case okR && okR2 && rstAfter > rstBefore:
	case strings.Contains(said, "refused"), strings.Contains(said, "reset"):
	case cerr == nil && res.ExitCode == 0:
	case cerr != nil, !okR, !okR2:
		// Nothing could be established either way, so nothing is concluded.
	default:
		return fmt.Sprintf(
			"the customer at %s can ping across this AS but not connect: a connection from "+
				"%s to %s in AS %d never arrived, so the transit carries ICMP and nothing else",
			sess.Addr, sess.PeerDevice, cand.Addr, cand.ASN), false
	}
	return "", true
}

// sessionAddrOf finds our own address on this link, as the customer sees it:
// the neighbour they hold a session with whose remote AS is ours.
func sessionAddrOf(ctx context.Context, env *Env, sess externalSession) string {
	res, err := env.Probe(ctx, sess.PeerDevice, []string{"vtysh", "-c", "show ip bgp summary json"})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	var doc struct {
		IPv4Unicast struct {
			Peers map[string]struct {
				RemoteAs int `json:"remoteAs"`
			} `json:"peers"`
		} `json:"ipv4Unicast"`
	}
	if json.Unmarshal([]byte(res.Stdout), &doc) != nil {
		return ""
	}
	var found []string
	for addr, p := range doc.IPv4Unicast.Peers {
		if p.RemoteAs == env.AS {
			found = append(found, addr)
		}
	}
	sort.Strings(found)
	for _, addr := range found {
		// The one on this link, which is the only one the host route can use.
		if r, err := env.Probe(ctx, sess.PeerDevice,
			[]string{"ip", "route", "get", addr}); err == nil && r.ExitCode == 0 &&
			strings.Contains(r.Stdout, " dev "+sess.PeerIface) {
			return addr
		}
	}
	return ""
}

// routableAddrOn picks an address of the customer's that the rest of the
// internet has a route back to, which an inter-AS link's own numbering is not.
func routableAddrOn(ctx context.Context, env *Env, sess externalSession) string {
	as, ok := env.Topology.ASes[sess.ASN]
	if !ok || as.Block == "" {
		return ""
	}
	res, err := env.Probe(ctx, sess.PeerDevice,
		[]string{"ip", "-o", "-4", "addr", "show", "scope", "global"})
	if err != nil || res.ExitCode != 0 {
		return ""
	}
	best := ""
	for iface, addrs := range parseIPAddrOutput(res.Stdout) {
		for _, a := range addrs {
			if !anyInSubnet([]string{a}, as.Block) {
				continue
			}
			bare := a
			if j := strings.IndexByte(bare, '/'); j > 0 {
				bare = bare[:j]
			}
			if iface == "lo" {
				return bare // a loopback is up as long as the router is
			}
			if best == "" {
				best = bare
			}
		}
	}
	return best
}

// echoesDeliveredTo reads one host's count of ICMP echo requests delivered to
// it, which is the kernel's own and cannot be raised by anything on the path.
func echoesDeliveredTo(ctx context.Context, env *Env, device string) (int, bool) {
	res, err := env.Probe(ctx, device, []string{"cat", "/proc/net/snmp"})
	if err != nil || res.ExitCode != 0 {
		return 0, false
	}
	return icmpInEchos(res.Stdout)
}

// transitTarget is somewhere beyond this AS that a customer has been offered.
type transitTarget struct {
	Prefix string
	ASN    int
	Addr   string
	Host   string
}

// transitTargets lists destinations whose reachability the customer is buying,
// nearest relationship first, skipping the customer's own address space and
// anything this AS originates itself -- reaching the provider is not transit.
func transitTargets(env *Env, sess externalSession, owed map[string]string) []transitTarget {
	var out []transitTarget
	for asn, as := range env.Topology.ASes {
		if asn == env.AS || asn == sess.ASN || as.Block == "" {
			continue
		}
		if _, ok := owed[as.Block]; !ok {
			continue
		}
		for _, d := range as.Devices {
			if d.Kind != model.KindHost || d.L2Domain != "" {
				continue
			}
			if a := firstAddr(d); a != "" {
				out = append(out, transitTarget{Prefix: as.Block, ASN: asn, Addr: a, Host: d.ID})
				break
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ASN < out[b].ASN })
	return out
}

// learnedFrom reports whether a route came from a particular neighbour address.
func learnedFrom(e bgpRoute, addr string) bool {
	for _, nh := range e.NextHops() {
		if nh == addr {
			return true
		}
	}
	return false
}

// pathContainsASN reports whether an AS path traverses a given AS.
func pathContainsASN(path string, asn int) bool {
	want := strconv.Itoa(asn)
	for _, f := range strings.Fields(path) {
		if f == want {
			return true
		}
	}
	return false
}

// learnedFromRelationship says which neighbour a path came from, preferring
// the evidence the submission cannot alter.
//
// A path's peerId is the address of the session it arrived on. An inbound
// route-map can set the next hop to anything it likes -- rewriting a
// customer's to an unrelated on-link address made that customer's routes
// invisible to this check, so ranking them below a peer's cost nothing -- but
// no policy can change which session a route came in on.
func learnedFromRelationship(e bgpRoute, relOf map[string]model.Relationship) (
	model.Relationship, string, bool) {
	if e.PeerID != "" {
		if rel, ok := relOf[e.PeerID]; ok {
			return rel, e.PeerID, true
		}
	}
	for _, nh := range e.NextHops() {
		if rel, ok := relOf[nh]; ok {
			return rel, nh, true
		}
	}
	return "", "", false
}

// sourceRelationship infers which neighbour a route was learned from.//
// Both spellings of the next hop are read. FRR uses a "nexthops" array for
// `show ip bgp` and a scalar "nextHop" for advertised routes, and this check
// runs over the latter -- so reading only the array meant every advertisement
// had an unknown source, no leak could ever be attributed, and a network
// providing free transit to the entire internet passed the question about not
// doing that.
func sourceRelationship(e bgpRoute, selfAS int, relOf map[string]model.Relationship,
	relOfASN map[int]model.Relationship) model.Relationship {
	for _, nh := range e.Nexthops {
		if rel, ok := relOf[nh.IP]; ok {
			return rel
		}
	}
	if e.NextHop != "" {
		if rel, ok := relOf[e.NextHop]; ok {
			return rel
		}
	}
	// The AS path is the fallback, and for this question the better signal:
	// an advertisement whose path begins with a neighbour is a route learned
	// from that neighbour, whatever the next hop was rewritten to.
	//
	// Our own prepends are skipped first. The traffic-engineering question
	// asks for `set as-path prepend <own> <own> <own>` towards a slow
	// neighbour, so an advertisement leaving this AS reads "3 3 3 9" -- and
	// reading only the first element found *ourselves*, which is in no
	// relationship map, so the route's origin was unknown and a leak of a
	// provider's route through a prepended session went unnoticed.
	f := strings.Fields(strings.TrimSpace(e.Path))
	for len(f) > 0 && f[0] == strconv.Itoa(selfAS) {
		f = f[1:]
	}
	if len(f) > 0 {
		var asn int
		if _, err := fmt.Sscanf(f[0], "%d", &asn); err == nil {
			if rel, ok := relOfASN[asn]; ok {
				return rel
			}
		}
	}
	return ""
}

func checkNoForbiddenOSPF(ctx context.Context, env *Env) Result {
	// Every router, or none: this check concludes from what it does not find,
	// so a router it could not read is a router whose forbidden statements it
	// would also not have found.
	external := externalRangesOf(ctx, env)
	if len(external.nets) == 0 {
		// Which networks are forbidden is not a matter of opinion, but it is a
		// matter of knowing what this system's sessions are. Not knowing means
		// not concluding: passing here would award the mark for a rule that
		// was applied to nothing.
		return Errored("config.no_forbidden_ospf", fmt.Errorf(
			"this system has no external session the grader can see, so which networks "+
				"must stay out of its interior routing cannot be decided"))
	}
	cfgs, err := runningConfigs(ctx, env)
	if err != nil {
		return Fail("config.no_forbidden_ospf", Evidence{
			Expected: "every router's configuration readable, with no inter-AS network under router ospf",
			Observed: "some configurations could not be read",
			Detail:   err.Error(),
			Hint:     "make sure FRR is running on every router before submitting",
			Command:  "show running-config",
		})
	}
	var found []string
	for _, r := range env.Routers() {
		out := cfgs[r.Name]
		inOSPF := false
		for _, line := range strings.Split(out, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "router ospf") {
				inOSPF = true
				continue
			}
			if inOSPF && (t == "exit" || t == "!") {
				inOSPF = false
				continue
			}
			if !inOSPF || !strings.HasPrefix(t, "network ") {
				continue
			}
			// The assignment is explicit that the inter-AS ranges must not be
			// in OSPF: advertising them internally breaks eBGP next-hop
			// resolution in confusing ways.
			//
			// Which ranges those are is read off the sessions this system
			// actually has, not from the two prefixes the manifest happens to
			// plan. A group that agreed a different peering range with their
			// neighbour -- which the assignment lets them do -- could put it
			// in OSPF and pass, while the rule exists precisely to stop that.
			if external.matches(strings.TrimPrefix(t, "network ")) {
				found = append(found, fmt.Sprintf("%s: %s", r.Name, t))
			}
		}
	}

	// And what OSPF is actually carrying, which is the question.
	//
	// Reading `network` statements finds one way of putting a prefix into OSPF
	// and misses every other. `redistribute connected` under `router ospf` puts
	// every inter-AS subnet into the interior with no network statement
	// anywhere, and this check passed a system doing exactly that while the
	// peering networks appeared as OSPF routes on every other router of the
	// system. The configuration is the intent; the routing table is the fact.
	for _, r := range env.Routers() {
		type routeEntry struct {
			Protocol string `json:"protocol"`
			Selected bool   `json:"selected"`
			Nexthops []struct {
				InterfaceName string `json:"interfaceName"`
			} `json:"nexthops"`
		}
		var byVRF map[string]map[string][]routeEntry
		if err := env.VtyshJSON(ctx, r.Name, "show ip route vrf all ospf json", &byVRF); err != nil {
			// An empty table is not an error, and FRR prints nothing at all
			// for it; anything else is.
			if s, verr := env.Vtysh(ctx, r.Name, "show ip route vrf all ospf json"); verr == nil &&
				strings.TrimSpace(s) == "" {
				continue
			}
			return Errored("config.no_forbidden_ospf", fmt.Errorf(
				"%s: its OSPF routes could not be read, so whether the inter-AS ranges are "+
					"in its interior routing cannot be decided: %w", r.Name, err))
		}
		for vrf, routes := range byVRF {
			for prefix, entries := range routes {
				if !external.matches(prefix) {
					continue
				}
				for _, e := range entries {
					if e.Protocol != "ospf" {
						continue
					}
					where := r.Name
					if vrf != "" && vrf != "default" {
						where += " (in VRF " + vrf + ")"
					}
					found = append(found, fmt.Sprintf(
						"%s carries %s as an OSPF route", where, prefix))
					break
				}
			}
		}
	}

	// And what OSPF is carrying that never reaches a routing table.
	//
	// A prefix redistributed with the maximum metric is flooded to every
	// router in the area and installed by none of them: LSInfinity means "do
	// not use this", so `show ip route ospf` is empty and the RIB test above
	// sees nothing. A reviewer put an inter-AS range into OSPF exactly that
	// way and the check passed. The database is where a prefix being "in OSPF"
	// is decided; a routing table is only what a router chose to do about it.
	lsdb, err := forbiddenInLSDB(ctx, env, external)
	if err != nil {
		return Errored("config.no_forbidden_ospf", err)
	}
	found = append(found, lsdb...)

	if len(found) == 0 {
		return Pass("config.no_forbidden_ospf", Evidence{
			Observed: "no inter-AS subnet is advertised in OSPF, carried as an OSPF route, " +
				"or present in the link-state database"})
	}
	sort.Strings(found)
	return Fail("config.no_forbidden_ospf", Evidence{
		Expected: "no inter-AS network in the interior routing protocol, however it got there",
		Observed: fmt.Sprintf("%d finding(s)", len(found)),
		Detail:   strings.Join(truncate(found, 8), "\n"),
		Hint: "external subnets belong to BGP, not to your interior routing protocol; " +
			"`redistribute connected` puts them there as surely as a network statement does",
		Command: "show running-config; show ip route ospf",
	})
}

// ospfLSDB is the part of each link-state advertisement that names a prefix.
type ospfLSDB struct {
	RouterLinkStates struct {
		Areas map[string][]struct {
			AdvertisingRouter string `json:"advertisingRouter"`
			RouterLinks       map[string]struct {
				LinkType       string `json:"linkType"`
				NetworkAddress string `json:"networkAddress"`
				NetworkMask    string `json:"networkMask"`
			} `json:"routerLinks"`
		} `json:"areas"`
	} `json:"routerLinkStates"`
	NetworkLinkStates struct {
		Areas map[string][]ospfPrefixLSA `json:"areas"`
	} `json:"networkLinkStates"`
	SummaryLinkStates struct {
		Areas map[string][]ospfPrefixLSA `json:"areas"`
	} `json:"summaryLinkStates"`
	ASExternalLinkStates []ospfPrefixLSA `json:"asExternalLinkStates"`
}

type ospfPrefixLSA struct {
	LinkStateID       string `json:"linkStateId"`
	AdvertisingRouter string `json:"advertisingRouter"`
	NetworkMask       int    `json:"networkMask"`
	Metric            int    `json:"metric"`
}

// finding is one forbidden prefix and where it was advertised.
type finding struct{ where, what string }

// forbiddenInLSDB reports every inter-AS prefix that appears in a link-state
// database, whatever kind of advertisement carried it there, whatever metric it
// was given, and in whichever VRF the instance runs.
func forbiddenInLSDB(ctx context.Context, env *Env, external externalRanges) ([]string, error) {
	kinds := []string{"router", "network", "summary", "external"}
	var (
		mu       sync.Mutex
		out      []string
		firstErr error
		seen     = map[string]bool{}
		wg       sync.WaitGroup
	)
	for _, r := range env.Routers() {
		for _, kind := range kinds {
			wg.Add(1)
			go func(router, kind string) {
				defer wg.Done()
				// Every VRF, not the default one. An OSPF instance in another
				// VRF is another routing domain, and reading only the default
				// meant the report could say no inter-AS range was in OSPF
				// while an instance beside it held one.
				var dbs map[string]ospfLSDB
				cmd := "show ip ospf vrf all database " + kind + " json"
				if err := env.VtyshJSON(ctx, router, cmd, &dbs); err != nil {
					// A router with no OSPF prints nothing at all, which is an
					// empty database and not a failure to read one.
					if s, verr := env.Vtysh(ctx, router, cmd); verr == nil &&
						strings.TrimSpace(s) == "" {
						return
					}
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf(
							"%s: its OSPF database could not be read, so whether the "+
								"inter-AS ranges are in its interior routing cannot be "+
								"decided: %w", router, err)
					}
					mu.Unlock()
					return
				}
				var hits []finding
				for vrf, db := range dbs {
					hits = append(hits, lsdbHits(db, external, vrf)...)
				}
				mu.Lock()
				for _, h := range hits {
					line := fmt.Sprintf("%s floods %s", h.where, h.what)
					if !seen[line] {
						seen[line] = true
						out = append(out, line)
					}
				}
				mu.Unlock()
			}(r.Name, kind)
		}
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	sort.Strings(out)
	return out, nil
}

// lsdbHits names the forbidden prefixes in one link-state database.
func lsdbHits(db ospfLSDB, external externalRanges, vrf string) []finding {
	where := func(router string) string {
		if vrf != "" && vrf != "default" {
			return router + " (in VRF " + vrf + ")"
		}
		return router
	}
	var hits []finding
	for _, lsas := range db.RouterLinkStates.Areas {
		for _, lsa := range lsas {
			for _, l := range lsa.RouterLinks {
				if l.NetworkAddress == "" {
					continue
				}
				p := l.NetworkAddress + "/" + strconv.Itoa(maskBits(l.NetworkMask))
				if external.matches(p) {
					hits = append(hits, finding{where(lsa.AdvertisingRouter),
						fmt.Sprintf("%s as a %s in its router advertisement", p,
							strings.ToLower(l.LinkType))})
				}
			}
		}
	}
	add := func(lsas []ospfPrefixLSA, what string) {
		for _, lsa := range lsas {
			p := lsa.LinkStateID + "/" + strconv.Itoa(lsa.NetworkMask)
			if external.matches(p) {
				hits = append(hits, finding{where(lsa.AdvertisingRouter),
					fmt.Sprintf("%s as %s (metric %d)", p, what, lsa.Metric)})
			}
		}
	}
	for _, lsas := range db.NetworkLinkStates.Areas {
		add(lsas, "a transit network")
	}
	for _, lsas := range db.SummaryLinkStates.Areas {
		add(lsas, "an inter-area summary")
	}
	add(db.ASExternalLinkStates, "an external route redistributed into OSPF")
	return hits
}

// maskBits turns OSPF's dotted network mask into a prefix length.
func maskBits(mask string) int {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		if n, err := strconv.Atoi(mask); err == nil {
			return n
		}
		return 32
	}
	bits := 0
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 32
		}
		for ; n > 0; n <<= 1 {
			bits++
			n &= 0xff
		}
	}
	return bits
}

// peerPlannedAddr is the address the manifest gave the far end of a link.
func peerPlannedAddr(i *model.Iface) string {
	if i.Peer == nil {
		return ""
	}
	return i.Peer.Addr4
}

// externalRanges are the networks this system's external sessions are on.
type externalRanges struct{ nets []netip.Prefix }

// externalRangesOf reads them off the sessions rather than off the plan.
func externalRangesOf(ctx context.Context, env *Env) externalRanges {
	var out externalRanges
	seen := map[string]bool{}
	addrs := []string{}
	for _, s := range externalSessions(ctx, env) {
		addrs = append(addrs, s.Addr)
	}
	// The planned ranges as well as the ones in use.
	//
	// Reading only what is live would make the rule apply to nothing on a
	// system whose sessions are all down -- which is the state a submission
	// that put the inter-AS range into OSPF is quite likely to be in.
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil || !i.Link.InterAS {
				continue
			}
			// Both ends of the planned link. The plan is the right source
			// here, and only here: this is about which networks are external,
			// which the manifest defines, rather than about which address a
			// group chose to peer on, which only the device knows.
			for _, planned := range []string{i.Addr4, peerPlannedAddr(i)} {
				if p, err := netip.ParsePrefix(planned); err == nil {
					addrs = append(addrs, p.Addr().String())
				}
			}
		}
	}
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		// The neighbour's address with the local prefix length; the exact
		// length matters less than the network, and any statement covering the
		// neighbour's address is the one the rule is about.
		for _, bits := range []int{24, 30, 31, 29, 28} {
			p := netip.PrefixFrom(a, bits).Masked()
			if !seen[p.String()] {
				seen[p.String()] = true
				out.nets = append(out.nets, p)
			}
		}
	}
	return out
}

// matches reports whether an OSPF network statement covers a session's network.
func (e externalRanges) matches(stmt string) bool {
	f := strings.Fields(stmt)
	if len(f) == 0 {
		return false
	}
	p, err := netip.ParsePrefix(f[0])
	if err != nil {
		return false
	}
	p = p.Masked()
	for _, n := range e.nets {
		if p.Contains(n.Addr()) || n.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func addrOf(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

// jsonUnmarshalLoose decodes JSON, tolerating the leading noise some vtysh
// versions emit before the document.
func jsonUnmarshalLoose(s string, out any) error {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if s == "" {
		return fmt.Errorf("empty output")
	}
	return json.Unmarshal([]byte(s), out)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// externalSession is one BGP session this AS has with somebody outside it.
type externalSession struct {
	Router string
	Addr   string
	Rel    model.Relationship
	ASN    int
	// PeerDevice is the device on the far side, which is not the submission's
	// to configure and is therefore where unforgeable evidence comes from.
	PeerDevice string
	// PeerIface is the interface the far side terminates this link on, which
	// is how a probe launched from over there is known to have entered this AS
	// through this session and not by some other way round.
	PeerIface string
}

// externalSessions lists every session with a neighbour outside this AS,
// including the one with an exchange's route server.
//
// The exchange used to be missing from every policy check, because a member's
// interface onto an exchange sits on a shared segment and the checks skipped
// anything that was not a point-to-point inter-AS link. So the question those
// checks exist to ask -- what may cross a session to somebody who is not a
// customer -- was never asked about the exchange, which is exactly where
// leaking a provider's route is the classic mistake and where the assignment
// spends a whole question. A submission that leaked everything to the exchange
// scored full marks for no transit.
func externalSessions(ctx context.Context, env *Env) []externalSession {
	var out []externalSession
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil {
				continue
			}
			switch {
			case i.Role == model.RoleIXPLink:
				// At an exchange the session is with the route server, and the
				// members behind it are peers by definition: only this AS's own
				// and its customers' routes may cross it.
				addr, asn := routeServerOn(env.Topology, i)
				if addr == "" {
					continue
				}
				rsDev := ""
				if rs, ok := routeServerDevice(env.Topology, asn); ok {
					rsDev = rs.ID
				}
				out = append(out, externalSession{Router: r.Name, Addr: addr,
					Rel: model.RelPeer, ASN: asn, PeerDevice: rsDev})
			case i.Link.InterAS && i.Peer != nil && i.Peer.Addr4 != "":
				rel := i.Link.PeerRelationship(i)
				asn, dev := 0, ""
				if i.Peer.Device != nil {
					asn, dev = i.Peer.Device.ASN, i.Peer.Device.ID
				}
				peerIface := ""
				if i.Peer != nil {
					peerIface = i.Peer.Name
				}
				out = append(out, externalSession{Router: r.Name, Addr: env.PeerAddr(ctx, i),
					Rel: rel, ASN: asn, PeerDevice: dev, PeerIface: peerIface})
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Router != out[b].Router {
			return out[a].Router < out[b].Router
		}
		return out[a].Addr < out[b].Addr
	})
	return out
}
