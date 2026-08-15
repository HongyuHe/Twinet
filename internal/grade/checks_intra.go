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
	"time"

	"github.com/HongyuHe/twinet/internal/model"
)

// This file registers the checks that grade the intra-domain half of the
// assignment: layer-2 isolation, addressing, OSPF, load balancing and tunnels.

func init() {
	Register(&Check{
		Name: "l3.addressing_matches_plan",
		Describe: "every router interface carries the address the assignment prescribes, " +
			"and no router carries one the plan does not mention",
		Run: checkAddressing,
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

	// Addresses the plan does not mention are marked, not merely mentioned.
	//
	// This used to report them and score them neither way, on the reasoning
	// that a student who adds an address while testing has not got the
	// addressing wrong. Two reviewers put the same objection: the question is
	// whether the addressing matches the plan, and a router carrying an address
	// the plan does not mention does not match it. Worse, an unplanned address
	// is the raw material for impersonation -- claiming a subnet that lives
	// somewhere else is exactly how a submission stands in for a part of the
	// network it is not, and that has been the shape of most of the defects
	// found in this grader.
	//
	// So an address outside every subnet in the lab is clutter and costs the
	// same as one wrong interface, while an address inside a subnet the plan
	// assigns elsewhere is a counterfeit and fails the check outright. An
	// address inside the interface's own subnet is neither: that is the
	// student's own choice, which the plan leaves to them.
	var extra, counterfeit []string
	planned := plannedSubnets(env)

	for _, r := range env.Routers() {
		out, err := env.Probe(ctx, r.ID, []string{"ip", "-o", "-4", "addr", "show", "scope", "global"})
		if err != nil {
			return Errored("l3.addressing_matches_plan", err)
		}
		have := parseIPAddrOutput(out.Stdout)
		known := map[string]bool{}
		for _, i := range r.Ifaces {
			if i.Addr4 != "" {
				known[i.Name+" "+i.Addr4] = true
			}
		}
		for iface, addrs := range have {
			for _, a := range addrs {
				if known[iface+" "+a] {
					continue
				}
				if i, ok := r.IfaceByName(iface); ok && ownSubnet(i, a) {
					continue // the student's own choice inside the mandated prefix
				}
				if where := impersonates(planned, a); where != "" {
					counterfeit = append(counterfeit, fmt.Sprintf(
						"%s:%s carries %s, which is inside %s -- a subnet the plan puts on %s",
						r.Name, iface, a, where, planned[where]))
					continue
				}
				extra = append(extra, fmt.Sprintf("%s:%s carries %s, which the plan does "+
					"not mention", r.Name, iface, a))
			}
		}

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

	sort.Strings(extra)
	sort.Strings(counterfeit)
	if len(counterfeit) > 0 {
		return Fail("l3.addressing_matches_plan", Evidence{
			Expected: "no router carrying an address out of a subnet that belongs elsewhere",
			Observed: fmt.Sprintf("%d address(es) claim a subnet the plan puts on another "+
				"interface", len(counterfeit)),
			Detail:  strings.Join(truncate(counterfeit, 6), "\n"),
			Hint:    "an address from somebody else's subnet makes this router answer for a part of the network it is not",
			Command: "ip -o -4 addr show scope global",
		})
	}
	if len(bad) == 0 && len(missing) == 0 && len(extra) == 0 {
		return Pass("l3.addressing_matches_plan", Evidence{
			Detail: fmt.Sprintf("all %d required addresses are configured, and no router "+
				"carries an address the plan does not mention", checked)})
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
	for _, e := range truncate(extra, 6) {
		fmt.Fprintf(&detail, "%s\n", e)
	}
	wrong := len(bad) + len(missing) + len(extra)
	return Partial("l3.addressing_matches_plan", ratio(checked-len(bad)-len(missing), checked+len(extra)), Evidence{
		Expected: fmt.Sprintf("%d addresses and nothing else", checked),
		Observed: fmt.Sprintf("%d of them wrong or missing, %d not in the plan",
			wrong-len(extra), len(extra)),
		Detail:  strings.TrimRight(detail.String(), "\n"),
		Hint:    "the required addresses are in the assignment's L3 topology figure",
		Command: "ip -o -4 addr show",
	})
}

// plannedSubnets maps every subnet in the lab to a short description of where
// it belongs, so an address found somewhere else can be named for what it is.
func plannedSubnets(env *Env) map[string]string {
	out := map[string]string{}
	for _, l := range env.Topology.Links {
		if l.Subnet == "" {
			continue
		}
		var ends []string
		for _, e := range []*model.Iface{l.A, l.B} {
			if e != nil && e.Device != nil {
				ends = append(ends, e.Device.ID+":"+e.Name)
			}
		}
		out[l.Subnet] = strings.Join(ends, " and ")
	}
	for _, d := range env.Topology.Devices {
		for _, i := range d.Ifaces {
			if i.Subnet == "" {
				continue
			}
			if _, ok := out[i.Subnet]; !ok {
				out[i.Subnet] = d.ID + ":" + i.Name
			}
		}
		if lo, ok := d.IfaceByName("lo"); ok && lo.Addr4 != "" {
			if p, err := netip.ParsePrefix(lo.Addr4); err == nil {
				s := p.Masked().String()
				if _, ok := out[s]; !ok {
					out[s] = d.ID + ":lo"
				}
			}
		}
	}
	return out
}

// ownSubnet reports whether an address is inside the prefix this interface is
// meant to sit in, which is the student's to choose within.
func ownSubnet(i *model.Iface, addr string) bool {
	if i.Subnet != "" && anyInSubnet([]string{addr}, i.Subnet) {
		return true
	}
	// A link the plan addresses but does not prescribe -- an inter-AS session,
	// whose numbering is agreed with the neighbour rather than dictated.
	if i.Link != nil && i.Link.Subnet != "" && anyInSubnet([]string{addr}, i.Link.Subnet) {
		return true
	}
	if i.Addr4 != "" {
		if p, err := netip.ParsePrefix(i.Addr4); err == nil &&
			anyInSubnet([]string{addr}, p.Masked().String()) {
			return true
		}
	}
	return false
}

// impersonates names the planned subnet an address has been taken from, if any.
func impersonates(planned map[string]string, addr string) string {
	ip, err := netip.ParsePrefix(addr)
	if err != nil {
		a, err2 := netip.ParseAddr(addr)
		if err2 != nil {
			return ""
		}
		ip = netip.PrefixFrom(a, a.BitLen())
	}
	best, bestBits := "", -1
	for s := range planned {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4() != ip.Addr().Is4() {
			continue
		}
		if p.Contains(ip.Addr()) && p.Bits() > bestBits {
			best, bestBits = s, p.Bits()
		}
	}
	return best
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
	// Which adjacency, not how many.
	//
	// This counted neighbours in state Full and compared the total with twice
	// the number of interior links. A count does not say *which* links: making
	// the interfaces of one link passive and building a tunnel between the same
	// two routers to carry an adjacency instead kept the total exactly right,
	// and the question -- which is about the interior links being adjacent --
	// reported all twenty-four of them Full. The topology says which interface
	// faces which router, and that is what is required to be adjacent.
	type want struct{ router, iface, peer string }
	var wanted []want
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil || i.Link.InterAS || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			if !i.Peer.Device.IsRouter() || i.Peer.Device.ASN != env.AS {
				continue
			}
			wanted = append(wanted, want{r.Name, i.Name, i.Peer.Device.Name})
		}
	}
	if len(wanted) == 0 {
		return Errored("ospf.full_adjacency",
			fmt.Errorf("AS %d has no interior link between routers", env.AS))
	}

	// What each router has, by interface.
	full := map[string]map[string]bool{}    // router -> iface -> a Full neighbour
	state := map[string]map[string]string{} // router -> iface -> worst state seen
	var extra []string
	for _, r := range env.Routers() {
		var out ospfNeighborJSON
		if err := env.VtyshJSON(ctx, r.Name, "show ip ospf neighbor json", &out); err != nil {
			// A router with OSPF entirely unconfigured is a legitimate student
			// failure, not a grader failure, so it counts as no adjacencies.
			continue
		}
		full[r.Name] = map[string]bool{}
		state[r.Name] = map[string]string{}
		planned := map[string]bool{}
		for _, w := range wanted {
			if w.router == r.Name {
				planned[w.iface] = true
			}
		}
		for id, ns := range out.Neighbors {
			for _, n := range ns {
				iface := n.IfaceName
				if i := strings.IndexByte(iface, ':'); i >= 0 {
					iface = iface[:i]
				}
				if strings.HasPrefix(n.NbrState, "Full") {
					full[r.Name][iface] = true
				} else if state[r.Name][iface] == "" {
					state[r.Name][iface] = n.NbrState
				}
				if !planned[iface] {
					extra = append(extra, fmt.Sprintf("%s is adjacent to %s over %s, which is "+
						"not an interior link of this AS", r.Name, id, iface))
				}
			}
		}
	}

	var stuck []string
	got := 0
	for _, w := range wanted {
		switch {
		case full[w.router][w.iface]:
			got++
		case state[w.router][w.iface] != "":
			stuck = append(stuck, fmt.Sprintf("%s -> %s on %s is %s",
				w.router, w.peer, w.iface, state[w.router][w.iface]))
		default:
			stuck = append(stuck, fmt.Sprintf("%s has no OSPF adjacency with %s on %s",
				w.router, w.peer, w.iface))
		}
	}
	sort.Strings(extra)

	if got == len(wanted) && len(stuck) == 0 && len(extra) == 0 {
		return Pass("ospf.full_adjacency", Evidence{
			Observed: fmt.Sprintf("all %d interior adjacencies are Full, each on the link "+
				"the plan gives it", got)})
	}
	sort.Strings(stuck)
	detail := append(append([]string{}, stuck...), extra...)
	score := ratio(got, len(wanted))
	if len(extra) > 0 {
		// An adjacency somewhere the plan does not have a link is not a
		// substitute for one it does.
		score *= 0.5
	}
	return Partial("ospf.full_adjacency", score, Evidence{
		Expected: fmt.Sprintf("%d adjacencies in state Full, one for each interior link end",
			len(wanted)),
		Observed: fmt.Sprintf("%d of them", got),
		Detail:   strings.Join(truncate(detail, 8), "\n"),
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
	// And it counts only as a route of the area, not as something redistributed
	// into it.
	//
	// "Protocol is ospf" is true of a route somebody redistributed from a
	// static blackhole: remove the genuine advertisement of a service subnet,
	// point a Null0 route at it on a different router and turn on
	// `redistribute static`, and the prefix is in every table, marked ospf,
	// reaching nowhere -- the service went to 100% loss while this check said
	// all thirty-two subnets were carried. OSPF itself distinguishes them: an
	// intra-area network route is "N", and a redistributed one is "N E1" or
	// "N E2". The subnet has to be in the area, which is what putting it in
	// OSPF means and what makes it survive the attached router being reached
	// another way.
	// Which router interface each subnet hangs off, according to the plan.
	//
	// Without this the check asked only whether *somebody* held the prefix as
	// an intra-area route, and a prefix has no memory of where it came from: a
	// reviewer took 3.0.199.0/24 out of OSPF on HOU, where the measurement
	// network actually is, put 3.0.199.254/24 on a dummy interface on CHI and
	// advertised it from there. Every router held 3.0.199.0/24 as an "N" route
	// and the check gave full credit for a measurement network that OSPF no
	// longer reached. A subnet is advertised when the router it is attached to
	// advertises it; anywhere else is a different subnet that happens to be
	// spelled the same.
	attached := map[string][]attachment{}
	for _, r := range routers {
		for _, i := range r.Ifaces {
			for p := range want {
				if ifacePlannedIn(i, p) {
					attached[p] = append(attached[p], attachment{Router: r.Name, Iface: i.Name})
				}
			}
		}
	}

	seen := map[string]map[string]bool{} // prefix -> routers holding it intra-area
	external := map[string]bool{}
	enabled := map[string]map[string]ospfIfaceState{} // router -> iface -> state
	read := 0
	var unreadable []string
	for _, r := range routers {
		var classes map[string]ospfRouteClass
		if err := env.VtyshJSON(ctx, r.Name, "show ip ospf route json", &classes); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		read++
		for prefix, c := range classes {
			switch {
			case strings.Contains(c.RouteType, "E"):
				external[prefix] = true
			case strings.HasPrefix(c.RouteType, "N"):
				if seen[prefix] == nil {
					seen[prefix] = map[string]bool{}
				}
				seen[prefix][r.Name] = true
			}
		}
		var ifaces ospfIfacesJSON
		if err := env.VtyshJSON(ctx, r.Name, "show ip ospf interface json", &ifaces); err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s interfaces: %v", r.Name, err))
			continue
		}
		enabled[r.Name] = ifaces.states()
	}
	if read == 0 {
		return Errored("ospf.subnets_advertised", fmt.Errorf(
			"no router's routing table could be read, so nothing could be assessed: %s",
			strings.Join(truncate(unreadable, 3), "; ")))
	}

	var absent, notes []string
	for p, why := range want {
		here := attached[p]
		// Somebody other than the attachment has to hold it, or it was never
		// flooded: a directly connected network is in its own router's OSPF
		// table whether or not any neighbour ever heard about it.
		elsewhere := false
		for r := range seen[p] {
			if !attachedTo(here, r) {
				elsewhere = true
				break
			}
		}
		remoteExists := len(routers) > len(here)
		switch {
		case len(here) == 0:
			// No interface in the plan sits in this subnet, so there is no
			// attachment to hold to; fall back to "somebody carries it".
			if len(seen[p]) == 0 {
				absent = append(absent, fmt.Sprintf("%s (%s)", p, why))
			}
		case !advertisedAt(enabled, here, p):
			where := describeAttachments(here)
			switch {
			case external[p] && len(seen[p]) == 0:
				absent = append(absent, fmt.Sprintf("%s (%s) is redistributed into OSPF as an "+
					"external route rather than advertised by %s, the router it is attached to",
					p, why, where))
			case len(seen[p]) > 0:
				absent = append(absent, fmt.Sprintf(
					"%s (%s) is in OSPF, but not from %s, where the plan attaches it: "+
						"some other router is advertising that prefix", p, why, where))
			default:
				absent = append(absent, fmt.Sprintf("%s (%s) is not in OSPF on %s", p, why, where))
			}
		case external[p] && len(seen[p]) == 0:
			absent = append(absent, fmt.Sprintf("%s (%s) is redistributed into OSPF as an "+
				"external route rather than advertised by the router it is attached to", p, why))
		case remoteExists && !elsewhere:
			absent = append(absent, fmt.Sprintf(
				"%s (%s) is enabled on %s but no other router has it as an intra-area route, "+
					"so it was never flooded", p, why, describeAttachments(here)))
		}
		if extra := advertisedElsewhere(enabled, here, p); len(extra) > 0 {
			notes = append(notes, fmt.Sprintf(
				"note: %s is also in OSPF on %s, which the plan does not attach to it",
				p, strings.Join(extra, ", ")))
		}
	}
	sort.Strings(absent)
	sort.Strings(notes)

	if len(absent) == 0 {
		observed := fmt.Sprintf(
			"all %d internal subnets are advertised by the router the plan attaches them to "+
				"and reach the rest of the area, checked across %d routers", len(want), read)
		return Pass("ospf.subnets_advertised", Evidence{Observed: observed,
			Detail: strings.Join(notes, "\n")})
	}
	return Partial("ospf.subnets_advertised", ratio(len(want)-len(absent), len(want)), Evidence{
		Expected: fmt.Sprintf("all %d internal subnets advertised in OSPF by the router "+
			"the plan attaches them to", len(want)),
		Observed: fmt.Sprintf("%d are not", len(absent)),
		Detail:   strings.Join(append(absent, notes...), "\n"),
		Hint:     "the DNS and measurement subnets must be advertised in OSPF too",
		Command:  "show ip ospf interface json",
	})
}

// attachment is one place the plan puts a subnet: an interface of a router.
type attachment struct {
	Router string
	Iface  string
}

func attachedTo(list []attachment, router string) bool {
	for _, a := range list {
		if a.Router == router {
			return true
		}
	}
	return false
}

func describeAttachments(list []attachment) string {
	var parts []string
	for _, a := range list {
		parts = append(parts, a.Router+":"+a.Iface)
	}
	sort.Strings(parts)
	return strings.Join(parts, " or ")
}

// ifacePlannedIn reports whether the plan puts this interface in that subnet.
func ifacePlannedIn(i *model.Iface, prefix string) bool {
	if i.Addr4 == "" {
		return false
	}
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	addr, err := netip.ParsePrefix(i.Addr4)
	if err != nil {
		return false
	}
	// A loopback is wanted as its own host route, which its /24 interface
	// address does not sit "inside" in the ordinary sense.
	if pfx.Bits() == 32 {
		return addr.Addr() == pfx.Addr()
	}
	return pfx.Contains(addr.Addr())
}

// advertisedAt reports whether OSPF is running on one of the planned
// attachment interfaces with an address that is actually in the subnet.
//
// Both halves matter. Without the first, a subnet counts as advertised when a
// dummy interface somewhere else in the AS carries the same numbers. Without
// the second, a student could leave OSPF enabled on the interface, readdress it
// out of the subnet, and still be credited for advertising a prefix that is no
// longer there.
func advertisedAt(enabled map[string]map[string]ospfIfaceState, here []attachment, prefix string) bool {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	for _, a := range here {
		st, ok := enabled[a.Router][a.Iface]
		if !ok || !st.Enabled {
			continue
		}
		for _, addr := range st.Addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			if pfx.Bits() == 32 {
				if ip == pfx.Addr() {
					return true
				}
				continue
			}
			if pfx.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// advertisedElsewhere names the router interfaces outside the plan's
// attachment that are running OSPF with an address in the subnet. A subnet
// injected from a second place is not what the assignment asks for even when
// the right router is also advertising it, and saying so in the report is what
// turns a silent duplicate into something a grader can see.
func advertisedElsewhere(enabled map[string]map[string]ospfIfaceState, here []attachment, prefix string) []string {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil || pfx.Bits() == 32 {
		return nil
	}
	var out []string
	for router, ifaces := range enabled {
		for name, st := range ifaces {
			if !st.Enabled {
				continue
			}
			planned := false
			for _, a := range here {
				if a.Router == router && a.Iface == name {
					planned = true
					break
				}
			}
			if planned {
				continue
			}
			for _, addr := range st.Addrs {
				ip, err := netip.ParseAddr(addr)
				if err == nil && pfx.Contains(ip) {
					out = append(out, router+":"+name)
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// ospfIfacesJSON is `show ip ospf interface json`: what OSPF itself believes
// it is running on, read per interface rather than inferred from a prefix
// turning up in a routing table.
type ospfIfacesJSON struct {
	Interfaces map[string]struct {
		OSPFEnabled bool `json:"ospfEnabled"`
		IfUp        bool `json:"ifUp"`
		InterfaceIP map[string]struct {
			IPAddress string `json:"ipAddress"`
			Area      string `json:"area"`
		} `json:"interfaceIp"`
		IPAddress string `json:"ipAddress"`
	} `json:"interfaces"`
}

type ospfIfaceState struct {
	Enabled bool
	Addrs   []string
}

func (j ospfIfacesJSON) states() map[string]ospfIfaceState {
	out := map[string]ospfIfaceState{}
	for name, e := range j.Interfaces {
		st := ospfIfaceState{Enabled: e.OSPFEnabled && e.IfUp}
		for addr := range e.InterfaceIP {
			st.Addrs = append(st.Addrs, addr)
		}
		if len(st.Addrs) == 0 && e.IPAddress != "" {
			st.Addrs = append(st.Addrs, e.IPAddress)
		}
		sort.Strings(st.Addrs)
		out[name] = st
	}
	return out
}

// ospfRouteClass is one entry of `show ip ospf route json`: how OSPF itself
// classifies a destination. "N" is an intra-area network, "N IA" an inter-area
// one, and "N E1"/"N E2" something redistributed from outside OSPF.
type ospfRouteClass struct {
	RouteType string `json:"routeType"`
	Area      string `json:"area,omitempty"`
	Cost      int    `json:"cost,omitempty"`
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

	// And the paths have to carry a packet.
	//
	// Everything above reads the forwarding tables, which say exactly which
	// next hops are installed and are the only honest way to establish that a
	// path exists -- sampling traceroutes can miss a live path entirely. What
	// the tables cannot say is whether anything gets through: a firewall rule
	// dropping this very traffic leaves every prescribed next hop installed
	// and every packet discarded, and that scored full marks for a question
	// about how traffic is carried. So the tables decide which paths exist and
	// a probe decides whether they work; neither substitutes for the other.
	var dead string
	if src, ok := env.Device(from); ok {
		addr := addrOnly(lo.Addr4)
		reached, err := env.reaches(ctx, src.ID, addr)
		switch {
		case err != nil:
			return Errored("ospf.ecmp_paths", fmt.Errorf(
				"probing %s from %s: %w", addr, from, err))
		case !reached:
			dead = fmt.Sprintf("%s cannot reach %s (%s) at all, so none of the installed "+
				"paths is carrying anything", from, to, addr)
			fmt.Fprintf(&detail, "%s\n", dead)
		}
	}

	got := make([]string, 0)
	for h := range nextHops[from] {
		got = append(got, h)
	}
	sort.Strings(got)

	if dead != "" {
		// Installed and useless is worse than partially installed: the marks
		// for this question are for traffic taking the intended paths.
		return Partial("ospf.ecmp_paths", 0, Evidence{
			Expected: fmt.Sprintf("%d equal-cost paths from %s to %s, carrying traffic",
				len(wantPaths), from, to),
			Observed: dead,
			Detail:   strings.TrimRight(detail.String(), "\n"),
			Hint: "the routes are installed, so this is not a routing problem: something " +
				"between the two is discarding the packets",
			Command: "show ip route json; ping",
		})
	}

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
	// Four at a time, not ten. The hosts of a layer-2 domain sit behind
	// deliberately slow links (10mbit, 1ms), and ten traceroutes at once
	// through one switch lose probes -- which this check would read as a
	// misconfiguration and take a mark for.
	sem := make(chan struct{}, 4)
	record := func(ok bool, format string, args ...any) {
		mu.Lock()
		results = append(results, outcome{ok, fmt.Sprintf(format, args...)})
		mu.Unlock()
	}

	// Same VLAN: reachable, and directly, in both directions.
	//
	// This ran i<j, one probe per unordered pair, while the cross-VLAN half
	// below deliberately runs every *ordered* pair. Reachability is not
	// symmetric and a student's mistake need not be either: a host that drops
	// what it sends to a neighbour, or a switch port filtering one way, leaves
	// the other direction working -- and whichever way the loop happened to
	// probe was the mark. A firewall rule dropping new outbound traffic to a
	// same-VLAN neighbour scored full marks.
	for _, v := range vlans {
		hs := hosts[v]
		for i := 0; i < len(hs); i++ {
			for j := 0; j < len(hs); j++ {
				if i == j {
					continue
				}
				wg.Add(1)
				go func(v int, src, dst *model.Device) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					hops, err := adjacentHopsRetrying(ctx, env, src, dst)
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
						hops, first, err := traceFirstHopRetrying(ctx, env, src, dst)
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
		srcIface string // set when probing from a shared service container
	}
	var pairs []probe
	for _, a := range hosts {
		for _, b := range hosts {
			if a.ID == b.ID || addrOf[b.ID] == "" {
				continue
			}
			pairs = append(pairs, probe{from: a, to: b})
		}
	}

	// The service networks, probed from the service's side.
	//
	// The measurement and DNS subnets are part of the assignment and were
	// graded only by whether OSPF carried the prefix -- no packet was ever sent
	// to or from them, and the counter on the measurement container read zero
	// after every run this project has ever done. That left the whole of a
	// service network's data plane resting on a routing table entry: a
	// reviewer moved the measurement prefix onto a dummy interface on another
	// router, and although the network was then unreachable the reachability
	// check never noticed, because it only ever probed hosts.
	//
	// The probe runs from the service container, which the platform owns and a
	// student cannot touch, so the source of the traffic is not something a
	// submission can arrange. Its reply has to find its way back through the
	// service subnet, which is the part that has to be advertised.
	for _, s := range serviceAttachments(env) {
		for _, h := range hosts {
			if addrOf[h.ID] == "" {
				continue
			}
			pairs = append(pairs, probe{from: s.Device, to: h, srcIface: s.Iface})
		}
	}
	if len(pairs) == 0 {
		return Errored("dataplane.internal_reachability",
			fmt.Errorf("AS %d has no addressed host to probe", env.AS))
	}

	// What each host received, before and after.
	//
	// A ping proves that something answered, not that the intended host did.
	// Redirecting echo requests for one host to another with a DNAT rule --
	// conntrack rewrites the reply on the way back, so the source sees a
	// perfectly ordinary answer from the address it asked about -- left every
	// probe succeeding while the host in question received nothing at all.
	// The kernel's own count of echo requests delivered to it is not something
	// a route or a NAT rule can arrange: if it did not go up, the packets did
	// not arrive there.
	//
	// Read once per host rather than once per pair, so 56 probes cost 16 extra
	// reads and not 112.
	echoesBefore := receivedEchoes(ctx, env, hosts)

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
			args := []string{"ping", "-c", "2", "-W", "2", "-i", "0.2"}
			if p.srcIface != "" {
				args = append(args, "-I", p.srcIface)
			}
			args = append(args, addr)
			res, err := env.Probe(ctx, p.from.ID, args)
			if err != nil || res.ExitCode != 0 {
				from := p.from.Name
				if p.srcIface != "" {
					from = p.from.ID + " (the " + p.from.Name + " network)"
				}
				mu.Lock()
				failed = append(failed, fmt.Sprintf("%s cannot reach %s (%s)",
					from, p.to.Name, addr))
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	tried := len(pairs)
	// Every host that was probed must have seen the probes.
	echoesAfter := receivedEchoes(ctx, env, hosts)
	var unseen []string
	sentTo := map[string]int{}
	for _, p := range pairs {
		sentTo[p.to.ID]++
	}
	for _, h := range hosts {
		want, ok := sentTo[h.ID]
		if !ok || want == 0 {
			continue
		}
		before, okB := echoesBefore[h.ID]
		after, okA := echoesAfter[h.ID]
		if !okB || !okA {
			continue // the counter could not be read; the ping stands on its own
		}
		if after <= before {
			unseen = append(unseen, fmt.Sprintf("%s answered %d probe(s) it never received: "+
				"something else is replying for it", h.Name, want))
		}
	}
	if len(unseen) > 0 {
		sort.Strings(unseen)
		return Fail("dataplane.internal_reachability", Evidence{
			Expected: "every host reachable from every other, and the packets arriving at the " +
				"host they were addressed to",
			Observed: fmt.Sprintf("%d host(s) never saw the traffic addressed to them", len(unseen)),
			Detail:   strings.Join(truncate(unseen, 6), "\n"),
			Hint: "a reply proves something answered, not that the right machine did; check " +
				"for address translation on the path",
			Command: "ping; /proc/net/snmp",
		})
	}
	if len(failed) == 0 {
		return Pass("dataplane.internal_reachability", Evidence{
			Observed: fmt.Sprintf("all %d ordered probes arrive, host to host and from every "+
				"service network, and every host received the traffic addressed to it", tried)})
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

// svcAttachment is one shared service container's connection into an AS.
type svcAttachment struct {
	Device *model.Device
	Iface  string
	Addr   string
}

// serviceAttachments finds the platform's service containers that hang off
// this AS, together with the interface facing it.
//
// A service container is wired to every AS at once, so which interface it uses
// decides which network the traffic goes through; probing without pinning it
// would let a working neighbour's link stand in for a broken one.
func serviceAttachments(env *Env) []svcAttachment {
	var out []svcAttachment
	for _, d := range env.Topology.Devices {
		if d.Kind != model.KindService {
			continue
		}
		for _, i := range d.Ifaces {
			if i.Link == nil || i.Addr4 == "" || i.Name == "lo" {
				continue
			}
			other := i.Link.A
			if other == i {
				other = i.Link.B
			}
			if other == nil || other.Device == nil || other.Device.ASN != env.AS {
				continue
			}
			addr := i.Addr4
			if j := strings.IndexByte(addr, '/'); j > 0 {
				addr = addr[:j]
			}
			out = append(out, svcAttachment{Device: d, Iface: i.Name, Addr: addr})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Device.ID != out[b].Device.ID {
			return out[a].Device.ID < out[b].Device.ID
		}
		return out[a].Iface < out[b].Iface
	})
	return out
}

// receivedEchoes reads each host's count of ICMP echo requests delivered to it.//
// The kernel keeps it; nothing a submission configures can raise it without the
// packets actually arriving.
func receivedEchoes(ctx context.Context, env *Env, hosts []*model.Device) map[string]int {
	out := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, h := range hosts {
		wg.Add(1)
		go func(h *model.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := env.Probe(ctx, h.ID, []string{"cat", "/proc/net/snmp"})
			if err != nil || res.ExitCode != 0 {
				return
			}
			if n, ok := icmpInEchos(res.Stdout); ok {
				mu.Lock()
				out[h.ID] = n
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return out
}

// icmpInEchos pulls InEchos out of /proc/net/snmp, by name rather than by
// column: the set of counters differs between kernels, and counting fields
// would read a different one on a different machine.
func icmpInEchos(body string) (int, bool) {
	lines := strings.Split(body, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "Icmp:") {
			continue
		}
		names := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		for j, n := range names {
			if n == "InEchos" && j < len(values) {
				v, err := strconv.Atoi(values[j])
				return v, err == nil
			}
		}
	}
	return 0, false
}

// traceHops counts the hops between two hosts.
func traceHops(ctx context.Context, env *Env, src, dst *model.Device) (int, error) {
	addr := deviceAddr4(ctx, env, dst)
	if addr == "" {
		return 0, fmt.Errorf("%s has no address configured", dst.Name)
	}
	// Two probes per hop. With one, a single dropped packet is reported as a
	// hop that did not answer, and over the slow links of a layer-2 domain
	// that happens often enough to cost a correct submission a mark.
	res, err := env.Probe(ctx, src.ID, []string{"traceroute", "-n", "-q", "2", "-w", "2", "-m", "8", addr})
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
	res, err := env.Probe(ctx, src.ID, []string{"traceroute", "-n", "-q", "2", "-w", "2", "-m", "8", addr})
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

// traceHopsRetrying and traceFirstHopRetrying try once more before reporting a
// failure.
//
// A dropped probe is not a misconfiguration. These hosts are behind
// deliberately slow links and a grading run puts several checks on them at
// once; a single lost traceroute was enough to cost a correct student a mark,
// which is the worst kind of wrong answer a grader can give because it looks
// exactly like a real finding.

// Three attempts, not two.
//
// The hosts of a layer-2 domain sit behind deliberately slow links, and a
// traceroute that loses its probe is indistinguishable from a host that cannot
// be reached. A mark that depends on the weather is not a mark.
const traceAttempts = 3

// adjacentHopsRetrying measures the distance to a neighbour in the same VLAN,
// priming the neighbour cache first.
//
// A host whose neighbour entry for its VLAN peer has gone stale sends the first
// packet to its default gateway, which forwards it: the traceroute then reads
// two hops and the submission loses a mark for a switch that is working
// perfectly. Measured twice on correct systems -- 9.96 of 10 once on AS 9 and
// once on AS 6, with the two hosts nine milliseconds and one hop apart when
// asked again. A ping resolves the neighbour and is thrown away; only then is
// the distance measured, and a result that is still not one is retried.
func adjacentHopsRetrying(ctx context.Context, env *Env, src, dst *model.Device) (int, error) {
	addr := deviceAddr4(ctx, env, dst)
	if addr == "" {
		return 0, fmt.Errorf("%s has no address configured", dst.Name)
	}
	var hops int
	var err error
	for i := 0; i < traceAttempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return hops, err
			case <-time.After(time.Duration(i) * 2 * time.Second):
			}
		}
		// Resolve the neighbour, and discard whatever it says: this is about
		// the ARP entry existing, not about reachability.
		_, _ = env.Probe(ctx, src.ID, []string{"ping", "-c", "1", "-W", "2", addr})
		hops, err = traceHops(ctx, env, src, dst)
		if err == nil && hops == 1 {
			return hops, nil
		}
	}
	return hops, err
}

func traceFirstHopRetrying(ctx context.Context, env *Env, src, dst *model.Device) (int, string, error) {
	var hops int
	var first string
	var err error
	for i := 0; i < traceAttempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return hops, first, err
			case <-time.After(time.Duration(i) * 2 * time.Second):
			}
		}
		hops, first, err = traceFirstHop(ctx, env, src, dst)
		if err == nil && hops > 0 && first != "" {
			return hops, first, nil
		}
	}
	return hops, first, err
}
