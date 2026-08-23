package grade

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HongyuHe/twinet/internal/alloc"
	"github.com/HongyuHe/twinet/internal/model"
	"github.com/HongyuHe/twinet/internal/netstate"
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
	owners := subnetOwners(env)
	planCarries := plannedAddrs(env)

	for _, r := range env.Routers() {
		// Every scope, not only the global one.
		//
		// A scope the reader filtered on is a place to put an address it will
		// not look at: `ip addr add X/32 dev lo scope link` is live, answers
		// for X, and was invisible here. The kernel's own -- 127.0.0.0/8 and
		// link-local -- are exempt because nobody configured them.
		state, err := env.RouterState(ctx, r.Name, netstate.QueryInterfaces)
		if err != nil {
			return Errored("l3.addressing_matches_plan", err)
		}
		have := map[string][]string{}
		for _, observed := range state.Interfaces {
			for _, address := range observed.Addresses {
				if address.Family == "ipv4" {
					have[observed.Name] = append(have[observed.Name], address.Prefix)
				}
			}
		}
		known := map[string]bool{}
		for _, i := range r.Ifaces {
			if i.Addr4 != "" {
				known[i.Name+" "+i.Addr4] = true
			}
		}
		for iface, addrs := range have {
			for _, a := range addrs {
				if known[iface+" "+a] || kernelOwned(a) {
					continue
				}
				if i, ok := r.IfaceByName(iface); ok && ownSubnet(i, a) {
					continue // the student's own choice inside the mandated prefix
				}
				if where := impersonates(planned, a); where != "" {
					// Standing in for a part of the network you are not is a
					// claim about a router, so it is the router that decides
					// this. An address inside a subnet the plan gives to this
					// very router counterfeits nothing -- there is no one else
					// it could be answering for -- and reporting it as
					// "a subnet the plan puts on another interface" while
					// naming this router's own interface as the owner said
					// something that was not true and took the whole mark for
					// it. It is still an address the plan does not mention, so
					// it still costs: "and nothing else" is what it falsifies.
					//
					// Taking another router's planned address is the exception
					// that has to survive this, because a shared link's subnet
					// belongs to both ends: the far end's address sitting on
					// this one is an impersonation inside a subnet that really
					// is partly ours.
					if owner, taken := planCarries[bareAddr(a)]; taken && owner.device != r.ID {
						counterfeit = append(counterfeit, fmt.Sprintf(
							"%s:%s carries %s, the address the plan puts on %s",
							r.Name, iface, a, owner.where))
						continue
					}
					if owners[where][r.ID] {
						extra = append(extra, fmt.Sprintf("%s:%s carries %s, which the plan "+
							"does not mention -- %s is this router's own subnet",
							r.Name, iface, a, where))
						continue
					}
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
			Expected: "no router carrying an address out of a subnet that belongs to another router",
			Observed: fmt.Sprintf("%d address(es) claim space the plan puts on another "+
				"router", len(counterfeit)),
			Detail:  strings.Join(truncate(counterfeit, 6), "\n"),
			Hint:    "an address from another router's subnet makes this one answer for a part of the network it is not",
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
	wrong := len(bad) + len(missing)
	// Two claims, weighted equally, because they are not the same kind of
	// thing. "Every prescribed address is there" is a count, and being short
	// one of forty-nine is being short one. "And nothing else is" is a property
	// of the whole system: one unplanned address falsifies it completely, and
	// scoring it as a fiftieth of the mark made a deduction too small to print.
	prescribed := ratio(checked-wrong, checked)
	clean := 1.0
	if len(extra) > 0 {
		clean = 0
	}
	return Partial("l3.addressing_matches_plan", 0.5*prescribed+0.5*clean, Evidence{
		Expected: fmt.Sprintf("%d addresses and nothing else", checked),
		Observed: fmt.Sprintf("%d of them wrong or missing, %d not in the plan",
			wrong, len(extra)),
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
	// Where the assignment dictates the address, only that address is the
	// student's to have. Excusing anything inside the same subnet let a second
	// address sit on a prescribed loopback unnoticed -- and a spare address in
	// the right subnet is exactly what an impersonation needs.
	if i.Prescribed {
		return false
	}
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

// subnetOwners maps every subnet in the lab to the routers the plan gives it
// to. A link's subnet belongs to both of its ends, so this is a set rather than
// a name: an address inside a subnet one of whose owners is the router carrying
// it is not standing in for anybody.
func subnetOwners(env *Env) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(subnet, device string) {
		subnet = normalPrefix(subnet)
		if subnet == "" || device == "" {
			return
		}
		if out[subnet] == nil {
			out[subnet] = map[string]bool{}
		}
		out[subnet][device] = true
	}
	for _, l := range env.Topology.Links {
		for _, e := range []*model.Iface{l.A, l.B} {
			if e != nil && e.Device != nil {
				add(l.Subnet, e.Device.ID)
			}
		}
	}
	for _, d := range env.Topology.Devices {
		for _, i := range d.Ifaces {
			add(i.Subnet, d.ID)
			if i.Link != nil {
				add(i.Link.Subnet, d.ID)
			}
			if i.Addr4 != "" {
				if p, err := netip.ParsePrefix(i.Addr4); err == nil {
					add(p.Masked().String(), d.ID)
				}
			}
		}
	}
	return out
}

// normalPrefix puts a subnet in the one form it can be compared in, so that
// 179.1.20.0/24 and 179.1.20.2/24 are recognised as the same subnet however
// they were written down.
func normalPrefix(subnet string) string {
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil {
		return strings.TrimSpace(subnet)
	}
	return p.Masked().String()
}

// plannedAddr is an address the plan puts somewhere, and where.
type plannedAddr struct {
	device string
	where  string
}

// plannedAddrs maps every address the plan hands out to the interface it
// belongs on. Wearing one of these is an impersonation wherever it happens,
// including inside a subnet the wearer part-owns: on a shared link, the far
// end's address is in a subnet that is legitimately ours too.
func plannedAddrs(env *Env) map[string]plannedAddr {
	out := map[string]plannedAddr{}
	for _, d := range env.Topology.Devices {
		for _, i := range d.Ifaces {
			if i.Addr4 == "" {
				continue
			}
			a := bareAddr(i.Addr4)
			if a == "" {
				continue
			}
			if _, seen := out[a]; !seen {
				out[a] = plannedAddr{device: d.ID, where: d.ID + ":" + i.Name}
			}
		}
	}
	return out
}

// bareAddr strips the prefix length from an address, so that the same address
// written with two different masks is recognised as the one address it is.
func bareAddr(addr string) string {
	if p, err := netip.ParsePrefix(addr); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(addr); err == nil {
		return a.String()
	}
	return ""
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

// kernelOwned reports whether an address is one the kernel puts there itself,
// which no submission chose and none should be marked for.
func kernelOwned(addr string) bool {
	ip, err := netip.ParsePrefix(addr)
	if err != nil {
		a, err2 := netip.ParseAddr(addr)
		if err2 != nil {
			return false
		}
		ip = netip.PrefixFrom(a, a.BitLen())
	}
	return ip.Addr().IsLoopback() || ip.Addr().IsLinkLocalUnicast()
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
		// DeadTimerMsec is how long this neighbour has left before it is
		// declared gone. Every hello resets it, so watching it is how a
		// stopped conversation is told from a state nobody has revised yet.
		DeadTimerMsec int64 `json:"routerDeadIntervalTimerDueMsec"`
	} `json:"neighbors"`
}

// deadTimers reads every router's remaining dead time per interface.
func deadTimers(ctx context.Context, env *Env) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range env.Routers() {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			var doc ospfNeighborJSON
			if err := env.VtyshJSON(ctx, r.Name, "show ip ospf neighbor json", &doc); err != nil {
				return
			}
			byIface := map[string]int64{}
			for _, ns := range doc.Neighbors {
				for _, n := range ns {
					iface := n.IfaceName
					if i := strings.IndexByte(iface, ':'); i >= 0 {
						iface = iface[:i]
					}
					if v, ok := byIface[iface]; !ok || n.DeadTimerMsec > v {
						byIface[iface] = n.DeadTimerMsec
					}
				}
			}
			mu.Lock()
			out[r.Name] = byIface
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
}

const (
	// OSPF's own default, used when a router will not say what it uses. It is
	// the shortest common interval, so assuming it can only make the liveness
	// window tighter than it needs to be, never looser.
	defaultHelloMsec = 10000
	// The longest this check will stand and watch. Forty-five seconds covers
	// both intervals RFC 2328 gives, ten and thirty. Beyond that the check
	// says it cannot tell rather than waiting arbitrarily long on a number the
	// student chose.
	maxWatchMsec = 45000
)

// watchFor is how long to watch a dead timer when hellos come every hello ms:
// long enough that a live adjacency must reset the timer at least once, and
// never so long that a student's choice of interval decides how long grading
// takes.
func watchFor(hello int64) int64 {
	w := int64(12000)
	if hello+2000 > w {
		w = hello + 2000
	}
	if w > maxWatchMsec {
		w = maxWatchMsec
	}
	return w
}

// missedHello says whether a dead timer that went from before to after over
// elapsed ms was reset in between.
//
// A hello sets the timer back to the dead interval, so over a window of
// elapsed ms the timer falls by elapsed less one interval for every hello that
// arrived: at most elapsed-hello if the adjacency is live, and the whole of
// elapsed if it is silent. Half an interval below elapsed lies between the two
// whatever the interval is.
func missedHello(before, after, elapsed, hello int64) bool {
	return before-after >= elapsed-hello/2
}

// ospfIfaceJSON is what a router says about its own OSPF timers.
type ospfIfaceJSON struct {
	Interfaces map[string]struct {
		HelloMsec int64 `json:"timerMsecs"`
		DeadSec   int64 `json:"timerDeadSecs"`
	} `json:"interfaces"`
}

// helloIntervals reads how often each interface actually sends a hello.
//
// The liveness test below watches the dead timer for a hello to reset it, so
// it has to watch for longer than the gap between hellos. Ten seconds is only
// OSPF's default: RFC 2328 specifies thirty for non-broadcast networks, and
// any interval is permitted. Reading the interval rather than assuming it is
// what keeps the test from calling a slow-hello adjacency dead.
//
// An interval that cannot be read is taken to be the default, which makes the
// window shorter and the test stricter -- never the other way round.
func helloIntervals(ctx context.Context, env *Env) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range env.Routers() {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			var doc ospfIfaceJSON
			if err := env.VtyshJSON(ctx, r.Name, "show ip ospf interface json", &doc); err != nil {
				return
			}
			byIface := map[string]int64{}
			for name, i := range doc.Interfaces {
				if i.HelloMsec > 0 {
					byIface[name] = i.HelloMsec
				}
			}
			mu.Lock()
			out[r.Name] = byIface
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
}

// linkDevice is what an interface says about itself beyond its name.
type linkDevice struct {
	Kind     string
	MAC      string
	Altnames []string
}

// linkIdentities reads every router's interfaces and returns, per router, what
// each name is actually attached to.
//
// The name is the student's to change; the tag Twinet stamps on the veth when
// it creates the link is not, and neither is whether the thing is a veth at
// all. Read together they say whether the interface carrying an adjacency is
// the link the plan drew or something wearing its name.
func linkIdentities(ctx context.Context, env *Env) map[string]map[string]linkDevice {
	out := map[string]map[string]linkDevice{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range env.Routers() {
		wg.Add(1)
		go func(r *model.Device) {
			defer wg.Done()
			res, err := env.Probe(ctx, r.ID, []string{"ip", "-d", "-j", "link", "show"})
			if err != nil || res.ExitCode != 0 {
				return
			}
			var devs []struct {
				IfName   string   `json:"ifname"`
				Address  string   `json:"address"`
				Altnames []string `json:"altnames"`
				LinkInfo struct {
					InfoKind string `json:"info_kind"`
				} `json:"linkinfo"`
			}
			if json.Unmarshal([]byte(res.Stdout), &devs) != nil {
				return
			}
			byName := map[string]linkDevice{}
			for _, d := range devs {
				byName[d.IfName] = linkDevice{
					Kind: d.LinkInfo.InfoKind, MAC: d.Address, Altnames: d.Altnames}
			}
			mu.Lock()
			out[r.Name] = byName
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	return out
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
	type want struct{ router, iface, peer, altname, mac string }
	var wanted []want
	for _, r := range env.Routers() {
		for _, i := range r.Ifaces {
			if i.Link == nil || i.Link.InterAS || i.Peer == nil || i.Peer.Device == nil {
				continue
			}
			if !i.Peer.Device.IsRouter() || i.Peer.Device.ASN != env.AS {
				continue
			}
			wanted = append(wanted, want{r.Name, i.Name, i.Peer.Device.Name,
				alloc.LinkAltname(env.Topology.Name, i.Link.ID), i.MAC})
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
		observed, err := env.RouterState(ctx, r.Name, netstate.QueryOSPF)
		if err != nil {
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
		for _, neighbor := range observed.OSPF {
			iface := neighbor.Interface
			if i := strings.IndexByte(iface, ':'); i >= 0 {
				iface = iface[:i]
			}
			if strings.HasPrefix(neighbor.State, "Full") {
				full[r.Name][iface] = true
			} else if state[r.Name][iface] == "" {
				state[r.Name][iface] = neighbor.State
			}
			if !planned[iface] {
				extra = append(extra, fmt.Sprintf("%s is adjacent to %s over %s, which is "+
					"not an interior link of this AS", r.Name, neighbor.RouterID, iface))
			}
		}
	}

	// An interface name is a label the student can move.
	//
	// The adjacency was bound to the plan by the name of the interface it ran
	// on, and a name is the one part of an interface anyone with root can
	// change. Renaming the real veth, building a GRE tunnel between the same
	// two routers and calling it by the planned name put every adjacency on a
	// tunnel while the planned links were down, and the check reported all
	// twenty-four Full "each on the link the plan gives it".
	//
	// Twinet stamps a tag derived from the link's identity onto both halves of
	// the veth it creates, so the link says which link it is. That, and its
	// being a veth rather than an encapsulation, is what the name was standing
	// in for.
	links := linkIdentities(ctx, env)

	// And that the conversation is still going on.
	//
	// A neighbour stays Full until the dead timer expires, which is forty
	// seconds: discarding OSPF between two routers and grading immediately
	// found every adjacency Full and carrying nothing. Every hello resets that
	// timer, so a second reading a hello interval later says whether one
	// arrived. A healthy adjacency cannot lose more than one hello interval of
	// dead time between two readings; a silent one loses the whole wait.
	// How long to watch is not a constant. It was twelve seconds, which
	// contains a hello only while the interval is the ten-second default;
	// RFC 2328 specifies thirty for non-broadcast networks. At a thirty-second
	// interval two windows in three contained no hello, and an adjacency that
	// had been up for hours with nothing retransmitted was reported as held up
	// by a timer -- differently on each run, so the same submission was worth
	// different marks depending on when it was graded.
	hellos := helloIntervals(ctx, env)
	helloOf := func(router, iface string) int64 {
		if h, ok := hellos[router][iface]; ok && h > 0 {
			return h
		}
		return int64(defaultHelloMsec)
	}
	watch := int64(12000)
	for _, w := range wanted {
		if got := watchFor(helloOf(w.router, w.iface)); got > watch {
			watch = got
		}
	}

	start := time.Now()
	before := deadTimers(ctx, env)
	select {
	case <-ctx.Done():
	case <-time.After(time.Duration(watch) * time.Millisecond):
	}
	after := deadTimers(ctx, env)
	elapsed := time.Since(start).Milliseconds()

	var stuck []string
	got := 0
	for _, w := range wanted {
		hello := helloOf(w.router, w.iface)
		switch {
		case elapsed < hello+2000:
			// Watching for less than one interval proves nothing either way,
			// and saying the adjacency is dead would be inventing a reading
			// that was never taken.
			stuck = append(stuck, fmt.Sprintf(
				"%s -> %s on %s says Full, but sends a hello only every %ds, which is "+
					"longer than this check watches for, so nothing here shows the "+
					"adjacency is still alive",
				w.router, w.peer, w.iface, hello/1000))
			continue
		default:
			if b, ok := before[w.router][w.iface]; ok && b > 0 {
				// Over a window of E with hellos every H, a live adjacency's
				// dead time falls by E minus one interval for each hello that
				// reset it, so by at most E-H. A silent one loses the whole E.
				// Half an interval below E separates the two.
				if a, ok2 := after[w.router][w.iface]; ok2 && missedHello(b, a, elapsed, hello) {
					stuck = append(stuck, fmt.Sprintf(
						"%s -> %s on %s says Full, but no hello arrived in the %ds it was "+
							"watched, though one is due every %ds: the state is held by a "+
							"timer that has not expired yet",
						w.router, w.peer, w.iface, elapsed/1000, hello/1000))
					continue
				}
			}
		}
		if id, known := links[w.router]; known {
			dev, present := id[w.iface]
			switch {
			case !present:
				stuck = append(stuck, fmt.Sprintf("%s has no interface called %s at all",
					w.router, w.iface))
				continue
			case dev.Kind != "" && dev.Kind != "veth":
				stuck = append(stuck, fmt.Sprintf(
					"%s's %s is a %s, not the link the plan puts there: an adjacency over an "+
						"encapsulation is not the interior link being adjacent",
					w.router, w.iface, dev.Kind))
				continue
			case w.altname != "" && !containsStr(dev.Altnames, w.altname):
				stuck = append(stuck, fmt.Sprintf(
					"%s's %s is not the interface Twinet created for the link to %s: it does "+
						"not carry that link's identity, so something else has been given "+
						"its name", w.router, w.iface, w.peer))
				continue
			case w.mac != "" && dev.MAC != "" && !strings.EqualFold(dev.MAC, w.mac):
				stuck = append(stuck, fmt.Sprintf(
					"%s's %s does not have the address Twinet gave the link to %s (%s, not %s)",
					w.router, w.iface, w.peer, dev.MAC, w.mac))
				continue
			}
		}
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
// deadHops probes every link the prescribed paths are made of, on the link
// itself, and names the ones that carry nothing.
//
// An end-to-end probe takes one path -- which one is a hash of the two
// addresses, and it is the same hash every time -- so two of three prescribed
// paths can be discarding everything while the question keeps its mark.
func deadHops(ctx context.Context, env *Env, paths [][]string) []string {
	type hop struct{ a, b string }
	seen := map[hop]bool{}
	var hops []hop
	for _, p := range paths {
		for i := 0; i+1 < len(p); i++ {
			h := hop{p[i], p[i+1]}
			if !seen[h] {
				seen[h] = true
				hops = append(hops, h)
			}
		}
	}
	var (
		mu     sync.Mutex
		broken []string
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, 8)
	for _, h := range hops {
		a, ok := env.Device(h.a)
		if !ok {
			continue
		}
		addrs := linksToward(env, h.a, h.b).peerAddrs()
		if len(addrs) == 0 {
			continue
		}
		wg.Add(1)
		go func(h hop, from *model.Device, addrs []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// A pair joined by more than one link has more than one way to
			// carry the hop, and the path names the routers rather than the
			// cable; one working link is the hop working. With the single link
			// between any pair in the shipped labs this is that link.
			for _, addr := range addrs {
				reached, err := env.reaches(ctx, from.ID, addr)
				if err != nil || reached {
					return
				}
			}
			mu.Lock()
			broken = append(broken, fmt.Sprintf(
				"%s cannot reach %s over the link between them (%s), so the path through "+
					"it carries nothing", h.a, h.b, strings.Join(addrs, ", ")))
			mu.Unlock()
		}(h, a, addrs)
	}
	wg.Wait()
	sort.Strings(broken)
	return broken
}

// sweepFlowCount is how many flows are aimed at the destination to find out
// whether every path carries them.
//
// The routers hash the source port to choose between equal-cost next hops, so
// distinct source ports spread over the paths -- and they do so at every
// router along the way, not only the first, which is what makes a path of
// three routers reachable by this. Thirty-two flows over the three paths of
// the shipped lab leave a chance of about one in ten thousand of never trying
// one of them, and failing to try a path can only understate a fault.
const sweepFlowCount = 32

// everyFlowArrives sends many flows between two routers and reports the ones
// that never arrived.
//
// A single end-to-end probe answers for a single path: which one it takes is a
// hash of the flow, and the same flow takes the same path every time. With
// three paths installed between two routers, one of them can discard
// everything sent along it while the probe, hashed onto another, reports the
// pair as healthy. That is not a hypothetical -- a rule dropping forwarded
// connections on one middle router cost a quarter of the traffic between two
// routers and left this question on full marks.
//
// The path a flow will take is not predicted. The kernel can be asked, but its
// answer for a forwarded packet turned out not to be what it then did with the
// packet, and a check that grades on a prediction grades on the wrong thing.
// What is asked instead is the question the mark is actually for: of the flows
// sent between these two, did every one of them arrive? A lost flow means some
// path is discarding traffic, and which one it is the student can find.
//
// Both protocols are spread across the sweep, alternating by port, because a
// filter is written per protocol as easily as per path.
func everyFlowArrives(ctx context.Context, env *Env, from, to string) (string, bool) {
	src, sok := env.Device(from)
	dst, dok := env.Device(to)
	if !sok || !dok {
		return "", true
	}
	slo, sok := src.IfaceByName("lo")
	dlo, dok := dst.IfaceByName("lo")
	if !sok || !dok || slo.Addr4 == "" || dlo.Addr4 == "" {
		return "", true
	}
	srcAddr, dstAddr := addrOnly(slo.Addr4), addrOnly(dlo.Addr4)

	base := 20000 + rand.IntN(20000)
	first := make([]string, 0, sweepFlowCount)
	second := make([]string, 0, sweepFlowCount)
	for i := range sweepFlowCount {
		first = append(first, strconv.Itoa(base+i))
		second = append(second, strconv.Itoa(base+sweepFlowCount+i))
	}
	lost, ok := lostFlows(ctx, env, src.ID, dst.ID, srcAddr, dstAddr, first)
	if !ok || len(lost) == 0 {
		return "", true
	}
	// A flow can go missing for reasons that are nobody's fault -- a frame
	// lost while a neighbour entry is resolved, a scheduler delay on a loaded
	// node -- and a mark should not turn on one of those. So the whole sweep
	// is repeated, from a fresh set of source ports, and the fault has to
	// still be there. A path that discards traffic discards the second sweep
	// as surely as the first; a frame lost once does not come back.
	//
	// Repeating only the flows that failed would not do, because a source port
	// is not a path: the second attempt would be hashed afresh and would
	// mostly land on the paths that work, which is a test that clears a real
	// fault most of the time.
	again, ok := lostFlows(ctx, env, src.ID, dst.ID, srcAddr, dstAddr, second)
	if !ok || len(again) == 0 {
		return "", true
	}
	return fmt.Sprintf(
		"%d of %d flows from %s to %s never arrived, and %d did: the paths are installed "+
			"and at least one of them is discarding what is sent along it",
		len(again), len(second), from, to, len(second)-len(again)), false
}

// lostFlows aims one flow from each of the given source ports at a port on the
// far side that nothing is listening on, and returns the ports whose flows
// were not seen arriving there.
//
// A flow that could not be sent is not a flow that was lost: a source port
// already in use fails to bind, and counting that as a discarded packet would
// blame a submission for the grader's own choice of port. The sender says
// which ports it managed to use and only those are looked for.
//
// The second return says whether the capture was in a position to testify at
// all. It is false when there was no witness, and also when the witness saw
// nothing whatsoever -- which is either a total blackhole, already reported by
// the end-to-end probe that runs before this, or a capture whose output could
// not be read. Neither is a per-path finding.
func lostFlows(ctx context.Context, env *Env, srcDev, dstDev, srcAddr, dstAddr string,
	ports []string) ([]string, bool) {

	if len(ports) == 0 {
		return nil, false
	}
	dport := probePort()
	// Every flow of the sweep lands on the same port, so the capture has to
	// hold all of them: a frame limit reached partway through stops the
	// capture, and a capture that stopped early is not a witness.
	tap := startArrivalTapN(ctx, env, dstDev, dport, 8*len(ports)+32)
	var b strings.Builder
	for i, p := range ports {
		if i%2 == 0 {
			fmt.Fprintf(&b, "e=$(nc -w 1 -s %s -p %s %s %s </dev/null 2>&1 >/dev/null); ",
				srcAddr, p, dstAddr, dport)
		} else {
			fmt.Fprintf(&b, "e=$(echo twinet | nc -u -w 1 -s %s -p %s %s %s 2>&1 >/dev/null); ",
				srcAddr, p, dstAddr, dport)
		}
		fmt.Fprintf(&b, "case \"$e\" in *bind*) ;; *) echo %s;; esac; ", p)
	}
	res, err := env.Probe(ctx, srcDev, []string{"sh", "-c", b.String()})
	arrived, _, live := tapFlowsOf(ctx, env, tap)
	if err != nil || !live || len(arrived) == 0 {
		return nil, false
	}
	var lost []string
	for _, p := range strings.Fields(res.Stdout) {
		if arrived[p] == 0 {
			lost = append(lost, p)
		}
	}
	sort.Strings(lost)
	return lost, true
}

// tapFlowsOf reads a capture's arrivals by source port, in the order the rest
// of this file reads captures.
func tapFlowsOf(ctx context.Context, env *Env, t *arrivalTap) (map[string]int, tapCounts, bool) {
	counts, byPort, live := t.seenFlows(ctx, env)
	return byPort, counts, live
}

// carriesTCPBothWays opens a connection each way between two routers, to a
// resets it sent -- together with a capture on the far side of the flow the
// probe creates, which is what makes the count attributable to this probe
// rather than to any traffic the submission cares to generate.
func carriesTCPBothWays(ctx context.Context, env *Env, from, to string) (string, bool) {
	ends := [][2]string{{from, to}, {to, from}}
	for _, e := range ends {
		src, ok := env.Device(e[0])
		if !ok {
			return "", true
		}
		dst, ok := env.Device(e[1])
		if !ok {
			return "", true
		}
		lo, ok := dst.IfaceByName("lo")
		if !ok || lo.Addr4 == "" {
			return "", true
		}
		addr := addrOnly(lo.Addr4)
		// One port for both protocols, drawn for this pair alone, so that a
		// single capture on the far side covers the connection and the
		// datagram and neither can be confused with anything else in flight.
		port := probePort()
		tap := startArrivalTap(ctx, env, dst.ID, port)
		// Between the loopbacks, which is the pair the question is about and
		// the pair a rule aimed at this traffic would name. Sourced from an
		// interface address instead, a probe misses a drop written against the
		// routers themselves and reads as a healthy path.
		args := []string{"nc", "-w", "3", "-z"}
		src4 := ""
		if slo, ok := src.IfaceByName("lo"); ok && slo.Addr4 != "" {
			src4 = addrOnly(slo.Addr4)
			args = append(args, "-s", src4)
		}
		args = append(args, addr, port)
		before, okB := tcpAnswers(ctx, env, dst.ID)
		_, _ = env.Probe(ctx, src.ID, args)
		after, okA := tcpAnswers(ctx, env, dst.ID)
		// And a datagram. A filter is written per protocol as easily as per
		// port: dropping UDP between the two loopbacks left the pings and the
		// connections working and the paths carrying two thirds of what they
		// should.
		udpBefore, okU := udpNoPortsV4(ctx, env, dst.ID)
		udpSent := sendDatagrams(ctx, env, src.ID, datagramProbe{
			srcAddr: src4, dstAddr: addr, port: port,
		})
		udpAfter, okU2 := udpNoPortsV4(ctx, env, dst.ID)
		frames, live := tap.seen(ctx, env)

		gotTCP := arrival{
			tapped: frames.tcp, tapLive: live,
			counted: offBoxDelta(before, after), counterOK: okB && okA,
		}
		if gotTCP.attributable() && !gotTCP.arrived() {
			return fmt.Sprintf(
				"%s answers pings from %s but no connection to it arrives -- %s: the paths "+
					"carry ICMP and nothing else", e[1], e[0], gotTCP.why()), false
		}
		gotUDP := arrival{
			tapped: frames.udp, tapLive: live,
			counted: offBoxDelta(udpBefore, udpAfter), counterOK: okU && okU2,
		}
		if udpSent && gotUDP.attributable() && !gotUDP.arrived() {
			return fmt.Sprintf(
				"%s answers pings and connections from %s but no datagram from it arrives "+
					"-- %s: something on the paths is filtering by protocol",
				e[1], e[0], gotUDP.why()), false
		}
	}
	return "", true
}

// udpNoPortsV4 reads a host's count of datagrams delivered to it for a port
// nothing is bound to, together with the loopback traffic that could have
// produced it.
func udpNoPortsV4(ctx context.Context, env *Env, device string) (counterWitness, bool) {
	return readCounter(ctx, env, device, "/proc/net/snmp", func(body string) (int, bool) {
		return snmpCounter(body, "Udp:", "NoPorts")
	})
}

// installedHop is one next hop of an installed route: the interface it leaves
// by, the address it is handed to, or both.
type installedHop struct{ iface, ip string }

// kernelLPM returns the selected/installed main-table route set that Linux
// would use for target. Kernel snapshots contain route prefixes rather than a
// daemon's exact /32 lookup, so requiring string equality made a valid OSPF
// aggregate look like no route at all. Equal-prefix/equal-metric routes are
// retained together so ECMP evidence is not collapsed to one next hop.
func kernelLPM(routes []netstate.Route, target string) []netstate.Route {
	dst, ok := lpmTargetAddr(target)
	if !ok {
		return nil
	}
	family := "ipv4"
	if dst.Is6() {
		family = "ipv6"
	}
	bestBits, bestMetric := -1, 0
	var out []netstate.Route
	for _, route := range routes {
		if !mainKernelTable(route.Table) || (!route.Selected && !route.Installed) {
			continue
		}
		if route.Family != "" && route.Family != family {
			continue
		}
		prefix, ok := routePrefix(route.Prefix, family)
		if !ok || !prefix.Contains(dst) {
			continue
		}
		bits := prefix.Bits()
		switch {
		case bits > bestBits:
			bestBits, bestMetric = bits, route.Metric
			out = []netstate.Route{route}
		case bits == bestBits && route.Metric < bestMetric:
			bestMetric = route.Metric
			out = []netstate.Route{route}
		case bits == bestBits && route.Metric == bestMetric:
			out = append(out, route)
		}
	}
	return out
}

func mainKernelTable(table string) bool {
	switch strings.TrimSpace(table) {
	case "", "main", "254":
		return true
	default:
		return false
	}
}

func routePrefix(raw, family string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "default" {
		if family == "ipv6" {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), true
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return prefix, true
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	return netip.Prefix{}, false
}

func lpmTargetAddr(target string) (netip.Addr, bool) {
	target = strings.TrimSpace(target)
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return prefix.Addr(), true
	}
	address, err := netip.ParseAddr(target)
	return address, err == nil
}

func (h installedHop) label() string {
	switch {
	case h.iface != "" && h.ip != "":
		return h.iface + " (" + h.ip + ")"
	case h.iface != "":
		return h.iface
	default:
		return h.ip
	}
}

// hopToward is how a forwarding table can show that a router sends traffic to
// a particular neighbour: over one of the interfaces the topology says faces
// that neighbour, or to one of the addresses the neighbour holds on them.
//
// This used to be the single string "port_" + neighbour, which is not a
// property of the network but of Twinet's own FRR renderer, which happens to
// name interfaces that way. A second link between the same pair is named
// differently, and so is every interface on a device configured by something
// other than FRR -- both of which the topology supports. A router forwarding
// perfectly well over such an interface was reported as not forwarding at all.
// What the neighbour is called is in the plan; it does not have to be guessed
// from a name.
type hopToward struct {
	ifaces map[string]bool
	addrs  map[string]bool
}

// linksToward reads out of the plan every interface of a that faces b, and
// every address of b on those links.
func linksToward(env *Env, a, b string) hopToward {
	out := hopToward{ifaces: map[string]bool{}, addrs: map[string]bool{}}
	dev, ok := env.Device(a)
	if !ok {
		return out
	}
	peer, ok := env.Device(b)
	if !ok {
		return out
	}
	for _, i := range dev.Ifaces {
		if i.Peer == nil || i.Peer.Device == nil || i.Peer.Device.ID != peer.ID {
			continue
		}
		out.ifaces[i.Name] = true
		if s := addrOnly(i.Peer.Addr4); s != "" {
			out.addrs[s] = true
		}
	}
	return out
}

// known says whether the plan has any link between the pair at all.
func (h hopToward) known() bool { return len(h.ifaces) > 0 || len(h.addrs) > 0 }

func (h hopToward) matches(hop installedHop) bool {
	return (hop.iface != "" && h.ifaces[hop.iface]) || (hop.ip != "" && h.addrs[hop.ip])
}

// installed says whether any of the router's next hops leads to the neighbour.
func (h hopToward) installed(hops []installedHop) bool {
	for _, hop := range hops {
		if h.matches(hop) {
			return true
		}
	}
	return false
}

// peerAddrs is the neighbour's addresses on the links between the pair.
func (h hopToward) peerAddrs() []string { return sortedKeysOfBool(h.addrs) }

func (h hopToward) describe() string {
	if len(h.ifaces) == 0 {
		return "no next hop toward it"
	}
	return "no next hop on " + strings.Join(sortedKeysOfBool(h.ifaces), " or ")
}

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
	nextHops := map[string][]installedHop{}
	read := map[string]bool{}
	other := map[string]bool{}
	fetch := func(router string) ([]installedHop, error) {
		if read[router] {
			return nextHops[router], nil
		}
		state, err := env.RouterState(ctx, router, netstate.QueryKernel)
		if err != nil {
			return nil, err
		}
		var hops []installedHop
		for _, route := range kernelLPM(state.Kernel.Routes, target) {
			// The protocol is what the question is about.
			//
			// It was decoded and then ignored, so three static routes over the
			// prescribed interfaces earned full marks for a question that asks
			// for equal-cost paths produced by OSPF costs. Hand-installed
			// routes do not react to a link failing, which is the entire point
			// of the exercise, and the two were indistinguishable in the mark.
			if route.Protocol != "" && route.Protocol != "ospf" {
				other[route.Protocol] = true
				continue
			}
			for _, nh := range route.NextHops {
				if nh.Device == "" && nh.Address == "" {
					continue
				}
				hops = append(hops, installedHop{iface: nh.Device, ip: nh.Address})
			}
		}
		if env.ShadowBatches {
			legacy, legacyOther, err := legacyECMPHops(ctx, env, router, target)
			if err != nil {
				return nil, fmt.Errorf("shadow read of %s's legacy route view: %w", router, err)
			}
			if !sameInstalledHopSet(hops, legacy) || !sameStringBoolSet(other, legacyOther) {
				return nil, fmt.Errorf(
					"snapshot kernel LPM differs from legacy `show ip route json` on %s for %s "+
						"(snapshot=%s legacy=%s); refusing to change this ECMP verdict",
					router, target, describeInstalledHops(hops), describeInstalledHops(legacy))
			}
		}
		nextHops[router] = hops
		read[router] = true
		return hops, nil
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
			leads := linksToward(env, path[i], path[i+1])
			if !leads.known() {
				ok = false
				fmt.Fprintf(&detail, "the plan has no link between %s and %s, so no "+
					"forwarding table can put the path through them\n", path[i], path[i+1])
				break
			}
			if !leads.installed(hops) {
				ok = false
				fmt.Fprintf(&detail, "%s does not forward toward %s (%s)\n",
					path[i], path[i+1], leads.describe())
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
				allowed[p[i]] = append(allowed[p[i]], p[i+1])
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
			var leads []hopToward
			for _, peer := range allowed[router] {
				leads = append(leads, linksToward(env, router, peer))
			}
			named := map[string]bool{}
			for _, h := range hops {
				prescribed := false
				for _, l := range leads {
					if l.matches(h) {
						prescribed = true
						break
					}
				}
				if prescribed || named[h.label()] {
					continue
				}
				named[h.label()] = true
				extra = append(extra, router+" via "+h.label())
				fmt.Fprintf(&detail, "%s also forwards toward %s over %s, which no "+
					"prescribed path uses\n", router, to, h.label())
			}
		}
		sort.Strings(extra)
	}

	// And the table the daemon writes has to be the one that decides.
	//
	// Everything above reads what the routing daemon reports. Two things can
	// make that not the table doing the forwarding. A policy rule is consulted
	// before any table is, so traffic can be sent to a different table
	// entirely. And the main table is shared: a second route for the same
	// destination with a lower metric wins, and if it is labelled with the
	// daemon's own protocol -- `ip route add ... proto ospf` -- the daemon
	// never notices it and goes on reporting its own route as best. Both leave
	// the equal-cost route installed, untouched and plainly visible, and this
	// check reported "balances over port_BOS, port_PHY" while the kernel sent
	// everything to port_BOS.
	var diverted string
	for _, router := range pathRouters(wantPaths) {
		dev, ok := env.Device(router)
		if !ok {
			continue
		}
		hops, err := fetch(router)
		if err != nil {
			// Already recorded by the loops above.
			continue
		}
		why, err := kernelDisagrees(ctx, env, dev.ID, target, hopNames(hops))
		if err != nil {
			return Errored("ospf.ecmp_paths", fmt.Errorf(
				"reading what %s does with traffic to %s: %w", router, target, err))
		}
		if why != "" {
			diverted = router + ": " + why
			break
		}
	}
	if diverted != "" {
		return Partial("ospf.ecmp_paths", 0, Evidence{
			Expected: fmt.Sprintf("traffic from %s to %s carried by the %d equal-cost paths",
				from, to, len(wantPaths)),
			Observed: diverted,
			Detail:   strings.TrimRight(detail.String(), "\n"),
			Hint: "the route the daemon reports is not the one forwarding this traffic, so " +
				"the equal-cost paths are installed and carry nothing; this question is " +
				"about the paths traffic takes, which OSPF costs alone should decide",
			Command: "ip rule show; ip route show to match " + target,
		})
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
		// One probe from end to end takes one of the paths, and says nothing
		// about the other two: which one it takes is a hash of the addresses,
		// and it is the same hash every time. So every hop of every prescribed
		// path is tried, on the link that hop uses, which is decided by the
		// plan and not by a hash.
		if dead == "" {
			if broken := deadHops(ctx, env, wantPaths); len(broken) > 0 {
				dead = fmt.Sprintf("%d hop(s) of the prescribed paths carry nothing",
					len(broken))
				for _, b := range broken {
					fmt.Fprintf(&detail, "%s\n", b)
				}
			}
		}
		// And something other than a ping. A path that answers ICMP and
		// discards the rest is not carrying traffic in any sense the question
		// means.
		if dead == "" {
			if why, ok := carriesTCPBothWays(ctx, env, from, to); !ok {
				dead = why
				fmt.Fprintf(&detail, "%s\n", why)
			}
		}
		// And on every path, not just the one the probe above was hashed
		// onto. Two of three paths can discard everything while a single
		// end-to-end flow, which takes one of them and the same one every
		// time, arrives and reports the pair healthy.
		if dead == "" && len(wantPaths) > 1 {
			if why, ok := everyFlowArrives(ctx, env, from, to); !ok {
				dead = why
				fmt.Fprintf(&detail, "%s\n", why)
			}
		}
	}

	got := make([]string, 0)
	seenHop := map[string]bool{}
	for _, h := range nextHops[from] {
		if !seenHop[h.label()] {
			seenHop[h.label()] = true
			got = append(got, h.label())
		}
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

// pathRouters names every router the prescribed paths pass through, in a
// stable order. The last hop of a path is left out: it is the destination, and
// what it does with traffic addressed to itself is not what is being asked.
func pathRouters(paths [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for i := 0; i+1 < len(p); i++ {
			if !seen[p[i]] {
				seen[p[i]] = true
				out = append(out, p[i])
			}
		}
	}
	sort.Strings(out)
	return out
}

// kernelHops reads the next hops out of "ip route show". A route with several
// of them prints one "nexthop via ... dev ..." line each; a route with one
// prints it on the line with the prefix.
// kernelRoute is one entry of a kernel routing table.
//
// The entries matter separately, rather than as one pile of next hops,
// because several can exist for the same destination and only one of them
// forwards: the kernel takes the longest prefix, and among equal prefixes the
// lowest metric. Reading them together says "balances over both links" about a
// router that has been told to prefer one.
type kernelRoute struct {
	prefix netip.Prefix
	metric int
	// kind is the route type when it is not a plain unicast route --
	// "blackhole", "unreachable" and the like, which forward nothing.
	kind string
	hops []installedHop
	text string
}

// routeKinds are the leading keywords iproute2 prints for a route that is not
// a plain unicast one. Everything but "unicast" discards the traffic or
// belongs to a table this reading does not reach.
var routeKinds = map[string]bool{
	"unicast": true, "local": true, "broadcast": true, "multicast": true,
	"anycast": true, "blackhole": true, "unreachable": true, "prohibit": true,
	"throw": true, "nat": true,
}

// kernelRoutes reads `ip route show` output into its entries. A line that
// starts with whitespace continues the entry above it, which is how multipath
// next hops are printed.
func kernelRoutes(out string) []kernelRoute {
	var routes []kernelRoute
	addHops := func(r *kernelRoute, f []string) {
		var h installedHop
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				h.ip = f[i+1]
			case "dev":
				h.iface = f[i+1]
			}
		}
		if h.ip != "" || h.iface != "" {
			r.hops = append(r.hops, h)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if n := len(routes); n > 0 {
				addHops(&routes[n-1], f)
			}
			continue
		}
		r := kernelRoute{text: strings.Join(f, " ")}
		if routeKinds[f[0]] {
			if f[0] != "unicast" {
				r.kind = f[0]
			}
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "default":
			r.prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		case strings.Contains(f[0], "/"):
			p, err := netip.ParsePrefix(f[0])
			if err != nil {
				continue
			}
			r.prefix = p.Masked()
		default:
			a, err := netip.ParseAddr(f[0])
			if err != nil {
				continue
			}
			r.prefix = netip.PrefixFrom(a, a.BitLen())
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "metric" {
				if m, err := strconv.Atoi(f[i+1]); err == nil {
					r.metric = m
				}
			}
		}
		addHops(&r, f)
		routes = append(routes, r)
	}
	return routes
}

// forwarding picks the entry that decides where traffic to dst goes: the
// longest prefix that covers it, and among those the lowest metric.
func forwarding(routes []kernelRoute, dst netip.Addr) (kernelRoute, bool) {
	var best kernelRoute
	found := false
	for _, r := range routes {
		if !r.prefix.IsValid() || !r.prefix.Contains(dst) {
			continue
		}
		switch {
		case !found,
			r.prefix.Bits() > best.prefix.Bits(),
			r.prefix.Bits() == best.prefix.Bits() && r.metric < best.metric:
			best, found = r, true
		}
	}
	return best, found
}

func kernelHops(out string) []installedHop {
	var hops []installedHop
	for _, r := range kernelRoutes(out) {
		hops = append(hops, r.hops...)
	}
	return hops
}

// hopNames reduces a set of next hops to the links they leave by, so two
// readings can be compared. The interface decides which link carries the
// traffic; the address is used only when the route names no interface.
func hopNames(hops []installedHop) map[string]bool {
	names := map[string]bool{}
	for _, h := range hops {
		name := h.iface
		if name == "" {
			name = h.ip
		}
		if name != "" {
			names[name] = true
		}
	}
	return names
}

func sameHops(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// mayCarry reports whether a policy rule can govern traffic to this
// destination. A rule that names no destination governs all of it.
func mayCarry(r ipRule, dst netip.Addr) bool {
	if r.to == "" || r.to == "all" {
		return true
	}
	if p, err := netip.ParsePrefix(r.to); err == nil {
		return p.Contains(dst)
	}
	if a, err := netip.ParseAddr(r.to); err == nil {
		return a == dst
	}
	// A destination that cannot be read is not a reason to conclude the rule
	// is harmless.
	return true
}

// kernelDisagrees reports how a router really forwards traffic to one
// destination when that differs from what the check has been reading, and
// returns "" when it does not.
//
// Two things can make the routing daemon's table not the one that decides. A
// policy rule is consulted before any table is, so traffic can be sent to a
// different table entirely. And the table the daemon writes is shared: another
// entry for the same destination with a lower metric wins, and if it is
// labelled with the daemon's own protocol the daemon never notices it and goes
// on reporting its own route as best. Both leave the equal-cost route
// installed, untouched and plainly visible, while every packet takes one link.
//
// The rule comparison is between two readings of the kernel: a rule that sends
// this traffic to a table holding the same next hops changes nothing, and a
// submission that writes one has answered the question. The main-table
// comparison is against the daemon, because that is the claim being made --
// the check reports the daemon's next hops, so the kernel has to agree with
// them.
func kernelDisagrees(ctx context.Context, env *Env, deviceID, target string,
	daemon map[string]bool) (string, error) {

	res, err := env.Probe(ctx, deviceID, []string{"sh", "-c",
		"ip rule show; echo '@@'; ip route show to match " + target})
	if err != nil {
		return "", err
	}
	rulesOut, mainOut, _ := strings.Cut(res.Stdout, "@@")
	rules, unsupported := parseIPRules(rulesOut)
	if len(unsupported) > 0 {
		return "", fmt.Errorf("policy rule %q selects on something a routing table "+
			"cannot be read for, so where this traffic goes cannot be established",
			unsupported[0])
	}
	dst, err := netip.ParseAddr(addrOnly(target))
	if err != nil {
		return "", fmt.Errorf("reading the destination %q: %w", target, err)
	}

	// What the main table really answers with. An empty answer means the
	// destination is this router's own or reached by no route at all, and
	// the probes further on are what settle that.
	main, ok := forwarding(kernelRoutes(mainOut), dst)
	if !ok {
		return "", nil
	}
	if main.kind != "" {
		return fmt.Sprintf("the kernel's own route for %s is %q, which forwards nothing",
			target, main.text), nil
	}
	want := hopNames(main.hops)
	if len(want) > 0 && len(daemon) > 0 && !sameHops(want, daemon) {
		return fmt.Sprintf("the daemon reports it forwards to %s over %s, but the route "+
			"the kernel prefers is %q, which uses %s", target,
			strings.Join(sortedKeysOfBool(daemon), ", "), main.text,
			strings.Join(sortedKeysOfBool(want), ", ")), nil
	}

	for _, r := range rules {
		if !mayCarry(r, dst) {
			continue
		}
		if r.table == "" {
			// No table to look in: the rule drops or rejects the traffic
			// rather than routing it.
			return fmt.Sprintf("policy rule %q takes traffic to %s out of the routing "+
				"tables altogether", r.text, target), nil
		}
		if r.table == "main" {
			continue
		}
		res, err := env.Probe(ctx, deviceID, []string{"sh", "-c",
			"ip route show table " + r.table + " to match " + target})
		if err != nil {
			return "", err
		}
		alt, ok := forwarding(kernelRoutes(res.Stdout), dst)
		if !ok {
			// Nothing there for this destination, so the lookup falls through
			// to the next rule and the daemon's table still decides.
			continue
		}
		if alt.kind != "" {
			return fmt.Sprintf("policy rule %q sends traffic to %s to table %s, where "+
				"%q forwards nothing", r.text, target, r.table, alt.text), nil
		}
		if got := hopNames(alt.hops); !sameHops(got, want) {
			return fmt.Sprintf("policy rule %q sends traffic to %s to table %s, which "+
				"forwards it over %s, not over %s", r.text, target, r.table,
				strings.Join(sortedKeysOfBool(got), ", "),
				strings.Join(sortedKeysOfBool(want), ", ")), nil
		}
	}
	return "", nil
}

// checkVLANIsolation verifies that hosts in the same VLAN reach each other
// directly while hosts in different VLANs are forced through the gateway.
// labDestinations is every address a frame in this lab could be addressed to:
// what the plan assigns anywhere in the topology, and what the hosts of this
// layer-2 domain and their gateway actually have configured. The live half
// matters because a student may address a host by hand, and a rule aimed at
// that address is a real way across.
func labDestinations(ctx context.Context, env *Env, hosts map[int][]*model.Device,
	gateway *model.Device) []netip.Prefix {

	var out []netip.Prefix
	add := func(s string) {
		if s = strings.TrimSpace(s); s == "" {
			return
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			return
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, as := range env.Topology.ASes {
		for _, d := range as.Devices {
			for _, i := range d.Ifaces {
				add(i.Addr4)
				add(i.Addr6)
			}
		}
	}
	var live []*model.Device
	for _, hs := range hosts {
		live = append(live, hs...)
	}
	if gateway != nil {
		live = append(live, gateway)
	}
	for _, d := range live {
		r, err := env.Probe(ctx, d.ID, []string{"ip", "-o", "addr", "show"})
		if err != nil || r.ExitCode != 0 {
			continue
		}
		for _, l := range strings.Split(r.Stdout, "\n") {
			f := strings.Fields(l)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "inet" || f[i] == "inet6" {
					add(f[i+1])
				}
			}
		}
	}
	return out
}

// flowDeliversNothing reports why a flow rule cannot carry a frame between two
// of this lab's hosts, or "" if it can.
//
// A rule restricted to a destination address that nothing in the lab has --
// left behind by a student testing whether traffic moves between two ports --
// never carries a frame, and failing the domain for it deducts for a crossing
// that does not exist. The counter is not what decides this: a rule that has
// matched nothing yet may match everything a minute later, so excusing rules
// whose n_packets is zero would pass a submission with its VLANs wide open.
// What decides it is whether any frame the lab can produce satisfies the match.
func flowDeliversNothing(match string, inv []netip.Prefix) string {
	var (
		field, val string
		got        bool
	)
	for _, tok := range strings.Split(strings.ReplaceAll(match, " ", ","), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(tok), "=")
		if !ok {
			continue
		}
		switch k {
		case "nw_dst", "ip_dst", "ipv4_dst", "ipv6_dst", "arp_tpa", "nd_target":
			// The narrowest constraint wins: several are a conjunction, and a
			// frame has to satisfy every one of them.
			field, val, got = k, v, true
		}
	}
	if !got {
		return ""
	}
	p, err := parseFlowPrefix(val)
	if err != nil {
		return "" // not understood, so not ruled out
	}
	// Multicast and broadcast are addressed to nobody in particular, so no
	// inventory can rule them out.
	if p.Addr().Is4() {
		mc := netip.MustParsePrefix("224.0.0.0/4")
		bc := netip.MustParsePrefix("255.255.255.255/32")
		if prefixesOverlap(p, mc) || prefixesOverlap(p, bc) {
			return ""
		}
	} else if prefixesOverlap(p, netip.MustParsePrefix("ff00::/8")) {
		return ""
	}
	for _, q := range inv {
		if prefixesOverlap(p, q) {
			return ""
		}
	}
	return fmt.Sprintf("only to %s=%s, which nothing in this lab has", field, val)
}

// parseFlowPrefix reads an address as a flow match writes it: bare, with a
// prefix length, or with a dotted mask.
func parseFlowPrefix(v string) (netip.Prefix, error) {
	if a, m, ok := strings.Cut(v, "/"); ok {
		if !strings.Contains(m, ".") && !strings.Contains(m, ":") {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return netip.Prefix{}, err
			}
			return p.Masked(), nil
		}
		mask, err := netip.ParseAddr(m)
		if err != nil {
			return netip.Prefix{}, err
		}
		ones := 0
		for _, b := range mask.AsSlice() {
			ones += bits.OnesCount8(b)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, ones).Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Overlaps(b)
}

// bridgeOnlyForwards reports whether every action on a bridge merely chooses
// where a frame goes. A bridge that rewrites addresses, resubmits, or learns
// can manufacture a frame addressed to anything, so on such a bridge no rule
// can be ruled out by what the lab addresses.
func bridgeOnlyForwards(lines []string) bool {
	inert := map[string]bool{
		"output": true, "normal": true, "drop": true, "flood": true, "all": true,
		"local": true, "in_port": true, "controller": true, "strip_vlan": true,
		"mod_vlan_vid": true, "mod_vlan_pcp": true, "push_vlan": true, "pop_vlan": true,
	}
	for _, line := range lines {
		at := strings.Index(line, "actions=")
		if at < 0 {
			continue
		}
		for _, a := range ovsSplitActions(line[at+8:]) {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			head, _, _ := strings.Cut(a, ":")
			head, _, _ = strings.Cut(head, "(")
			head = strings.ToLower(strings.TrimSpace(head))
			if _, err := strconv.Atoi(head); err == nil {
				continue // a bare port number
			}
			if !inert[head] {
				return false
			}
		}
	}
	return true
}

// crossVLANForwarding names any rule a switch of this domain has been given
// that forwards a frame from a port in one VLAN out of a port in another.
//
// A broadcast probe finds a shared broadcast domain; it does not find a rule
// aimed at one flow. This reads what the switch has actually been told to do,
// which covers every protocol at once and needs no packet.
func crossVLANForwarding(ctx context.Context, env *Env, domain string,
	inv []netip.Prefix) (leaks, notes []string) {

	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil, nil
	}
	var out []string
	for _, d := range as.Devices {
		if d.Kind != model.KindSwitch {
			continue
		}
		if domain != "" && d.L2Domain != "" && d.L2Domain != domain {
			continue
		}
		tags, err := env.Probe(ctx, d.ID,
			[]string{"ovs-vsctl", "--columns=name,tag", "--format=csv", "list", "port"})
		if err != nil || tags.ExitCode != 0 {
			out = append(out, fmt.Sprintf(
				"%s could not be asked which VLAN its ports are in, so nothing it forwards "+
					"was read", d.Name))
			continue
		}
		_, vlanOfPort := ovsPortMap("", tags.Stdout)
		// Anything the kernel has been told to copy, before the switch's own
		// tables. `tc filter ... action mirred egress mirror dev <other>` on
		// an access port copies frames into another VLAN without touching a
		// single OpenFlow rule, and reading only the flow table missed it
		// entirely.
		out = append(out, mirroredPorts(ctx, env, d, vlanOfPort)...)
		out = append(out, ovsMirrors(ctx, env, d, vlanOfPort)...)

		// Every bridge the switch has, not the one the reference answer
		// happens to build. `br0` was the only name ever asked for, and
		// `ovs-ofctl show br0` failing meant this switch was passed over in
		// silence -- so a submission that did its forwarding on a bridge by
		// any other name was never read at all.
		list, err := env.Probe(ctx, d.ID, []string{"ovs-vsctl", "list-br"})
		if err != nil || list.ExitCode != 0 {
			out = append(out, fmt.Sprintf(
				"%s could not be asked which bridges it has, so nothing it forwards was read",
				d.Name))
			continue
		}
		var bridges []string
		for _, b := range strings.Split(list.Stdout, "\n") {
			if b = strings.TrimSpace(b); b != "" {
				bridges = append(bridges, b)
			}
		}
		if len(bridges) == 0 {
			out = append(out, fmt.Sprintf("%s has no bridge, so it switches nothing", d.Name))
			continue
		}

		g := &ovsGraph{vlanOf: vlanOfPort, edges: map[string]map[string]bool{}}
		for _, br := range bridges {
			ports, err := env.Probe(ctx, d.ID, []string{"ovs-ofctl", "show", br})
			if err != nil || ports.ExitCode != 0 {
				out = append(out, fmt.Sprintf(
					"%s's bridge %s could not be read, so what it forwards is unknown",
					d.Name, br))
				continue
			}
			// Port numbers are the bridge's own, so they are resolved against
			// the bridge that used them and not against whichever bridge was
			// read first.
			byNum, _ := ovsPortMap(ports.Stdout, "")

			// A bridge under a controller does not forward by its table alone.
			// The controller is a program of the student's own, free to send
			// any frame anywhere on any packet-in, and the flow table shows
			// none of it. The reference switch has no controller, so saying so
			// costs a correct answer nothing.
			if c, err := env.Probe(ctx, d.ID,
				[]string{"ovs-vsctl", "get-controller", br}); err == nil && c.ExitCode == 0 &&
				strings.TrimSpace(c.Stdout) != "" {
				out = append(out, fmt.Sprintf(
					"%s's bridge %s is run by a controller (%s), which decides where frames "+
						"go, so what it forwards is not in its table", d.Name, br,
					strings.Join(strings.Fields(c.Stdout), " ")))
			}

			// The buckets of every group, because a flow's action can be a
			// group and the flow table then says nothing at all about where
			// the frame goes. A switch with no group is the normal case, so
			// an error here is not one.
			groups := map[string]string{}
			if gr, err := env.Probe(ctx, d.ID,
				[]string{"ovs-ofctl", "dump-groups", br}); err == nil && gr.ExitCode == 0 {
				groups = ovsGroupBuckets(gr.Stdout)
			}

			flows, err := env.Probe(ctx, d.ID, []string{"ovs-ofctl", "dump-flows", br})
			if err != nil || flows.ExitCode != 0 {
				out = append(out, fmt.Sprintf(
					"%s's bridge %s would not say what it forwards", d.Name, br))
				continue
			}
			anywhere := "*" + br
			for _, n := range byNum {
				g.link(n, anywhere)
			}
			// Read once for the flows and once more for whether any of them
			// ends at NORMAL, because a flow that rewrites a frame and then
			// resubmits it is delivered by whichever later flow does.
			var lines []string
			bridgeHasNormal := false
			for _, line := range strings.Split(flows.Stdout, "\n") {
				if !strings.Contains(line, "actions=") {
					continue
				}
				lines = append(lines, line)
				for _, a := range ovsSplitActions(line[strings.Index(line, "actions=")+8:]) {
					if strings.EqualFold(strings.TrimSpace(a), "normal") {
						bridgeHasNormal = true
					}
				}
			}
			inertBridge := bridgeOnlyForwards(lines)
			for _, line := range lines {
				at := strings.Index(line, "actions=")
				// A rule no frame of this lab can satisfy carries nothing
				// across, whatever ports it names. Only on a bridge that
				// merely chooses where frames go: one that rewrites or
				// resubmits can manufacture a frame addressed to anything.
				if inertBridge {
					if why := flowDeliversNothing(line[:at], inv); why != "" {
						notes = append(notes, fmt.Sprintf(
							"%s has a rule that forwards %s, so it carries nothing between "+
								"VLANs; it is not counted against you, but remove it", d.Name, why))
						continue
					}
				}
				in, outs := ovsFlowPorts(line, byNum, groups)
				for _, o := range outs {
					iv, ok1 := vlanOfPort[in]
					ov, ok2 := vlanOfPort[o]
					switch {
					case in != "" && ok1 && ok2 && iv != ov:
						out = append(out, fmt.Sprintf(
							"%s is told to send frames from %s (VLAN %d) out of %s (VLAN %d)",
							d.Name, in, iv, o, ov))
					case in == "" && ok2:
						out = append(out, fmt.Sprintf(
							"%s is told to send frames out of %s (VLAN %d) whatever port they "+
								"arrived on", d.Name, o, ov))
					}
					if in == "" {
						g.link(anywhere, o)
					} else {
						g.link(in, o)
					}
				}

				// What the actions do to the frame before the switch decides
				// where it goes. A flow that names no output port at all can
				// still carry a frame into another VLAN, by retagging it or
				// by changing which port it counts as having arrived on and
				// then letting the switch forward it by VLAN.
				for _, u := range ovsUnreadableActions(line[at+8:], byNum, vlanOfPort) {
					out = append(out, d.Name+" "+u)
				}
				rw := ovsWalkActions(line[at+8:], byNum)
				msg, to, known := normalCrossing(d.Name, line[:at], in, rw, vlanOfPort, bridgeHasNormal)
				if msg != "" {
					out = append(out, msg)
				}
				if msg != "" && known {
					from := anywhere
					if in != "" {
						from = in
					}
					for _, n := range byNum {
						if v, ok := vlanOfPort[n]; ok && v == to {
							g.link(from, n)
						}
					}
				}
			}
		}
		// A frame put out of a patch port comes in on its peer, which is how
		// two bridges are joined. Following that is what makes a second
		// bridge worth reading: on its own it holds no VLAN, and the way
		// across is the pair of hops through it.
		for a, b := range ovsPatchPeers(ctx, env, d) {
			g.patch(a, b)
		}
		out = append(out, g.crossings(d.Name)...)
	}
	sort.Strings(out)
	sort.Strings(notes)
	return out, notes
}

// ovsGraph is where a frame can get to inside one switch: the ports, and every
// hop the switch has been told to make between them.
//
// One bridge's flow table is not the whole switch. Bridges are joined by patch
// ports -- what goes out of one arrives on its peer -- so a frame can leave a
// VLAN 10 port, cross into a second bridge, and come back out somewhere in
// VLAN 20 without any single flow naming ports in two VLANs. Reading the hops
// as a graph is what makes that visible.
type ovsGraph struct {
	vlanOf map[string]int
	// from -> to -> whether the hop crosses between bridges.
	edges map[string]map[string]bool
}

func (g *ovsGraph) add(from, to string, isPatch bool) {
	if from == "" || to == "" {
		return
	}
	if g.edges[from] == nil {
		g.edges[from] = map[string]bool{}
	}
	g.edges[from][to] = g.edges[from][to] || isPatch
}

// link records a hop the switch makes within one bridge.
func (g *ovsGraph) link(from, to string) { g.add(from, to, false) }

// patch records the hop from a patch port to the peer it arrives on.
func (g *ovsGraph) patch(from, to string) { g.add(from, to, true) }

// crossings names the ways a frame can get from a port in one VLAN to a port
// in another by way of a second bridge.
//
// Hops within a single bridge are reported where they are read, port by port,
// so only paths that leave the bridge are named here -- otherwise one flow
// would be complained about twice.
func (g *ovsGraph) crossings(dev string) []string {
	srcs := make([]string, 0, len(g.vlanOf))
	for p := range g.vlanOf {
		srcs = append(srcs, p)
	}
	sort.Strings(srcs)

	var out []string
	for _, src := range srcs {
		v := g.vlanOf[src]
		type step struct {
			port    string
			crossed bool
		}
		seen := map[step]bool{{src, false}: true}
		queue := []step{{src, false}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			nexts := make([]string, 0, len(g.edges[cur.port]))
			for n := range g.edges[cur.port] {
				nexts = append(nexts, n)
			}
			sort.Strings(nexts)
			for _, n := range nexts {
				st := step{n, cur.crossed || g.edges[cur.port][n]}
				if seen[st] {
					continue
				}
				if u, ok := g.vlanOf[n]; ok && u != v && st.crossed {
					out = append(out, fmt.Sprintf(
						"%s is told to carry frames from %s (VLAN %d) across to %s (VLAN %d) "+
							"by way of another bridge", dev, src, v, n, u))
					queue = nil
					break
				}
				seen[st] = true
				queue = append(queue, st)
			}
		}
	}
	return out
}

// ovsPatchPeers reads which of a switch's ports are patch ports, and the port
// each one delivers to.
func ovsPatchPeers(ctx context.Context, env *Env, d *model.Device) map[string]string {
	peers := map[string]string{}
	r, err := env.Probe(ctx, d.ID, []string{"ovs-vsctl", "--columns=name,type,options",
		"--format=csv", "list", "interface"})
	if err != nil || r.ExitCode != 0 {
		return peers
	}
	for _, line := range strings.Split(r.Stdout, "\n") {
		i := strings.Index(line, "peer=")
		if i < 0 {
			continue
		}
		// The name is the first field; options hold commas of their own, so
		// the peer is read from where it is written rather than by counting
		// fields.
		name := strings.Trim(strings.TrimSpace(strings.SplitN(line, ",", 2)[0]), `"`)
		peer := line[i+len("peer="):]
		if j := strings.IndexAny(peer, `,}" `); j >= 0 {
			peer = peer[:j]
		}
		if name != "" && peer != "" && name != "name" {
			peers[name] = peer
		}
	}
	return peers
}

// mirroredPorts names the traffic-control rules on a switch that copy frames
// from a port in one VLAN to a port in another.
//
// The switch's own flow table is not the only place a frame can be told to go
// somewhere: the kernel will copy one for anybody who asks, and a rule doing
// that leaves the flow table exactly as it should be.
func mirroredPorts(ctx context.Context, env *Env, d *model.Device,
	vlanOf map[string]int) []string {
	var out []string
	for port, iv := range vlanOf {
		for _, dir := range []string{"ingress", "egress"} {
			res, err := env.Probe(ctx, d.ID,
				[]string{"tc", "filter", "show", "dev", port, dir})
			if err != nil || res.ExitCode != 0 {
				continue
			}
			for _, line := range strings.Split(res.Stdout, "\n") {
				t := strings.TrimSpace(line)
				if !strings.Contains(t, "mirred") {
					continue
				}
				// "... (Egress Mirror to device port_P_EUH) pipe"
				i := strings.LastIndex(t, "device ")
				if i < 0 {
					continue
				}
				target := strings.Fields(t[i+len("device "):])
				if len(target) == 0 {
					continue
				}
				to := strings.Trim(target[0], "()")
				ov, ok := vlanOf[to]
				if !ok || ov == iv {
					continue
				}
				out = append(out, fmt.Sprintf(
					"%s is told to copy frames %s on %s (VLAN %d) to %s (VLAN %d)",
					d.Name, dir, port, iv, to, ov))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ovsMirrors names the switch's own port mirrors that copy frames from a port
// in one VLAN into a port in another.
//
// A mirror is the switch's built-in copier. It leaves the flow table and the
// kernel's traffic control exactly as a correct switch would have them, and
// still duplicates every frame of one port onto another whatever VLAN either
// is in.
func ovsMirrors(ctx context.Context, env *Env, d *model.Device,
	vlanOf map[string]int) []string {
	res, err := env.Probe(ctx, d.ID,
		[]string{"ovs-vsctl", "--columns=_uuid,name", "--format=csv", "list", "port"})
	if err != nil || res.ExitCode != 0 {
		return nil
	}
	byUUID := map[string]string{}
	for _, rec := range ovsCSV(res.Stdout) {
		if len(rec) >= 2 {
			byUUID[strings.TrimSpace(rec[0])] = strings.TrimSpace(rec[1])
		}
	}
	mirrors, err := env.Probe(ctx, d.ID, []string{"ovs-vsctl",
		"--columns=select_src_port,select_dst_port,select_all,output_port",
		"--format=csv", "list", "mirror"})
	if err != nil || mirrors.ExitCode != 0 {
		return nil
	}
	var out []string
	for _, rec := range ovsCSV(mirrors.Stdout) {
		if len(rec) < 4 {
			continue
		}
		from := append(ovsPortNames(rec[0], byUUID), ovsPortNames(rec[1], byUUID)...)
		if strings.Contains(rec[2], "true") {
			for _, p := range byUUID {
				from = append(from, p)
			}
		}
		for _, to := range ovsPortNames(rec[3], byUUID) {
			ov, ok := vlanOf[to]
			if !ok {
				continue
			}
			for _, src := range from {
				iv, ok := vlanOf[src]
				if !ok || iv == ov {
					continue
				}
				out = append(out, fmt.Sprintf(
					"%s is told to copy every frame of %s (VLAN %d) onto %s (VLAN %d)",
					d.Name, src, iv, to, ov))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ovsCSV parses what `ovs-vsctl --format=csv` prints, keeping whatever it
// managed to read when a line will not parse.
func ovsCSV(s string) [][]string {
	r := csv.NewReader(strings.NewReader(s))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	var out [][]string
	for {
		rec, err := r.Read()
		if err != nil {
			return out
		}
		out = append(out, rec)
	}
}

// ovsPortNames turns a database field holding one port row, or a set of them,
// into the names of those ports.
func ovsPortNames(field string, byUUID map[string]string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(field, func(r rune) bool {
		return r == '[' || r == ']' || r == ',' || r == ' ' || r == '"'
	}) {
		if n, ok := byUUID[t]; ok {
			out = append(out, n)
		}
	}
	return out
}

// ovsPortMap reads the switch's port numbering and each port's access VLAN.
func ovsPortMap(show, tags string) (map[string]string, map[string]int) {
	byNum := map[string]string{}
	for _, line := range strings.Split(show, "\n") {
		t := strings.TrimSpace(line)
		i := strings.IndexByte(t, '(')
		j := strings.IndexByte(t, ')')
		if i <= 0 || j <= i {
			continue
		}
		if _, err := strconv.Atoi(t[:i]); err != nil {
			continue
		}
		byNum[t[:i]] = t[i+1 : j]
	}
	vlan := map[string]int{}
	for _, line := range strings.Split(tags, "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(f[1], "\"[] "))
		if err != nil {
			continue
		}
		vlan[strings.TrimSpace(f[0])] = n
	}
	return byNum, vlan
}

// ovsFlowPorts pulls the ingress port and every port a flow can send a frame
// out of, from one line of `ovs-ofctl dump-flows`, resolving numbers to names.
func ovsFlowPorts(line string, byNum map[string]string, groups map[string]string) (string, []string) {
	// The match ends where the actions begin, and they are separated by a
	// space, not a comma. Reading in_port out of the whole line made the port
	// of `in_port=1 actions=output:2` come out as `1 actions=output:2`, which
	// resolved to no port at all -- so the flow was read as one that had never
	// said where its frames came from, and the rule that catches a frame
	// leaving its VLAN never fired on it.
	match, actions := line, ""
	if i := strings.Index(line, "actions="); i >= 0 {
		match, actions = line[:i], line[i+len("actions="):]
	}
	in := ""
	for _, f := range strings.Split(match, ",") {
		t := strings.TrimSpace(f)
		if v, ok := strings.CutPrefix(t, "in_port="); ok {
			in = ovsPortName(v, byNum)
		}
	}
	return in, ovsActionPorts(actions, byNum, groups, map[string]bool{})
}

// ovsPortName resolves a port number to the port's name where it can.
func ovsPortName(tok string, byNum map[string]string) string {
	// `ovs-ofctl --names` prints ports by name and in quotes, and a quoted
	// name matches nothing: not the number table, and not the VLAN table
	// either, so the port was treated as one this had never heard of.
	tok = strings.Trim(tok, " \t,)\"")
	if n, ok := byNum[tok]; ok {
		return n
	}
	return tok
}

// ovsActionPorts expands one action string into every port it can put a frame
// on, following each group it names into that group's buckets.
//
// "output:" is not the only way to emit a frame, and reading only that was
// enough to miss `enqueue:8:0`, which puts the frame on a queue of port 8 and
// sends it exactly as `output` would. Every action that names a port counts,
// and the ones that name none but reach every port -- flood, all -- count as
// reaching all of them.
//
// A group is a second table the flow table only points at: `actions=group:461`
// names no port whatsoever, and the frame leaves by whichever port the group's
// buckets say. Reading only the flow table saw an action with no destination
// and found nothing to complain about, so a group carrying a frame from one
// VLAN straight into another scored full marks.
func ovsActionPorts(actions string, byNum map[string]string,
	groups map[string]string, seen map[string]bool) []string {
	var outs []string
	// Anything of the form "<verb>:<port>[:...]", plus the port-in-parens form.
	for _, verb := range []string{"output:", "enqueue:", "resubmit:"} {
		rest := actions
		for {
			i := strings.Index(rest, verb)
			if i < 0 {
				break
			}
			rest = rest[i+len(verb):]
			end := strings.IndexAny(rest, ", \t")
			tok := rest
			if end >= 0 {
				tok = rest[:end]
			}
			// enqueue names the port first and the queue after a colon;
			// resubmit names a port before a comma inside parentheses.
			tok = strings.TrimLeft(tok, "(")
			if j := strings.IndexByte(tok, ':'); j >= 0 {
				tok = tok[:j]
			}
			if tok != "" {
				outs = append(outs, ovsPortName(tok, byNum))
			}
		}
	}
	for _, form := range []string{"output(port="} {
		rest := actions
		for {
			i := strings.Index(rest, form)
			if i < 0 {
				break
			}
			rest = rest[i+len(form):]
			end := strings.IndexAny(rest, ",) \t")
			if end < 0 {
				end = len(rest)
			}
			if tok := rest[:end]; tok != "" {
				outs = append(outs, ovsPortName(tok, byNum))
			}
		}
	}
	// Every group the actions name, and every group those name in turn. The
	// visited set is what stops a group that points at itself from spinning.
	for _, verb := range []string{"group:", "group_id="} {
		rest := actions
		for {
			i := strings.Index(rest, verb)
			if i < 0 {
				break
			}
			rest = rest[i+len(verb):]
			id := rest
			if end := strings.IndexAny(id, ",) \t"); end >= 0 {
				id = id[:end]
			}
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			if b, ok := groups[id]; ok {
				outs = append(outs, ovsActionPorts(b, byNum, groups, seen)...)
			}
		}
	}
	// Actions that reach every port at once. Matched as whole actions: the
	// letters "all" inside a longer word are not the flood action, and
	// expanding on those would take marks off a switch that forwards nothing
	// of the sort.
	for _, a := range ovsSplitActions(actions) {
		l := strings.ToLower(strings.TrimSpace(a))
		if l == "flood" || l == "all" {
			for _, n := range byNum {
				outs = append(outs, n)
			}
			break
		}
	}
	return outs
}

// ovsUnreadableActions describes the actions of a flow whose effect this
// cannot work out, which is not the same as a flow that does nothing.
//
// `output:NXM_NX_REG0[]` sends the frame wherever a register says, and the
// register is filled in by earlier flows; a reader looking for a port number
// finds a token that is not one, and a destination that cannot be named cannot
// be said to be in the frame's own VLAN. `learn(...)` installs flows that do
// not exist yet, so the table does not yet say what the switch will do. Both
// are reported as unread rather than passed over: this is the difference
// between "it forwards nothing across" and "what it forwards could not be
// read".
func ovsUnreadableActions(actions string, byNum map[string]string,
	vlanOf map[string]int) []string {
	var out []string
	for _, raw := range ovsSplitActions(actions) {
		a := strings.TrimSpace(raw)
		l := strings.ToLower(a)
		if strings.HasPrefix(l, "learn(") {
			out = append(out, "installs flows of its own with `learn`, which are not in the "+
				"table yet, so what it will forward could not be read")
			continue
		}
		tok, ok := strings.CutPrefix(l, "output:")
		if !ok {
			continue
		}
		tok = strings.Trim(tok, " \t\"")
		// Back out of the port it came in on is not a way into another VLAN.
		if tok == "" || tok == "in_port" {
			continue
		}
		name := ovsPortName(tok, byNum)
		if _, known := vlanOf[name]; known {
			continue
		}
		if _, known := byNum[tok]; known {
			continue
		}
		out = append(out, fmt.Sprintf(
			"is told to send frames out of `%s`, which is not a port this could name, so "+
				"the VLAN they leave in could not be read", strings.TrimSpace(a)))
	}
	return out
}

// ovsRewrite is what an action list does to a frame before the switch decides
// where it goes: which VLAN it is now in, which port it now counts as having
// arrived on, and whether it is then handed to NORMAL.
//
// This is the difference between reading an action list and running it.
// `actions=NORMAL` puts a frame out of the ports of its own VLAN and leaks
// nothing, which is why it was read as harmless. But an action list is a
// program: `load:4->NXM_OF_IN_PORT[],mod_vlan_vid:20,NORMAL` hands NORMAL a
// frame that is now tagged 20 and now claims to have come in on port 4, and
// NORMAL faithfully delivers it into VLAN 20. Nothing in that flow names an
// output port, so a reader looking for output ports finds none.
type ovsRewrite struct {
	vlan      int  // the VLAN the frame carries after the rewrites
	vlanKnown bool // whether that VLAN could be worked out
	vlanSet   bool // whether the actions touched the tag at all
	inPort    string
	inKnown   bool
	inSet     bool
	normal    bool // handed to NORMAL, which forwards by VLAN
	resubmit  bool // handed back to the tables, which may end at NORMAL
}

// ovsVLANValue reads the VLAN out of an action's argument. The forms differ:
// `mod_vlan_vid:20` carries the id on its own, while `set_field:4116->vlan_vid`
// and the VLAN_TCI register carry the present bit above it.
func ovsVLANValue(tok string, masked bool) (int, bool) {
	tok = strings.TrimSpace(tok)
	if i := strings.IndexByte(tok, '/'); i >= 0 { // value/mask
		tok = tok[:i]
	}
	n, err := strconv.ParseUint(tok, 0, 32)
	if err != nil {
		return 0, false
	}
	if masked {
		return int(n & 0xfff), true
	}
	return int(n), true
}

// ovsWalkActions runs an action list far enough to know what the frame looks
// like by the time the switch decides where to send it.
func ovsWalkActions(actions string, byNum map[string]string) ovsRewrite {
	var r ovsRewrite
	for _, raw := range ovsSplitActions(actions) {
		a := strings.TrimSpace(raw)
		l := strings.ToLower(a)
		switch {
		case l == "normal":
			r.normal = true
		case strings.HasPrefix(l, "resubmit"):
			r.resubmit = true
			// resubmit(<port>,<table>) re-runs the tables with the frame
			// counting as having arrived on that port.
			if i := strings.IndexByte(a, '('); i >= 0 {
				arg := a[i+1:]
				arg = strings.TrimSuffix(strings.TrimSpace(arg), ")")
				port := arg
				if j := strings.IndexByte(port, ','); j >= 0 {
					port = port[:j]
				}
				if port = strings.TrimSpace(port); port != "" {
					r.inSet = true
					r.inPort = ovsPortName(port, byNum)
					_, r.inKnown = byNum[strings.TrimSpace(port)]
				}
			}
		case strings.HasPrefix(l, "mod_vlan_vid:"):
			r.vlanSet = true
			r.vlan, r.vlanKnown = ovsVLANValue(a[len("mod_vlan_vid:"):], false)
		case strings.HasPrefix(l, "strip_vlan"), strings.HasPrefix(l, "pop_vlan"):
			// The frame leaves untagged, so NORMAL gives it the VLAN of
			// whichever port it counts as having arrived on.
			r.vlanSet, r.vlanKnown, r.vlan = true, true, 0
		case strings.HasPrefix(l, "push_vlan"):
			r.vlanSet, r.vlanKnown = true, false
		case strings.HasPrefix(l, "set_field:"), strings.HasPrefix(l, "load:"):
			arrow := strings.Index(a, "->")
			if arrow < 0 {
				continue
			}
			val := a[strings.IndexByte(a, ':')+1 : arrow]
			dst := strings.ToLower(a[arrow+2:])
			switch {
			case strings.Contains(dst, "vlan_vid"), strings.Contains(dst, "vlan_tci"):
				r.vlanSet = true
				r.vlan, r.vlanKnown = ovsVLANValue(val, true)
			case strings.Contains(dst, "dl_vlan"):
				r.vlanSet = true
				r.vlan, r.vlanKnown = ovsVLANValue(val, false)
			case strings.Contains(dst, "in_port"):
				r.inSet = true
				if n, ok := ovsVLANValue(val, false); ok {
					num := strconv.Itoa(n)
					r.inPort = ovsPortName(num, byNum)
					_, r.inKnown = byNum[num]
				}
			}
		case strings.HasPrefix(l, "move:"):
			if strings.Contains(l, "in_port") {
				r.inSet = true // copied from somewhere; the value is not readable here
			}
			if strings.Contains(l, "vlan_vid") || strings.Contains(l, "vlan_tci") {
				r.vlanSet = true
			}
		}
	}
	return r
}

// ovsMatchVLAN is the VLAN a frame is in when it reaches a flow: the tag the
// flow matches on if it names one, otherwise the VLAN of the port it came in
// on, because an access port's frames are in its VLAN by definition.
func ovsMatchVLAN(line, in string, vlanOf map[string]int) (int, bool) {
	for _, f := range ovsSplitActions(line) {
		t := strings.TrimSpace(f)
		if v, ok := strings.CutPrefix(t, "dl_vlan="); ok {
			if n, ok := ovsVLANValue(v, false); ok {
				return n, true
			}
		}
		if v, ok := strings.CutPrefix(t, "vlan_tci="); ok {
			if n, ok := ovsVLANValue(v, true); ok {
				return n, true
			}
		}
	}
	if in != "" {
		if v, ok := vlanOf[in]; ok {
			return v, true
		}
	}
	return 0, false
}

// normalCrossing reports a flow that rewrites a frame and then lets the switch
// forward it by VLAN, when the VLAN it is forwarded in is not the one it
// arrived in. It returns the delivered VLAN so the caller can record where
// such a frame can get to.
//
// It says nothing about a flow that rewrites nothing: `priority=0
// actions=NORMAL` is the whole of a correct switch's table, and NORMAL on an
// untouched frame keeps it in its own VLAN.
func normalCrossing(dev, line, in string, r ovsRewrite,
	vlanOf map[string]int, bridgeHasNormal bool) (string, int, bool) {
	if !r.vlanSet && !r.inSet {
		return "", 0, false
	}
	if !r.normal && (!r.resubmit || !bridgeHasNormal) {
		return "", 0, false
	}
	from, fromKnown := ovsMatchVLAN(line, in, vlanOf)

	// Where the frame ends up: its own tag if it still has one, otherwise the
	// VLAN of the port it now counts as having arrived on.
	to, toKnown := 0, false
	switch {
	case r.vlanSet && r.vlanKnown && r.vlan != 0:
		to, toKnown = r.vlan, true
	case r.inSet && r.inKnown:
		to, toKnown = vlanOf[r.inPort]
	case !r.inSet && in != "":
		to, toKnown = vlanOf[in]
	}

	where := "frames"
	if in != "" {
		where = "frames from " + in
	}
	switch {
	case fromKnown && toKnown && from == to:
		return "", 0, false
	case fromKnown && toKnown:
		return fmt.Sprintf(
			"%s is told to put %s (VLAN %d) into VLAN %d and then forward them by VLAN, "+
				"which delivers them there", dev, where, from, to), to, true
	default:
		// One end could not be worked out, and a rewrite was made. Which VLAN
		// the frame is delivered in is then not something this can vouch for.
		return fmt.Sprintf(
			"%s is told to rewrite %s before forwarding them by VLAN, so the VLAN they are "+
				"delivered in is not the one they arrived in", dev, where), to, toKnown
	}
}

// ovsSplitActions splits an action list into its actions, keeping whatever is
// inside parentheses or brackets together: `resubmit(,10)` and
// `load:4->NXM_OF_IN_PORT[]` are each one action, commas and all.
func ovsSplitActions(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// ovsGroupBuckets reads `ovs-ofctl dump-groups` into the buckets of every
// group, keyed by group id.
func ovsGroupBuckets(dump string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(dump, "\n") {
		t := strings.TrimSpace(line)
		i := strings.Index(t, "group_id=")
		if i < 0 {
			continue
		}
		id := t[i+len("group_id="):]
		if j := strings.IndexAny(id, ", \t"); j >= 0 {
			id = id[:j]
		}
		// From the first bucket onwards, and no earlier: what comes before it
		// names the group's type, and `type=all` is not an instruction to
		// flood -- reading it as one would fail every switch that has a group.
		j := strings.Index(t, "bucket=")
		if id == "" || j < 0 {
			continue
		}
		out[id] += "," + t[j:]
	}
	return out
}

// crossVLANFrames sends a broadcast in one VLAN and asks the other whether it
// arrived, returning what leaked and how many ordered pairs were tried.
//
// The observation is the target's own neighbour table. An ARP request names its
// sender, and a kernel that answers one records who asked; a kernel that never
// sees the frame has nothing to record. This works where watching for a reply
// does not, because a switch can be made to copy frames one way only, and then
// the answer goes back into the VLAN it came from and the sender hears nothing
// while the other VLAN has seen everything.
func crossVLANFrames(ctx context.Context, env *Env, vlans []int,
	hosts map[int][]*model.Device, sem chan struct{}) (leaked []string, tested, unread int) {
	type pair struct{ src, dst *model.Device }
	var pairs []pair
	for a := range vlans {
		for b := range vlans {
			if a == b {
				continue
			}
			for _, src := range hosts[vlans[a]] {
				for _, dst := range hosts[vlans[b]] {
					pairs = append(pairs, pair{src, dst})
				}
			}
		}
	}
	var (
		mu    sync.Mutex
		leaks []string
		wg    sync.WaitGroup
	)
	for _, p := range pairs {
		wg.Add(1)
		go func(p pair) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			srcIf, srcAddr := accessPort(p.src)
			dstIf, dstAddr := accessPort(p.dst)
			if srcIf == "" || srcAddr == "" || dstIf == "" || dstAddr == "" {
				return
			}
			// Forget anything already known about the sender, so what is there
			// afterwards can only have arrived during the probe.
			_, _ = env.Probe(ctx, p.dst.ID, []string{"ip", "neigh", "del", srcAddr, "dev", dstIf})
			res, err := env.Probe(ctx, p.src.ID,
				[]string{"arping", "-c", "2", "-w", "3", "-I", srcIf, dstAddr})
			// Exit 1 is "nobody answered", which is the correct answer here.
			// Anything that means the probe never ran -- no such command, no
			// such interface -- must not be counted as an isolated pair.
			if err != nil || res.ExitCode > 1 {
				return
			}
			// A pair counts as tested once its destination has been read.
			// Counting it before meant a neighbour table that could not be
			// read -- the probe never ran, so it recorded nothing -- was
			// scored as a pair the frame did not reach.
			seen, err := env.Probe(ctx, p.dst.ID,
				[]string{"ip", "neigh", "show", srcAddr, "dev", dstIf})
			if err != nil || seen.ExitCode != 0 {
				mu.Lock()
				unread++
				mu.Unlock()
				return
			}
			mu.Lock()
			tested++
			mu.Unlock()
			if !strings.Contains(seen.Stdout, "lladdr") {
				return
			}
			mu.Lock()
			leaks = append(leaks, fmt.Sprintf(
				"a broadcast frame sent by %s in VLAN %d arrived at %s in VLAN %d, "+
					"which recorded the sender: the two VLANs are one broadcast domain",
				p.src.Name, vlanOf(p.src), p.dst.Name, vlanOf(p.dst)))
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Strings(leaks)
	return leaks, tested, unread
}

// accessPort names the interface a host sits on in its layer-2 domain, and the
// address it answers to there.
func accessPort(d *model.Device) (string, string) {
	for _, i := range d.Ifaces {
		if i.Name == "lo" || i.Addr4 == "" {
			continue
		}
		addr := i.Addr4
		if j := strings.IndexByte(addr, '/'); j > 0 {
			addr = addr[:j]
		}
		return i.Name, addr
	}
	return "", ""
}

// vlanOf reports the VLAN a host is meant to be in.
func vlanOf(d *model.Device) int {
	for _, i := range d.Ifaces {
		if i.VLAN > 0 {
			return i.VLAN
		}
	}
	return 0
}

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
						record(false, "VLAN %d: the distance from %s to %s could not be "+
							"measured (%v)", v, src.Name, dst.Name, err)
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
							record(false, "the path from %s to %s across VLANs could not be "+
								"measured (%v)", src.Name, dst.Name, err)
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

	// And then layer 2 itself.
	//
	// Everything above is about IP: hosts in one VLAN are adjacent, hosts in
	// two are separated by the gateway. None of it looks at frames, and a
	// switch that copies frames from one VLAN's port onto another's leaves all
	// of it true -- off-subnet traffic still goes through the gateway, because
	// that is a routing decision the host makes before any frame exists. A
	// reviewer mirrored one access port onto another with `tc ... mirred` and
	// the check gave full marks to two VLANs that were the same broadcast
	// domain.
	//
	// So a broadcast is sent, and the far side is asked whether it saw it. An
	// ARP request for the other host's address is answered by nobody when the
	// VLANs are separate, and when they are not the target's own kernel records
	// the sender -- which it does even when the copy is one-directional and the
	// reply never comes back, as the reviewer's was.
	// And what the switches have been told to forward.
	//
	// The probe above sends a broadcast, which is what a shared broadcast
	// domain leaks. It is not what a rule aimed at one flow leaks: an
	// OpenFlow entry copying HTTPS from a VLAN 10 port to a VLAN 20 port
	// carried a connection between two VLANs while every broadcast stayed
	// where it belonged, and the question kept its mark. A switch that has
	// been told to send a frame from a port in one VLAN out of a port in
	// another is not keeping them apart, whatever the frame is.
	rules, notes := crossVLANForwarding(ctx, env, domain,
		labDestinations(ctx, env, hosts, gateway))
	probed, tested, unread := crossVLANFrames(ctx, env, vlans, hosts, sem)
	if tested == 0 && unread > 0 {
		return Errored("l2.vlan_isolation", fmt.Errorf(
			"no host could be asked whether a frame from the other VLAN reached it "+
				"(%d pair(s) unreadable), so whether the VLANs are separate is unknown",
			unread))
	}
	if unread > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d pair(s) could not be read, so the verdict covers the other %d",
			unread, tested))
	}
	leaks := append(rules, probed...)
	for i := 0; i < tested-len(probed); i++ {
		record(true, "")
	}
	// Isolation is a property of the domain and not a proportion of it. One
	// frame crossing means the two VLANs are one broadcast domain, however
	// many pairs behaved; scoring it as a twentieth of the question made a
	// deduction of three hundredths for two VLANs that were not separate.
	if crossed := len(leaks); crossed > 0 {
		for _, r := range results {
			if !r.ok {
				leaks = append(leaks, r.detail)
			}
		}
		return Fail("l2.vlan_isolation", Evidence{
			Expected: "no frame sent in one VLAN reaching another, and nothing arranged to send one",
			Observed: fmt.Sprintf("%d way(s) across, from %d forwarding rule(s) and %d of %d "+
				"probed pairs", crossed, len(rules), len(probed), tested),
			Detail:  strings.Join(truncate(leaks, 8), "\n"),
			Hint:    "an access port belongs to one VLAN; check for anything bridging, mirroring or forwarding between them",
			Command: "arping; ip neigh show; ovs-vsctl list-br; ovs-ofctl dump-flows <bridge>",
		})
	}

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
	detail.WriteString(strings.Join(truncate(append(problems, notes...), 8), "\n"))

	if total > 0 && passed == total {
		return Pass("l2.vlan_isolation", Evidence{
			Observed: fmt.Sprintf("%d VLANs isolated correctly, routed via %s", len(vlans), gateway.Name),
			Detail:   strings.Join(truncate(notes, 8), "\n")})
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
	var pairs []reachabilityProbe
	for _, a := range hosts {
		for _, b := range hosts {
			if a.ID == b.ID || addrOf[b.ID] == "" {
				continue
			}
			pairs = append(pairs, reachabilityProbe{from: a, to: b})
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
			pairs = append(pairs, reachabilityProbe{from: s.Device, to: h, srcIface: s.Iface})
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
	// a route or a NAT rule can arrange. It is something the host itself can
	// arrange, though: the counter takes no interest in where a packet came
	// from, and a host pinging its own loopback address raises it one for one,
	// so the DNAT above plus a background `ping 127.0.0.1` put it back to
	// passing while the host still received nothing. What is counted is
	// therefore the arrivals that cannot have come from the host itself.
	//
	// Read once per host rather than once per pair, so 56 probes cost 16 extra
	// reads and not 112.
	echoesBefore := receivedEchoes(ctx, env, hosts)

	failed, batchedPings := batchedPingFailures(ctx, env, pairs, addrOf)
	if !batchedPings {
		failed = legacyPingFailures(ctx, env, pairs, addrOf)
	}

	// And the same pairs, with something other than a ping.
	//
	// Every probe above is ICMP. A rule discarding TCP between two hosts left
	// all eighty-eight of them succeeding and the question at full marks,
	// while nothing but a ping could cross between the two. A connection is
	// attempted to a port nothing is listening on, so no service has to be
	// arranged, and the destination's own count of what reached it is read --
	// a refusal proves only that somebody answered, and any router on the way
	// can send one carrying the destination's address.
	var pingOnly []string
	if !batchedTransportVerified(ctx, env, hosts, addrOf) {
		// A batch that cannot prove every flow falls back to the original
		// per-destination witnesses. Wrong submissions therefore retain the
		// full discriminator; healthy references avoid hundreds of remote
		// command round trips.
		pingOnly = unreachableByTCP(ctx, env, hosts, addrOf)
		pingOnly = append(pingOnly, unreachableByUDP(ctx, env, hosts, addrOf)...)
	}
	sort.Strings(pingOnly)
	failed = append(failed, pingOnly...)

	tried := len(pairs) + len(hosts)*(len(hosts)-1)
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
		// Every probe sends two echo requests, so asking for one apiece still
		// leaves room for a lost packet. Asking for a count at all is the
		// point: the test was that the counter had moved by anything at all,
		// which let a single packet from anywhere stand as the witness for
		// every probe sent to that host.
		arrived := arrivedFromOffBox(before, after)
		if arrived < want {
			unseen = append(unseen, fmt.Sprintf("%s answered %d probe(s), but only %d echo "+
				"request(s) reached it from off the machine: something else is replying for it",
				h.Name, want, arrived))
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
	// A path that carries pings and nothing else is half a working network,
	// however few pairs show it. Counted as a fraction of a hundred and
	// forty-four probes the deduction was three thousandths and the total
	// still printed ten out of ten, which is the same as not noticing.
	score := ratio(tried-len(failed), tried)
	if len(pingOnly) > 0 && score > 0.5 {
		score = 0.5
	}
	return Partial("dataplane.internal_reachability", score, Evidence{
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

// unreachableByTCP tries a connection between every ordered pair of hosts and
// names the ones where the packets do not arrive.
//
// The port is one nothing listens on, so the answer from a host that receives
// the attempt is a reset. But a reset is not proof that the host received
// anything: any router on the way can send one carrying the destination's
// address, and a student whose network drops forwarded TCP could clear this
// check with a single `REJECT --reject-with tcp-reset` rule. The destination's
// own count of the resets it sent is the witness, and silence there is
// something on the path swallowing the attempt.
func unreachableByTCP(ctx context.Context, env *Env, hosts []*model.Device,
	addrOf map[string]string) []string {
	type attempt struct{ from, to *model.Device }
	var pairs []attempt
	for _, a := range hosts {
		for _, b := range hosts {
			if a.ID == b.ID || addrOf[b.ID] == "" {
				continue
			}
			pairs = append(pairs, attempt{a, b})
		}
	}

	// Serialised by destination, so a counter that moved belongs to the
	// attempt that moved it rather than to somebody else's probe.
	rounds := roundsByDestinationOf(pairs, func(p attempt) string { return p.to.ID })
	try := func(round []attempt) map[string]string {
		var mu sync.Mutex
		bad := map[string]string{}
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16)
		for _, p := range round {
			wg.Add(1)
			go func(p attempt) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				addr := addrOf[p.to.ID]
				w, ok := tryConnection(ctx, env, p.from.ID, p.to.ID, addr, probePort())
				if !ok || w.reached() {
					return
				}
				mu.Lock()
				bad[p.from.ID+"\x00"+p.to.ID] = fmt.Sprintf(
					"%s can ping %s (%s) but no connection to it arrives: something on the "+
						"path carries ICMP and discards the rest", p.from.Name, p.to.Name, addr)
				mu.Unlock()
			}(p)
		}
		wg.Wait()
		return bad
	}

	var out []string
	// A round that finds something is run again before any of it is reported,
	// for the reason set out over unreachableByUDP: one observation of a path
	// is one observation however many packets it took, and a path that really
	// discards connections discards the second round too.
	for _, round := range rounds {
		bad := try(round)
		if len(bad) == 0 {
			continue
		}
		for pair, why := range try(round) {
			if _, both := bad[pair]; both {
				out = append(out, why)
			}
		}
	}
	sort.Strings(out)
	return out
}

// unreachableByUDP sends a datagram between every ordered pair of hosts and
// names the ones that do not arrive.
//
// Arrival is read at the far side, from a capture of the flow on its own
// interfaces together with its count of datagrams delivered for a port nothing
// is bound to. The sender cannot be trusted to tell: when the datagram is
// dropped it hears nothing, and hearing nothing is exactly what `nc` reports as
// success. Nor can the count on its own, which the receiving host raises for
// itself by sending a datagram to one of its own closed ports.
//
// The pairs are done in rounds, each round a different offset, so that no two
// senders aim at the same host at once and the counter says who arrived.
//
// A round that finds something is run again before any of it is reported. Three
// datagrams sent back to back are milliseconds apart, so they are one
// observation of the path and not three: they survive a packet dropped on its
// own, and nothing that lasts. Whatever it is that takes a pair out for a
// second at a time -- and 300 datagrams over the pair that failed a real class
// run arrived, 300 of 300, when it was asked afterwards -- a path that is
// really discarding the protocol discards the second round as surely as the
// first. This is finding 116's rule in the place it was not applied.
func unreachableByUDP(ctx context.Context, env *Env, hosts []*model.Device,
	addrOf map[string]string) []string {
	n := len(hosts)
	if n < 2 {
		return nil
	}
	var out []string
	for k := 1; k < n; k++ {
		bad := udpRound(ctx, env, hosts, addrOf, k)
		if len(bad) == 0 {
			continue
		}
		for pair, why := range udpRound(ctx, env, hosts, addrOf, k) {
			if _, both := bad[pair]; both {
				out = append(out, why)
			}
		}
	}
	sort.Strings(out)
	return out
}

// udpRound sends a datagram between every pair of one round and returns the
// ones that did not arrive, keyed by the pair so that a second round can be
// compared with the first.
func udpRound(ctx context.Context, env *Env, hosts []*model.Device,
	addrOf map[string]string, k int) map[string]string {
	n := len(hosts)
	out := map[string]string{}
	// One port per destination for this round, so that each capture
	// watches for exactly the datagram aimed at that host.
	ports := map[string]string{}
	for i := range hosts {
		dst := hosts[(i+k)%n]
		if addrOf[dst.ID] != "" {
			ports[dst.ID] = probePort()
		}
	}
	taps := startTaps(ctx, env, ports)
	before := udpCounters(ctx, env, hosts)
	var wg sync.WaitGroup
	var mu sync.Mutex
	unsent := map[string]bool{}
	for i, src := range hosts {
		dst := hosts[(i+k)%n]
		if addrOf[dst.ID] == "" {
			continue
		}
		wg.Add(1)
		go func(src, dst *model.Device) {
			defer wg.Done()
			ok := sendDatagrams(ctx, env, src.ID, datagramProbe{
				srcAddr: addrOf[src.ID],
				dstAddr: addrOf[dst.ID],
				port:    ports[dst.ID],
			})
			if !ok {
				mu.Lock()
				unsent[src.ID+"\x00"+dst.ID] = true
				mu.Unlock()
			}
		}(src, dst)
	}
	wg.Wait()
	after := udpCounters(ctx, env, hosts)
	seen := readTaps(ctx, env, taps)
	for i, src := range hosts {
		dst := hosts[(i+k)%n]
		b, okB := before[dst.ID]
		a, okA := after[dst.ID]
		frames, live := seen[dst.ID].counts, seen[dst.ID].live
		got := arrival{
			tapped: frames.udp, tapLive: live,
			counted: offBoxDelta(b, a), counterOK: okB && okA,
		}
		if !got.attributable() || got.arrived() {
			continue
		}
		// Nothing left the sender, so nothing can be concluded about the
		// path between them.
		if unsent[src.ID+"\x00"+dst.ID] {
			continue
		}
		out[src.ID+"\x00"+dst.ID] = fmt.Sprintf(
			"a datagram from %s to %s (%s) never arrived -- %s -- though pings and "+
				"connections do: something on the path is filtering by protocol",
			src.Name, dst.Name, addrOf[dst.ID], got.why())
	}
	return out
}

// udpCounters reads every host's count of datagrams delivered for an unbound
// port, at once.
func udpCounters(ctx context.Context, env *Env, hosts []*model.Device) map[string]counterWitness {
	out := map[string]counterWitness{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(h *model.Device) {
			defer wg.Done()
			if n, ok := udpNoPortsV4(ctx, env, h.ID); ok {
				mu.Lock()
				out[h.ID] = n
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return out
}

// arrivedFromOffBox is how many ICMP echo requests reached a host from
// somewhere other than itself, between two readings of its counters.
//
// Loopback packets are counted both as echo requests and on the loopback
// device, so subtracting the one from the other leaves arrivals the host
// cannot have generated. Traffic the host sends to other machines does not
// enter either count, which matters because the hosts are probe sources as
// well as probe destinations.
func arrivedFromOffBox(before, after hostTraffic) int {
	n := (after.echoes - before.echoes) - (after.loopRx - before.loopRx)
	if n < 0 {
		return 0
	}
	return n
}

// hostTraffic is what a host's own kernel says was delivered to it.
type hostTraffic struct {
	echoes int // ICMP echo requests delivered, wherever they came from
	loopRx int // packets delivered over the loopback device
}

// receivedEchoes reads, per host, the kernel's count of ICMP echo requests
// delivered to it and of packets delivered over its loopback device.
//
// The echo counter on its own is not a witness that anything arrived from the
// network. It counts every echo request the kernel took delivery of, and a
// ping to 127.0.0.1 raises it exactly as much as a ping from another machine,
// so answering for a host elsewhere and leaving `ping 127.0.0.1` running on it
// made the counter climb while nothing addressed to it ever got there.
//
// A loopback packet is counted a second time, on the loopback device, and a
// probe sent by the grader never touches that device. The difference between
// the two counts is therefore a number of echo requests that cannot have come
// from the host itself. Other loopback traffic subtracts from it as well, so
// it is a lower bound rather than an exact count -- which is the direction to
// err in, since it can fail to credit an arrival but never invent one.
func receivedEchoes(ctx context.Context, env *Env, hosts []*model.Device) map[string]hostTraffic {
	out := map[string]hostTraffic{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, h := range hosts {
		wg.Add(1)
		go func(h *model.Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := env.Probe(ctx, h.ID, []string{"cat", "/proc/net/snmp", "/proc/net/dev"})
			if err != nil || res.ExitCode != 0 {
				return
			}
			if n, ok := icmpInEchos(res.Stdout); ok {
				mu.Lock()
				out[h.ID] = hostTraffic{echoes: n, loopRx: loopbackRx(res.Stdout)}
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return out
}

// loopbackRx pulls the loopback device's received packet count out of
// /proc/net/dev, whose columns are bytes first and packets second.
func loopbackRx(body string) int {
	for _, line := range strings.Split(body, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			return 0
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// icmpInEchos pulls InEchos out of /proc/net/snmp, by name rather than by
// column: the set of counters differs between kernels, and counting fields
// would read a different one on a different machine.
func icmpInEchos(body string) (int, bool) {
	return snmpCounter(body, "Icmp:", "InEchos")
}

// snmpCounter reads one named counter out of /proc/net/snmp, which prints a
// row of names and then a row of values.
//
// By name, never by position: the columns differ between kernels, and reading
// the wrong one is a number that looks plausible and means something else.
func snmpCounter(body, section, field string) (int, bool) {
	lines := strings.Split(body, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], section) || !strings.HasPrefix(lines[i+1], section) {
			continue
		}
		names := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		for j, n := range names {
			if n == field && j < len(values) {
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
	// A traceroute that did not run is not a destination that did not answer.
	// Being unable to reach the far side exits zero and prints "!N" or "*",
	// so a non-zero exit means the measurement was never made -- and reading
	// it as zero hops reported a host as unreachable on no evidence at all.
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("traceroute on %s exited %d: %s",
			src.Name, res.ExitCode, firstLine(res.Stderr))
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
	if res.ExitCode != 0 {
		return 0, "", fmt.Errorf("traceroute on %s exited %d: %s",
			src.Name, res.ExitCode, firstLine(res.Stderr))
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
	res, err := env.Observe(ctx, d.ID, []string{"sh", "-c",
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
	res, err := env.Observe(ctx, d.ID, []string{"sh", "-c",
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
