package grade

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HongyuHe/twinet/internal/mcast"
	"github.com/HongyuHe/twinet/internal/model"
)

// Checks for the advanced-networks course's multicast exercise.
//
// The exercise asks for PIM sparse mode on every interface, IGMP where the
// hosts are, and one rendezvous point for a group range. It would be easy, and
// wrong, to grade that by reading the configuration back: a student who typed
// the commands on the wrong interfaces, or pointed the routers at a rendezvous
// point that is not reachable, has a configuration that looks right and a
// network where nothing is delivered.
//
// So the delivery check does what the exercise's last section does. It joins a
// group on one host, sends to that group from another, and requires the packets
// to arrive -- and then reads the multicast forwarding tables of the routers
// along the way, because a packet that arrived by flooding is not multicast.

func init() {
	Register(&Check{
		Name:     "multicast.pim_enabled",
		Describe: "PIM runs on every router interface, and IGMP on the host-facing ones",
		Run:      checkPIMEnabled,
	})
	Register(&Check{
		Name:     "multicast.rendezvous_point",
		Describe: "every router agrees on the rendezvous point for the group range",
		Run:      checkRendezvousPoint,
	})
	Register(&Check{
		Name:     "multicast.delivery",
		Describe: "a packet sent to a joined group reaches the host that joined it, over a tree",
		Run:      checkMulticastDelivery,
	})
	Register(&Check{
		Name:     "multicast.no_flooding",
		Describe: "a host that did not join the group does not receive it",
		Run:      checkMulticastNoFlooding,
	})
}

// pimInterfaces reads the interfaces PIM is running on, with the number of
// neighbours each has formed.
//
// The count is the point. `ip pim passive` puts an interface in this table with
// state up and never sends or accepts a hello on it, so a router configured
// that way on every transit port has a perfect-looking PIM configuration and no
// adjacencies at all -- one site of the exercise was disconnected exactly that
// way with all four marks still awarded. A transit interface with no PIM
// neighbour is not running PIM in any sense the exercise means.
func pimInterfaces(ctx context.Context, env *Env, router string) (map[string]int, error) {
	var raw map[string]any
	if err := env.VtyshJSON(ctx, router, "show ip pim interface json", &raw); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for k, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if st, ok := m["state"].(string); ok && !strings.EqualFold(st, "up") {
			continue
		}
		n := 0
		if f, ok := m["pimNeighbors"].(float64); ok {
			n = int(f)
		}
		out[k] = n
	}
	return out, nil
}

// igmpInterfaces reads the interfaces IGMP is running on.
func igmpInterfaces(ctx context.Context, env *Env, router string) (map[string]bool, error) {
	var raw map[string]any
	if err := env.VtyshJSON(ctx, router, "show ip igmp interface json", &raw); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// FRR lists every PIM interface here, with state "mtrc" where IGMP is
		// not actually enabled. Grading on presence alone would pass a student
		// who enabled PIM and never touched IGMP -- which is half the exercise.
		if s, ok := m["state"].(string); ok && !strings.EqualFold(s, "up") {
			continue
		}
		out[k] = true
	}
	return out, nil
}

// wantsPIM reports the interfaces of a router the exercise asks for.
//
// The loopback is included. It used to be skipped, and the check went on
// reporting "PIM is up on every interface of all 6 routers" while PIM had been
// removed from every one of them -- a claim about a set the check had excluded
// from itself. It is not a formality either: the rendezvous point is addressed
// by its loopback precisely so that it survives a link going down, and a
// loopback without PIM is a rendezvous point that cannot register a source.
func wantsPIM(d *model.Device) (all, hostFacing []string) {
	for _, i := range d.Ifaces {
		if i.Name == "" {
			continue
		}
		all = append(all, i.Name)
		switch i.Role {
		case model.RoleHostLink, model.RoleL2Access, model.RoleL2Trunk:
			hostFacing = append(hostFacing, i.Name)
		}
	}
	sort.Strings(all)
	sort.Strings(hostFacing)
	return all, hostFacing
}

func checkPIMEnabled(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || !as.Multicast.Enabled {
		return Errored("multicast.pim_enabled",
			fmt.Errorf("AS %d does not declare the multicast exercise", env.AS))
	}
	var missingPIM, missingIGMP, unreadable []string
	routers, checked := env.Routers(), 0
	for _, r := range routers {
		want, hostIfaces := wantsPIM(r)
		got, err := pimInterfaces(ctx, env, r.Name)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		checked++
		hostFacing := map[string]bool{}
		for _, n := range hostIfaces {
			hostFacing[n] = true
		}
		for _, name := range want {
			n, present := got[name]
			switch {
			case !present:
				missingPIM = append(missingPIM, r.Name+"/"+name)
			case name == "lo":
				// A loopback has no neighbour and is not meant to: it is
				// there so the rendezvous point has an address that outlives
				// any one link. Running PIM on it is the requirement; having
				// somebody on the other end is not.
			case !hostFacing[name] && n == 0:
				// A link between two routers with PIM on both ends has a
				// neighbour. None means one end is passive, or is not
				// running PIM at all.
				missingPIM = append(missingPIM,
					fmt.Sprintf("%s/%s (no PIM neighbour)", r.Name, name))
			}
		}
		if len(hostIfaces) == 0 {
			continue
		}
		ig, err := igmpInterfaces(ctx, env, r.Name)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		for _, name := range hostIfaces {
			if !ig[name] {
				missingIGMP = append(missingIGMP, r.Name+"/"+name)
			}
		}
	}
	// A router that could not be read has not been assessed, and a verdict that
	// covers only the routers that answered is not a verdict about the system.
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return Errored("multicast.pim_enabled", fmt.Errorf(
			"%d of %d router(s) could not be read: %s",
			len(unreadable), len(routers), strings.Join(truncate(unreadable, 3), "; ")))
	}
	if checked == 0 {
		return Errored("multicast.pim_enabled", fmt.Errorf("AS %d has no routers", env.AS))
	}
	sort.Strings(missingPIM)
	sort.Strings(missingIGMP)
	switch {
	case len(missingPIM) == 0 && len(missingIGMP) == 0:
		return Pass("multicast.pim_enabled", Evidence{
			Observed: fmt.Sprintf("PIM is up on every interface of all %d routers, and IGMP "+
				"on every host-facing one", checked)})
	case len(missingPIM) > 0 && len(missingIGMP) > 0:
		return Fail("multicast.pim_enabled", Evidence{
			Expected: "ip pim on every interface, ip igmp on the host-facing ones",
			Observed: fmt.Sprintf("%d interface(s) without PIM and %d without IGMP",
				len(missingPIM), len(missingIGMP)),
			Detail: strings.Join(truncate(append(append([]string{}, missingPIM...),
				missingIGMP...), 8), "\n"),
			Hint:    "PIM goes on all of them, including the ones facing hosts; IGMP only on those",
			Command: "show ip pim interface; show ip igmp interface",
		})
	case len(missingPIM) > 0:
		return Partial("multicast.pim_enabled", 0.5, Evidence{
			Expected: "ip pim on every interface",
			Observed: fmt.Sprintf("%d interface(s) are not running PIM", len(missingPIM)),
			Detail:   strings.Join(truncate(missingPIM, 8), "\n"),
			Command:  "show ip pim interface",
		})
	default:
		return Partial("multicast.pim_enabled", 0.5, Evidence{
			Expected: "ip igmp on every host-facing interface",
			Observed: fmt.Sprintf("%d host-facing interface(s) are not running IGMP",
				len(missingIGMP)),
			Detail: strings.Join(truncate(missingIGMP, 8), "\n"),
			Hint: "without IGMP the router never learns that its host wants the group, " +
				"so nothing is ever delivered to it",
			Command: "show ip igmp interface",
		})
	}
}

// rangeSplit reports a mapping that carves part of the declared group range
// off to a different rendezvous point, or "" if none does.
func rangeSplit(out, groups, want string) string {
	declared, err := netip.ParsePrefix(groups)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[1], "/") {
			continue
		}
		pfx, err := netip.ParsePrefix(f[1])
		if err != nil || f[0] == want {
			continue
		}
		// Inside the declared range and pointing somewhere else.
		if declared.Overlaps(pfx) && pfx.Bits() >= declared.Bits() {
			return fmt.Sprintf("%s of the declared range %s is sent to %s, not %s",
				pfx, groups, f[0], want)
		}
	}
	return ""
}

func checkRendezvousPoint(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || !as.Multicast.Enabled {
		return Errored("multicast.rendezvous_point",
			fmt.Errorf("AS %d does not declare the multicast exercise", env.AS))
	}
	want := rpAddress(as)
	if want == "" {
		return Errored("multicast.rendezvous_point",
			fmt.Errorf("the lab declares %q as the rendezvous point but it has no loopback",
				as.Multicast.RP))
	}
	// The group the rest of the exercise sends to: whatever mapping covers it
	// is the one that decides where the tree is rooted.
	testAddr, terr := netip.ParseAddr(as.Multicast.TestGroup)
	if terr != nil {
		return Errored("multicast.rendezvous_point", fmt.Errorf(
			"the lab declares %q as its test group, which is not an address: %w",
			as.Multicast.TestGroup, terr))
	}

	var wrong, unreadable []string
	agreed := 0
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show ip pim rp-info")
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		// The mapping that would actually be used for the group under test.
		//
		// This compared the group range exactly, so any other mapping was
		// ignored -- and PIM does not ignore them: it takes the most specific
		// prefix covering the group. Adding `ip pim rp <someone else>
		// 237.0.0.10/32` alongside the declared /24 pointed the tested group
		// at a different router on every one of the six, and the check went on
		// reporting that they all agreed. The rule PIM uses is the rule read
		// here.
		found, foundBits := "", -1
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || !strings.Contains(f[1], "/") {
				continue
			}
			pfx, err := netip.ParsePrefix(f[1])
			if err != nil {
				continue
			}
			if !pfx.Contains(testAddr) || pfx.Bits() <= foundBits {
				continue
			}
			found, foundBits = f[0], pfx.Bits()
		}
		// And the rest of the range, not only the address under test.
		//
		// The tested group is one address of the declared range, and PIM takes
		// the most specific mapping for each group separately: `ip pim rp
		// <somewhere unreachable> 237.0.0.128/25` leaves the tested address
		// alone and takes half the range with it, which was worth nothing.
		// Anything more specific than the declared range, pointing somewhere
		// else, is part of that range going to the wrong root.
		if split := rangeSplit(out, as.Multicast.Groups, want); split != "" {
			wrong = append(wrong, fmt.Sprintf("%s: %s", r.Name, split))
			continue
		}
		switch found {
		case want:
			agreed++
		case "":
			wrong = append(wrong, fmt.Sprintf("%s has no rendezvous point covering %s",
				r.Name, as.Multicast.TestGroup))
		default:
			wrong = append(wrong, fmt.Sprintf("%s sends %s to %s, not %s (the most specific "+
				"mapping covering it wins, whatever the declared range says)",
				r.Name, as.Multicast.TestGroup, found, want))
		}
	}
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		return Errored("multicast.rendezvous_point", fmt.Errorf(
			"%d router(s) could not be read: %s",
			len(unreadable), strings.Join(truncate(unreadable, 3), "; ")))
	}
	if len(wrong) == 0 && agreed > 0 {
		return Pass("multicast.rendezvous_point", Evidence{
			Observed: fmt.Sprintf("all %d routers use %s as the rendezvous point for %s",
				agreed, want, as.Multicast.Groups)})
	}
	sort.Strings(wrong)
	return Partial("multicast.rendezvous_point", ratio(agreed, agreed+len(wrong)), Evidence{
		Expected: fmt.Sprintf("every router pointing at %s for %s", want, as.Multicast.Groups),
		Observed: fmt.Sprintf("%d of %d routers agree", agreed, agreed+len(wrong)),
		Detail:   strings.Join(truncate(wrong, 6), "\n"),
		Hint: "the rendezvous point is addressed by its loopback so it survives a link " +
			"going down while another path to it is up",
		Command: "show ip pim rp-info",
	})
}

// rpAddress is the loopback address of the declared rendezvous point.
func rpAddress(as *model.AS) string {
	for _, r := range as.Routers {
		if r.Name != as.Multicast.RP {
			continue
		}
		if lo, ok := r.IfaceByName("lo"); ok && lo.Addr4 != "" {
			return strings.SplitN(lo.Addr4, "/", 2)[0]
		}
	}
	return ""
}

// hostsOf returns the hosts of the AS under test, with the interface each one
// faces its router on.
func hostsOf(env *Env) []*model.Device {
	var out []*model.Device
	as, ok := env.Topology.ASes[env.AS]
	if !ok {
		return nil
	}
	for _, d := range as.Devices {
		if d.Kind == model.KindHost {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// hostIface is the name of a host's interface towards its router.
func hostIface(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Name != "lo" && i.Name != "" {
			return i.Name
		}
	}
	return ""
}

// seen is what one host observed on the group during a run.
//
// The counts are kept apart because they answer different questions. Delivery
// is `arrived`, and only that: a packet the host's own stack looped back to it
// is this host talking to itself, which is what `looped` counts, and a host
// whose site receives nothing can produce as many of those as it likes.
type seen struct {
	joined    bool
	reported  bool // the host said what it saw, rather than never saying
	arrived   int  // packets of this run's, off the wire
	looped    int  // packets of this run's, generated on this host
	foreign   int  // packets on the group this run did not send
	elsewhere int  // packets on the group carrying some other source address
	sources   []string
	raw       string
}

// mcastReport turns what a host reported into what it means for this run.
//
// The host is not asked to decide. It says what it saw -- a digest, a source
// and where the kernel says each packet came from -- and the matching against
// what was sent happens here, because only here is it known what was sent.
func mcastReport(out string, want map[string]bool) seen {
	s := seen{raw: strings.TrimSpace(out)}
	srcs := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 2 && f[0] == "twinet-mcast":
			for _, kv := range f[1:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					continue
				}
				switch k {
				case "joined":
					s.joined = v == "true"
					// The summary line is printed once the run finishes, so
					// its presence is what separates a host that watched the
					// wire and saw nothing from one that never watched.
					s.reported = true
				case "elsewhere":
					// Packets on the group carrying a source other than the
					// one this run sent from. The host is told about them
					// because a submission generating its own traffic on the
					// group is the commonest reason a site sees something and
					// still has no tree.
					n, err := strconv.Atoi(v)
					if err == nil {
						s.elsewhere = n
					}
				}
			}
		case len(f) == 4 && f[0] == "packet":
			if !want[f[1]] {
				s.foreign++
				continue
			}
			if f[3] == "outgoing" || f[3] == "loopback" {
				s.looped++
				continue
			}
			s.arrived++
			srcs[f[2]] = true
		}
	}
	for k := range srcs {
		s.sources = append(s.sources, k)
	}
	sort.Strings(s.sources)
	return s
}

// receiveOn joins a group on a host and reports what arrived.
//
// The join and the observation happen in one process on purpose: a socket that
// has joined the group is what makes the host send an IGMP report, and closing
// it is what makes it leave. Doing them separately -- join with one tool,
// listen with another -- leaves the membership behind after the check and
// changes the next one's result.
func receiveOn(ctx context.Context, env *Env, host *model.Device, group, from string,
	seconds int) (string, error) {

	iface := hostIface(host)
	if iface == "" {
		return "", fmt.Errorf("%s has no interface to join on", host.Name)
	}
	res, err := env.Probe(ctx, host.ID, []string{"twinet-mcast", "-recv",
		"-group", group, "-iface", iface, "-from", from,
		"-seconds", fmt.Sprint(seconds)})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s could not listen on %s: %s", host.Name, group,
			firstLine(res.Stderr+res.Stdout))
	}
	return res.Stdout + res.Stderr, nil
}

// lastHop is the router a host's packets reach first, and the name of the
// interface on that router facing it.
//
// That interface is what has to appear in the router's outgoing interface list
// for the group: it is the one thing about delivery that is the network's doing
// and not the host's, so it is what tells a tree that reaches the site from a
// host that arranged to see packets some other way.
func lastHop(h *model.Device) (*model.Device, string) {
	for _, i := range h.Ifaces {
		if i.Link == nil {
			continue
		}
		other := i.Link.A
		if other == i {
			other = i.Link.B
		}
		if other == nil || other.Device == nil {
			continue
		}
		switch other.Device.Kind {
		case model.KindRouter:
			return other.Device, other.Name
		case model.KindSwitch:
			// A host behind a switch still has a router on the segment; the
			// interface that matters is the router's, not the switch's.
			if r, name := routerOnSegment(other.Device, h); r != nil {
				return r, name
			}
		}
	}
	return nil, ""
}

// routerOnSegment finds the router attached to a switch, skipping the host that
// asked.
func routerOnSegment(sw *model.Device, skip *model.Device) (*model.Device, string) {
	for _, i := range sw.Ifaces {
		if i.Link == nil {
			continue
		}
		other := i.Link.A
		if other == i {
			other = i.Link.B
		}
		if other == nil || other.Device == nil || other.Device == skip {
			continue
		}
		if other.Device.Kind == model.KindRouter {
			return other.Device, other.Name
		}
	}
	return nil, ""
}

// tree is what one router holds for the group while the traffic is flowing.
type tree struct {
	carriesSource bool
	oil           map[string]bool
}

// treeOn reads a router's multicast forwarding state for the group.
//
// Both entries are read. Whether the last-hop router forwards on the shared
// tree or has switched to the source's own is a matter of timing that the
// exercise does not ask about, and the outgoing interface list means the same
// thing either way: this router has been told, by IGMP, to put the group on
// that segment.
func treeOn(ctx context.Context, env *Env, router, group, src string) tree {
	var doc map[string]map[string]struct {
		OIL map[string]json.RawMessage `json:"oil"`
	}
	t := tree{oil: map[string]bool{}}
	if err := env.VtyshJSON(ctx, router, "show ip mroute json", &doc); err != nil {
		return t
	}
	for source, e := range doc[group] {
		if source == src {
			t.carriesSource = true
		}
		for name := range e.OIL {
			t.oil[name] = true
		}
	}
	return t
}

// sendTo sends a few packets to a group from a host, each carrying the tag this
// run drew.
func sendTo(ctx context.Context, env *Env, host *model.Device, group, tag string, n int) error {
	iface := hostIface(host)
	if iface == "" {
		return fmt.Errorf("%s has no interface to send from", host.Name)
	}
	// A time to live of one is the default and would never leave the segment,
	// which is the mistake the exercise warns about; the check must not make
	// it, or every submission fails for the grader's reason.
	res, err := env.Probe(ctx, host.ID, []string{"twinet-mcast", "-send",
		"-group", group, "-iface", iface, "-tag", tag,
		"-count", fmt.Sprint(n), "-ttl", "10"})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s could not send to %s: %s", host.Name, group,
			firstLine(res.Stderr+res.Stdout))
	}
	return nil
}

// multicastTag is the token stamped on the packets one run sends.
//
// Drawn when the check runs, and never published, so that a submission cannot
// arrange for anything else on the group to be counted as the grader's traffic.
func multicastTag() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		// Failing closed here would make grading depend on the kernel's
		// entropy pool; the clock is unpredictable enough to a configuration
		// written before the run.
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// hostAddr4 is the address a host's packets will carry, which is what the
// routers' forwarding state must name if the tree is the one being measured.
func hostAddr4(d *model.Device) string {
	for _, i := range d.Ifaces {
		if i.Name == "lo" || i.Addr4 == "" {
			continue
		}
		if ip, _, err := net.ParseCIDR(i.Addr4); err == nil {
			return ip.String()
		}
	}
	return ""
}

// multicastRun joins a group on several hosts at once, sends from another, and
// returns what each listener saw along with the forwarding state of the
// routers.
//
// Every site, not a fixed pair. Choosing the first and last host in name order
// tested one path through the topology and left the rest unmeasured: making one
// router passive on all of its transit interfaces disconnected a whole site
// while the pair this check happened to use went on working, and the exercise
// awarded all four marks. The listeners run concurrently because the tree is
// built once and shared -- measuring each site in turn would take six times as
// long and answer a different question, since a tree built for one receiver is
// not the tree built for six.
func multicastRun(ctx context.Context, env *Env, receivers []*model.Device,
	bystanders []*model.Device, src *model.Device, group string) (
	got map[string]seen, trees map[string]tree, err error) {

	tag := multicastTag()
	want := mcast.Digests(tag, multicastPackets)
	srcAddr := hostAddr4(src)
	if srcAddr == "" {
		return nil, nil, fmt.Errorf("%s has no address, so the tree its packets build "+
			"cannot be told from anyone else's", src.Name)
	}
	type result struct {
		name string
		out  string
		err  error
	}
	done := make(chan result, len(receivers)+len(bystanders))
	wantJoin := map[string]bool{}
	for _, h := range receivers {
		wantJoin[h.Name] = true
	}
	for _, h := range receivers {
		go func(h *model.Device) {
			out, err := receiveOn(ctx, env, h, group, srcAddr, 25)
			done <- result{h.Name, out, err}
		}(h)
	}
	// A host that does not join, watching the same segment. Anything it sees is
	// traffic nobody asked it to receive.
	for _, h := range bystanders {
		go func(h *model.Device) {
			iface := hostIface(h)
			res, err := env.Probe(ctx, h.ID, []string{"twinet-mcast", "-listen",
				"-group", group, "-iface", iface, "-from", srcAddr, "-seconds", "25"})
			if err != nil {
				done <- result{h.Name, "", err}
				return
			}
			if res.ExitCode != 0 {
				done <- result{h.Name, "", fmt.Errorf("%s could not watch %s: %s", h.Name,
					group, firstLine(res.Stderr+res.Stdout))}
				return
			}
			done <- result{h.Name, res.Stdout + res.Stderr, nil}
		}(h)
	}
	// The listeners have to be listening before the source starts, or the tree
	// is built after the packets have gone and nothing arrives for a reason
	// that has nothing to do with the submission.
	select {
	case <-time.After(8 * time.Second):
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	if err := sendTo(ctx, env, src, group, tag, multicastPackets); err != nil {
		return nil, nil, err
	}
	// Read the trees while the traffic is still flowing: multicast forwarding
	// state expires, so a table read after the sender stops is empty for a
	// correct submission. Only state naming this source counts: a host sending
	// to the group on its own segment creates an entry of its own, so "some
	// router has state for the group" is satisfied by every submission that
	// leaves a sender running anywhere.
	trees = map[string]tree{}
	for _, r := range env.Routers() {
		trees[r.Name] = treeOn(ctx, env, r.Name, group, srcAddr)
	}
	got = map[string]seen{}
	for i := 0; i < len(receivers)+len(bystanders); i++ {
		select {
		case res := <-done:
			if res.err != nil {
				return got, trees, res.err
			}
			got[res.name] = mcastReport(res.out, want)
		case <-ctx.Done():
			return got, trees, ctx.Err()
		}
	}
	// A host that never said what it saw is not a host that saw nothing.
	// Reading silence as an empty wire passed a submission whose bystander
	// listener did not run -- nothing was reported, so nothing had leaked --
	// and failed one whose receiver's did not. Neither is an observation, so
	// neither is graded: the question is held for review instead.
	for _, h := range append(append([]*model.Device{}, receivers...), bystanders...) {
		st := got[h.Name]
		switch {
		case !st.reported:
			return got, trees, fmt.Errorf(
				"%s never reported what reached it on %s, so what did is unknown",
				h.Name, group)
		case wantJoin[h.Name] && !st.joined:
			return got, trees, fmt.Errorf(
				"%s did not join %s, so its receiving nothing says nothing about the tree",
				h.Name, group)
		case !wantJoin[h.Name] && st.joined:
			return got, trees, fmt.Errorf(
				"%s joined %s, so its receiving something is not a leak", h.Name, group)
		}
	}
	return got, trees, nil
}

// multicastPackets is how many packets one run sends. Enough that a single lost
// one does not decide a mark, few enough that the run stays inside the window
// the listeners are open for.
const multicastPackets = 25

// cast is one round: who sends, who joins, and who merely listens.
type cast struct {
	src        *model.Device
	recv       []*model.Device
	bystanders []*model.Device
}

// deliveryCasts is who sends and who joins, over enough rounds that every host
// is a receiver in one of them.
//
// One round used to be enough by construction: every host but the source
// joined. The source was always the same host -- the last one, sorted -- so
// that host was never tested as a receiver, and a submission that blocked
// multicast to that one site kept full marks. Found by blocking the group at
// that host's own router with an iptables rule, which is a thing a student can
// do because a student has root in their containers.
//
// So the source moves. Two rounds, with the first and the last host taking a
// turn, and every host is a receiver in at least one of them.
func deliveryCasts(hosts []*model.Device) []cast {
	if len(hosts) < 2 {
		return nil
	}
	pick := func(srcIdx int) cast {
		c := cast{src: hosts[srcIdx]}
		for i, h := range hosts {
			if i != srcIdx {
				c.recv = append(c.recv, h)
			}
		}
		return c
	}
	return []cast{pick(len(hosts) - 1), pick(0)}
}

// floodingCasts is who sends, who joins and who listens without joining, over
// enough rounds that every host overhears at least once.
//
// The same defect in the other direction: the source and the one receiver were
// fixed, so those two hosts were never bystanders, and a submission that
// flooded to exactly them passed. The second round moves both.
func floodingCasts(hosts []*model.Device) []cast {
	if len(hosts) < 3 {
		return nil
	}
	n := len(hosts)
	build := func(srcIdx, recvIdx int) cast {
		c := cast{src: hosts[srcIdx], recv: []*model.Device{hosts[recvIdx]}}
		for i, h := range hosts {
			if i != srcIdx && i != recvIdx {
				c.bystanders = append(c.bystanders, h)
			}
		}
		return c
	}
	rounds := []cast{build(n-1, 0)}
	if n >= 4 {
		// A different source and a different receiver, so the two hosts left
		// out of the first round are listening in the second.
		rounds = append(rounds, build(1, 2))
	}
	return rounds
}

func checkMulticastDelivery(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || !as.Multicast.Enabled {
		return Errored("multicast.delivery",
			fmt.Errorf("AS %d does not declare the multicast exercise", env.AS))
	}
	group := as.Multicast.TestGroup
	if group == "" {
		return Errored("multicast.delivery", fmt.Errorf("the lab declares no test group"))
	}
	hosts := hostsOf(env)
	casts := deliveryCasts(hosts)
	if len(casts) == 0 {
		return Errored("multicast.delivery",
			fmt.Errorf("multicast needs at least two hosts; this AS has %d", len(hosts)))
	}

	var missed []string
	delivered, wanted := 0, 0
	forwarding := map[string]bool{}
	covered := map[string]bool{}
	var sources []string
	for _, c := range casts {
		got, trees, err := multicastRun(ctx, env, c.recv, nil, c.src, group)
		if err != nil {
			return Errored("multicast.delivery", err)
		}
		sources = append(sources, c.src.Name)
		for _, h := range c.recv {
			wanted++
			covered[h.Name] = true
			why, ok := deliveredTo(h, got[h.Name], trees, group, c.src)
			if ok {
				delivered++
				continue
			}
			missed = append(missed, why)
		}
		for name, t := range trees {
			if t.carriesSource {
				forwarding[name] = true
			}
		}
	}
	// Every host has to have been a receiver somewhere, or this is the old
	// check with more steps.
	var untested []string
	for _, h := range hosts {
		if !covered[h.Name] {
			untested = append(untested, h.Name)
		}
	}
	if len(untested) > 0 {
		sort.Strings(untested)
		return Errored("multicast.delivery", fmt.Errorf(
			"%d host(s) were never tested as receivers (%s), so no verdict covers them",
			len(untested), strings.Join(untested, ", ")))
	}
	var routers []string
	for name := range forwarding {
		routers = append(routers, name)
	}
	sort.Strings(routers)
	sort.Strings(missed)

	switch {
	case len(missed) == 0 && len(routers) >= 2:
		return Pass("multicast.delivery", Evidence{
			Observed: fmt.Sprintf("every one of the %d host(s) received %s as a receiver, "+
				"across %d source(s) (%s), over a tree through %s",
				len(covered), group, len(casts), strings.Join(sources, ", "),
				strings.Join(routers, ", "))})
	case len(missed) == 0:
		return Partial("multicast.delivery", 0.5, Evidence{
			Expected: "a multicast tree carrying the group from the source to every receiver",
			Observed: fmt.Sprintf("all %d delivery(s) arrived, but only %d router(s) have any "+
				"forwarding state for %s", delivered, len(routers), group),
			Detail: strings.Join(routers, ", "),
			Hint: "a packet that arrives with no tree behind it arrived by some other means; " +
				"check `show ip mroute` on the routers between the hosts",
			Command: "show ip mroute",
		})
	default:
		return Partial("multicast.delivery", ratio(delivered, wanted), Evidence{
			Expected: fmt.Sprintf("every host receiving %s, whoever is sending it", group),
			Observed: fmt.Sprintf("%d of %d delivery(s) got nothing", len(missed), wanted),
			Detail: strings.Join(append(truncate(missed, 6),
				"routers with forwarding state: "+strings.Join(routers, ", ")), "\n"),
			Hint: "the receiver joins with IGMP, its router tells the rendezvous point with " +
				"PIM, and the source's first packet builds the rest of the tree; a site that " +
				"gets nothing usually has a transit interface that is not forming a PIM " +
				"adjacency",
			Command: "show ip mroute; show ip pim state; show ip pim neighbor",
		})
	}
}

// deliveredTo says whether the network carried the source's packets to this
// host, and if not, what was seen instead.
//
// Two things have to hold, and neither is redundant. The packets have to have
// arrived on the wire, which is the host's own kernel reporting where each
// frame came from and is the only part a host cannot arrange for itself. And
// the router on the host's segment has to have been told, by IGMP, to put the
// group there -- which is the network's doing and not the host's, and is what
// separates a tree that reaches a site from a site that found some other way to
// see the traffic.
func deliveredTo(h *model.Device, s seen, trees map[string]tree, group string,
	src *model.Device) (string, bool) {

	switch {
	case s.arrived == 0 && s.looped > 0:
		return fmt.Sprintf("%s saw %d packet(s) of %s's on %s, but every one of them was "+
			"generated on the host itself rather than arriving on the wire",
			h.Name, s.looped, src.Name, group), false
	case s.arrived == 0 && s.elsewhere > 0:
		return fmt.Sprintf("%s never received %s sent by %s; %d packet(s) for the group did "+
			"reach it, but carrying somebody else's source address",
			h.Name, group, src.Name, s.elsewhere), false
	case s.arrived == 0:
		return fmt.Sprintf("%s never received %s sent by %s", h.Name, group, src.Name), false
	}
	r, iface := lastHop(h)
	if r == nil {
		// Nothing in the shipped labs reaches this, and a host with no router
		// on its segment cannot be graded on whether a tree reached it.
		return fmt.Sprintf("%s has no router on its segment, so what reached it "+
			"cannot be attributed to a tree", h.Name), false
	}
	if !trees[r.Name].oil[iface] {
		return fmt.Sprintf("%s saw %s's packets, but %s is not putting %s on %s: "+
			"the traffic reached the host without the tree being asked to deliver it",
			h.Name, src.Name, r.Name, group, iface), false
	}
	return "", true
}

func checkMulticastNoFlooding(ctx context.Context, env *Env) Result {
	as, ok := env.Topology.ASes[env.AS]
	if !ok || !as.Multicast.Enabled {
		return Errored("multicast.no_flooding",
			fmt.Errorf("AS %d does not declare the multicast exercise", env.AS))
	}
	group := as.Multicast.TestGroup
	hosts := hostsOf(env)
	if len(hosts) < 3 || group == "" {
		return Errored("multicast.no_flooding",
			fmt.Errorf("this check needs three hosts and a test group"))
	}
	casts := floodingCasts(hosts)
	if len(casts) == 0 {
		return Errored("multicast.no_flooding",
			fmt.Errorf("this check needs three hosts and a test group"))
	}

	var leaked []string
	listened, overheard := 0, map[string]bool{}
	var anyDelivered bool
	for _, c := range casts {
		got, _, err := multicastRun(ctx, env, c.recv, c.bystanders, c.src, group)
		if err != nil {
			return Errored("multicast.no_flooding", err)
		}
		if got[c.recv[0].Name].arrived == 0 {
			// Nothing was delivered at all, so there is nothing to have
			// leaked. That is the delivery question's failure, not this one,
			// and marking it twice would punish one mistake in two places.
			return Errored("multicast.no_flooding", fmt.Errorf(
				"nothing was delivered to %s from %s, so whether anybody else received it "+
					"says nothing", c.recv[0].Name, c.src.Name))
		}
		anyDelivered = true
		for _, h := range c.bystanders {
			listened++
			overheard[h.Name] = true
			if s := got[h.Name]; s.arrived > 0 {
				leaked = append(leaked, fmt.Sprintf("%s saw %d packet(s) of %s (sent by %s) "+
					"on its segment without joining it", h.Name, s.arrived, group, c.src.Name))
			}
		}
	}
	if !anyDelivered {
		return Errored("multicast.no_flooding",
			fmt.Errorf("nothing was delivered in any round, so nothing can have leaked"))
	}
	// Every host has to have listened without joining at least once. The
	// source and the receiver were fixed, so those two were never bystanders,
	// and a submission flooding to exactly them passed.
	var untested []string
	for _, h := range hosts {
		if !overheard[h.Name] {
			untested = append(untested, h.Name)
		}
	}
	if len(untested) > 0 {
		sort.Strings(untested)
		return Errored("multicast.no_flooding", fmt.Errorf(
			"%d host(s) never listened without joining (%s), so no verdict covers them",
			len(untested), strings.Join(untested, ", ")))
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		return Partial("multicast.no_flooding", ratio(listened-len(leaked), listened),
			Evidence{
				Expected: fmt.Sprintf("only hosts that joined %s receiving it", group),
				Observed: fmt.Sprintf("%d of %d listening host(s) that did not join received "+
					"it anyway", len(leaked), listened),
				Detail: strings.Join(truncate(leaked, 6), "\n"),
				Hint: "packets reaching a host that never asked for them means they are being " +
					"flooded rather than forwarded along a tree",
				Command: "show ip mroute",
			})
	}
	return Pass("multicast.no_flooding", Evidence{
		Observed: fmt.Sprintf("across %d round(s), every one of the %d host(s) listened for %s "+
			"without joining and received nothing", len(casts), len(overheard), group)})
}
