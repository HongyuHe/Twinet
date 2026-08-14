package grade

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

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
func wantsPIM(d *model.Device) (all, hostFacing []string) {
	for _, i := range d.Ifaces {
		if i.Name == "" || i.Name == "lo" {
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
	var wrong, unreadable []string
	agreed := 0
	for _, r := range env.Routers() {
		out, err := env.Vtysh(ctx, r.Name, "show ip pim rp-info")
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		found := ""
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || !strings.Contains(f[1], "/") {
				continue
			}
			// The group range must be the declared one; a rendezvous point for
			// some other range is not an answer to this question.
			if f[1] != as.Multicast.Groups {
				continue
			}
			found = f[0]
		}
		switch found {
		case want:
			agreed++
		case "":
			wrong = append(wrong, fmt.Sprintf("%s has no rendezvous point for %s",
				r.Name, as.Multicast.Groups))
		default:
			wrong = append(wrong, fmt.Sprintf("%s points at %s, not %s", r.Name, found, want))
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

// receiveOn joins a group on a host and reports what arrived.
//
// The join and the listen are the same operation: a socket that has joined the
// group is what makes the host send an IGMP report, and closing it is what
// makes it leave. Doing them separately -- join with one tool, listen with
// another -- leaves the membership behind after the check and changes the next
// one's result.
func receiveOn(ctx context.Context, env *Env, host *model.Device, group string,
	seconds int) (string, error) {

	iface := hostIface(host)
	if iface == "" {
		return "", fmt.Errorf("%s has no interface to join on", host.Name)
	}
	res, err := env.Probe(ctx, host.ID, []string{"twinet-mcast", "-recv",
		"-group", group, "-iface", iface, "-seconds", fmt.Sprint(seconds)})
	if err != nil {
		return "", err
	}
	return res.Stdout + res.Stderr, nil
}

// sendTo sends a few packets to a group from a host.
func sendTo(ctx context.Context, env *Env, host *model.Device, group string, n int) error {
	iface := hostIface(host)
	if iface == "" {
		return fmt.Errorf("%s has no interface to send from", host.Name)
	}
	// A time to live of one is the default and would never leave the segment,
	// which is the mistake the exercise warns about; the check must not make
	// it, or every submission fails for the grader's reason.
	res, err := env.Probe(ctx, host.ID, []string{"twinet-mcast", "-send",
		"-group", group, "-iface", iface, "-count", fmt.Sprint(n), "-ttl", "10"})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s could not send to %s: %s", host.Name, group,
			firstLine(res.Stderr+res.Stdout))
	}
	return nil
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
	got map[string]string, trees map[string]string, err error) {

	type result struct {
		name string
		out  string
		err  error
	}
	done := make(chan result, len(receivers)+len(bystanders))
	for _, h := range receivers {
		go func(h *model.Device) {
			out, err := receiveOn(ctx, env, h, group, 25)
			done <- result{h.Name, out, err}
		}(h)
	}
	// A host that does not join, listening on the same port. Anything it
	// receives is traffic nobody asked it to receive.
	for _, h := range bystanders {
		go func(h *model.Device) {
			iface := hostIface(h)
			res, err := env.Probe(ctx, h.ID, []string{"twinet-mcast", "-listen",
				"-group", group, "-iface", iface, "-seconds", "25"})
			if err != nil {
				done <- result{h.Name, "", err}
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
	if err := sendTo(ctx, env, src, group, 25); err != nil {
		return nil, nil, err
	}
	// Read the trees while the traffic is still flowing: multicast forwarding
	// state expires, so a table read after the sender stops is empty for a
	// correct submission.
	trees = map[string]string{}
	for _, r := range env.Routers() {
		if out, err := env.Vtysh(ctx, r.Name, "show ip mroute"); err == nil {
			trees[r.Name] = out
		}
	}
	got = map[string]string{}
	for i := 0; i < len(receivers)+len(bystanders); i++ {
		select {
		case res := <-done:
			if res.err != nil {
				return got, trees, res.err
			}
			got[res.name] = res.out
		case <-ctx.Done():
			return got, trees, ctx.Err()
		}
	}
	return got, trees, nil
}

// multicastCast is who sends, who joins and who merely listens.
//
// Every host but the source joins, and the source itself is the bystander: it
// is the one host guaranteed to see the traffic if anything is flooding, and
// making it the control costs no extra device. A topology with more hosts than
// routers would leave some out; there are none here, and the check says how
// many it covered.
func multicastCast(hosts []*model.Device) (src *model.Device, recv, bystanders []*model.Device) {
	if len(hosts) < 2 {
		return nil, nil, nil
	}
	src = hosts[len(hosts)-1]
	recv = append(recv, hosts[:len(hosts)-1]...)
	return src, recv, nil
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
	src, recv, _ := multicastCast(hosts)
	if src == nil {
		return Errored("multicast.delivery",
			fmt.Errorf("multicast needs at least two hosts; this AS has %d", len(hosts)))
	}

	got, trees, err := multicastRun(ctx, env, recv, nil, src, group)
	if err != nil {
		return Errored("multicast.delivery", err)
	}
	var missed []string
	delivered := 0
	for _, h := range recv {
		if strings.Contains(got[h.Name], "received") {
			delivered++
			continue
		}
		missed = append(missed, fmt.Sprintf("%s never received %s", h.Name, group))
	}
	var forwarding []string
	for name, out := range trees {
		if strings.Contains(out, group) {
			forwarding = append(forwarding, name)
		}
	}
	sort.Strings(forwarding)
	sort.Strings(missed)

	switch {
	case len(missed) == 0 && len(forwarding) >= 2:
		return Pass("multicast.delivery", Evidence{
			Observed: fmt.Sprintf("all %d receiver(s) got %s from %s, over a tree through %s",
				delivered, group, src.Name, strings.Join(forwarding, ", "))})
	case len(missed) == 0:
		return Partial("multicast.delivery", 0.5, Evidence{
			Expected: "a multicast tree carrying the group from the source to every receiver",
			Observed: fmt.Sprintf("all %d receiver(s) got %s, but only %d router(s) have any "+
				"forwarding state for it", delivered, group, len(forwarding)),
			Detail: strings.Join(forwarding, ", "),
			Hint: "a packet that arrives with no tree behind it arrived by some other means; " +
				"check `show ip mroute` on the routers between the hosts",
			Command: "show ip mroute",
		})
	default:
		return Partial("multicast.delivery", ratio(delivered, len(recv)), Evidence{
			Expected: fmt.Sprintf("every host receiving what %s sends to %s", src.Name, group),
			Observed: fmt.Sprintf("%d of %d receiver(s) got nothing", len(missed), len(recv)),
			Detail: strings.Join(append(truncate(missed, 6),
				"routers with forwarding state: "+strings.Join(forwarding, ", ")), "\n"),
			Hint: "the receiver joins with IGMP, its router tells the rendezvous point with " +
				"PIM, and the source's first packet builds the rest of the tree; a site that " +
				"gets nothing usually has a transit interface that is not forming a PIM " +
				"adjacency",
			Command: "show ip mroute; show ip pim state; show ip pim neighbor",
		})
	}
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
	// One receiver and every other host listening without joining, rather than
	// one fixed bystander. A submission that floods to five sites and not to
	// the one host this check happened to pick used to pass it.
	recv := hosts[0]
	src := hosts[len(hosts)-1]
	var bystanders []*model.Device
	bystanders = append(bystanders, hosts[1:len(hosts)-1]...)
	if len(bystanders) == 0 {
		return Errored("multicast.no_flooding",
			fmt.Errorf("every host is either the source or the receiver, so nothing is left "+
				"to overhear the group"))
	}

	got, _, err := multicastRun(ctx, env, []*model.Device{recv}, bystanders, src, group)
	if err != nil {
		return Errored("multicast.no_flooding", err)
	}
	if !strings.Contains(got[recv.Name], "received") {
		// Nothing was delivered at all, so there is nothing to have leaked.
		// That is the delivery question's failure, not this one, and marking it
		// twice would punish one mistake in two places.
		return Errored("multicast.no_flooding", fmt.Errorf(
			"nothing was delivered to %s, so whether anybody else received it says nothing",
			recv.Name))
	}
	var leaked []string
	for _, h := range bystanders {
		if strings.Contains(got[h.Name], "received") {
			leaked = append(leaked, fmt.Sprintf("%s received %s without joining it",
				h.Name, group))
		}
	}
	sort.Strings(leaked)
	if len(leaked) > 0 {
		return Partial("multicast.no_flooding", ratio(len(bystanders)-len(leaked), len(bystanders)),
			Evidence{
				Expected: fmt.Sprintf("only hosts that joined %s receiving it", group),
				Observed: fmt.Sprintf("%d of %d host(s) that did not join received it anyway",
					len(leaked), len(bystanders)),
				Detail: strings.Join(truncate(leaked, 6), "\n"),
				Hint: "packets reaching a host that never asked for them means they are being " +
					"flooded rather than forwarded along a tree",
				Command: "show ip mroute",
			})
	}
	return Pass("multicast.no_flooding", Evidence{
		Observed: fmt.Sprintf("%s received %s and all %d host(s) that did not join received "+
			"nothing", recv.Name, group, len(bystanders))})
}
