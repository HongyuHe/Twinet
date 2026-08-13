package cli

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/HongyuHe/twinet/internal/model"
)

// Addresses the assignment lets a group choose.
//
// The COS-461 text leaves the inter-AS peering addresses to be agreed between
// neighbouring groups. Twinet plans them, and until now graded against its plan:
// the other end of every session is a rendered reference expecting the planned
// address, so a group that agreed something else with their neighbour could not
// bring the session up at all and lost the marks for every question that
// depends on it. That is a submission marked wrong for an answer the assignment
// permits.
//
// So the neighbours are adapted to the submission instead. For each inter-AS
// link of the system being graded, whatever address the group actually
// configured is read off their interface; if it is not the planned one, the
// reference on the other side is given an address in the same subnet and a
// session to theirs, built by copying its own configuration for the planned
// address with the address substituted -- so the relationship, the policy and
// the route-maps are exactly what the reference would have used.
//
// Everything is undone after the wave, because the next submission is graded
// against the reference as the manifest describes it.

// peerAdaptation is one neighbour's end of one link, adapted.
type peerAdaptation struct {
	Device  string // the reference device that was changed
	Iface   string
	Added   string // the address it was given
	Session string // the neighbour address it was told to peer with
	Because string // what the student did that required it
}

// adaptNeighbours makes the reference side of every inter-AS link match the
// addresses a submission actually used.
//
// It returns what it changed, and an undo. Failure to adapt one link is
// reported rather than fatal: the group loses that session, which is the same
// outcome as before, and the rest of the wave still runs.
func adaptNeighbours(ctx context.Context, exec execFn, top *model.Topology, as int) (
	[]peerAdaptation, func(context.Context) error, []string) {

	var done []peerAdaptation
	var problems []string

	for _, l := range top.Links {
		if l.A == nil || l.B == nil || l.A.Device == nil || l.B.Device == nil {
			continue
		}
		var mine, theirs *model.Iface
		switch {
		case l.A.Device.ASN == as && l.B.Device.ASN != as:
			mine, theirs = l.A, l.B
		case l.B.Device.ASN == as && l.A.Device.ASN != as:
			mine, theirs = l.B, l.A
		default:
			continue
		}
		if mine.Owner == model.OwnerPlatform || mine.Name == "" || theirs.Addr4 == "" {
			continue
		}
		// An exchange is a shared segment with a route server; its addressing
		// is the exchange's, not a bilateral agreement, so it is left alone.
		if mine.Role == model.RoleIXPLink || l.Segment != "" {
			continue
		}

		chosen, err := ifaceAddr4(ctx, exec, model.DeviceID(as, mine.Device.Name), mine.Name)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", mine.Device.ID, err))
			continue
		}
		if chosen == "" {
			// Nothing configured: that is the group's own answer, and the
			// reference stays as it is.
			continue
		}
		if planned, err := netip.ParsePrefix(mine.Addr4); err == nil {
			if got, err := netip.ParsePrefix(chosen); err == nil && got == planned {
				continue // they used the planned address
			}
		}

		ad, err := adaptOnePeer(ctx, exec, theirs, mine.Addr4, chosen)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", theirs.Device.ID, err))
			continue
		}
		ad.Because = fmt.Sprintf("AS %d configured %s on %s instead of the planned %s",
			as, chosen, mine.Name, mine.Addr4)
		done = append(done, ad)
	}

	undo := func(ctx context.Context) error {
		var errs []string
		for _, ad := range done {
			if err := undoOnePeer(ctx, exec, ad); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("%s", strings.Join(errs, "; "))
		}
		return nil
	}
	sort.Slice(done, func(i, j int) bool { return done[i].Device < done[j].Device })
	return done, undo, problems
}

// adaptOnePeer gives the reference end of a link an address in the subnet the
// student chose and a session to the address they configured.
func adaptOnePeer(ctx context.Context, exec execFn, peer *model.Iface,
	plannedTheirs, chosen string) (peerAdaptation, error) {

	var ad peerAdaptation
	their, err := netip.ParsePrefix(chosen)
	if err != nil {
		return ad, fmt.Errorf("%q is not an address", chosen)
	}
	planned, err := netip.ParsePrefix(peer.Addr4)
	if err != nil {
		return ad, fmt.Errorf("the reference side has no planned address")
	}
	// The reference keeps the host part it was given where that fits, so the
	// two ends stay recognisable; otherwise it takes the next address after
	// the student's, which is inside the subnet by construction.
	mine := netip.PrefixFrom(planned.Addr(), their.Bits())
	if !their.Contains(planned.Addr()) || planned.Addr() == their.Addr() {
		next := their.Addr().Next()
		if next == their.Addr() || !their.Contains(next) {
			return ad, fmt.Errorf("no address is left in %s for the other end", their)
		}
		if next == their.Addr() {
			next = next.Next()
		}
		mine = netip.PrefixFrom(next, their.Bits())
	}

	dev := peer.Device.ID
	// The reference's own configuration for the planned session is copied with
	// the address substituted, so the relationship, policies and route-maps are
	// exactly what it would have used. Writing them out here instead would
	// duplicate the renderer, and the copy cannot drift from it.
	was, err := netip.ParsePrefix(plannedTheirs)
	if err != nil {
		return ad, fmt.Errorf("the planned address of the other end is not an address")
	}
	body, err := neighbourBlock(ctx, exec, dev, was.Addr().String())
	if err != nil {
		return ad, err
	}
	if body == "" {
		return ad, fmt.Errorf("no configuration for the planned neighbour %s to copy",
			was.Addr())
	}
	lines := []string{
		fmt.Sprintf("ip addr replace %s brd + dev %s", mine, peer.Name),
	}
	res, err := exec(ctx, dev, []string{"sh", "-c", strings.Join(lines, "\n")})
	if err != nil {
		return ad, err
	}
	if res.ExitCode != 0 {
		return ad, fmt.Errorf("addressing %s: %s", peer.Name, firstLine(res.Stderr+res.Stdout))
	}

	cfg := strings.ReplaceAll(body, was.Addr().String(), their.Addr().String())
	if err := vtyshConfigure(ctx, exec, dev, cfg); err != nil {
		return ad, err
	}
	return peerAdaptation{
		Device: dev, Iface: peer.Name, Added: mine.String(), Session: their.Addr().String(),
	}, nil
}

// undoOnePeer removes what adaptOnePeer added.
func undoOnePeer(ctx context.Context, exec execFn, ad peerAdaptation) error {
	if err := vtyshConfigure(ctx, exec, ad.Device, fmt.Sprintf(
		"router bgp %s\n no neighbor %s\nexit", asnOfDevice(ad.Device), ad.Session)); err != nil {
		return err
	}
	res, err := exec(ctx, ad.Device, []string{"sh", "-c",
		fmt.Sprintf("ip addr del %s dev %s 2>/dev/null; exit 0", ad.Added, ad.Iface)})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: removing %s: %s", ad.Device, ad.Added, firstLine(res.Stderr))
	}
	return nil
}

// neighbourBlock returns every configuration line of a router that mentions one
// neighbour address, in the order and nesting vtysh will accept back.
func neighbourBlock(ctx context.Context, exec execFn, device, addr string) (string, error) {
	res, err := exec(ctx, device, []string{"vtysh", "-c", "show running-config"})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: reading the configuration: %s", device, firstLine(res.Stderr))
	}
	var out []string
	var section string
	var inAF bool
	for _, line := range strings.Split(res.Stdout, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "router bgp "):
			section = t
			inAF = false
			continue
		case strings.HasPrefix(t, "address-family "):
			inAF = true
			continue
		case t == "exit-address-family":
			inAF = false
			continue
		case t == "exit" || t == "!":
			continue
		}
		if section == "" || !strings.Contains(t, addr) {
			continue
		}
		if inAF {
			out = append(out, "  "+t)
		} else {
			out = append(out, " "+t)
		}
	}
	if len(out) == 0 {
		return "", nil
	}
	// Rebuild the nesting: the neighbour statement first, then the
	// address-family lines, which is the order vtysh requires.
	var top, af []string
	for _, l := range out {
		if strings.HasPrefix(l, "  ") {
			af = append(af, l)
		} else {
			top = append(top, l)
		}
	}
	body := section + "\n" + strings.Join(top, "\n")
	if len(af) > 0 {
		body += "\n address-family ipv4 unicast\n" + strings.Join(af, "\n") +
			"\n exit-address-family"
	}
	return body + "\nexit", nil
}

// vtyshConfigure feeds configuration to a router and reports what it rejected.
func vtyshConfigure(ctx context.Context, exec execFn, device, body string) error {
	script := "vtysh -c 'configure terminal' " +
		strings.Join(quotedLines(body), " ")
	res, err := exec(ctx, device, []string{"sh", "-c", script})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 || strings.Contains(res.Stdout, "% ") {
		return fmt.Errorf("%s: %s", device, firstLine(res.Stdout+res.Stderr))
	}
	return nil
}

func quotedLines(body string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, "-c "+shellQuote(l))
	}
	return out
}

// ifaceAddr4 reads the address a device actually has on an interface.
func ifaceAddr4(ctx context.Context, exec execFn, device, iface string) (string, error) {
	res, err := exec(ctx, device, []string{"sh", "-c",
		fmt.Sprintf("ip -o -4 addr show dev %s scope global 2>/dev/null | awk '{print $4}' | head -1", iface)})
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("reading %s: %s", iface, firstLine(res.Stderr))
	}
	return strings.TrimSpace(res.Stdout), nil
}

// asnOfDevice reads the AS number back out of a device identifier.
func asnOfDevice(id string) string {
	if i := strings.Index(id, "/"); i > 2 && strings.HasPrefix(id, "as") {
		return id[2:i]
	}
	return ""
}
