package fault

import (
	"context"
	"fmt"
	"strings"
)

// Faults of the provider network.
//
// VPN membership was listed as unimplementable while the lab had no L3VPN to
// break. It has one now, so the fault is built rather than excused.
//
// Its neighbour in NIKA's taxonomy, mpls_label_limit_exceeded, is not here, and
// the attempt to build it is worth recording. The label limit that matters is
// net.mpls.platform_labels, which is read-only inside a container -- the same
// limitation that already requires the agent to write the per-interface MPLS
// input flag from the namespace. FRR's own "mpls label global-block" was tried
// as a substitute and does not constrain what LDP has already distributed:
// narrowing it to two labels left the forwarding table untouched, and clearing
// every LDP neighbour to force re-allocation left it untouched again. A fault
// that configures something and changes nothing is worse than an absent one,
// so it stays absent and stays counted as a gap.

func init() {
	Register(&Fault{
		Name: "host_vpn_membership_missing", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom: "One site of a customer cannot reach the customer's other sites. Every " +
			"session is established, the provider's core is healthy, and the other sites " +
			"reach each other normally.",
		Describe: "A customer-facing interface is removed from its VPN routing table, so " +
			"that site's routes are neither imported nor exported.",

		// The interface is taken out of its table rather than shut down,
		// because the point of the fault is that everything looks up. A site
		// whose port is down is a five-second diagnosis; a site whose port is
		// up, whose BGP session is established, and whose routes go nowhere is
		// the failure this exercise is about.
		//
		// The binding is a kernel one -- FRR uses Linux VRF devices, and the
		// interface is enslaved to the VRF device rather than named in the
		// interface stanza -- so this is `ip link set nomaster`, not a
		// configuration line. Looking for it in the running configuration
		// finds nothing, which is how the first version of this fault refused
		// to inject on a router that was plainly carrying a VPN.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, vrf, err := vrfBoundIface(ctx, e, t)
			if err != nil {
				return nil, err
			}
			// The VPN's route distinguisher and route targets are recorded
			// before anything is touched, because taking the interface out of
			// the table makes FRR re-derive them and it does not derive what
			// was configured. Without this, resolving the fault leaves the
			// site advertised under a route target nobody imports: the
			// customer is still cut off, this router's own tables look
			// correct, and the lab no longer matches any recorded ground
			// truth. That is a worse state than the fault itself.
			rd, rts := vpnTargets(ctx, e, t, vrf)
			st := State{"iface": iface, "vrf": vrf, "rd": rd}
			for i, rt := range rts {
				st[fmt.Sprintf("rt%d", i)] = rt
			}
			if _, err := e.Run(ctx, t.DeviceID(),
				"ip", "link", "set", iface, "nomaster"); err != nil {
				return nil, err
			}
			return st, nil
		},

		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			// The symptom is that the table no longer reaches the site.
			// Checking that the link is out of the VRF would prove the command
			// ran; checking the routing table proves the site left the VPN.
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show ip route vrf "+s["vrf"])
				},
				func(o string) bool { return !strings.Contains(o, s["iface"]) })
			if err != nil {
				return Evidence{}, err
			}
			gone := !strings.Contains(out, s["iface"])
			return Evidence{
				Verified: gone,
				Expected: fmt.Sprintf("%s no longer appears in table %s, so the site "+
					"behind it is not in the VPN", s["iface"], s["vrf"]),
				Observed: firstLine(out),
			}, nil
		},

		// Putting the interface back is not enough to put the network back.
		//
		// While the port was out of the table this router withdrew the site's
		// prefix from VPNv4, and the other provider edge dropped it. Restoring
		// the binding makes this router learn the prefix again locally, but
		// nothing makes it re-originate what it withdrew, so the far edge
		// stays without a route and the customer's other site remains
		// unreachable -- with every session up and this router's own table
		// looking perfectly correct.
		//
		// That was observed: the site behind this router was reachable from
		// here and from nowhere else, and the fault appeared to have been
		// resolved. A fault that cannot be undone is worse than one that never
		// worked, because the lab is left broken in a way that no longer
		// matches any recorded ground truth.
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if _, err := e.Run(ctx, t.DeviceID(),
				"ip", "link", "set", s["iface"], "master", s["vrf"]); err != nil {
				return err
			}
			lines := []string{
				"configure terminal",
				"router bgp " + asnOf(t) + " vrf " + s["vrf"],
				" address-family ipv4 unicast",
			}
			if s["rd"] != "" {
				lines = append(lines, "  rd vpn export "+s["rd"])
			}
			for i := 0; ; i++ {
				rt, ok := s[fmt.Sprintf("rt%d", i)]
				if !ok {
					break
				}
				lines = append(lines, "  "+rt)
			}
			lines = append(lines, " exit-address-family", "end")
			if err := e.VtyshConfig(ctx, t.DeviceID(), lines...); err != nil {
				return err
			}
			// The withdrawal has to be undone as well as the configuration:
			// the far edge dropped this site's prefix while the port was out
			// of the table, and nothing re-originates it on its own.
			return e.VtyshConfig(ctx, t.DeviceID(), "clear bgp vrf "+s["vrf"]+" *")
		},
	})
}

// vrfBoundIface finds an interface the target has enslaved to a VPN table.
//
// It reads the kernel rather than the model or the running configuration. The
// model would be wrong if a student had moved the port themselves, and the
// running configuration does not carry the binding at all: FRR uses Linux VRF
// devices, so an interface in a VPN is one whose master is the VRF device. The
// first version of this looked for a "vrf" line in the interface stanza and
// concluded that a router plainly carrying two customers had no VPN on it.
func vrfBoundIface(ctx context.Context, e *Env, t Target) (string, string, error) {
	if i, v := t.Param("iface", ""), t.Param("vrf", ""); i != "" && v != "" {
		return i, v, nil
	}
	out, err := e.Run(ctx, t.DeviceID(), "ip", "-o", "link", "show")
	if err != nil {
		return "", "", err
	}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		var name, master string
		for i, w := range f {
			switch {
			case i == 1 && strings.HasSuffix(w, ":"):
				name = strings.SplitN(strings.TrimSuffix(w, ":"), "@", 2)[0]
			case w == "master" && i+1 < len(f):
				master = f[i+1]
			}
		}
		if name != "" && master != "" && name != "lo" {
			return name, master, nil
		}
	}
	return "", "", fmt.Errorf("no interface on %s is in a VPN routing table, "+
		"so there is no VPN membership to remove", t.DeviceID())
}

// vpnTargets reads a VPN's route distinguisher and route targets from the
// running configuration, so that a fault which disturbs them can put back what
// was there rather than what FRR would derive.
func vpnTargets(ctx context.Context, e *Env, t Target, vrf string) (string, []string) {
	out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
	if err != nil {
		return "", nil
	}
	var rd string
	var rts []string
	inVRF := false
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 4 && f[0] == "router" && f[1] == "bgp" && f[2] != "" && f[len(f)-1] == vrf {
			inVRF = true
			continue
		}
		if inVRF && len(f) >= 2 && f[0] == "router" {
			break
		}
		if !inVRF || len(f) < 3 {
			continue
		}
		switch {
		case f[0] == "rd" && f[1] == "vpn" && f[2] == "export" && len(f) > 3:
			rd = f[3]
		case f[0] == "rt" && f[1] == "vpn":
			rts = append(rts, strings.TrimSpace(ln))
		}
	}
	return rd, rts
}

// asnOf is the AS number a target's device belongs to, as a string, which is
// what a "router bgp" line needs.
func asnOf(t Target) string {
	id := t.DeviceID()
	if i := strings.IndexByte(id, '/'); i > 2 {
		return strings.TrimPrefix(id[:i], "as")
	}
	return ""
}
