package fault

import (
	"context"
	"fmt"
	"strings"
)

// Link failures, routing misconfigurations, attacks and resource contention.

func init() {
	// ---- link failures -------------------------------------------------
	Register(&Fault{
		Name: "link_down", Category: CatLink, Needs: []Capability{CapInterface},
		Symptom:  "Users report connectivity issues to other hosts.",
		Describe: "An interface was administratively shut down.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+iface+" down"); err != nil {
				return nil, err
			}
			return State{"iface": iface}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "cat /sys/class/net/"+iface+"/operstate 2>/dev/null")
			state := strings.TrimSpace(out)
			return Evidence{Verified: state == "down", Expected: "down", Observed: state}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["iface"] == "" {
				return nil
			}
			_, err := e.Sh(ctx, t.DeviceID(), "ip link set "+s["iface"]+" up")
			return err
		},
	})

	Register(&Fault{
		Name: "link_flap", Category: CatLink, Needs: []Capability{CapInterface, CapProcess},
		Symptom:  "Users report intermittent connectivity issues to other hosts.",
		Describe: "An interface is being cycled up and down on a fixed schedule.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			// The period is fixed rather than random so an episode replays
			// exactly; a benchmark whose fault differs run to run is not one.
			down := t.Param("down_seconds", "5")
			up := t.Param("up_seconds", "10")
			script := fmt.Sprintf(
				"while true; do ip link set %s down; sleep %s; ip link set %s up; sleep %s; done",
				iface, down, iface, up)
			if _, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("nohup sh -c %q >/dev/null 2>&1 & echo $! > /run/twinet_flap.pid", script)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "pidfile": "/run/twinet_flap.pid"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _ := e.Try(ctx, t.DeviceID(),
				"test -f /run/twinet_flap.pid && kill -0 $(cat /run/twinet_flap.pid) 2>/dev/null && echo running || echo stopped")
			return Evidence{Verified: strings.Contains(out, "running"),
				Expected: "the flap loop running", Observed: strings.TrimSpace(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"if [ -f %s ]; then kill $(cat %s) 2>/dev/null; rm -f %s; fi; ip link set %s up 2>/dev/null || true",
				s["pidfile"], s["pidfile"], s["pidfile"], s["iface"]))
			return err
		},
	})

	Register(&Fault{
		Name: "link_fragmentation_disabled", Category: CatLink, Needs: []Capability{CapInterface},
		Symptom:  "Users report partial packet loss when communicating with other hosts.",
		Describe: "An interface's MTU was lowered, so larger packets are dropped rather than fragmented.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "cat /sys/class/net/"+iface+"/mtu")
			old := strings.TrimSpace(out)
			if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+iface+" mtu 576"); err != nil {
				return nil, err
			}
			return State{"iface": iface, "mtu": old}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "cat /sys/class/net/"+iface+"/mtu")
			return Evidence{Verified: strings.TrimSpace(out) == "576",
				Expected: "576", Observed: strings.TrimSpace(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["mtu"] == "" {
				return nil
			}
			_, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("ip link set %s mtu %s", s["iface"], s["mtu"]))
			return err
		},
	})

	// ---- node errors ----------------------------------------------------
	Register(&Fault{
		Name: "frr_service_down", Category: CatNodeError, Needs: []Capability{CapService, CapFRR},
		Symptom:  "Users report connectivity issues to other hosts in the network.",
		Describe: "The routing daemon was stopped, so the router stops participating in OSPF and BGP.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			// watchfrr exists to restart the daemons it supervises, so stopping
			// bgpd alone either does nothing lasting or leaves watchfrr holding
			// its pid lock, which then prevents the service from starting again.
			// The supervisor has to go first, and the daemons are killed by
			// path so the match is unambiguous.
			_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				"/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true",
				killMatching("/usr/lib/frr/"),
				"for i in 1 2 3 4 5; do " + procRunning("/bgpd") + " || break; sleep 1; done",
				"true",
			}, "; "))
			if err != nil {
				return nil, err
			}
			return State{"service": "frr"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _ := e.Try(ctx, t.DeviceID(), procRunning("/bgpd")+" && echo running || echo stopped")
			return Evidence{Verified: strings.Contains(out, "stopped"),
				Expected: "bgpd stopped", Observed: strings.TrimSpace(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Stale pid files survive a killed supervisor and make the next
			// start refuse with "the daemon is already running", which would
			// leave the router permanently dead after a single fault.
			// The daemons also take a moment to bind, so returning early would
			// race the post-resolve verification.
			_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				killMatching("/usr/lib/frr/watchfrr"),
				"sleep 1",
				"rm -f /run/frr/*.pid /var/run/frr/*.pid 2>/dev/null || true",
				"/usr/lib/frr/frrinit.sh start >/dev/null 2>&1 || true",
				"for i in 1 2 3 4 5 6 7 8 9 10; do " + procRunning("/bgpd") + " && break; sleep 1; done",
				procRunning("/bgpd"),
			}, "; "))
			if err != nil {
				return fmt.Errorf("FRR did not come back up on %s: %w", t.DeviceID(), err)
			}
			return nil
		},
	})

	Register(&Fault{
		Name: "host_crash", Category: CatEndHost, Needs: []Capability{CapProcess},
		Symptom:  "A host stopped responding entirely.",
		Describe: "The device's networking was torn down, so it is present but unreachable.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			d, err := e.Device(t)
			if err != nil {
				return nil, err
			}
			var names []string
			for _, i := range d.Ifaces {
				if i.Name != "lo" {
					names = append(names, i.Name)
				}
			}
			for _, n := range names {
				if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+n+" down"); err != nil {
					return nil, err
				}
			}
			return State{"ifaces": strings.Join(names, ",")}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			var up int
			for _, n := range strings.Split(s["ifaces"], ",") {
				if n == "" {
					continue
				}
				out, _ := e.Try(ctx, t.DeviceID(),
					"cat /sys/class/net/"+n+"/flags 2>/dev/null")
				// Bit 0 of the interface flags is IFF_UP, which reflects the
				// administrative state we actually changed; operstate also
				// depends on the peer and would make this flap.
				if v := strings.TrimSpace(out); v != "" {
					if n, err := parseHexFlags(v); err == nil && n&1 == 1 {
						up++
					}
				}
			}
			return Evidence{Verified: up == 0, Expected: "no interface administratively up",
				Observed: fmt.Sprintf("%d up", up)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			for _, n := range strings.Split(s["ifaces"], ",") {
				if n == "" {
					continue
				}
				if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+n+" up"); err != nil {
					return err
				}
			}
			return nil
		},
	})

	// ---- misconfigurations ---------------------------------------------
	Register(&Fault{
		Name: "ospf_neighbor_missing", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "Traffic between two sites takes a longer path than it should.",
		Describe: "The OSPF network statement covering one link was removed, so the adjacency never forms.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			net, err := ospfNetworkFor(e, t)
			if err != nil {
				return nil, err
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(),
				"configure terminal", "router ospf", "no network "+net+" area 0", "end"); err != nil {
				return nil, err
			}
			return State{"network": net}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			net, err := ospfNetworkFor(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: !strings.Contains(out, "network "+net+" area"),
				Expected: "no network statement for " + net}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["network"] == "" {
				return nil
			}
			return e.VtyshConfig(ctx, t.DeviceID(),
				"configure terminal", "router ospf", "network "+s["network"]+" area 0", "end")
		},
	})

	Register(&Fault{
		Name: "bgp_asn_misconfig", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "Some hosts are experiencing connectivity issues.",
		Describe: "A BGP neighbour's remote AS number was changed, so the session never establishes.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			peer, asn, err := ebgpPeer(e, t)
			if err != nil {
				return nil, err
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS),
				fmt.Sprintf("no neighbor %s remote-as %d", peer, asn),
				fmt.Sprintf("neighbor %s remote-as %d", peer, asn+64500),
				"end"); err != nil {
				return nil, err
			}
			return State{"peer": peer, "asn": fmt.Sprint(asn)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			peer, asn, err := ebgpPeer(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			want := fmt.Sprintf("neighbor %s remote-as %d", peer, asn)
			return Evidence{Verified: !strings.Contains(out, want),
				Expected: "the remote AS is no longer " + fmt.Sprint(asn)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["peer"] == "" {
				return nil
			}
			return e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS),
				fmt.Sprintf("no neighbor %s", s["peer"]),
				fmt.Sprintf("neighbor %s remote-as %s", s["peer"], s["asn"]),
				"end")
		},
	})

	Register(&Fault{
		Name: "icmp_acl_block", Category: CatMisconfig, Needs: []Capability{CapNFT},
		Symptom:  "Some destinations do not respond to ping, though other traffic works.",
		Describe: "A firewall rule drops ICMP echo requests.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			// iptables rather than nft: every Twinet image ships it, and a
			// fault that depends on a tool the target lacks is not a fault, it
			// is a broken benchmark case.
			if _, err := e.Sh(ctx, t.DeviceID(),
				"iptables -w -A INPUT -p icmp --icmp-type echo-request -j DROP"); err != nil {
				return nil, err
			}
			return State{"rule": "INPUT -p icmp --icmp-type echo-request -j DROP"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, code := e.Try(ctx, t.DeviceID(),
				"iptables -w -C INPUT -p icmp --icmp-type echo-request -j DROP 2>&1 && echo present")
			return Evidence{Verified: code == 0 && strings.Contains(out, "present"),
				Expected: "an ICMP drop rule", Observed: firstLine(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			_, err := e.Sh(ctx, t.DeviceID(),
				"iptables -w -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || true")
			return err
		},
	})

	Register(&Fault{
		Name: "bgp_missing_route_advertisement", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "One network has become unreachable from the rest of the Internet.",
		Describe: "The AS stopped originating its own prefix, so nobody can route to it.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			as, ok := e.Topology.ASes[t.AS]
			if !ok || as.Block == "" {
				return nil, fmt.Errorf("AS %d has no prefix in the plan", t.AS)
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS), "address-family ipv4 unicast",
				"no network "+as.Block, "end"); err != nil {
				return nil, err
			}
			return State{"prefix": as.Block}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			as := e.Topology.ASes[t.AS]
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: !strings.Contains(out, "network "+as.Block),
				Expected: "the AS no longer originates " + as.Block}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["prefix"] == "" {
				return nil
			}
			return e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS), "address-family ipv4 unicast",
				"network "+s["prefix"], "end")
		},
	})

	// ---- attacks --------------------------------------------------------
	Register(&Fault{
		Name: "bgp_hijacking", Category: CatAttack, Needs: []Capability{CapFRR},
		Symptom:  "Traffic for a network is being diverted somewhere it should not go.",
		Describe: "An AS is originating a prefix that belongs to somebody else.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			victim := t.Prefix
			if victim == "" && t.Peer > 0 {
				if as, ok := e.Topology.ASes[t.Peer]; ok {
					victim = as.Block
				}
			}
			if victim == "" {
				return nil, fmt.Errorf("bgp_hijacking needs a prefix or a victim AS")
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS), "address-family ipv4 unicast",
				"network "+victim, "end"); err != nil {
				return nil, err
			}
			return State{"prefix": victim}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			victim := s["prefix"]
			if victim == "" {
				victim = t.Prefix
			}
			if victim == "" {
				return Evidence{}, fmt.Errorf("no hijacked prefix recorded")
			}
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			// The AS's own prefix is always originated, so the predicate must
			// name the victim's prefix specifically.
			return Evidence{Verified: strings.Contains(out, "network "+victim),
				Expected: "AS " + fmt.Sprint(t.AS) + " originates " + victim,
				Observed: victim}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["prefix"] == "" {
				return nil
			}
			return e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS), "address-family ipv4 unicast",
				"no network "+s["prefix"], "end")
		},
	})

	// ---- resource contention -------------------------------------------
	Register(&Fault{
		Name: "link_bandwidth_throttling", Category: CatContention, Needs: []Capability{CapTC},
		Symptom:  "Transfers across one path are far slower than expected.",
		Describe: "A token bucket was installed on an interface, capping its throughput.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			rate := t.Param("rate", "64kbit")
			prev, _ := e.Try(ctx, t.DeviceID(), "tc qdisc show dev "+iface)
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"tc qdisc replace dev %s root tbf rate %s burst 32kbit latency 400ms", iface, rate)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "prev": strings.TrimSpace(prev)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "tc qdisc show dev "+iface)
			return Evidence{Verified: strings.Contains(out, "tbf"), Observed: firstLine(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// The link's own shaping is reapplied by the next deploy; removing
			// the root qdisc returns it to the platform's default.
			_, err := e.Sh(ctx, t.DeviceID(),
				"tc qdisc del dev "+s["iface"]+" root 2>/dev/null || true")
			return err
		},
	})

	Register(&Fault{
		Name: "link_high_packet_corruption", Category: CatContention, Needs: []Capability{CapTC},
		Symptom:  "Users see retransmissions and stalls across one path.",
		Describe: "netem was told to corrupt a percentage of packets on an interface.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			pct := t.Param("corrupt", "10%")
			if _, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("tc qdisc replace dev %s root netem corrupt %s", iface, pct)); err != nil {
				return nil, err
			}
			return State{"iface": iface}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "tc qdisc show dev "+iface)
			return Evidence{Verified: strings.Contains(out, "corrupt"), Observed: firstLine(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			_, err := e.Sh(ctx, t.DeviceID(),
				"tc qdisc del dev "+s["iface"]+" root 2>/dev/null || true")
			return err
		},
	})
}

// killMatching terminates processes whose command line contains pattern,
// without killing the shell that is running the command.
//
// `pkill -f /usr/lib/frr/` looks right and is a trap: the shell executing it
// has that very string in its own command line, so pkill kills itself and the
// fault fails with exit 143 having done half its work.
func killMatching(pattern string) string {
	return "for p in $(ps -ef 2>/dev/null | grep -v grep | grep " + shellQuote(pattern) +
		" | awk '{print $1}'); do [ \"$p\" != \"$$\" ] && kill \"$p\" 2>/dev/null; done; true"
}

// procRunning builds a portable "is this process running" test.
//
// busybox's pgrep does not implement -x the way procps does: it silently
// matches nothing, so `pgrep -x bgpd` reported a running daemon as stopped.
// That made a fault claim success without ever taking effect, which is the
// worst possible failure for a benchmark. Matching the command line with ps is
// portable across both.
func procRunning(pattern string) string {
	return "ps -ef 2>/dev/null | grep -v grep | grep -q " + shellQuote(pattern)
}

// parseHexFlags reads the 0x-prefixed interface flag word.
func parseHexFlags(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "0x%x", &n); err != nil {
		return 0, err
	}
	return n, nil
}

// faultIface picks the interface a link fault acts on.
func faultIface(e *Env, t Target) (string, error) {
	if t.Iface != "" {
		return t.Iface, nil
	}
	d, err := e.Device(t)
	if err != nil {
		return "", err
	}
	for _, i := range d.Ifaces {
		if i.Name != "lo" && i.Link != nil {
			return i.Name, nil
		}
	}
	return "", fmt.Errorf("device %s has no wired interface to fail", d.ID)
}

// ospfNetworkFor returns the network statement covering the target interface.
func ospfNetworkFor(e *Env, t Target) (string, error) {
	d, err := e.Device(t)
	if err != nil {
		return "", err
	}
	name := t.Iface
	for _, i := range d.Ifaces {
		if name != "" && i.Name != name {
			continue
		}
		if i.Role != "intra-as" || i.Link == nil || i.Link.Subnet == "" {
			continue
		}
		return i.Link.Subnet, nil
	}
	return "", fmt.Errorf("device %s has no internal link to remove from OSPF", d.ID)
}

// ebgpPeer returns an external neighbour of the target router.
func ebgpPeer(e *Env, t Target) (addr string, asn int, err error) {
	d, err := e.Device(t)
	if err != nil {
		return "", 0, err
	}
	for _, i := range d.Ifaces {
		if i.Link == nil || !i.Link.InterAS || i.Peer == nil || i.Peer.Addr4 == "" {
			continue
		}
		if t.Peer > 0 && i.Peer.Device.ASN != t.Peer {
			continue
		}
		return strings.SplitN(i.Peer.Addr4, "/", 2)[0], i.Peer.Device.ASN, nil
	}
	return "", 0, fmt.Errorf("device %s has no external BGP neighbour", d.ID)
}
