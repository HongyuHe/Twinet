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
			// One pidfile per interface, not per device. A device with two
			// flapping links would otherwise overwrite the first record with
			// the second, and resolving would leave the first loop running
			// forever: an unattributable fault, on a lab everyone believes is
			// clean, that no later episode can explain.
			pidfile := "/run/twinet_flap_" + safeFileName(iface) + ".pid"
			if out, code := e.Try(ctx, t.DeviceID(),
				fmt.Sprintf("test -f %s && kill -0 $(cat %s) 2>/dev/null && echo running", pidfile, pidfile)); code == 0 &&
				strings.Contains(out, "running") {
				return nil, fmt.Errorf("%s is already being flapped; resolve that first", iface)
			}
			script := fmt.Sprintf(
				"while true; do ip link set %s down; sleep %s; ip link set %s up; sleep %s; done",
				iface, down, iface, up)
			if _, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("nohup sh -c %q >/dev/null 2>&1 & echo $! > %s", script, pidfile)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "pidfile": pidfile}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			pidfile := s["pidfile"]
			if pidfile == "" {
				return Evidence{}, fmt.Errorf("no flap loop was recorded for this fault")
			}
			out, _, err := e.TryE(ctx, t.DeviceID(), fmt.Sprintf(
				"test -f %s && kill -0 $(cat %s) 2>/dev/null && echo running || echo stopped", pidfile, pidfile))
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: strings.Contains(out, "running"),
				Expected: "the flap loop running", Observed: strings.TrimSpace(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["pidfile"] == "" || s["iface"] == "" {
				return fmt.Errorf("no flap loop was recorded, so it cannot be stopped")
			}
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
		Name: "host_crash", Category: CatEndHost, Needs: []Capability{CapLifecycle},
		Symptom:  "A host stopped responding entirely.",
		Describe: "The device's processes were frozen, so it holds its addresses but answers nothing.",
		// A frozen container, not an interface taken down. The difference is
		// the whole diagnostic value of the fault: a paused machine still owns
		// its addresses and its neighbours still believe the link is up, so
		// traffic is sent and silently lost. Taking the interfaces down instead
		// tells every neighbour immediately, which is a different and far
		// easier problem.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			if _, err := e.Device(t); err != nil {
				return nil, err
			}
			if err := e.Do(ctx, t.DeviceID(), "pause"); err != nil {
				return nil, err
			}
			return State{"paused": "true"}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			// The platform is asked, not the device. A frozen machine cannot
			// answer for itself, and its silence is equally consistent with an
			// unreachable node -- so reading a failed command as proof of the
			// fault would report success on an outage, and report the fault
			// resolved on one too.
			st, err := e.State(ctx, t.DeviceID())
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: st == "paused",
				Observed: "the container is " + st,
				Expected: "the container is paused",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return e.Do(ctx, t.DeviceID(), "unpause")
		},
	})

	Register(&Fault{
		Name: "host_network_down", Category: CatEndHost, Needs: []Capability{CapInterface},
		Symptom:  "A host is unreachable, and its neighbours report the link as down.",
		Describe: "Every interface on the device was administratively taken down.",
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
		Describe: "The router's own BGP AS number was changed, so every session it has stops establishing.",
		// The router's own AS number is changed, not a neighbour's remote-as.
		// The distinction matters: changing one neighbour statement breaks one
		// session, while changing the local AS breaks all of them at once and
		// makes every peer report the mismatch from the other side. Only the
		// second matches the fault of the same name in the taxonomy this is
		// meant to be comparable with, and a benchmark whose faults merely
		// share names with another's is not comparable at all.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			asn, err := localASN(ctx, e, t)
			if err != nil {
				return nil, err
			}
			wrong := asn + 600
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("no router bgp %d", asn),
				"end"); err != nil {
				return nil, err
			}
			// The old process is gone, so the replacement is announced under
			// the wrong number with nothing else configured, which is exactly
			// what a mistyped AS number does in practice.
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", wrong),
				"end"); err != nil {
				return nil, err
			}
			return State{"asn": fmt.Sprint(asn), "wrong": fmt.Sprint(wrong)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			wrong := "router bgp " + s["wrong"]
			return Evidence{
				Verified: strings.Contains(out, wrong),
				Observed: wrong,
				Expected: "router bgp " + s["asn"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["asn"] == "" {
				return fmt.Errorf("no original AS number was recorded")
			}
			// The undo is scoped to what the injection did: remove the wrong
			// instance and replay only the BGP section of the configuration on
			// disk. Restarting FRR would be simpler and is what an earlier
			// version did, but it also discards every unrelated edit a student
			// or another fault has made since -- a repair that silently
			// destroys state it was never asked about.
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("no router bgp %s", s["wrong"]), "end"); err != nil {
				return err
			}
			_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				"set -e",
				// Extract just "router bgp <n>" and its indented body.
				fmt.Sprintf("awk '/^router bgp %s$/{f=1} f{print} f&&/^exit$/{f=0}' /etc/frr/frr.conf > /tmp/twinet_bgp.conf", s["asn"]),
				"test -s /tmp/twinet_bgp.conf",
				"vtysh -f /tmp/twinet_bgp.conf",
				"rm -f /tmp/twinet_bgp.conf",
			}, "\n"))
			if err != nil {
				return fmt.Errorf("replaying the router's own BGP configuration: %w", err)
			}
			return nil
		},
	})

	Register(&Fault{
		Name: "bgp_peer_asn_misconfig", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "One neighbour is unreachable, while the others are fine.",
		Describe: "One BGP neighbour statement names the wrong remote AS, so that single session never establishes.",
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
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			want := fmt.Sprintf("neighbor %s remote-as %s", s["peer"], s["asn"])
			return Evidence{Verified: !strings.Contains(out, want),
				Expected: "the remote AS is no longer " + s["asn"]}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["peer"] == "" {
				return fmt.Errorf("no peer was recorded for this fault")
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
			return State{"iface": iface, "rate": rate, "prev": strings.TrimSpace(prev)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "tc qdisc show dev "+iface)
			// The presence of a token bucket proves nothing: the link's own
			// bandwidth is enforced with one, so a repaired link has one too.
			// Only the throttled rate distinguishes the two, which is why the
			// rate is recorded at injection rather than re-derived here.
			want := normaliseRate(s["rate"])
			return Evidence{
				Verified: want != "" && strings.Contains(normaliseRate(out), want),
				Observed: firstLine(out),
				Expected: "a token bucket at " + s["rate"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreShaping(ctx, e, t, s["iface"])
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
			return restoreShaping(ctx, e, t, s["iface"])
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
// restoreShaping puts an interface back to the shaping the topology declares.
//
// Deleting the fault's qdisc is not enough. A Twinet link carries its own
// delay, bandwidth and loss, installed at deploy time as the root qdisc, and a
// fault that replaces the root and then deletes it leaves the link faster and
// closer than the topology says. Nothing reports that: the link still works,
// it is merely no longer the link the lab describes, and every later
// measurement on it is quietly wrong.
// normaliseRate makes tc's rendering of a rate comparable with the one asked
// for: tc prints "64Kbit" where the request said "64kbit".
func normaliseRate(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

func restoreShaping(ctx context.Context, e *Env, t Target, iface string) error {
	if iface == "" {
		return fmt.Errorf("no interface recorded for this fault")
	}
	// The platform reapplies the shaping through the same code path the
	// deployer uses, which is the only way the result is guaranteed to equal a
	// freshly deployed link rather than merely resemble one.
	return e.Reshaped(ctx, t.DeviceID(), iface)
}

// localASN reads the AS number the router actually runs BGP under, rather than
// the one the topology says it should, so a fault reverses what it found.
func localASN(ctx context.Context, e *Env, t Target) (int, error) {
	out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 3 && f[0] == "router" && f[1] == "bgp" {
			var n int
			if _, err := fmt.Sscanf(f[2], "%d", &n); err == nil {
				return n, nil
			}
		}
	}
	if t.AS != 0 {
		return t.AS, nil
	}
	return 0, fmt.Errorf("%s is not running BGP, so its AS number cannot be changed", t.DeviceID())
}

// safeFileName makes an interface name usable in a path.
func safeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

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
