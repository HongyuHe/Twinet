package fault

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Link failures, routing misconfigurations, attacks and resource contention.

func init() {
	// ---- link failures -------------------------------------------------
	Register(&Fault{
		Name: "link_down", Category: CatLink, Needs: []Capability{CapInterface},
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return "", err
			}
			out, _ := e.Try(ctx, t.DeviceID(), "ip -o link show dev "+iface)
			if out != "" && !strings.Contains(out, "state UP") && !strings.Contains(out, "UP,") {
				return iface + " on " + t.DeviceID() + " is already down", nil
			}
			return "", nil
		},
		Symptom:  "Users report connectivity issues to other hosts.",
		Describe: "An interface was administratively shut down.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			// Taking an interface down takes its connected route with it, and
			// with that every manually added route that resolved through it --
			// typically the default. Bringing the interface back up restores
			// only the connected route, so without this the device is left
			// reachable on its own subnet and nowhere else.
			routes := saveRoutes(ctx, e, t)
			if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+iface+" down"); err != nil {
				return nil, err
			}
			return State{"iface": iface, "routes": routes}, nil
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
			if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+s["iface"]+" up"); err != nil {
				return err
			}
			return restoreRoutes(ctx, e, t, s["routes"])
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
			// A second loop on the same interface would fight the first, and
			// resolving would stop only the one that was recorded: the link
			// keeps flapping on a lab everyone believes is clean, and no later
			// episode can explain it. The running loop is found by its command
			// line, which is a property of the fault itself rather than a
			// marker left behind for the purpose.
			if out, code := e.Try(ctx, t.DeviceID(), procRunning(
				fmt.Sprintf("ip link set %s down", iface))); code == 0 && strings.Contains(out, "running") {
				return nil, fmt.Errorf("%s is already being flapped; resolve that first", iface)
			}
			out, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("nohup sh -c %q >/dev/null 2>&1 & echo $!", script))
			if err != nil {
				return nil, err
			}
			pid := strings.TrimSpace(out)
			if pid == "" {
				return nil, fmt.Errorf("the flap loop did not report a process id, so it could not be tracked")
			}
			return State{"iface": iface, "pids": pid}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			if s["pids"] == "" {
				return Evidence{}, fmt.Errorf("no flap loop was recorded for this fault")
			}
			alive, err := countAlive(ctx, e, t, s["pids"])
			if err != nil {
				return Evidence{}, err
			}
			if alive > 0 {
				return Evidence{Verified: true,
					Expected: "the flap loop running, or the link it left down",
					Observed: fmt.Sprintf("%d flap loop(s) running", alive)}, nil
			}
			// The loop spends a third of its cycle with the link down, so
			// killing it is as likely as not to leave the interface down for
			// good -- which Resolve has always known and repaired, and which
			// this check used to be blind to. Counting loops alone reported
			// the fault gone while the link carried nothing at all and every
			// ping across it was lost. A dead loop is not the same as an
			// undone fault, and saying otherwise is a claim about the link
			// made without looking at it.
			state, _, err := e.TryE(ctx, t.DeviceID(),
				"cat /sys/class/net/"+s["iface"]+"/operstate 2>/dev/null")
			if err != nil {
				return Evidence{}, err
			}
			if strings.TrimSpace(state) == "down" {
				return Evidence{Verified: true,
					Expected: "the flap loop running, or the link it left down",
					Observed: "no flap loop is running, but it stopped on a down " +
						"cycle and " + s["iface"] + " is still down"}, nil
			}
			return Evidence{Verified: false,
				Expected: "the flap loop running, or the link it left down",
				Observed: "no flap loop is running and " + s["iface"] + " is " +
					strings.TrimSpace(state)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["pids"] == "" || s["iface"] == "" {
				return fmt.Errorf("no flap loop was recorded, so it cannot be stopped")
			}
			if err := killPIDs(ctx, e, t, s["pids"]); err != nil {
				return err
			}
			// The loop may have been killed mid-cycle, with the link down.
			_, err := e.Sh(ctx, t.DeviceID(),
				fmt.Sprintf("ip link set %s up 2>/dev/null || true", s["iface"]))
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
		Precondition: func(ctx context.Context, e *Env, t Target) (string, error) {
			out, _, err := e.FRRTry(ctx, t.DeviceID(), procRunning("/bgpd")+" && echo running || echo stopped")
			if err != nil {
				return "", err
			}
			if strings.Contains(out, "stopped") {
				return "FRR is not running on " + t.DeviceID() + " to begin with", nil
			}
			return "", nil
		},
		Symptom:  "Users report connectivity issues to other hosts in the network.",
		Describe: "The routing daemon was stopped, so the router stops participating in OSPF and BGP.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			// watchfrr exists to restart the daemons it supervises, so stopping
			// bgpd alone either does nothing lasting or leaves watchfrr holding
			// its pid lock, which then prevents the service from starting again.
			// The supervisor has to go first, and the daemons are killed by
			// path so the match is unambiguous.
			_, err := e.FRRSh(ctx, t.DeviceID(), strings.Join([]string{
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
			out, _, err := e.FRRTry(ctx, t.DeviceID(), procRunning("/bgpd")+" && echo running || echo stopped")
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{Verified: strings.Contains(out, "stopped"),
				Expected: "bgpd stopped", Observed: strings.TrimSpace(out)}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Stale pid files survive a killed supervisor and make the next
			// start refuse with "the daemon is already running", which would
			// leave the router permanently dead after a single fault.
			// The daemons also take a moment to bind, so returning early would
			// race the post-resolve verification.
			_, err := e.FRRSh(ctx, t.DeviceID(), strings.Join([]string{
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
			routes := saveRoutes(ctx, e, t)
			for _, n := range names {
				if _, err := e.Sh(ctx, t.DeviceID(), "ip link set "+n+" down"); err != nil {
					return nil, err
				}
			}
			return State{"ifaces": strings.Join(names, ","), "routes": routes}, nil
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
			return restoreRoutes(ctx, e, t, s["routes"])
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
			// The claim is that the adjacency never forms, so that is what is
			// checked. Reading back the absence of the network statement only
			// proved vtysh had accepted "no network", which it had already
			// reported; it would have passed just as happily on a router whose
			// neighbour was still fully adjacent through another statement
			// covering the same link.
			peer, err := ospfPeerAcross(e, t)
			if err != nil {
				return Evidence{}, err
			}
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show ip ospf neighbor")
				},
				func(o string) bool { return !strings.Contains(o, peer) })
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: !strings.Contains(out, peer),
				Observed: firstLine(matchingLine(out, peer)),
				Expected: "no OSPF adjacency with " + peer,
			}, nil
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
			// The claim is that every session stops establishing. Confirming
			// the wrong number appears in the configuration confirmed only
			// that the typo was typed -- it would have passed on a router
			// whose sessions were all still up, which is the one outcome that
			// would mean the fault had not happened.
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show bgp summary")
				},
				func(o string) bool { return establishedPeers(o) == 0 })
			if err != nil {
				return Evidence{}, err
			}
			n := establishedPeers(out)
			return Evidence{
				Verified: n == 0,
				Observed: fmt.Sprintf("%d established session(s)", n),
				Expected: "no established BGP sessions",
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
			// mktemp rather than a fixed name: a resolve that fails partway
			// would otherwise leave a file naming the framework behind on a
			// device an agent is about to be asked to diagnose.
			_, err := e.Sh(ctx, t.DeviceID(), strings.Join([]string{
				"set -e",
				"f=$(mktemp)",
				"trap 'rm -f \"$f\"' EXIT",
				// Extract just "router bgp <n>" and its indented body.
				fmt.Sprintf("awk '/^router bgp %s$/{f=1} f{print} f&&/^exit$/{f=0}' /etc/frr/frr.conf > \"$f\"", s["asn"]),
				"test -s \"$f\"",
				"vtysh -f \"$f\"",
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
			// The session must be up before it is broken.
			//
			// Verification waits for it to stop being established, which a
			// session that was never established satisfies immediately -- so
			// the fault reported success on a peering that was already down
			// for some other reason, and the recorded cause was not the reason.
			if out, _ := e.Try(ctx, t.DeviceID(), "vtysh -c 'show bgp summary'"); !peerEstablished(out, peer) {
				return nil, fmt.Errorf("the session with %s on %s is not established to "+
					"begin with, so breaking it would change nothing while claiming to be "+
					"the cause", peer, t.DeviceID())
			}
			// Everything the configuration says about this neighbour is
			// captured first.
			//
			// Undoing this fault removes the neighbour and adds it back, and
			// `no neighbor X` in FRR deletes *all* of it -- the route-maps
			// bound to it, its address-family settings, everything. Re-adding
			// `neighbor X remote-as N` restored the session and nothing else,
			// so the router came back with no policy at all on that session
			// and leaked every route it knew to a provider. The fault reported
			// a clean resolve, and the lab was quietly wrong from then on.
			base, af, cerr := neighborConfig(ctx, e, t, peer)
			if cerr != nil {
				// Injecting without having captured what this neighbour holds
				// means resolving cannot put it back, and undoing this fault
				// deletes the neighbour outright -- so the router would come
				// back with no policy on that session and leak every route it
				// knows. Better not to inject at all.
				return nil, cerr
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("router bgp %d", t.AS),
				fmt.Sprintf("no neighbor %s remote-as %d", peer, asn),
				fmt.Sprintf("neighbor %s remote-as %d", peer, asn+64500),
				"end"); err != nil {
				return nil, err
			}
			return State{"peer": peer, "asn": fmt.Sprint(asn),
				"cfg": strings.Join(base, "\n"), "cfgaf": strings.Join(af, "\n")}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			// The claim is that this one session stops establishing. Checking
			// that the old remote-as line is gone confirms only that the edit
			// landed -- it says nothing about the session, which is the thing
			// an agent diagnosing this would look at.
			peer := s["peer"]
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show bgp summary")
				},
				func(o string) bool { return !peerEstablished(o, peer) })
			if err != nil {
				return Evidence{}, err
			}
			up := peerEstablished(out, peer)
			return Evidence{
				Verified: !up,
				Observed: firstLine(matchingLine(out, peer)),
				Expected: "the session with " + peer + " not established",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["peer"] == "" {
				return fmt.Errorf("no peer was recorded for this fault")
			}
			cmds := []string{"configure terminal", fmt.Sprintf("router bgp %d", t.AS),
				fmt.Sprintf("no neighbor %s", s["peer"]),
				fmt.Sprintf("neighbor %s remote-as %s", s["peer"], s["asn"])}
			for _, l := range splitNonEmpty(s["cfg"]) {
				if strings.Contains(l, "remote-as") {
					continue
				}
				cmds = append(cmds, l)
			}
			if af := splitNonEmpty(s["cfgaf"]); len(af) > 0 {
				cmds = append(cmds, "address-family ipv4 unicast")
				cmds = append(cmds, af...)
				cmds = append(cmds, "exit-address-family")
			}
			cmds = append(cmds, "end")
			return e.VtyshConfig(ctx, t.DeviceID(), cmds...)
		},
	})
}

// neighborConfig returns every configuration line naming a neighbour, split
// into the ones that live directly under `router bgp` and the ones that live
// inside an address family.
//
// Restoring a neighbour means restoring all of it. The route-maps bound to a
// session are what stop a router handing every route it knows to a provider,
// and they live in the address-family block.
func neighborConfig(ctx context.Context, e *Env, t Target, peer string) (base, af []string, err error) {
	out, code, err := e.TryE(ctx, t.DeviceID(), "vtysh -c 'show running-config'")
	if err != nil {
		return nil, nil, err
	}
	if code != 0 {
		return nil, nil, fmt.Errorf("%s: its configuration could not be read, so what this "+
			"fault would delete could not be captured first", t.DeviceID())
	}
	inAF := false
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "address-family "):
			inAF = true
			continue
		case l == "exit-address-family":
			inAF = false
			continue
		case strings.HasPrefix(l, "router "):
			inAF = false
		}
		if !strings.HasPrefix(l, "neighbor "+peer+" ") {
			continue
		}
		if inAF {
			af = append(af, l)
		} else {
			base = append(base, l)
		}
	}
	return base, af, nil
}

func init() {
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
			// The claim is that the AS stops originating its prefix, so the
			// prefix must actually leave the BGP table. The configuration
			// check passed the moment the statement was removed, which is
			// before BGP has withdrawn anything and would have passed even if
			// the prefix were still being originated by another statement.
			as := e.Topology.ASes[t.AS]
			block := as.Block
			// What must stop is this router originating the prefix, which FRR
			// marks "sourced" on the locally generated path.
			//
			// Not "the prefix disappears": every router in the AS originates
			// it, so the others keep it in this one's table over iBGP and it
			// never goes away. An earlier check for the prefix being absent
			// could therefore never pass on any multi-router AS, which is all
			// of them here -- the fault was rolled back every time and the
			// fault type was in practice unusable.
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show bgp ipv4 unicast "+block)
				},
				func(o string) bool { return !strings.Contains(o, "sourced") })
			if err != nil {
				return Evidence{}, err
			}
			gone := !strings.Contains(out, "sourced")
			return Evidence{
				Verified: gone,
				Observed: boolWord(gone, "the router no longer originates "+block,
					"the router still originates "+block),
				Expected: block + " no longer originated here",
			}, nil
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
			// The claim is that this router originates someone else's prefix,
			// so look for it in the BGP table as a local origin. The
			// configuration check confirmed a `network` statement had been
			// typed, which is true even when BGP refuses to originate the
			// prefix because no matching route exists -- a hijack that never
			// left the router and that no victim would ever see.
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show bgp ipv4 unicast "+victim)
				},
				func(o string) bool { return locallyOriginated(o) })
			if err != nil {
				return Evidence{}, err
			}
			got := locallyOriginated(out)
			originated := firstLine(out)
			if !got {
				originated = "the router is not originating " + victim
			}
			return Evidence{Verified: got,
				Expected: "AS " + fmt.Sprint(t.AS) + " originates " + victim,
				Observed: originated}, nil
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

// killPIDs stops processes the injector started, by process id.
//
// Process ids are recorded in the injection record the controller keeps, not in
// a file inside the container. A file called /run/twinet_flap_eth0.pid names the
// framework, the fault and the interface, so anything with a shell on the
// device can read the answer off the disk. For a lab that exists to measure how
// well an agent diagnoses faults, leaving the solution lying in the filesystem
// does not just weaken the measurement, it invalidates it.
func killPIDs(ctx context.Context, e *Env, t Target, pids string) error {
	list := strings.Fields(pids)
	if len(list) == 0 {
		return fmt.Errorf("no process was recorded, so none can be stopped")
	}
	_, err := e.Sh(ctx, t.DeviceID(),
		fmt.Sprintf("for p in %s; do kill $p 2>/dev/null; done; true", strings.Join(list, " ")))
	return err
}

// countAlive reports how many of the recorded processes are still running.
func countAlive(ctx context.Context, e *Env, t Target, pids string) (int, error) {
	list := strings.Fields(pids)
	if len(list) == 0 {
		return 0, nil
	}
	out, _, err := e.TryE(ctx, t.DeviceID(), fmt.Sprintf(
		"n=0; for p in %s; do kill -0 $p 2>/dev/null && n=$((n+1)); done; echo $n",
		strings.Join(list, " ")))
	if err != nil {
		return 0, err
	}
	n, convErr := strconv.Atoi(strings.TrimSpace(out))
	if convErr != nil {
		return 0, fmt.Errorf("could not read how many processes are alive from %q", strings.TrimSpace(out))
	}
	return n, nil
}

// ospfPeerAcross names the router on the other end of the link this fault
// removed from OSPF, so verification can look for the adjacency itself rather
// than for the configuration line that was supposed to cause it to drop.
//
// It resolves the same interface ospfNetworkFor chose, so the two cannot
// disagree about which link the fault is about.
func ospfPeerAcross(e *Env, t Target) (string, error) {
	d, err := e.Device(t)
	if err != nil {
		return "", err
	}
	for _, i := range d.Ifaces {
		if t.Iface != "" && i.Name != t.Iface {
			continue
		}
		if i.Role != "intra-as" || i.Link == nil || i.Link.Subnet == "" {
			continue
		}
		if i.Peer == nil || i.Peer.Device == nil {
			return "", fmt.Errorf("the link from %s on %s has no resolved peer, so the "+
				"adjacency cannot be checked", i.Name, d.ID)
		}
		// FRR lists neighbours by router ID, which the platform sets to the
		// peer's loopback address.
		if lo, ok := i.Peer.Device.IfaceByName("lo"); ok && lo.Addr4 != "" {
			return addrOnly(lo.Addr4), nil
		}
		return addrOnly(i.Peer.Addr4), nil
	}
	return "", fmt.Errorf("device %s has no internal link to remove from OSPF", d.ID)
}

// establishedPeers counts the sessions in `show bgp summary` that are actually
// up. FRR prints the prefix count in the state column once a session
// establishes and a state name while it is not, so a column that parses as a
// number is an established session.
func establishedPeers(summary string) int {
	n := 0
	for _, ln := range strings.Split(summary, "\n") {
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		if net.ParseIP(f[0]) == nil {
			continue
		}
		if _, err := strconv.Atoi(f[9]); err == nil {
			n++
		}
	}
	return n
}

// peerEstablished reports whether one neighbour's session is up in the output
// of `show bgp summary`. FRR prints a prefix count once a session establishes
// and a state name while it is not, so a numeric state column means up.
func peerEstablished(summary, peer string) bool {
	if peer == "" {
		return false
	}
	for _, ln := range strings.Split(summary, "\n") {
		f := strings.Fields(ln)
		if len(f) < 10 || f[0] != peer {
			continue
		}
		_, err := strconv.Atoi(f[9])
		return err == nil
	}
	return false
}

// ospfPeerOnNetwork names the router reached across a particular subnet, so a
// verifier can watch the adjacency that a fault actually disturbed rather than
// whichever one it would have picked independently.
func ospfPeerOnNetwork(e *Env, t Target, subnet string) (string, error) {
	if subnet == "" {
		return ospfPeerAcross(e, t)
	}
	d, err := e.Device(t)
	if err != nil {
		return "", err
	}
	for _, i := range d.Ifaces {
		if i.Link == nil || i.Link.Subnet != subnet || i.Peer == nil || i.Peer.Device == nil {
			continue
		}
		if lo, ok := i.Peer.Device.IfaceByName("lo"); ok && lo.Addr4 != "" {
			return addrOnly(lo.Addr4), nil
		}
		return addrOnly(i.Peer.Addr4), nil
	}
	return "", fmt.Errorf("no link on %s carries subnet %s, so the adjacency the fault "+
		"changed cannot be identified", d.ID, subnet)
}

// locallyOriginated reports whether `show bgp <prefix>` shows a path this
// router originates itself.
//
// It used to look for the word "Local" anywhere in the output, and every
// learned path prints "Local host: <addr>, Local port: 179". So the check was
// true whenever the prefix was in the table at all -- which for a hijack of a
// real neighbour's prefix is always. The fault could then never be resolved:
// its own verification insisted it was still present after the configuration
// had been removed. That happened on this cluster and needed a hand repair.
//
// FRR prints a locally originated path as a line containing only "Local".
func locallyOriginated(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "Local" {
			return true
		}
	}
	return false
}
