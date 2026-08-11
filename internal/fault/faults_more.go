package fault

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Faults of routing policy, resource contention, and the switch fabric.
//
// The contention faults deserve a note. It is tempting to emulate a busy
// machine by adding delay, because delay is easy to inject and easy to verify.
// It is also wrong: delay is a property of the path and shows up in a
// traceroute, while contention is a property of the endpoint and does not. An
// agent that learns "slow means add delay to a link" from a benchmark built
// that way has learned something false about real networks. These faults
// therefore consume the real resource -- processor time, memory, socket
// backlog -- and are undone by releasing it.

// randomCookie returns a per-injection identifier for a flow rule.
//
// A fixed constant was used here, and it is spelled out in this repository:
// anything that has read the source -- which for an agent being benchmarked is
// a realistic assumption -- can list the switch's flows, see the one carrying
// the known cookie, and read the fault straight off it without diagnosing
// anything. Even without the source, the same value on every injection is a
// tell across episodes.
//
// The value is recorded in the controller's injection record, which is the only
// place that needs it, and nothing about it identifies the framework.
func randomCookie() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a flow cookie: %w", err)
	}
	// Leading nibble forced non-zero so the value is a plausible controller
	// cookie rather than one that stands out by being short.
	b[0] |= 0x10
	return "0x" + hex.EncodeToString(b[:]), nil
}

func init() {
	// ---- routing --------------------------------------------------------

	Register(&Fault{
		Name: "bgp_blackhole_route_leak", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "Traffic to a range of addresses is drawn to the wrong network and disappears.",
		Describe: "A router originates a covering prefix it does not own, so traffic follows it and is dropped.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			prefix := t.Prefix
			if prefix == "" && t.Peer > 0 {
				if as, ok := e.Topology.ASes[t.Peer]; ok {
					prefix = as.Block
				}
			}
			if prefix == "" {
				return nil, fmt.Errorf("bgp_blackhole_route_leak needs a prefix or a victim AS")
			}
			asn, err := localASN(ctx, e, t)
			if err != nil {
				return nil, err
			}
			// Announced and simultaneously discarded locally: the route is
			// attractive to everyone else and goes nowhere. Announcing without
			// the discard would merely be a hijack, which is a different fault
			// with a different signature.
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("ip route %s Null0", prefix),
				fmt.Sprintf("router bgp %d", asn),
				" address-family ipv4 unicast",
				fmt.Sprintf("  network %s", prefix),
				" exit-address-family",
				"end"); err != nil {
				return nil, err
			}
			return State{"prefix": prefix, "asn": fmt.Sprint(asn)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			leaked := strings.Contains(out, "network "+s["prefix"]) &&
				strings.Contains(out, "ip route "+s["prefix"]+" Null0")
			return Evidence{
				Verified: leaked,
				Observed: boolWord(leaked, "the prefix is originated and discarded locally", "no leak present"),
				Expected: "the router originates " + s["prefix"] + " into a null route",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["prefix"] == "" {
				return fmt.Errorf("no leaked prefix was recorded")
			}
			return e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				fmt.Sprintf("no ip route %s Null0", s["prefix"]),
				fmt.Sprintf("router bgp %s", s["asn"]),
				" address-family ipv4 unicast",
				fmt.Sprintf("  no network %s", s["prefix"]),
				" exit-address-family",
				"end")
		},
	})

	Register(&Fault{
		Name: "ospf_area_misconfiguration", Category: CatMisconfig, Needs: []Capability{CapFRR},
		Symptom:  "Two routers on the same link never become neighbours, though the link is up.",
		Describe: "One network was moved into a different OSPF area, so the adjacency never forms.",
		// The area is changed on the network statement, not with "ip ospf area"
		// on the interface. The lab -- like the assignment it implements --
		// puts interfaces into OSPF with network statements, and FRR rejects
		// the interface form when the two would disagree. Injecting the wrong
		// one produced an empty error from vtysh and a fault that never fired.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			network, area, err := ospfNetworkArea(ctx, e, t)
			if err != nil {
				return nil, err
			}
			wrong := t.Param("area", "9")
			if wrong == area {
				wrong = "8"
			}
			if err := e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				"router ospf",
				fmt.Sprintf(" no network %s area %s", network, area),
				fmt.Sprintf(" network %s area %s", network, wrong),
				"end"); err != nil {
				return nil, err
			}
			return State{"network": network, "area": area, "wrong": wrong}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, err := e.Vtysh(ctx, t.DeviceID(), "show running-config")
			if err != nil {
				return Evidence{}, err
			}
			want := fmt.Sprintf("network %s area %s", s["network"], s["wrong"])
			return Evidence{
				Verified: strings.Contains(out, want),
				Observed: want,
				Expected: fmt.Sprintf("network %s area %s", s["network"], s["area"]),
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["network"] == "" {
				return fmt.Errorf("no network was recorded for this fault")
			}
			return e.VtyshConfig(ctx, t.DeviceID(), "configure terminal",
				"router ospf",
				fmt.Sprintf(" no network %s area %s", s["network"], s["wrong"]),
				fmt.Sprintf(" network %s area %s", s["network"], s["area"]),
				"end")
		},
	})

	// ---- resource contention -------------------------------------------

	Register(&Fault{
		Name: "sender_resource_contention", Category: CatContention, Needs: []Capability{CapProcess},
		Symptom:  "One machine's transfers are slow, while the network between it and everything else is idle.",
		Describe: "Processor time on the sender is consumed, so it cannot fill the link.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			return burnCPU(ctx, e, t)
		},
		Verify:  verifyBurn,
		Resolve: resolveBurn,
	})

	Register(&Fault{
		Name: "receiver_resource_contention", Category: CatContention, Needs: []Capability{CapProcess},
		Symptom:  "Transfers to one machine are slow; the same transfer to its neighbour is fast.",
		Describe: "Processor time on the receiver is consumed, so it cannot drain its socket buffers.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			return burnCPU(ctx, e, t)
		},
		Verify:  verifyBurn,
		Resolve: resolveBurn,
	})

	Register(&Fault{
		Name: "sender_application_delay", Category: CatContention, Needs: []Capability{CapTC},
		Symptom:  "One machine responds slowly, though the network to it is fast and it is not busy.",
		Describe: "The sender's own egress is delayed, so the application appears slow rather than the path.",
		// Egress only, and on the host rather than a router, so a traceroute
		// through the same path stays fast. That asymmetry is the entire
		// diagnostic value: it is what distinguishes a slow application from a
		// slow network, and a fault that delayed both would teach the opposite.
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			delay := t.Param("delay", "400ms")
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"tc qdisc replace dev %s root netem delay %s", iface, delay)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "delay": delay}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "tc qdisc show dev "+s["iface"])
			if err != nil {
				return Evidence{}, err
			}
			want := parseDuration(s["delay"])
			return Evidence{
				Verified: want > 0 && netemDelayMS(out) >= want*0.9,
				Observed: firstLine(out),
				Expected: "egress delayed by " + s["delay"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreShaping(ctx, e, t, s["iface"])
		},
	})

	Register(&Fault{
		Name: "incast_traffic_network_limitation", Category: CatContention, Needs: []Capability{CapTC},
		Symptom:  "Many senders to one destination collapse in throughput; a single sender is fine.",
		Describe: "The destination's queue was shrunk, so simultaneous arrivals are dropped rather than buffered.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			iface, err := faultIface(e, t)
			if err != nil {
				return nil, err
			}
			limit := t.Param("limit", "4")
			// A tiny queue rather than added loss: incast is a queueing
			// failure, and reproducing it with random loss would look similar
			// in a throughput graph while being a different phenomenon with a
			// different fix.
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"tc qdisc replace dev %s root netem limit %s", iface, limit)); err != nil {
				return nil, err
			}
			return State{"iface": iface, "limit": limit}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "tc qdisc show dev "+s["iface"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(out, "limit "+s["limit"]+" "),
				Observed: firstLine(out),
				Expected: "a queue of " + s["limit"] + " packets",
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			return restoreShaping(ctx, e, t, s["iface"])
		},
	})

	Register(&Fault{
		Name: "web_dos_attack", Category: CatAttack, Needs: []Capability{CapProcess},
		Symptom:  "A service stops answering, and the machine hosting it is saturated.",
		Describe: "A flood of connections is aimed at a service until it cannot accept more.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			victim := t.Param("victim", "")
			if victim == "" {
				v, _, err := arpVictim(e, t)
				if err != nil {
					return nil, err
				}
				victim = v
			}
			port := t.Param("port", "53")
			// Bounded rather than unbounded: an attack that consumes the node
			// itself takes down every other lab sharing it, which is a fault in
			// the platform rather than in the network under study.
			script := fmt.Sprintf(
				"nohup sh -c 'while true; do for i in 1 2 3 4 5 6 7 8; do "+
					"(echo | timeout 1 nc %s %s >/dev/null 2>&1 &) ; done; sleep 0.2; done' "+
					">/dev/null 2>&1 & echo $!", victim, port)
			out, err := e.Sh(ctx, t.DeviceID(), script)
			if err != nil {
				return nil, err
			}
			pid := strings.TrimSpace(out)
			if pid == "" {
				return nil, fmt.Errorf("the flood did not report a process id, so it could not be tracked")
			}
			return State{"pids": pid, "victim": victim, "port": port}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			alive, err := countAlive(ctx, e, t, s["pids"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: alive > 0,
				Observed: fmt.Sprintf("%d flooding process(es)", alive),
				Expected: "a flood aimed at " + s["victim"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			if s["pids"] == "" {
				return fmt.Errorf("no flood was recorded, so it cannot be stopped")
			}
			if err := killPIDs(ctx, e, t, s["pids"]); err != nil {
				return err
			}
			_, err := e.Sh(ctx, t.DeviceID(), killMatching("timeout 1 nc"))
			return err
		},
	})

	// ---- switch fabric --------------------------------------------------

	Register(&Fault{
		Name: "flow_rule_shadowing", Category: CatMisconfig, Needs: []Capability{CapOVS},
		Symptom:  "One host on a segment cannot be reached, though the switch says the port is up.",
		Describe: "A high-priority drop rule was installed on the switch, shadowing the rules below it.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			br := t.Param("bridge", "br0")
			port := t.Param("port", "")
			if port == "" {
				p, err := firstSwitchPort(ctx, e, t, br)
				if err != nil {
					return nil, err
				}
				port = p
			}
			// The rule carries a cookie so it can be removed exactly. Deleting
			// by match does not work: ovs-ofctl ignores priority when matching
			// for deletion, so "del-flows priority=60000,in_port=1" removes
			// every rule on that port -- including the lab's own -- or, with a
			// cookie-less match that happens not to apply, nothing at all. The
			// first silently breaks the switch; the second leaves the fault in
			// place while reporting that it was resolved.
			cookie, err := randomCookie()
			if err != nil {
				return nil, err
			}
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl add-flow %s 'cookie=%s,priority=60000,in_port=%s,actions=drop'",
				br, cookie, port)); err != nil {
				return nil, err
			}
			return State{"bridge": br, "port": port, "cookie": cookie}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "ovs-ofctl dump-flows "+s["bridge"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(out, "priority=60000") && strings.Contains(out, "actions=drop"),
				Observed: matchingLine(out, "priority=60000"),
				Expected: "a priority 60000 drop rule on port " + s["port"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Refuse rather than delete by an empty cookie. "cookie=/-1" is a
			// wildcard: it would remove every flow on the bridge, including the
			// lab's own, and report success.
			if s["bridge"] == "" || s["cookie"] == "" {
				return fmt.Errorf("no bridge and cookie were recorded for this fault, "+
					"so the rule it installed cannot be identified; removing by match would "+
					"take the switch's own rules with it (device %s)", t.DeviceID())
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl del-flows %s 'cookie=%s/-1'", s["bridge"], s["cookie"]))
			return err
		},
	})

	Register(&Fault{
		Name: "flow_rule_loop", Category: CatMisconfig, Needs: []Capability{CapOVS},
		Symptom:  "The segment is saturated and hosts on it become unreachable.",
		Describe: "A flow rule sends traffic back out the port it arrived on, so frames circulate.",
		Inject: func(ctx context.Context, e *Env, t Target) (State, error) {
			br := t.Param("bridge", "br0")
			port := t.Param("port", "")
			if port == "" {
				p, err := firstSwitchPort(ctx, e, t, br)
				if err != nil {
					return nil, err
				}
				port = p
			}
			// IN_PORT is the explicit "send it back where it came from" action,
			// which OVS otherwise refuses to do. Without it there is no loop,
			// and the fault would install a rule that changes nothing.
			cookie, err := randomCookie()
			if err != nil {
				return nil, err
			}
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl add-flow %s 'cookie=%s,priority=59000,in_port=%s,actions=IN_PORT'",
				br, cookie, port)); err != nil {
				return nil, err
			}
			return State{"bridge": br, "port": port, "cookie": cookie}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "ovs-ofctl dump-flows "+s["bridge"])
			if err != nil {
				return Evidence{}, err
			}
			return Evidence{
				Verified: strings.Contains(out, "priority=59000"),
				Observed: matchingLine(out, "priority=59000"),
				Expected: "a rule returning traffic to port " + s["port"],
			}, nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Refuse rather than delete by an empty cookie. "cookie=/-1" is a
			// wildcard: it would remove every flow on the bridge, including the
			// lab's own, and report success.
			if s["bridge"] == "" || s["cookie"] == "" {
				return fmt.Errorf("no bridge and cookie were recorded for this fault, "+
					"so the rule it installed cannot be identified; removing by match would "+
					"take the switch's own rules with it (device %s)", t.DeviceID())
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl del-flows %s 'cookie=%s/-1'", s["bridge"], s["cookie"]))
			return err
		},
	})
}

// matchingLine returns the first line containing a substring, for evidence that
// quotes what was actually seen rather than whatever came first.
func matchingLine(out, want string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, want) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// burnCPU occupies the device's processors.
//
// Real work, not simulated slowness: contention is a property of the endpoint
// and must not appear in a traceroute, or an agent learns from the benchmark
// that "slow" always means "add delay to a link", which is false about real
// networks and worse than teaching it nothing.
func burnCPU(ctx context.Context, e *Env, t Target) (State, error) {
	n := t.Param("workers", "4")
	script := fmt.Sprintf(
		"i=0; while [ $i -lt %s ]; do nohup sh -c 'while :; do :; done' >/dev/null 2>&1 & "+
			"echo $!; i=$((i+1)); done", n)
	out, err := e.Sh(ctx, t.DeviceID(), script)
	if err != nil {
		return nil, err
	}
	pids := strings.Join(strings.Fields(out), " ")
	if pids == "" {
		return nil, fmt.Errorf("no worker reported a process id, so they could not be tracked")
	}
	return State{"pids": pids, "workers": n}, nil
}

func verifyBurn(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
	alive, err := countAlive(ctx, e, t, s["pids"])
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Verified: alive > 0,
		Observed: fmt.Sprintf("%d worker(s) consuming processor time", alive),
		Expected: s["workers"] + " workers",
	}, nil
}

func resolveBurn(ctx context.Context, e *Env, t Target, s State) error {
	if s["pids"] == "" {
		return fmt.Errorf("no workers were recorded, so they cannot be stopped")
	}
	return killPIDs(ctx, e, t, s["pids"])
}

// ospfNetworkArea returns one network statement the router has, and its area.
//
// A statement the router genuinely has, rather than one derived from the model:
// the point of the fault is to move something that is currently working, and
// removing a statement that was never there leaves the configuration unchanged
// while every command reports success.
func ospfNetworkArea(ctx context.Context, e *Env, t Target) (network, area string, err error) {
	out, code, err := e.TryE(ctx, t.DeviceID(),
		"vtysh -c 'show running-config' | awk '/^router ospf$/{f=1;next} /^!/{f=0} f && $1==\"network\"{print $2, $4; exit}'")
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(strings.TrimSpace(out))
	if code != 0 || len(f) != 2 {
		return "", "", fmt.Errorf("%s has no OSPF network statement to move", t.DeviceID())
	}
	return f[0], f[1], nil
}

// firstSwitchPort picks a port on the switch's bridge.
func firstSwitchPort(ctx context.Context, e *Env, t Target, bridge string) (string, error) {
	out, code, err := e.TryE(ctx, t.DeviceID(), fmt.Sprintf(
		"ovs-ofctl show %s 2>/dev/null | awk -F'[( ]+' '/^ [0-9]+\\(/{print $2; exit}'", bridge))
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(out)
	if code != 0 || p == "" {
		return "", fmt.Errorf("%s has no ports on bridge %s", t.DeviceID(), bridge)
	}
	return p, nil
}
