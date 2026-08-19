package fault

import (
	"context"
	"fmt"
	"strconv"
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

// Flow rules an injected fault installs carry nothing that identifies them.
//
// They used to carry a cookie -- first a constant, then a random value -- so
// that resolving could delete exactly the injected rule. But a switch in this
// lab has one flow, "cookie=0x0, priority=0, actions=NORMAL", so any rule with
// a non-zero cookie and a priority of 60000 is visibly not part of the lab.
// Anything that has read this source, which for an agent being benchmarked on
// root-cause analysis is a realistic assumption, could list the flows and read
// the fault off the one that stands out, without diagnosing anything.
//
// A fault should look like the misconfiguration it is imitating. These
// priorities are what somebody writing an access rule by hand would use, the
// cookie is left at the default like everything else, and the rule is removed
// with `--strict`, which matches the priority and the match exactly -- so the
// injected rule can be deleted precisely without carrying a label.
const (
	ovsDropPriority = 100
	ovsLoopPriority = 200
)

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
			// The damage is that traffic for the prefix is drawn here and
			// dropped, so check the forwarding table: the route must be in the
			// RIB pointing at Null0. Confirming both configuration lines were
			// typed said nothing about whether the router had installed
			// anything, and a leak that is not installed swallows no traffic.
			prefix := s["prefix"]
			out, err := e.Settled(ctx, SymptomWindow,
				func(c context.Context) (string, error) {
					return e.Vtysh(c, t.DeviceID(), "show ip route "+prefix)
				},
				// FRR reports a discard route as "unreachable (blackhole)" in
				// `show ip route`; the Null0 spelling only exists in the
				// configuration, so looking for it here never matched and the
				// fault was rolled back as ineffective every time.
				func(o string) bool { return strings.Contains(o, "blackhole") })
			if err != nil {
				return Evidence{}, err
			}
			leaked := strings.Contains(out, "blackhole")
			return Evidence{
				Verified: leaked,
				Observed: boolWord(leaked, "traffic for "+prefix+" is discarded here",
					"the router has no discard route for "+prefix),
				Expected: "the router originates " + prefix + " into a null route",
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
			// Moving a link into another area breaks the adjacency across it,
			// because OSPF neighbours must agree on the area. That broken
			// adjacency is the symptom an operator sees, so that is what is
			// checked. The configuration line being present proved only that
			// the area had been retyped.
			// The peer is resolved from the network the injection actually
			// moved, not from the target's first internal link. Those are
			// chosen by different code -- inject reads the running config,
			// the other reads the model -- and when they disagreed the
			// verifier watched an adjacency the fault had not touched, saw it
			// still up, and rolled back a fault that had worked perfectly.
			peer, err := ospfPeerOnNetwork(e, t, s["network"])
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
			down := !strings.Contains(out, peer)
			return Evidence{
				Verified: down,
				Observed: boolWord(down, "no adjacency with "+peer,
					firstLine(matchingLine(out, peer))),
				Expected: "the adjacency with " + peer + " is down, the areas disagreeing",
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
			// The victim must be something that is actually listening.
			//
			// This used to pick an arbitrary neighbour off the ARP table and
			// aim at port 53, which on a host runs nothing at all. The flood
			// then hit a closed port: the "attack" produced no symptom, the
			// service it claimed to overwhelm was never touched, and the fault
			// verified as successful because its own process was running. An
			// episode with no symptom is worse than an absent fault, because it
			// looks like a working one and whatever the agent concludes is
			// scored against a cause that was never present.
			//
			// The lab's resolver is the default: it is a real server, on a real
			// port, that every host in the lab depends on.
			victim := t.Param("victim", "")
			port := t.Param("port", "53")
			if victim == "" {
				v, err := labResolver(ctx, e, t)
				if err != nil {
					return nil, err
				}
				victim = v
			}
			if !listening(ctx, e, t, victim, port) {
				return nil, fmt.Errorf("nothing is listening on %s port %s, so flooding it would "+
					"produce no symptom; name a victim that runs the service", victim, port)
			}
			// Bounded rather than unbounded: an attack that consumes the node
			// itself takes down every other lab sharing it, which is a fault in
			// the platform rather than in the network under study.
			// Recorded before the flood so the effect can be measured rather
			// than assumed.
			baseline := probeServiceHealth(ctx, e, t, victim, port)
			if baseline <= 0 {
				return nil, fmt.Errorf("%s port %s did not answer before the flood started, "+
					"so any later failure could not be attributed to it", victim, port)
			}

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
			return State{"pids": pid, "victim": victim, "port": port,
				"baseline_ok": strconv.Itoa(baseline)}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			alive, err := countAlive(ctx, e, t, s["pids"])
			if err != nil {
				return Evidence{}, err
			}
			if alive == 0 {
				return Evidence{
					Verified: false,
					Observed: "the flood is not running",
					Expected: "a flood aimed at " + s["victim"],
				}, nil
			}
			// The flood running is the mechanism. What has to be true is that
			// the service is worse off than it was, measured against what it
			// managed before the flood started.
			now := probeServiceHealth(ctx, e, t, s["victim"], s["port"])
			base, _ := strconv.Atoi(s["baseline_ok"])
			return Evidence{
				Verified: alive > 0 && now < base,
				Observed: fmt.Sprintf("%d flooding process(es); %s answered %d of 6 requests, "+
					"against %d of 6 before", alive, s["victim"], now, base),
				Expected: "fewer requests answered while the flood runs",
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
		Name: "flow_rule_shadowing", Category: CatNodeError, Needs: []Capability{CapOVS},
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
			// The rule is removed later with --strict on this exact priority
			// and match, so it needs no label. Deleting
			// by match does not work: ovs-ofctl ignores priority when matching
			// for deletion, so "del-flows priority=60000,in_port=1" removes
			// every rule on that port -- including the lab's own -- or, with a
			// cookie-less match that happens not to apply, nothing at all. The
			// first silently breaks the switch; the second leaves the fault in
			// place while reporting that it was resolved.
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl add-flow %s 'priority=%d,in_port=%s,actions=drop'",
				br, ovsDropPriority, port)); err != nil {
				return nil, err
			}
			return State{"bridge": br, "port": port}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "ovs-ofctl dump-flows "+s["bridge"])
			if err != nil {
				return Evidence{}, err
			}
			return ovsFlowEvidence(out, ovsDropPriority, s["port"], "drop",
				"a drop rule on port "+s["port"]), nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Refuse rather than delete by an empty cookie. "cookie=/-1" is a
			// wildcard: it would remove every flow on the bridge, including the
			// lab's own, and report success.
			if s["bridge"] == "" || s["port"] == "" {
				return fmt.Errorf("no bridge and port were recorded for this fault, "+
					"so the rule it installed cannot be identified; removing by match would "+
					"take the switch's own rules with it (device %s)", t.DeviceID())
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl --strict del-flows %s 'priority=%d,in_port=%s'",
				s["bridge"], ovsDropPriority, s["port"]))
			return err
		},
	})

	Register(&Fault{
		Name: "flow_rule_loop", Category: CatNodeError, Needs: []Capability{CapOVS},
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
			if _, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl add-flow %s 'priority=%d,in_port=%s,actions=IN_PORT'",
				br, ovsLoopPriority, port)); err != nil {
				return nil, err
			}
			return State{"bridge": br, "port": port}, nil
		},
		Verify: func(ctx context.Context, e *Env, t Target, s State) (Evidence, error) {
			out, _, err := e.TryE(ctx, t.DeviceID(), "ovs-ofctl dump-flows "+s["bridge"])
			if err != nil {
				return Evidence{}, err
			}
			return ovsFlowEvidence(out, ovsLoopPriority, s["port"], "IN_PORT",
				"a rule returning traffic to port "+s["port"]), nil
		},
		Resolve: func(ctx context.Context, e *Env, t Target, s State) error {
			// Refuse rather than delete by an empty cookie. "cookie=/-1" is a
			// wildcard: it would remove every flow on the bridge, including the
			// lab's own, and report success.
			if s["bridge"] == "" || s["port"] == "" {
				return fmt.Errorf("no bridge and port were recorded for this fault, "+
					"so the rule it installed cannot be identified; removing by match would "+
					"take the switch's own rules with it (device %s)", t.DeviceID())
			}
			_, err := e.Sh(ctx, t.DeviceID(), fmt.Sprintf(
				"ovs-ofctl --strict del-flows %s 'priority=%d,in_port=%s'",
				s["bridge"], ovsLoopPriority, s["port"]))
			return err
		},
	})
}

// ovsFlowOn returns the flow-table line whose match selects exactly the given
// priority and ingress port, along with its action list.
//
// Substring search cannot answer this question. "priority=100" and
// "actions=drop" can come from two entirely different rules, so a table holding
// an unrelated drop and an unrelated priority-100 forward satisfies both tests
// while nothing is dropped; "in_port=1" is a prefix of "in_port=10", so a rule
// on port 10 answers for port 1; and ovs-ofctl does not promise a field order,
// so a fixed "priority=100,in_port=1" needle is a guess about formatting rather
// than a reading of the rule. Splitting each line into its match fields and its
// actions asks what the rule actually selects.
func ovsFlowOn(out string, priority int, port string) (line, actions string, ok bool) {
	if port == "" {
		return "", "", false
	}
	wantPrio := fmt.Sprintf("priority=%d", priority)
	wantPort := "in_port=" + port
	for _, l := range strings.Split(out, "\n") {
		i := strings.Index(l, " actions=")
		if i < 0 {
			continue
		}
		var gotPrio, gotPort bool
		for _, f := range strings.Split(l[:i], ",") {
			switch strings.TrimSpace(f) {
			case wantPrio:
				gotPrio = true
			case wantPort:
				gotPort = true
			}
		}
		if gotPrio && gotPort {
			return strings.TrimSpace(l), strings.TrimSpace(l[i+len(" actions="):]), true
		}
	}
	return "", "", false
}

// hasAction reports whether an ovs-ofctl action list contains a given action as
// a whole term. "drop" must not be found inside a longer action name, and OVS
// prints IN_PORT in upper case while it is written in lower case on the wire.
func hasAction(actions, want string) bool {
	for _, a := range strings.Split(actions, ",") {
		if strings.EqualFold(strings.TrimSpace(a), want) {
			return true
		}
	}
	return false
}

// ovsFlowEvidence reports on the rule the fault recorded, not on whatever else
// the table happens to hold. When the recorded port carries no such rule the
// observation says so, and names the rule that does sit at that priority if
// there is one, because "the rule moved to another port" and "the rule is gone"
// are different situations for whoever is reading the report.
func ovsFlowEvidence(out string, priority int, port, action, expected string) Evidence {
	line, actions, ok := ovsFlowOn(out, priority, port)
	if ok && hasAction(actions, action) {
		return Evidence{Verified: true, Observed: line, Expected: expected}
	}
	obs := fmt.Sprintf("no rule at priority=%d on port %s", priority, port)
	if ok {
		obs = fmt.Sprintf("the rule at priority=%d on port %s does not %s: %s",
			priority, port, action, line)
	} else if other := matchingLine(out, fmt.Sprintf("priority=%d", priority)); other != "" {
		obs = fmt.Sprintf("%s; a rule at that priority sits elsewhere: %s", obs, other)
	}
	return Evidence{Verified: false, Observed: obs, Expected: expected}
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

// labResolver returns the address the target host is configured to resolve
// against, which is a server the lab actually runs.
func labResolver(ctx context.Context, e *Env, t Target) (string, error) {
	out, _ := e.Try(ctx, t.DeviceID(),
		`awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null`)
	addr := strings.TrimSpace(out)
	if addr == "" {
		return "", fmt.Errorf("%s has no resolver configured, so there is no service to flood",
			t.DeviceID())
	}
	return addr, nil
}

// listening reports whether a TCP or UDP service answers on an address.
//
// resolvableName derives a name the lab's own resolver certainly serves: the
// device's hostname in its own search domain.
const resolvableName = "n=$(hostname); " +
	"d=$(awk '/^search/{print $2; exit}' /etc/resolv.conf 2>/dev/null); " +
	"q=$n; [ -n \"$d\" ] && q=$n.$d; "

// busybox has no /dev/tcp, so this uses whichever of nc or socat the image
// carries; a probe that cannot run returns false, because injecting on the
// strength of "we could not tell" is how an episode ends up with no symptom.
func listening(ctx context.Context, e *Env, t Target, addr, port string) bool {
	out, _ := e.Try(ctx, t.DeviceID(), fmt.Sprintf(
		// The device's own name is one the lab's resolver certainly serves.
		// Asking for the root zone instead returns no answer and dig exits 9,
		// which reads identically to a server that is not there.
		`%sif [ %q = 53 ]; then dig +time=2 +tries=1 @%s "$q" >/dev/null 2>&1 && echo yes; `+
			`else (echo | timeout 2 nc -w 2 %s %s >/dev/null 2>&1 && echo yes); fi`,
		resolvableName, port, addr, addr, port))
	return strings.Contains(out, "yes")
}

// probeServiceHealth counts how many of a fixed number of requests the service
// answers.
//
// Timing was tried first and does not work here: busybox's date has no %N, so
// every measurement came back as zero milliseconds and the comparison passed by
// default -- which is precisely the shape of verification this fault was
// criticised for. Counting answered requests needs no sub-second clock and
// measures the thing the symptom describes: a service that stops answering.
func probeServiceHealth(ctx context.Context, e *Env, t Target, addr, port string) int {
	const attempts = 6
	script := fmt.Sprintf(
		`%sok=0; i=0; while [ $i -lt %d ]; do `+
			`if [ %q = 53 ]; then dig +time=1 +tries=1 @%s "$q" >/dev/null 2>&1 && ok=$((ok+1)); `+
			`else echo | timeout 1 nc -w 1 %s %s >/dev/null 2>&1 && ok=$((ok+1)); fi; `+
			`i=$((i+1)); done; echo $ok`,
		resolvableName, attempts, port, addr, addr, port)
	out, code := e.Try(ctx, t.DeviceID(), script)
	if code != 0 {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return -1
	}
	return n
}
