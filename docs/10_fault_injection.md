# 10 — Fault injection and root-cause analysis

## 1. Objective

Beyond teaching, Twinet is to serve as a platform for **assessing an AI agent's
ability to perform root-cause analysis** on a live network. Concretely:

> Twinet must be able to inject, verify and resolve the fault types that the
> [NIKA](https://github.com/sands-lab/nika) framework defines
> (`/users/hy/nika`), so that a NIKA-style incident can be reproduced on a
> Twinet lab and an agent's diagnosis scored against machine-readable ground
> truth.

NIKA is "SWE-bench for network troubleshooting": it registers **60 fault types**
across six categories and evaluates an agent that is connected to a live network
while the incident is ongoing. It already abstracts over lab backends —
today Kathará and containerlab. **Twinet's goal is to become a third backend**,
and a better one: reproducible by construction, scalable across a cluster, and
carrying ground truth in its own model rather than alongside it.

This is not a bolt-on. It changes several requirements elsewhere in this plan,
which §6 records.

## 2. Why this fits Twinet

A teaching platform and an RCA benchmark want strikingly similar things, and
Twinet has already built most of the hard parts for the first:

| RCA benchmark needs | Twinet already has |
|---|---|
| Bit-identical reproduction of a scenario | Deterministic allocation; the topology is a pure function of the manifest ([02](02_architecture.md) §4) |
| A clean baseline to reset to between episodes | The durable state store and capture/restore in `internal/state` and `internal/deploy` |
| Many concurrent independent episodes | AS-granular placement across a cluster ([04](04_networking_and_scaleout.md)) |
| Machine-readable ground truth | The provisioning contract already records the *expected* answer beside the deployed one ([03](03_topology_model.md) §4) |
| Assertions about live network state | The grading engine's 17 checks and convergence predicates ([06](06_grading.md)) |
| An injectable, reversible perturbation | The `behaviours:` block, which already expresses a BGP hijack ([03](03_topology_model.md) §7) |

The `behaviours:` concept generalises directly into fault injection. What was a
single scripted hijack for the RPKI exercise becomes the general mechanism.

Note the symmetry that makes this cheap: **`verify_fault` is a grading check
with the sign flipped.** Both assert a property of a live network and return
structured evidence. One codebase serves both.

## 3. The model

### 3.1 A fault is a first-class object

```yaml
faults:
  # A fault is declared once and can be instantiated many times against
  # different targets, which is what turns dozens of fault types into hundreds of
  # reproducible incidents.
  ospf-adjacency-lost:
    type: ospf_neighbor_missing        # a registered fault type
    category: misconfiguration          # NIKA's taxonomy
    target:
      as: 12
      device: PHY
      iface: port_NYC
    # Ground truth is authored with the fault, not derived afterwards, so it
    # cannot disagree with what was actually injected.
    ground_truth:
      faulty_devices: [as12/PHY]
      detailed_cause: >
        The OSPF network statement covering the PHY-NYC subnet was removed, so
        the adjacency never forms and traffic reroutes over the longer path.
    # What an agent should be told, and no more.
    symptom: Users report intermittent slowness between the datacentres.
```

### 3.2 The lifecycle

Every fault implements the same four operations, mirroring NIKA's
`ProblemBase`:

| Operation | Contract |
|---|---|
| `Inject(ctx, target)` | Apply the fault. Idempotent: injecting twice is injecting once. |
| `Verify(ctx, target)` | Confirm the fault is actually active, with evidence. An incident that failed to inject must never be presented to an agent as a puzzle. |
| `Resolve(ctx, target)` | Undo it, returning the network to baseline. |
| `GroundTruth()` | The machine-readable answer, in NIKA's `ProblemGroundTruth` shape. |

`Verify` is what makes the benchmark trustworthy. NIKA retries verification
because container state is transient; Twinet has a better primitive for this
already — the convergence predicates of [06](06_grading.md) §3 — so verification
waits for the fault to *manifest* rather than sleeping and hoping.

### 3.3 Ground truth

Emitted in NIKA's shape so scoring code is shared, not reimplemented:

```json
{
  "is_anomaly": true,
  "faulty_devices": ["as12/PHY"],
  "root_cause_category": "misconfiguration",
  "root_cause_name": ["ospf_neighbor_missing"],
  "detailed_cause": "The OSPF network statement covering ... was removed."
}
```

## 4. Coverage of NIKA's fault taxonomy

NIKA's registry currently defines **60** injectable root causes
(`/users/hy/nika/docs/failure-types.md`). Twinet registers **42** fault types,
of which **40 are NIKA types**; the remaining two (`bgp_peer_asn_misconfig`,
`host_network_down`) are Twinet's own.

The numbers below are produced by diffing `twinet fault list --json` against
NIKA's table, not by counting entries in this document. An earlier revision
claimed 47 of 48 by counting types the plan intended to add; the count was wrong
in both terms and stayed wrong through two reviews, which is a good argument for
generating it.

| | Count |
|---|---:|
| NIKA types | 60 |
| Implemented in Twinet | **40** |
| Not implemented | 20 |
| Twinet-only types | 2 |
| Total Twinet types | **42** |

Reproduce the accounting with:

```
twinet fault list --json | jq -r '.[].name' | sort > /tmp/have
grep '^| `' /users/hy/nika/docs/failure-types.md \
  | awk -F'|' '{gsub(/[ `]/,"",$3); print $3}' | sort -u > /tmp/want
comm -23 /tmp/want /tmp/have    # NIKA types Twinet does not implement
```

### 4.1 What is not implemented, and why

The 20 gaps are not scattered: they are four substrates Twinet does not emulate,
plus one family that is a design change rather than a fault.

| Group | Types | What it would take |
|---|---:|---|
| P4 / BMv2 | 6 | A `p4` device kind running BMv2 with a P4 program and a control plane |
| Kubernetes | 4 | A Kubernetes node kind, or delegation to NIKA's existing backend |
| DHCP | 5 | A DHCP server in the service image, and hosts that lease rather than are addressed |
| VPN membership | — | **implemented**, once the advanced-networks lab gave the platform an L3VPN to break: `host_vpn_membership_missing` takes a customer-facing port out of its routing table |
| SDN southbound | 3 | A `controller` device kind speaking OpenFlow to the OVS switches |
| Other | 2 | `mpls_label_limit_exceeded`, `load_balancer_overload` |

`mpls_label_limit_exceeded` was attempted and abandoned, which is worth
recording because the reason is not obvious. The limit that produces the fault
is `net.mpls.platform_labels`, and that file is read-only inside a container —
the same limitation that already forces the node agent to write the
per-interface MPLS input flag from the namespace rather than letting the
container do it. FRR's own `mpls label global-block` was tried as a substitute
and does not constrain labels LDP has already distributed: narrowing it to two
labels left the forwarding table unchanged, and clearing every LDP neighbour to
force re-allocation left it unchanged again. A fault that configures something
and changes nothing is worse than an absent one, so it is absent and counted as
a gap.

Twinet addresses every host statically from the plan, because the plan is also
the grading key: a check can say "the address is not the one the assignment
specifies" precisely because Twinet knows what that address is. Introducing DHCP
means introducing an address Twinet did not choose, which the grader would then
have to discover rather than know. That is a real design change, not a fault to
add, and it is why the DHCP family is listed here rather than implemented.

The P4 and SDN groups fit the device-kind model directly and are the natural
next extension. The Kubernetes group is a poor fit: those are a container
orchestrator's failure modes rather than a network's, and NIKA already has a
backend for them. **Recommendation: add P4 and SDN controller kinds; delegate
Kubernetes to NIKA's existing backend rather than duplicating it.**

### 4.2 What is implemented

All 39 shared types round-trip against a live cluster in
`TestEveryFaultRoundTrips`: each is injected, verified to have taken effect,
resolved, and then verified to be gone *and* to have left the device as it was
found (§4.3).

- **End-host failures.** `host_incorrect_ip`, `host_missing_ip`,
  `host_incorrect_netmask`, `host_incorrect_gateway`, `host_incorrect_dns`,
  `host_ip_conflict`, `host_crash`, `host_static_blackhole`. Because the model
  records the *correct* address, a wrong one is produced by perturbing a
  known-good value rather than hard-coded.
- **Link failures.** `link_down`, `link_detach`, `link_flap`,
  `link_fragmentation_disabled`, `dns_service_down`, `frr_service_down`.
- **Misconfiguration.** The BGP family (`bgp_asn_misconfig`,
  `bgp_missing_route_advertisement`, `bgp_blackhole_route_leak`), the OSPF
  family (`ospf_neighbor_missing`, `ospf_area_misconfiguration`), the packet
  filter family (`icmp_acl_block`, `bgp_acl_block`, `ospf_acl_block`,
  `http_acl_block`, `arp_acl_block`, `dns_port_blocked`), `mac_address_conflict`,
  and the OVS flow-rule faults `flow_rule_loop` and `flow_rule_shadowing`.
- **Under attack.** `bgp_hijacking`, `arp_cache_poisoning`, `web_dos_attack`,
  and the DNS record faults.
- **Resource contention.** `link_bandwidth_throttling`,
  `link_high_packet_corruption`, `dns_lookup_latency`,
  `incast_traffic_network_limitation`, `sender_resource_contention`,
  `receiver_resource_contention`, `sender_application_delay`.

### 4.3 Resolving is held to the baseline, not to the predicate

A fault is not undone when its own predicate goes false. It is undone when the
device is as the injection found it, and the difference between those two has
cost this project a week of grading.

`host_incorrect_gateway` pointed a host's default route at a dead neighbour and
resolved by deleting the default route; where no prior route had been recorded
it put nothing back. Its verifier asked "is the route via the wrong gateway?",
the answer was no, and the resolve was reported as clean — while the host was
left with no default route at all. The damage surfaced much later as a single
unreachable host in a grading run, by which point nothing connected it to the
fault that caused it.

So the engine now fingerprints the device before injecting, again immediately
after, and records the difference: the lines the fault introduced and the lines
it took away. Resolving must leave neither. The check is per-injection rather
than whole-state, so two faults active on one device do not accuse each other.

Recording the delta immediately found four more instances of the same class:
every fault that removes an address or downs an interface loses the routes that
resolved through it, and restoring the address or the link does not bring them
back. Those faults now save and replay the affected routes.

The fingerprint deliberately excludes state that moves on its own — routes
learned from BGP or OSPF, netem's per-creation random seed, interface indices,
and IPv6 link-local addresses derived from a MAC — because a check that reports
a difference on a healthy network is a check that gets switched off. It is
versioned, so refining it cannot strand injections recorded by an older build in
a state no undo can clear.

## 5. Integration with NIKA

Two directions, and both are worth having.

### 5.1 Twinet as a NIKA backend

NIKA's `LabRuntime` is an abstract base with a capability set
(`exec, inspect, node_status, interface, ip, route, dns, service, tc, nft,
iptables, process, pidfile, file, frr, traffic, k8s`) and about fifty semantic
operations that faults call: `set_interface_state`, `get_host_ip`,
`add_nft_drop_rule`, `tc_set_netem`, `frr_get_bgp_asn_number`, `kill_process`,
and so on.

Twinet exposes these through an adapter that subclasses NIKA's `LabRuntime`, so
NIKA's existing fault implementations run against a Twinet lab. They run
unmodified, but only once the runtime is told to present the `kathara` device
dialect: NIKA's problem classes dispatch on a literal backend name and refuse
anything they do not recognise, whatever the runtime implements. See
`contrib/nika/README.md`.

```
NIKA problem  ──▶  LabRuntime (twinet)  ──▶  twinetd API        ──▶  device
```

The adapter is small because the agent API already brokers exec into any
container on any node. The one thing Twinet must add is a **capability
declaration** so NIKA can refuse a fault the backend cannot serve rather than
injecting it half-way — the `required_capabilities` mechanism NIKA already has.

What Twinet brings that the existing backends do not:

- **Scale.** Kathará and containerlab are single-host. An RCA evaluation over
  hundreds of episodes is embarrassingly parallel and currently bounded by one
  machine; Twinet spreads episodes across a cluster.
- **Reproducibility.** Deterministic allocation means the same manifest yields
  the same addresses, identifiers and MACs on every run, on every machine. An
  agent's transcript from one episode is directly comparable with another's.
- **A clean reset.** The state store makes "return to baseline" a real
  operation rather than a full teardown and rebuild.

### 5.2 Twinet's native fault API

Twinet also exposes faults directly, so an incident can be run without NIKA:

```bash
twinet fault list                          # every registered fault type
twinet fault inject ospf-adjacency-lost    # apply, then verify it manifested
twinet fault verify ospf-adjacency-lost    # is it *still* doing what it claims
twinet fault resolve ospf-adjacency-lost
twinet fault status --json                 # what is currently injected
twinet incident run --scenario incidents/ospf.yaml --agent <endpoint>
```

`twinet fault verify` is worth using and easy to overlook. Injection verifies
once, but a lab runs for a long time afterwards: an interface comes back up, a
daemon is restarted, a student repairs the thing by accident, a container is
replaced and the fault goes with it. An evaluation that assumes the fault is
still present scores an agent's conclusion against a network that no longer has
the problem — which is worse than having no fault at all, because the episode
looks valid and its ground truth is wrong. Re-verify before scoring, or on a
timer for a long-running episode.

An **incident** is the reproducible unit: a lab manifest, a baseline, a set of
faults, and the ground truth. `twinet incident run` builds the lab, establishes
the baseline, injects, verifies, hands an endpoint to the agent, and scores the
diagnosis. It is the same machinery as `twinet grade`, pointed at a different
question: not "did the student configure this correctly" but "did the agent
work out what was wrong".

## 6. Consequences for the rest of the plan

Recording these here so they are not discovered late.

1. **Observability becomes a product surface, not a convenience.** What an
   agent can see *is* the benchmark. The telemetry an agent may query — routing
   tables, interface counters, logs, packet captures, the connectivity matrix —
   must be deliberate and, crucially, **must not leak the answer**. A fault
   labelled in a container label that an agent can read makes the task trivial.
   Ground truth must live only in the control plane.

2. **Baseline capture becomes mandatory, not optional.** An episode is
   *inject → observe → resolve → verify baseline restored*. Without a trustworthy
   baseline, episode *n+1* inherits episode *n*'s damage and results become
   unreproducible. The state store already built for protecting student work is
   exactly this mechanism, used for a second purpose.

3. **The ephemeral-lab work planned for grading is now doubly load-bearing.**
   Per-submission labs and per-incident labs are the same feature. It should be
   built once, generally.

4. **Faults must be resolvable, which constrains how they are injected.**
   A fault applied by rewriting a config file wholesale cannot be cleanly undone.
   Every fault must therefore record enough to reverse itself, or be expressed
   as a reversible delta. This is a design constraint on the fault API, not an
   afterthought.

5. **Determinism must extend to timing.** `link_flap` and `web_dos_attack` are
   time-varying. Reproducibility requires a seeded, recorded schedule rather
   than wall-clock randomness, so an episode can be replayed exactly.

6. **New services are needed.** DHCP (four fault types), a web service and load
   balancer (three), and traffic generation (four) are prerequisites. These join
   the [05](05_services.md) list, motivated now by two consumers rather than one.

7. **Isolation matters more.** In a class, one group's mistake affecting another
   is a nuisance. In a benchmark it is a corrupted measurement. Fault blast
   radius must be bounded and asserted.

## 7. Acceptance criteria

1. `twinet fault list` reports every registered type with its NIKA category and
   required capabilities.
2. All **47 in-substrate fault types** inject, verify and resolve on a Twinet
   lab, each covered by a test that asserts the fault manifests *and* that
   resolving it restores the baseline exactly.
3. Injecting a fault twice, and resolving one never injected, are both no-ops.
4. Ground truth serialises to NIKA's `ProblemGroundTruth` schema and is
   never observable from inside the lab.
5. NIKA runs an unmodified benchmark scenario against a Twinet backend and
   produces the same verdict it produces on containerlab for the same fault.
6. An episode is bit-reproducible: the same manifest, fault set and seed produce
   the same addresses, identifiers and fault schedule on any node.
7. **100 concurrent incident episodes** run across the cluster, each isolated,
   each resetting cleanly to baseline.

## 8. Milestone

This is **M8**, sequenced after the grading engine (M5), whose check framework
and ephemeral labs it reuses, and after the services (M2), which several fault
types require. See [07](07_roadmap.md).

## Coverage as measured

Counted by diffing `twinet fault list --json` against NIKA's registry; see §4
for the command. Do not edit these by hand — regenerate them.

| | Count |
| --- | --- |
| Registered in Twinet | 41 |
| NIKA types total | 60 |
| **Covered** | **39** |
| Not yet covered | 21 |

The 21 are not arbitrary: each needs a substrate the lab does not run — six P4,
five DHCP, four Kubernetes, three SDN southbound, and three others. They are
absent because the substrates are, and adding a fault against a service that
does not exist would produce an episode with no symptom, which is worse than an
absent fault because it looks like a working one.

Every registered fault is exercised against the live cluster by `make e2e`,
which injects and resolves all thirty-seven in about thirty-six seconds. A fault
that cannot be undone is treated as a failure there, because an episode that
contaminates the next one is worse than an episode that never ran.
