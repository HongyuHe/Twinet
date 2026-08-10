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
  # different targets, which is what turns 60 fault types into hundreds of
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

## 4. Coverage of NIKA's 60 fault types

Honest accounting. Of the 60 registered types, **47 map onto the substrate
Twinet already has or will have from the milestones in this plan**; 13 need
device or service kinds Twinet does not model today.

| Category | Types | On today's substrate | Needs new substrate |
|---|---:|---:|---|
| End-host failures | 9 | 9 | — |
| Link failures | 7 | 6 | `bmv2_switch_down` (P4) |
| Misconfigurations | 17 | 14 | 3 Kubernetes types |
| Network node errors | 13 | 5 | 5 P4, 1 Kubernetes, 2 SDN southbound |
| Network under attack | 6 | 6 | — |
| Resource contention | 8 | 8 | — |
| **Total** | **60** | **47** | **13** |

### 4.1 Directly supported

- **End-host failures (9/9).** `host_incorrect_ip`, `host_missing_ip`,
  `host_incorrect_netmask`, `host_incorrect_gateway`, `host_incorrect_dns`,
  `host_ip_conflict`, `host_crash`, `dns_record_error`,
  `host_vpn_membership_missing`. All are `ip`/`resolv.conf`/container-state
  operations on a host, which the runtime and `netx` already do. Twinet has an
  advantage here: because the model records the *correct* address, an incorrect
  one is generated by perturbing a known-good value rather than hard-coded.

- **Link failures (6/7).** `link_down`, `link_detach`, `link_flap`,
  `link_fragmentation_disabled`, `dns_service_down`, `dhcp_service_down`.
  `link_down` and `link_flap` are `netx` interface-state changes; `link_detach`
  removes the veth; fragmentation is an MTU/DF manipulation. Service-down faults
  need the DNS and DHCP services of [05](05_services.md).

- **Misconfigurations (14/17).** The BGP family (`bgp_asn_misconfig`,
  `bgp_acl_block`, `bgp_missing_route_advertisement`,
  `bgp_blackhole_route_leak`), the OSPF family (`ospf_neighbor_missing`,
  `ospf_area_misconfiguration`, `ospf_acl_block`), the ACL family
  (`icmp_acl_block`, `http_acl_block`, `arp_acl_block`, `dns_port_blocked`),
  `host_static_blackhole`, `mac_address_conflict`, `dhcp_missing_subnet`. FRR
  and nftables operations, both of which Twinet drives already.

- **Network under attack (6/6).** `bgp_hijacking` already exists as a
  behaviour and is the basis of the RPKI exercise. `arp_cache_poisoning`, the
  three `dhcp_spoofed_*` variants and `web_dos_attack` need an attacker device
  and traffic generation, which is a host container with a script.

- **Resource contention (8/8).** `link_bandwidth_throttling`,
  `link_high_packet_corruption` and `dns_lookup_latency` are `tc` operations —
  and Twinet's shaping layer is now tested to program the *correct* burst and
  queue, which matters more here than anywhere: an RCA benchmark whose
  bandwidth fault is silently eight times off is measuring the wrong thing.
  `incast_traffic_network_limitation`, `sender_*`/`receiver_resource_contention`
  and `sender_application_delay` need traffic generation and cgroup limits,
  both available through the runtime.

- **Network node errors (5/13).** `frr_service_down`,
  `mpls_label_limit_exceeded`, and the OVS flow-rule faults `flow_rule_loop` and
  `flow_rule_shadowing` (Twinet runs real Open vSwitch, so these are
  `ovs-ofctl` operations without needing a controller).

### 4.2 Requiring new substrate

These are **not refused, but scoped**. Each needs a new device kind, and the
kind system is the extension point for exactly this:

| Group | Types | What is needed |
|---|---|---|
| P4 / BMv2 | `bmv2_switch_down`, `p4_table_entry_missing`, `p4_table_entry_misconfig`, `p4_header_definition_error`, `p4_compilation_error_parser_state`, `p4_aggressive_detection_thresholds` | A `p4` device kind running BMv2 with a P4 program and a control plane |
| Kubernetes | `k8s_coredns_isolated`, `k8s_networkpolicy_deny`, `k8s_worker_apiserver_partition`, `k8s_clusterip_routing_broken` | A Kubernetes node kind, or delegation to NIKA's existing Kubernetes backend |
| SDN southbound | `sdn_controller_crash`, `southbound_port_block`, `southbound_port_mismatch` | A `controller` device kind (ONOS or Ryu) speaking OpenFlow to the OVS switches |

The P4 and SDN groups are a natural fit for Twinet's model and are proposed as
follow-on work. The Kubernetes group is a poor fit: it is a container
orchestrator's failure modes, not a network's, and NIKA already has a backend
for it. **Recommendation: implement P4 and SDN controller kinds; delegate
Kubernetes to NIKA's existing backend rather than duplicating it.**

## 5. Integration with NIKA

Two directions, and both are worth having.

### 5.1 Twinet as a NIKA backend

NIKA's `LabRuntime` is an abstract base with a capability set
(`exec, inspect, node_status, interface, ip, route, dns, service, tc, nft,
iptables, process, pidfile, file, frr, traffic, k8s`) and about fifty semantic
operations that faults call: `set_interface_state`, `get_host_ip`,
`add_nft_drop_rule`, `tc_set_netem`, `frr_get_bgp_asn_number`, `kill_process`,
and so on.

Twinet will expose these through a thin adapter, so NIKA's existing 60 fault
implementations run unmodified against a Twinet lab:

```
NIKA problem  ──▶  LabRuntime (twinet)  ──▶  twinet agent API  ──▶  device
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
twinet fault verify ospf-adjacency-lost
twinet fault resolve ospf-adjacency-lost
twinet fault status --json                 # what is currently injected
twinet incident run --scenario incidents/ospf.yaml --agent <endpoint>
```

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
