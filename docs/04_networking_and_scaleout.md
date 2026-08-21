# 04 — Networking and scale-out

> **Documentation status: shipped mechanism; measurements are canonical only
> in [09](09_status.md).** A logical point-to-point lab link must not be
> confused with the host overlay object that carries it.

## Link realization

Same-node endpoints are connected by a veth pair moved into their container
network namespaces. A logical cross-node link remains a two-endpoint segment
with its own deterministic VNI, shaping, and ownership metadata.

New cross-node deployments use a **shared** overlay:

```text
container -- veth -- VLAN-filtering bridge -- external VXLAN -- underlay
                          ^                    ^
                          |                    |
                 one per lab/node pair   one per lab/node pair
```

For every `(lab, node pair)`, the engine creates one flow-based/external VXLAN
device and one VLAN-filtering bridge. Each logical link receives a deterministic
bridge VLAN mapping to its VNI, plus the corresponding FDB binding. This bounds
the host-level overlay objects by node pairs while retaining wire isolation for
each logical link.

The old per-link bridge/VXLAN implementation remains only for safe recognition
and cleanup of legacy objects. It is not the description of new deployments.
There is no EVPN control plane claim and no claim that the teaching protocol
multicast exercise uses underlay multicast.

Authenticated `twinet node sweep` evidence is recorded in
[09](09_status.md): active shared-overlay bindings must be classified through
the agents' ownership data, not by an earlier shell-only orphan heuristic.

## MTU and shaping

The agent applies link shaping at the container-side interface, so the
bandwidth/delay/queue policy is the same whether a link is local or crosses the
underlay. The underlay budget accounts for VXLAN encapsulation and node checks
refuse an incompatible requested MTU.

**Measured environment finding:** the documented cluster did not retain jumbo
frames, so its lab links use a uniform 1450-byte MTU. This is an environment
fact, not a universal default; see
[09 — Environment findings](09_status.md#environment-findings).

## Placement and admission

Placement records keep assignments stable across controller invocations.
Ordinary ASes are atomic placement units; a declared distributable Clos can use
its explicit placement groups. Rebalance and node drain use fenced coordination
and staged placement records rather than treating a move as a local rename.

Placement is not admission. Before a clustered deployment or harness wave
mutates runtime state, strict admission compares resolved resource requests
with live allocatable inventory. Missing inventory and overload are refusals.
`--overcommit` is an explicit audited override, not an implicit scheduling
fallback.

The current scale result is **measured**, not a capacity promise:
[09 — Measurements](09_status.md#measurements) records its topology, node
count, timing, utilization, and qualification.

## Durable state and node loss

The state policy distinguishes a local single-copy lab from a replicated
cluster policy. Agents capture student-owned state, exchange content-addressed
artifacts, persist acknowledgements, and require the configured evidence at
destructive/migration boundaries. Peer state transfer uses a peer-scoped mTLS
route rather than controller mutation credentials.

This is a shipped implementation path. It does not justify an unconditional
claim that every failure mode has passed live acceptance: the known recovery
limits and remaining acceptance work are listed in [09](09_status.md).

## Access and services are not front-node singletons

Gateway and web endpoint policies can publish ordered multi-endpoint sets with
active-active or active-standby behavior. Service replication policies can
place singleton, per-node, fixed-replica, or sharded services. A manifest may
still deliberately pin a service for a particular deployment, but the
architecture does not require a singleton “front node.”

## Historical terminology

Earlier architecture text called every cross-node link “a per-link VXLAN,”
quoted an obsolete underlay latency experiment, and described all access,
web, and VPN services as front-node singletons. Those statements are
historical design notes and are not retained as current behavior.
