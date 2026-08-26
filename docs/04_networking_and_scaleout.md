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

### Scale request calibration

Requests are a guaranteed steady-state/convergence share, not a Docker burst
cap. The bundled scale manifest reserves `0.04` CPU for a router shell plus
`0.08` for its private FRR control sidecar (`0.12` aggregate), `0.02` for a
host, `0.04` for a switch, and `0.10` for a service. Its existing CPU/memory/PID
limits remain burst caps (for example, the router remains `2 CPU / 512Mi`).

`twinet inspect --capacity -m examples/scale` reports every primary request,
FRR controls separately, node totals, and static-capacity pressure. The
three-worker planning result is 110.60 requested CPU against 151.20 allocatable
CPU before the front-node reserve; the heaviest placed node remains below 80%.
Memory, PID, FD, disk, and netdev reservations remain explicit, and the scale
manifest reserves front-node service headroom.
`placement.convergence.max_concurrent` queues router starts instead of inflating idle CPU requests;
the node-wide convergence limiter also protects concurrent labs.

The 22 GiB / load-13-of-56 observation in [09](09_status.md) motivated this
calibration, but it is not evidence for the revised sidecar-aware deployment.
Run a live initial deploy and capture peak agent inventory before promoting
this planning result to a measured acceptance claim. Agent status exposes
`inventory.used` and the agent-lifetime high-water `inventory.peak` for that
capture.

The current scale result is **measured**, not a capacity promise:
[09 — Measurements](09_status.md#measurements) records its topology, node
count, timing, utilization, and qualification.

## Durable state and node loss

The state policy distinguishes a local single-copy lab from a replicated
cluster policy. Agents capture student-owned state, exchange content-addressed
artifacts, persist acknowledgements, and require the configured evidence at
destructive/migration boundaries. Peer state transfer uses a peer-scoped mTLS
route rather than controller mutation credentials. Each node has a
replication-only peer client leaf separate from its listener certificate;
peer retries use bounded backoff and node status reports failed or missing
peer acknowledgements. Rolling replacement of a peer leaf signed by the
cluster CA is supported without granting controller authority.

Recovery does not treat a matching container/VNI inventory as success. Before
commit it checks the exact rendered files plus host addresses/default routes,
switch VLAN state, router NOS readiness, and service health for every touched
device. A solved host regains its reference address and route; a teaching-mode
student-owned interface remains deliberately blank unless a saved student
snapshot requires it.

No-change deploy observation also probes compact live semantic fingerprints.
An address/route/BGP-session drift becomes a targeted configure/ready plan;
an actually healthy no-change deployment still has zero mutation steps.

A zero-change deployment and degraded semantic health are mutually exclusive
answers. Agents publish their audited convergence state — the same evidence
`twinet node status` shows — in the read-only plan preflight and in every apply
response. The controller refuses a no-op witness from a node reporting drifted
devices, and a deployment that reports no changes against a degraded cluster
fails with a non-zero status naming the drift instead of printing
`0 devices, 0 links`.

Repair of a shared trunk is bounded and non-destructive. One node pair carries
one trunk, so replacing its receive socket destroys every VNI binding on it;
the bindings are therefore recorded and reinstalled across any such
replacement, and unattended repair never forces one at all — it restores the
missing binding, host port, address, or interface for the one device it is
repairing. Distributed drift that no local repair can fix is retried for a
bounded number of cycles and then enters an explicit terminal state that is
alerted, counted in `twinet_semantic_repair_terminal`, and named in node
status. It is never retried for ever, and a later healthy observation clears
it.

FRR routers use a private control sidecar: legacy daemons in the student shell
are stopped before the sidecar owns the daemon set, and recovery refuses
duplicate sidecar daemons. `twinet node status` reports primary topology
containers separately from internal control sidecars and includes a concrete
container-list error when Docker inventory cannot be read.

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
