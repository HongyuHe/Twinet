# 02 — Architecture

> **Documentation status: shipped architecture plus explicit limits.** This
> document describes APIs and data paths present in the source tree. Live
> acceptance and performance evidence belongs in
> [09 — Implementation status](09_status.md), not in this design summary.

## Control plane and agent transport

`twinet` expands a manifest, resolves placement, performs admission, and
coordinates node agents. `twinetd` owns the privileged node-local work:
containers, network namespaces, links, overlays, state capture, and repair.

The controller-to-agent protocol is an **HTTP/JSON API**, implemented with
Go's `net/http`; it is not gRPC. On a non-loopback listener an agent refuses to
start without a TLS 1.3 server certificate, key, and client CA. It requires and
verifies client certificates, then applies its scoped authorization and
controller-token checks. Plain HTTP is limited to loopback or an explicit
development override.

The API includes status/inventory, apply phases, destroy, exec/attach, state
transfer, fenced lease operations, overlay reservations, events, and metrics.
The raw attach stream reuses the authenticated HTTP/TLS connection rather than
opening a weaker side channel.

```text
operator / CLI
       |
       | HTTPS + mTLS + JSON
       v
  node agents  ---- runtime Engine API ---- containers
       |                   |
       +---- netlink ---- namespaces, veths, shared VXLAN fabric
```

## Runtime and command boundary

Docker, Podman, and containerd are registered runtime backends. Docker's normal
implementation uses the Docker **Engine API**; a CLI fallback has narrower
semantics. Podman and containerd each have a bounded live integration result
recorded in [09](09_status.md).

Selection is a manifest and agent contract, not an implicit property of the
host. `placement.runtime` states the lab's backend and `placement.nodes[]`
may narrow it per node; `--runtime`/`TWINET_RUNTIME` overrides both for one
invocation and every node at once; `twinetd -runtime` is what an agent actually
runs, and the controller refuses to mutate a node that reports a different
backend. Validation checks the selection against the registry's declared
capabilities before a deployment acquires a lease. Every bundled example
declares its backend; an omitted selection still means Docker, for manifests
written before the registry existed, and validation says so.

The exact registered runtime and executable lists are generated in
[09](09_status.md), so this document does not claim that Twinet consists of two
binaries or one dependency-free binary.

A deployment needs Linux networking privileges, a reachable container engine of
the selected kind, and the images the manifest selects. Static Go linking can
simplify packaging for individual helpers, but does not remove those
operational dependencies. [12](12_operator_guide.md) is the runbook that
installs them.

## Desired state, observed state, and durable state

Manifest expansion and allocation are deterministic: names, addresses, VNIs,
and placement inputs can be reproduced from the authored lab. Container labels
remain useful observed state for reconciliation.

That does **not** mean Twinet has no state store. The node-local store persists
student-owned snapshots, the applied topology, holds and exemptions,
coordination high-water marks, overlay claims, ephemeral lab deadlines, event
journals, and replica acknowledgements. Content-addressed records and atomic
current pointers make a restart/recovery path possible without treating student
work as disposable derived state.

Every durable write is a temporary file, an fsync and a rename, and the
temporary is removed on every path including a failed rename. A process killed
between the two leaves one behind; opening the store sweeps temporaries older
than an hour, which is far longer than any write and short enough that the disk
holding the only copy of a class's work does not accumulate them. The node
event journal is append-only with size-bounded compaction rather than a full
rewrite per event, so the work of recording an event is the size of that event
rather than the size of everything the node has recorded.

The deployment engine captures student-owned state before destructive
boundaries and restores it after a replacement. Clustered policies can require
replica acknowledgements in separate failure domains before destructive work.
The exact policy fields and the limits of node-loss recovery are described in
[Networking and scale-out](04_networking_and_scaleout.md).

## Cluster mutation and ownership

Agents issue short-lived, opaque, **fenced** mutation leases per lab. Fence
generation high-water marks and unfinished transaction data are persisted; a
restarted or stale controller cannot resume an older mutation merely because it
still has a token. Apply uses prepare/commit/finalize phases and reserves
cross-node overlay identifiers under the same fence.

The in-process per-lab operation lock prevents overlapping local work. It is
not a replacement for the cluster fence, and it is not described as one.

## Lab lifetime: durable and ephemeral labs

A teaching lab is durable. It exists because a course says so, it outlives
every controller process, and nothing removes it automatically.

A lab may instead be deployed **ephemeral**, which says the opposite: it exists
only while a controller is running, and nobody's work is in it. Grading
harnesses are the only ephemeral labs today, and `internal/harness` marks every
harness it builds. The marker travels on the apply request and on the persisted
topology, so an agent restart still knows which kind of lab it is holding.

An ephemeral lab has a durable deadline on each node. The controller extends it
by heartbeat (`POST /v1/ephemeral`); no heartbeat can extend it past an
absolute ceiling measured from first deployment, and a heartbeat can never
create a lifetime for a lab no deployment declared disposable. When the
deadline passes, the node reclaims the lab on its own authority: it takes a
fresh internal fence, preempts its own repair loop, removes the containers, the
overlays it owns, its reservations and its records, and forgets it. A lab that
is currently leased by a live controller or held for grading defers rather than
being taken away, and every reason to defer is itself time-bounded.

This is what makes a killed grading controller survivable. Without it an
abandoned harness is indistinguishable from a course's lab: its containers are
running so collection protects it, its topology record is on disk so every
restart rehydrates it, reconciliation repairs it forever, and its own repair
lease answers a later destroy with a conflict.

## Network realization

Same-node links use veth pairs. A logical cross-node link has a VNI, but new
deployments do **not** create one VXLAN netdev per logical link. They use one
external/flow-based VXLAN and one VLAN-filtering bridge per `(lab, node pair)`;
deterministic bridge VLAN mappings select each logical VNI. Legacy per-link
overlay cleanup remains only for safe upgrade/recovery.

This arrangement keeps logical link isolation while bounding host overlay
objects by node pairs. Details, MTU behavior, and placement are in
[Networking and scale-out](04_networking_and_scaleout.md).

## Observability and admission

Agents publish bounded-cardinality Prometheus text at `/metrics` and retain a
bounded, durable, lab-scoped event stream at `/v1/events`. `twinet events`
merges node pages and can follow them. These are shipped surfaces, not roadmap
items.

Before a clustered deployment mutates nodes, strict admission reads live
inventory and compares fully resolved resource requests with allocatable
capacity. Unknown capacity and overload are refusals; `--overcommit` is an
audited escape hatch. This is distinct from Docker hard limits.

## NOS and generated interiors

The registered NOS providers are FRR and BIRD. Providers declare capabilities;
manifest validation rejects a router/NOS request the provider cannot support.
BIRD support is intentionally narrower than FRR's: it does not claim Twinet
support for MPLS/LDP, VRF, multicast, DHCP, RPKI, or tunnels through BIRD.

The shared generator registry includes `explicit`, `ring`, `two-tier`, and
`clos` interiors. Expansion produces ordinary devices and links; a declared
distributable Clos may be split only along its defined placement groups.
Source support is not a claim that every live course acceptance scenario has
been measured.

## Historical design material

Earlier revisions of this document described gRPC, two binaries, a stateless
controller with no store, per-link VXLAN devices, a planned event stream, and a
singleton front node. Those were design assumptions, not the current
implementation, and are intentionally not retained as present-tense behavior.
