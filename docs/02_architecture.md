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

Docker and Podman are registered runtime backends. Docker's normal
implementation uses the Docker **Engine API**; a CLI fallback has narrower
semantics. Podman's API contract has a bounded live integration result recorded
in [09](09_status.md), but registration/testing does **not** make it a
manifest-selectable or agent-selectable runtime: that selection work remains
pending. The exact registered runtime and executable lists are generated in
[09](09_status.md), so this document does not claim that Twinet consists of two
binaries or one dependency-free binary.

A deployment needs Linux networking privileges, a reachable Docker Engine, and
the images selected by the manifest. Static Go linking can simplify packaging
for individual helpers, but does not remove those operational dependencies.

## Desired state, observed state, and durable state

Manifest expansion and allocation are deterministic: names, addresses, VNIs,
and placement inputs can be reproduced from the authored lab. Container labels
remain useful observed state for reconciliation.

That does **not** mean Twinet has no state store. The node-local store persists
student-owned snapshots, the applied topology, holds and exemptions,
coordination high-water marks, overlay claims, event journals, and replica
acknowledgements. Content-addressed records and atomic current pointers make a
restart/recovery path possible without treating student work as disposable
derived state.

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
