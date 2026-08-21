# 05 — Services and access

> **Documentation status: shipped interfaces with measured evidence linked to
> [09](09_status.md).** This page does not turn a source capability into a
> claim that a particular course deployment has accepted it live.

## Service model

Services are declared in the lab model and expanded into deterministic service
instances. A service can use one of these replication modes:

| Mode | Shipped model behavior |
|---|---|
| `singleton` | One compatibility instance |
| `per-node` | One deterministic replica per selected node |
| `replicas` | A fixed replica count |
| `sharded` | Deterministic shard identities and attachment selection |

Replica identity, placement record keys, and attachment targets are explicit in
the expanded topology. A service policy can therefore be reviewed and
validated without assuming that every service belongs on a special front node.

The repository includes service/rendering support for course components such as
DNS, RPKI/RTR, matrix/measurement, and web surfaces. The status ledger records
which end-to-end behavior has been measured and which historical features
remain absent (for example, the historical-snapshot web time slider).

## Endpoint and access model

Gateway and web endpoints use an endpoint policy rather than an intrinsic
singleton node. The model supports ordered multi-endpoint active-active and
active-standby configurations; an optional VIP is an environment-dependent
convenience, not the source of truth for access.

The SSH gateway authorizes device access by identity and owner label, then
proxies execution to the node hosting that device. This removes the need to
describe every student as owning a host-level port or a dedicated proxy
container. Legacy access compatibility may be configured by a lab, but should
not be read as a security boundary.

`twinet save` and `twinet restore` preserve Twinet archives with topology and
integrity metadata. The old predecessor-platform directory-layout exporter and
gateway SFTP workflow are not claimed as shipped; see
[09 — Remaining work](09_status.md#remaining-work).

## Metrics and events

Agents expose bounded-cardinality Prometheus text at `/metrics`. They also
retain a bounded, durable, scoped event ring at `/v1/events`; the CLI's
`twinet events` command merges node streams and can follow them. Metrics omit
unbounded tenant/device/error labels, while events carry bounded identifiers and
can be filtered by lab.

These observability surfaces are shipped. A missing external metrics collector,
dashboard, or historical web view must not be represented as a missing metric
or event API.

## Images and dependencies

The build produces the executable entry points and image inputs found in this
repository. The exact executable list is generated from `cmd/*` in
[09](09_status.md); Docker Engine, Linux networking capabilities, and the
selected container images remain runtime dependencies. This documentation does
not claim a single self-contained binary or a fixed five-image inventory.

## Evidence boundary

The measured web/matrix and course-service results, if any, are stated in
[09](09_status.md). They are specific observations. The source model's service
replication and endpoint support are not a claim that failover, VIP behavior,
or every service replica has completed a live acceptance run.
