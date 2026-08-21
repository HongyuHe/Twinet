# 07 — Roadmap

> **Documentation status: historical plan and future acceptance targets.**
> This is not the implementation ledger. Source-verified capabilities and
> measured runs are recorded in [09 — Implementation status](09_status.md).
> A completed-looking item here must never override an explicit remaining item
> in that ledger.

## Current interpretation of the original milestones

| Milestone | Current status | Evidence boundary |
|---|---|---|
| M0 — foundations | Source-verified | Model, manifest validation, schema, and tests exist |
| M1 — single-node core | Source-verified | Expansion, Docker runtime, wiring, rendering, and deployment code exist |
| M2 — services and access | Partly shipped | Endpoint/service models, gateway, save/restore, web, metrics, and events exist; the ledger names remaining service/UI work |
| M3 — cluster fabric | Source-verified and measured in part | HTTP+mTLS agents, fenced coordination, shared overlays, and placement exist; named cluster observations are in 09 |
| M4 — operations | Partly shipped | Holds, repair, events, persistence, and fencing exist; minimal desired/observed reconciliation is not claimed complete |
| M5 — grading | Source-verified and measured in part | Rubrics, checks, class/batch modes, and reports exist; throughput claims remain qualified measurements |
| M6 — scale validation | Measured target not met | The recorded class-scale deployment is evidence, not completion of the original target |
| M7 — course parity | Partly shipped | Advanced MPLS/VRF and multicast examples exist; no blanket course-parity acceptance is claimed |
| M8 — fault/RCA | Separately maintained | See [10](10_fault_injection.md); do not infer its live acceptance from this roadmap |
| M9 — heterogeneous NOS | Source-verified in part | FRR/BIRD providers and capability validation exist; broad mixed-vendor live acceptance is not claimed |
| M10 — generated interiors | Source-verified in part | The registered interior generators exist; full live-cluster acceptance remains unmeasured |

## Open acceptance work

The current remaining-work table in [09](09_status.md#remaining-work) is the
authoritative list. In particular, a source capability must not silently become
“done” merely because the historical deliverable was listed here.

## Historical targets

<!-- benchmark: target -->
The original plan set targets for a class-scale deployment, class-sized grading,
soak duration, and broad course parity. They remain **targets**, not achieved
performance claims. The measured class-scale run is explicitly recorded as
above the original deployment target in
[09 — Measurements](09_status.md#measurements).

<!-- benchmark: target -->
Any future acceptance run must state the topology, node count, image/runtime
revision, admission state, workload, successful/quarantined submissions, and
wall-clock metric. A target must be labelled “target”; a result must be labelled
“measured” and link to the canonical status ledger.

## Historical design notes

The original milestones mentioned a gRPC agent API, a stateless two-binary
deployment, one overlay device per logical cross-node link, a planned event
stream, and a singleton front node. Those were planning assumptions. The
shipped architecture uses HTTP/JSON+mTLS, persistent state, source-generated
binary facts, shared overlays, events/metrics, and endpoint policies; see
[02](02_architecture.md), [04](04_networking_and_scaleout.md), and
[05](05_services.md).
