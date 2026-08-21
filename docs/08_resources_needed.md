# 08 — Resources and decisions

> **Documentation status: historical decision record.** The environment facts
> and requests that originally appeared here were time-bound planning inputs.
> They are not a promise that machines, credentials, images, ports, or access
> remain available today. Current measured environment findings belong in
> [09](09_status.md).

## Decisions retained from the original plan

| Decision | Historical rationale | Current documentation boundary |
|---|---|---|
| Go implementation | Typed model and native Linux networking APIs | The source now has multiple executables and Docker/Linux dependencies; it is not described as one dependency-free binary |
| Purpose-built cluster agent | Avoid a Kubernetes control-plane dependency for this workload | The agent is HTTP/JSON+mTLS and has persistent state/coordination; it is not the older gRPC/stateless design |
| Manifest-driven labs | Avoid duplicated addressing/topology generators | Deterministic allocation coexists with durable student/control state |
| Course compatibility | Preserve useful teaching workflows where practical | Only interfaces and exporters listed as shipped in 09 are claimed |
| Scale-out | Place topology across nodes | Measured capacity is environment-specific and is not inferred from a planning estimate |

## Current resource questions

The following are operational inputs for a future live deployment, not completed
requirements inferred from source code:

- a supported Linux/Docker environment and the privileges needed by the node
  agent;
- a protected control-plane network and mTLS material;
- explicit capacity/inventory data for strict admission;
- a published endpoint policy if students need external gateway or web access;
- real, anonymised submissions only where a course owner authorizes their use
  for grader validation; and
- an explicit operator acknowledgement before destructive benchmark, chaos, or
  soak commands.

The repository intentionally does not treat a successful unit test as proof
that any of these external resources exist.

## Evidence and acceptance

The latest recorded underlay MTU finding, deployment observations, and grading
measurements are **measured** evidence in [09](09_status.md), not re-stated
here. Any future capacity or timing goal is a **target** until that ledger
records a named run.

<!-- benchmark: target -->
Requests for additional nodes, long-duration soak runs, or class-scale grading
deadlines are targets/planning inputs. They are not current acceptance claims.
