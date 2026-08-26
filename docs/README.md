# Twinet documentation

This directory is intentionally a mixed record: the early design documents
explain why Twinet was built, while [`09_status.md`](09_status.md) records what
the checked source and named cluster runs actually support.

## Reading status labels

| Label | Meaning |
|---|---|
| **Shipped / source-verified** | Present in this repository and covered by an automated test or source-derived documentation gate. |
| **Measured** | Observed in the named environment and recorded in [09](09_status.md); not a general performance promise. |
| **Target / planned** | An acceptance criterion or desired capability that has not been claimed as measured. |
| **Historical** | An assessment, original design, or decision record retained for context. It is not an implementation claim. |

The source facts block in [09](09_status.md) is machine-checked against
`cmd/*`, the runtime/NOS/interior/fault registries, and statistics emitted by a
CLI built from this source tree.

## Documents

| # | Document | Status and purpose |
|---|---|---|
| 01 | [Assessment](01_assessment.md) | Historical review of the predecessor platform |
| 02 | [Architecture](02_architecture.md) | Shipped architecture, with explicit non-claims |
| 03 | [Topology model](03_topology_model.md) | Shipped model capabilities and compatibility limits |
| 04 | [Networking and scale-out](04_networking_and_scaleout.md) | Shipped overlay/placement/durability model; measurements link to 09 |
| 05 | [Services and access](05_services.md) | Shipped service, endpoint, access, and observability behavior |
| 06 | [Grading](06_grading.md) | Shipped grading modes and measured evidence boundary |
| 07 | [Roadmap](07_roadmap.md) | Historical targets and remaining acceptance work |
| 08 | [Resources and decisions](08_resources_needed.md) | Historical environment/decision record |
| 09 | [Implementation status](09_status.md) | Canonical source facts, measurements, and remaining work |
| 10 | [Fault injection and RCA](10_fault_injection.md) | Separately maintained NIKA work |
| 11 | [Scalability and reliability objectives](11_scalability_and_reliability_objectives.md) | Separately maintained objectives and review gate |
| 12 | [Operator guide](12_operator_guide.md) | Shipped runbook: prerequisites, PKI, bootstrap, deploy, grade, recover, and safe removal |

## Documentation checks

Run both gates before changing documentation:

```sh
go test ./internal/cli -run 'Test(EveryDocumented|Documentation)'
python3 scripts/check_docs.py
```

The Go test rejects stale command names, flags no command accepts, and stale
generated capability facts. The Python checker validates local Markdown links,
referenced paths, and benchmark labels.
