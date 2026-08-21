# Twinet

Twinet is a Go implementation of a container-based teaching network twin. It
builds, places, operates, and grades labs made of real Linux containers,
routers, and switches.

> **Documentation status.** “Shipped” below means a capability exists in this
> source tree and is covered by automated checks. “Measured” means a result was
> observed on the named cluster run in
> [the status ledger](docs/09_status.md); it is not a release or capacity
> promise. “Target” and “historical” claims are explicitly labelled in the
> supporting documents.

## Shipped implementation

- The controller talks to node agents through an HTTP/JSON API. A non-loopback
  agent requires TLS 1.3 mutual authentication (plus its controller token);
  this is **not gRPC**.
- The build contains several command entry points, not just a controller and
  agent. The source-generated list, runtime/NOS registries, interior generators,
  fault count, and bundled-example statistics are checked in
  [`docs/09_status.md`](docs/09_status.md).
- Docker and Podman are registered runtimes; Docker uses the Docker Engine API.
  Podman's API contract has a bounded live integration result in the status
  ledger, but manifest/agent runtime selection is still pending. Twinet
  therefore has host and image dependencies; it is not a one-binary,
  dependency-free deployment.
- Deterministic allocation still derives names, addresses, and link identifiers
  from a manifest. Student-owned configuration, topology/coordination records,
  event journals, and replica acknowledgements are instead persisted in the
  state store.
- Cluster mutation uses fenced leases and transactional agent phases. Cross-node
  links share one external VXLAN device per lab/node pair; bridge VLAN-to-VNI
  bindings isolate logical links.
- State and services have replication policies, strict live-inventory admission
  runs before cluster mutation, and agents expose bounded Prometheus metrics and
  a durable, scoped event stream.
- FRR and BIRD are registered NOS providers. `explicit`, `ring`, `two-tier`,
  and `clos` are registered interior generators. Capability validation refuses
  unsupported NOS/topology combinations before deployment.

The precise scope and evidence for these features are deliberately kept out of
marketing language: see [Implementation status](docs/09_status.md).

## Evidence, not promises

The current measured reference deployment is a 12-AS lab. Its timing range,
the class-scale result, and grading measurements are recorded only in
[`docs/09_status.md#measurements`](docs/09_status.md#measurements). They are
measurements from a specific three-node environment, not claims that every
machine or course will obtain the same result.

Multicast and the RPKI hijack exercise are implemented examples with grading
checks and behaviour/fault support. Their source coverage does not imply that
every course acceptance scenario has been run live; the distinction is recorded
in the status ledger.

## Documentation

| Document | Scope |
|---|---|
| [Assessment](docs/01_assessment.md) | Historical assessment of the predecessor platform |
| [Architecture](docs/02_architecture.md) | Source-verified control-plane and persistence architecture |
| [Topology model](docs/03_topology_model.md) | Manifest, NOS, interior, and behaviour model |
| [Networking and scale-out](docs/04_networking_and_scaleout.md) | Shared overlay, placement, durability, and admission design |
| [Services and access](docs/05_services.md) | Services, replicas, access, metrics, and events |
| [Grading](docs/06_grading.md) | Shipped grading modes and evidence boundaries |
| [Roadmap](docs/07_roadmap.md) | Historical targets and remaining acceptance work |
| [Resources and decisions](docs/08_resources_needed.md) | Historical decision record and current evidence boundary |
| [Implementation status](docs/09_status.md) | Canonical shipped/target/measured ledger |
| [Fault injection and RCA](docs/10_fault_injection.md) | NIKA fault work (maintained separately) |
| [Scalability and reliability objectives](docs/11_scalability_and_reliability_objectives.md) | Objectives and review gate (maintained separately) |

## Validation

Documentation gates are executable:

```sh
go test ./internal/cli -run 'Test(EveryDocumentedCommandExists|Documentation)'
python3 scripts/check_docs.py
```

The first command checks documented commands and source-derived capability
facts. The second checks Markdown local links, referenced paths, and benchmark
labels. Full source validation remains:

```sh
go test ./...
```

## Credits

Twinet builds on the teaching ideas of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project) by
the Networked Systems Group at ETH Zürich. It shares no code with that project.
