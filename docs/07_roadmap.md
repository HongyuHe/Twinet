# 07 — Roadmap

Milestones are ordered so that each one ends in something demonstrable, and so
that the riskiest assumptions are tested early (M3, the cluster fabric, is
deliberately not left to the end — its core primitive is already validated).

> **Optimisation target.** Development cost — in time or money — is explicitly
> *not* a constraint on this project. The sole objective is the best possible
> outcome: correctness, clarity, maintainability, and scale. Where a cheap
> shortcut and a thorough solution disagree, take the thorough one. Build the
> test, write the doc, generate the schema, measure the benchmark, and delete
> the special case. Day estimates below are for sequencing only, never as a
> reason to cut scope.

Effort is given in working days of focused implementation.

---

## M0 — Foundations (2 d)

**Deliver:** repo skeleton, CI, and the typed model.

- Go module, package layout (doc 02 §3), `golangci-lint`, `go test` in GitHub
  Actions, `goreleaser` for binaries, `docker buildx` for images.
- `internal/model`: `Lab`, `AS`, `Device`, `Iface`, `Link`, `L2Domain`,
  `Service`, `Peering`, with the `provisioned/student/expected` contract.
- JSON Schema **generated from** the Go structs (no dual source of truth).
- `twinet validate` with aggregated, positioned error reporting.

**Acceptance:** `twinet validate examples/demo/twinet.yaml` reports all seeded
errors in one pass, with `file:line:col`; schema generation is a CI check.

---

## M1 — Single-node core (5 d)

**Deliver:** deploy a real, working 12-AS mini-Internet on node-0.

- `internal/manifest` (load/merge/inherit), `internal/expand` (AS templates →
  concrete devices), `internal/ipam` (expression evaluation + overlap
  detection), `internal/alloc` (deterministic VNI/MAC/port/name).
- `internal/runtime/docker` + `internal/runtime/fake`.
- `internal/netx`: veth, netns, rename/MAC/MTU/up, altnames, `tc netem`+`tbf`,
  OVS port programming inside switch containers.
- `internal/plan`: staged DAG (`image→create→wire→configure→healthy→ready`),
  worker pool, readiness predicates (no sleeps).
- `twinet deploy | destroy | inspect | exec | graph`.
- Images: `twinet-router`, `twinet-host`, `twinet-switch`.
- Config rendering: FRR/`daemons`/host addressing for *provisioned* items only.

**Acceptance:** `twinet deploy examples/demo` brings up 12 ASes (~300
containers) on node-0; `twinet inspect` shows all healthy; a manually
configured AS reaches another AS; `twinet destroy` leaves zero residue
(no containers, veths, netns, or bridges).

---

## M2 — Services and access (5 d)

**Deliver:** the full service federation and the student experience.

- DNS zone generation + `twinet-dns`; forward and reverse for every prescribed
  subnet.
- Distributed matrix prober; structured looking-glass collector; BGP policy
  analyzer (RFC 7908 + Gao-Rexford against declared relationships).
- IXP route server with community-gated relay.
- Krill + Routinator provisioning via a typed client (root CA, per-AS child CA,
  TAL distribution, RTR wiring), fully idempotent.
- Measurement vantage point.
- Web UI (embedded Go templates): matrix, looking glass, AS connections, BGP
  analysis, Krill proxy.
- SSH gateway: identities, authz by label, `goto`/`save`/`restore`/`status`
  built-ins, tab completion, audit log, legacy `2000+X` ports, SFTP for bundles.
- `twinet save` / `twinet restore` in the legacy layout + `manifest.json`.
- `twinet gen roster` (CSV → ASN assignment, credentials, hand-outs).

**Acceptance:** a student SSHes in, configures OSPF+iBGP+eBGP by hand following
the COS-461 wiki verbatim, sees the matrix turn green, issues a ROA in Krill,
and downloads a config bundle — with no step in the wiki needing edits beyond
the hostname.

---

## M3 — Cluster fabric (4 d)

**Deliver:** the same lab spread across node-0/1/2.

- `twinetd` as a systemd service; `twinet node bootstrap|status`; mTLS.
- gRPC API and typed client; exec brokering for the gateway.
- Cross-node VXLAN links (deterministic VNI, static FDB, uniform MTU).
- `internal/place`: AS-granular bin-packing + cross-node edge minimisation;
  stable placement; `twinet inspect placement`.
- Node sysctls/modules applied automatically.
- **M3-1 validation task:** confirm `eno2` supports MTU 9000 on all nodes;
  otherwise pin lab MTU to 1450 uniformly.

**Acceptance:** the 12-AS demo deploys across 3 nodes; a cross-node inter-AS
link shows the configured 2.5 ms / 1 mbit (not 0.16 ms / 10 Gbit); killing
`twinetd` on node-1 does not disturb traffic; restarting it re-inventories
correctly; `twinet destroy` cleans all three nodes.

---

## M4 — Reconciliation and operations (3 d)

**Deliver:** safe day-2 operations — the thing the current platform lacks most.

- `internal/reconcile`: observed-vs-desired diff, change classes
  (`live/config/rewire/restart/recreate`), `--dry-run`, `--only as=N`.
- `twinet redeploy`, per-AS status table, partial-failure semantics.
- Declarative `behaviours:` (BGP hijack apply/revert, link failure injection,
  scheduled events).
- `twinet events`, Prometheus metrics, periodic snapshots + time-slider in the
  web UI (subsumes the history container and the GIF pipeline).
- Backup/restore of the whole lab state.

**Acceptance:** change one link's delay and redeploy — only `tc` is touched;
add an AS mid-semester — only the new AS and its peers' links are created;
restart one student's router — no other AS observes a flap.

---

## M5 — Grading engine (6 d)

**Deliver:** parallel, reproducible autograding.

- `internal/grade`: check registry, rubric loader, scheduler, report writers
  (JSON/HTML/CSV).
- Convergence predicates library.
- GoBGP-based test doubles (`bgp-speaker`, `ixp-route-server`) with
  announce/withdraw, crafted origins/paths/communities, RIB-in inspection.
- Grading-lab synthesis from a submission + class manifest + pinned RPKI
  snapshot; `twinet grade`, `--live`, `replay`.
- The full COS-461 check set (doc 06 §5) and `rubric/cos461.yaml`.
- Student-facing `check <question>` in the gateway.

**Acceptance:** grade 100 synthetic submissions (generated by mutating a
reference solution) in **under 15 minutes** on the cluster, with scores matching
hand-verified expectations on a 10-submission audit set; two runs of the same
submission produce byte-identical scores.

---

## M6 — Scale validation (3 d)

**Deliver:** evidence for the scale-out claim.

- 80-AS class manifest (~2,000 containers) deployed across the cluster.
- Measure: deploy wall-clock, memory/CPU per node, convergence time, matrix
  probe latency, gateway login latency under load, grading throughput.
- Profile and fix the top bottlenecks; document tuning.
- Publish a reproducible benchmark script and results table.

**Acceptance:** an 80-AS lab deploys in **under 10 minutes**, reaches full
BGP convergence with the reference solution, and stays stable for 24 h under a
synthetic student-activity load.

**Measured:** an 84-AS lab (2012 devices, 2927 links, 419 of them crossing
nodes) deploys across three nodes in **22 minutes 38 seconds** — over the
target, and recorded here rather than quietly restated. Two things are worth
separating. The target was set before anything had been built, against no
evidence; and the deployment is not close to the hardware's limits, using 22 GiB
of 251 and a load average of 13 against 56 cores. The time is spent serialising
work per node, not waiting on the machines, so the honest statement is that the
number is beatable and has not yet been beaten. The 24-hour soak has not been
run.

---

## M7 — Course parity and documentation (4 d)

**Deliver:** the courses actually run on it.

- `twinet import mini-internet` for the legacy config format.
- Port the advanced-networks exercises: MPLS/LDP, BGP-free core, BGP/MPLS VPN
  with VRFs, PIM-SM/IGMP multicast (these need kernel MPLS modules and
  additional FRR daemons, already provisioned in M3/M1).
- Port the COS-461 lab as `examples/cos461/`, including the assignment's
  addressing tables generated from the manifest.
- `twinet solve` reference-solution renderer; use it as the e2e smoke test.
- User guide, operator guide, course-author guide, migration guide, API
  reference; `mkdocs` site published from the repo.

**Acceptance:** every question in the COS-461 wiki and both advanced-course
exercises are solvable end-to-end on Twinet, verified by `twinet solve` +
`twinet grade` scoring 10/10.

---

---

## M8 — Fault injection and RCA evaluation (8 d)

**Deliver:** Twinet as a platform for measuring an AI agent's root-cause
analysis, covering the NIKA fault taxonomy. Full design in
[10](10_fault_injection.md).

- `internal/fault`: the fault registry, the `Inject`/`Verify`/`Resolve`/
  `GroundTruth` lifecycle, and reversibility as an enforced contract.
- The **47 in-substrate fault types** of NIKA's 60, across all six categories.
- Seeded, recorded schedules for time-varying faults (`link_flap`,
  `web_dos_attack`) so an episode replays exactly.
- Baseline capture and restore between episodes, reusing `internal/state`.
- `twinet fault list|inject|verify|resolve|status` and `twinet incident run`.
- A NIKA `LabRuntime` adapter exposing the ~50 semantic operations its faults
  call, plus a capability declaration so NIKA refuses a fault this backend
  cannot serve rather than injecting it half-way.
- The prerequisite services several fault types need: DHCP, a web service and
  load balancer, and traffic generation.

**Acceptance:** all 47 in-substrate types inject, verify and resolve, each with
a test asserting the fault manifests *and* that resolving restores the baseline
exactly; ground truth serialises to NIKA's schema and is not observable from
inside the lab; NIKA runs an unmodified scenario against the Twinet backend and
agrees with containerlab's verdict; 100 concurrent episodes run across the
cluster, each isolated and each resetting cleanly.

**Deferred, deliberately:** the 13 fault types needing substrate Twinet does not
model. P4/BMv2 (6) and an SDN controller (3) are proposed follow-on device
kinds; the 4 Kubernetes types are a poor fit and should be delegated to NIKA's
existing Kubernetes backend rather than duplicated.

---

## Summary

| Milestone | Days | Cumulative |
|---|---|---|
| M0 Foundations | 2 | 2 |
| M1 Single-node core | 5 | 7 |
| M2 Services and access | 5 | 12 |
| M3 Cluster fabric | 4 | 16 |
| M4 Reconciliation and ops | 3 | 19 |
| M5 Grading engine | 6 | 25 |
| M6 Scale validation | 3 | 28 |
| M7 Course parity and docs | 4 | 32 |
| M8 Fault injection and RCA | 8 | 40 |

## Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Container density per node lower than assumed | Medium | M6 measures it early against a real 80-AS lab; placement already supports adding nodes with a one-line change; per-AS resource limits are declarative |
| Underlay MTU cannot exceed 1500 | Medium | Uniform 1450 lab MTU; validated in M3-1; the failure mode is cosmetic, not functional |
| FRR version differences vs. the course wiki (command syntax) | Medium | Pin the FRR version by digest; golden-file tests over rendered configs; `twinet solve` runs the wiki's exact commands in CI |
| Krill/Routinator provisioning API changes | Low | Pin by digest; typed client with contract tests against the pinned image |
| Grading fidelity: an ephemeral lab differs subtly from the live class network | Medium | Keep `--live` mode; M5 acceptance cross-validates ephemeral vs. live scores on an audit set |
| Scope creep from the advanced course (MPLS/VRF/multicast) | Medium | Deferred to M7, behind the same primitives; no core redesign needed |
| Single control-plane machine becomes a bottleneck at 100+ ASes | Low | Control plane is stateless and fan-out only; probing and exec already run agent-side |
| A fault cannot be cleanly reversed, so episodes contaminate each other | Medium | Reversibility is a contract every fault must satisfy, asserted by a test that compares the post-resolve state against the captured baseline; the state store provides the fallback of a full restore |
| Ground truth leaks into the lab, making an RCA task trivial | Medium | Ground truth lives only in the control plane and is never written to a container, a label or a file an agent can read; asserted by a test that greps the whole lab for the answer |
| NIKA's fault implementations assume a Kathará or containerlab detail | Medium | The adapter is written against NIKA's declared capability set, and M8's acceptance includes running an unmodified NIKA scenario and comparing verdicts |
