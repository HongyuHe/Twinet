# 11 - Scalability, reliability, and extensibility objectives

> **How to read this document.** Section 1 was written at the audit that
> commissioned the objectives, and section 4's **Problem** paragraphs record
> the state of the tree *at that audit*. They are the motivation for each
> objective, not a description of the current implementation: several have been
> implemented since, and where that is so the objective carries a shipped
> contract underneath it. What the source supports today is recorded in
> [09](09_status.md), which is the canonical ledger; what an operator does with
> it is [12](12_operator_guide.md). Where this document and 09 disagree about a
> capability, 09 is the one to believe.

## 1. Verdict

Twinet is already a materially better teaching and assessment platform than the
mini-Internet implementation it replaces. It has a typed topology model,
deterministic addressing, isolated grading, multi-node links, configuration
preservation, and a fault lifecycle that neither mini-Internet, containerlab,
nor Kathara provides as one coherent product.

It does **not** yet meet all of its own design goals.

The three-node implementation proves that Twinet can distribute a course lab.
It has not yet proved that Twinet is a reliable cluster orchestrator. As
recorded at the audit that commissioned these objectives:

- the 84-AS deployment took 22 minutes 38 seconds, against a target below 10
  minutes;
- fair grading of 100 submissions was projected at about 3 hours 15 minutes,
  against a target below 15 minutes;
- an eight-way grading run saturated the cluster and quarantined a correct
  submission;
- cluster mutation, overlay allocation, capacity admission, node failover, and
  student-state replication were not transactional;
- every router ran FRR and every AS interior was explicitly enumerated;
- the 24-hour scale soak and automated multi-node chaos gates had not run.

Of those, the transactional gap (O4, O3, O7), the single-NOS and
explicit-interior limits (O10, O11), and the missing chaos/soak automation
(O15) have shipped contracts and gates. The 2,020-device deployment target has
now passed three consecutive live runs below ten minutes; the 100-submission
grading target and required 24-hour soak remain open. See
[section 3](#3-evidence-that-drives-the-objectives).

Development cost in time or money is not a constraint. The objectives below
therefore optimize solely for correctness, scalability, operability, and the
quality of the final system.

## 2. Comparison with existing frameworks

The mini-Internet comparison follows the source audit already recorded in
[01](01_assessment.md). The containerlab comparison uses its official
[multi-node documentation](https://containerlab.dev/manual/multi-node/), public
runtime and node-kind interfaces, and
[Clabernetes](https://containerlab.dev/manual/clabernetes/). The Kathara
comparison follows its local manager, Docker, and Kubernetes implementations.

| Property | mini-Internet | containerlab | Kathara | Twinet at this revision |
|---|---|---|---|---|
| Multi-node deployment | None; one Docker host | Core is single-host; manual VXLAN or separate Clabernetes for Kubernetes | Kubernetes backend distributes pods and collision domains | Native three-node placement and shared VXLAN; no HA scheduler. Node loss is an operator-driven fenced `twinet node drain` or an audited `on_node_loss: reschedule` deployment, never an automatic failover |
| Topology model | Eight positional files and shell-derived state | Mature generic YAML and node-kind model | Simple Netkit-compatible `lab.conf` model | Strong typed course model, templates, IPAM, and inter-AS generation |
| Vendor breadth | FRR-centric | More than 40 NOS kinds, plus vrnetlab VMs | Generic image/backend abstraction | Two registered NOS providers, FRR and BIRD, behind one capability-validated interface; canonical and 84-AS mixed-NOS reference grades both passed live at 10/10 |
| Runtime breadth | Docker-specific scripts | Docker and Podman abstractions | Docker and Kubernetes managers | Three registered backends: Docker, Podman, and native containerd. Every bundled example declares one of them, and `--runtime` overrides it per run |
| Reconciliation | Teardown and rebuild | Real topology/link diff classes for supported changes | Kubernetes supplies declarative reconciliation in that backend | Idempotent apply, event-driven repair, and bounded desired/observed device classes (live, config, rewire, restart, recreate, delete, unknown) through `twinet node reconcile`; deploy still computes no minimal cluster-wide change plan |
| Distributed scheduling | None | None in core; Kubernetes in Clabernetes | Kubernetes scheduler | Static AS placement from manifest-declared nodes |
| Observability | Ad hoc containers and text files | Strong CLI plus external telemetry ecosystem | Runtime stats and Kubernetes tooling | Matrix and looking glass, bounded Prometheus metrics, a durable scoped event stream (`twinet events`), and agent-reported allocatable/used inventory |
| Teaching workflow | Excellent pedagogy, fragile machinery | General network labs | Strong educational UX | Best course semantics of the four |
| Autograding | Slow, invasive, serial | Not a first-class product | Not a first-class product | Isolated, rubric-driven, evidence-aware, but far above the throughput target |
| RCA/fault injection | Ad hoc scenarios | External tooling | NIKA-compatible substrate | First-class reversible faults and protected ground truth; 60 of 60 NIKA types (56 native, 4 explicitly delegated) |

The right direction is not to replace Twinet with one of these frameworks.
Twinet should retain its course compiler, grader, preservation model, and fault
engine while adopting the proven substrate properties that the mature systems
already demonstrate: pluggable runtimes and NOS kinds from containerlab, and
declarative scheduling, admission, failover, and reconciliation from
Kubernetes-backed systems.

## 3. Evidence that drives the objectives

The first table is historical audit evidence. The second is current
three-node evidence; neither is a claim about another environment.

| Evidence | Result |
|---|---:|
| 84 ASes / 2,012 devices / 2,927 links / three nodes | 22m38s deployment |
| Placement computation for that topology | 0.46s |
| Links crossing the fabric | 302 / 2,927 (10.3%) |
| Service links crossing the fabric | 204 / 320 (64%) |
| Fair reduced-harness grading at concurrency 8 | about 3h15m projected for 100; one observed infrastructure quarantine |
| VNI test, 100 concurrent 300-link labs | 23 collisions before sequential deconfliction |
| Authenticated cluster sweep after agent rollout | 0 orphan overlays; 28/24/14 active overlays on node-0/1/2 |
| Production Go, recounted at this revision (`cmd` and `internal`, excluding `_test.go`) | 112,046 lines |
| Core orchestration Go, recounted at this revision (agent, client, deploy, place, plan, netx, state) | 38,225 lines |
| Go tests, recounted at this revision (every `_test.go`) | 57,505 lines |

| Current acceptance evidence | Result |
|---|---:|
| 84 AS / 2,020 devices / 2,927 links, run 1 | 472.438 s deploy + 84.694 s convergence = **557.181 s**; 1/1 and 10/10 |
| Same source and cluster, run 2 | 452.019 s + 84.123 s = **536.191 s**; 1/1 and 10/10 |
| Same source and cluster, run 3 | 461.108 s + 84.439 s = **545.595 s**; 1/1 and 10/10 |
| Abandoned grading harness | Killed controller; all nodes self-reaped at lease expiry while COS461 deployed |
| Immutable images | Seven `0.1-7f6ed89` manifests remotely verified; all bundled examples release-locked |

**The scale topology changed shape after the historical deployment.** The
22m38s run measured 2,012 devices. [`examples/scale`](../examples/scale) now
expands to 84 ASes, 2,020 devices, and 2,927 links and is the topology used by
the three current runs above.

Machine-readable evidence from a re-run is not kept in this tree. The benchmark,
chaos, and soak runners write JSON under the untracked `reports/` path and the
cluster workflow uploads it as a build artifact; a result belongs with the run
that produced it.

The hardware was not saturated during the 84-AS deployment. Placement took less
than a second. The dominant problems were orchestration, process creation,
global serialization, repeated observation, convergence strategy, and missing
admission control rather than graph partitioning or raw machine capacity.

## 4. Required objectives

Every objective is mandatory. An implementation is not complete because an
interface or design exists; it is complete only when its acceptance test has
run successfully.

Each **Problem** below is the condition observed at the audit that commissioned
the objective, written in the past tense for that reason. It is not a statement
about the current tree: several are closed, and where an objective has shipped
its contract is recorded underneath it and, canonically, in
[09](09_status.md).

### O1 - Meet the scale and grading targets

**Problem.** The two headline acceptance targets were missed at the audit:
deployment by more than 2x and grading by about 13x. The current deployment
target is now met in three consecutive runs; 100-submission throughput and the
24-hour stability claim remain unproven.

**Required outcome.**

- Deploy and converge the 84-AS reference lab in under 10 minutes.
- Grade 100 deterministic synthetic submissions in under 15 minutes without
  mutating the class lab.
- Run the reference lab for 24 hours under synthetic student, matrix, save, and
  fault activity with no unexplained process death, stale overlay, lost
  configuration, or false grading deduction.
- Record phase timings and resource consumption so a regression names its
  bottleneck.

### O2 - Remove orchestration hot-path serialization

**Problem.** The runtime spawned the Docker CLI for lifecycle and exec calls,
all namespace work passed through one global mutex, deployment had whole-stage
barriers, and capture and teardown were sequential. The Docker Engine API,
native containerd, and Podman backends have since replaced the CLI default.

**Required outcome.**

- Use a long-lived Docker/containerd API client for lifecycle, list, inspect,
  exec, copy, and event operations; retain a CLI fallback only as an explicit
  compatibility mode.
- Replace process-wide namespace serialization with namespace-scoped netlink
  handles or an equivalently safe concurrent implementation.
- Execute the dependency DAG as a DAG, allowing create, wire, configure, and
  readiness work to pipeline when their own prerequisites are satisfied.
- Use bounded parallel capture, pruning, and teardown.
- A no-change deployment performs no file copy, daemon restart, interface
  recreation, or shaping update.

**Acceptance.** Trace a 2,012-device initial deployment and no-change redeploy.
The trace must prove useful concurrency, no global namespace lock, no Docker CLI
processes on the default path, and zero unintended mutations on redeploy.

**Shipped planning contract.** Node-local planning derives every deployment-wide
value once. Multiplex overlay parameters -- the bridge VLAN per cross-node VNI,
the outer MTU and the deconflicted UDP port per node pair -- are a pure function
of the placed topology, so they are computed in one pass over the link set per
topology instead of once per cross-node link; on the 84-AS lab that is one scan
of 2,927 links rather than 186 of them, and
`TestScaleBuildDerivesOverlayParametersOnce` asserts the bound directly. Per
device rendering, final runtime-spec derivation, and desired wire hashing carry
no shared state and are fanned out across the host's CPUs, and the wire hash
observation computed is reused by the wire step rather than recomputed.
`BenchmarkScaleBuildPlan` measures the whole pass on the release-gate topology.

Configuration writes the platform's rendered files without first reading each
one back when this apply pass created the container from its image, because
nothing can be there to compare against yet; a container that already existed
keeps the comparison, which is what keeps an unchanged file from being
rewritten and keeps a no-change redeploy free of mutations.
`TestFreshContainersSkipRedundantConfigurationReads` pins both halves.

### O3 - Add real admission control and backpressure

**Problem.** `cpus` and `memory` were container limits that acted as placement
demand only when optional node capacities were present. Bundled cluster
manifests declared no capacities, so placement was effectively based on
container count. Different labs each created their own worker pool with no
node-wide limit.

**Required outcome.**

- Model resource **requests** separately from hard **limits**.
- Discover allocatable CPU, memory, disk, PID, file-descriptor, and network
  device capacity from every agent.
- Make strict admission the default; require an explicit, audited override for
  overcommit.
- Add node-wide budgets for lifecycle calls, exec/probes, netlink work, image
  pulls, and state capture across all labs.
- Schedule grading harnesses from available capacity rather than a fixed
  concurrency number.

`twinetd` sizes those shared budgets from host CPU count and exposes
`-limit-apply`, `-limit-lifecycle`, `-limit-container-create`,
`-limit-container-start`, `-limit-exec-probe`, `-limit-netlink`,
`-limit-image-pull`, `-limit-capture`, and `-limit-convergence` overrides.
The outer apply/lifecycle ceilings remain 48 so independent stages can
pipeline. Isolated Docker API measurements on node-0 found combined
create+start throughput effectively flat from width 4 through 48
(0.86-1.00 containers/s), while p95 latency rose from 5.4s to 53.2s. Separate
create and start batches sustained 1.03 containers/s at width 4 versus 1.00 at
48; therefore each Docker operation has its own four-slot gate while the
broader DAG continues scheduling wiring and configuration work.

The same isolated 64-container sweep measured rootful Podman at
1.81-1.88 containers/s per node (best at width 8), an extrapolated
5.63 containers/s across three equal nodes. Direct containerd in a dedicated
namespace measured 7.13 containers/s at width 4. Podman is therefore the
low-risk existing backend for a first scale rerun; native containerd has much
more headroom. Twinet now uses the native containerd gRPC API in a dedicated
per-agent namespace, with OCI hardening/resources/mounts, a root-only PID-1
exec broker, lifecycle/events/netns/copy support, and exact cleanup rather than
a benchmark-only `ctr` path.
Runtime-specific defaults use four create/start slots for Docker, eight for
Podman, and sixteen for containerd. Containerd's simple lifecycle ceiling was
flat through width 48, while real hardened specs spend additional independent
time materializing bind/init state; sixteen pipelines that work without
exceeding the measured daemon ceiling. A live 84-AS run then showed all sixteen
containerd convergence slots continuously occupied: about 60 routers completed
configuration per node in two minutes, while CPU remained below the 56-core
host ceiling. Containerd therefore uses up to 48 convergence slots on large
hosts, still bounded by the independent 48-slot apply/exec budgets; smaller
hosts scale that default from their CPU count. All limits remain independently
tunable.

**Shipped admission contract.** `cpus`, `memory`, and `pids` are container
limits; `requests` are independent scheduler reservations for CPU, memory,
PIDs, ephemeral storage, file descriptors, and netdevs. Agents report
physical, allocatable, observed-used, and Twinet-reserved inventory, with
unknown dimensions explicitly null/named rather than represented as zero.
Cluster deploy refuses an over-capacity or unknown assignment before writing a
placement record or beginning a mutation. `--overcommit` is the explicit,
recorded and agent-logged exception. Batch grading prebuilds harness demand and
queues capacity-safe waves; `--parallel` only caps a wave.

**Acceptance.** An intentionally oversized lab is refused before creating
anything. Eight grading harnesses on the three-node cluster are queued to a safe
width and all correct submissions complete without infrastructure quarantine.

### O4 - Make cluster mutation and overlay allocation transactional

**Problem.** Operation leases were local to each node, so concurrent
controllers could each win a different subset of nodes. Overlay deconfliction
was a query-then-apply operation, so concurrent labs could select the same
apparently free identifier.

**Required outcome.**

- Introduce a cluster-scoped per-lab lease with TTL, ordered acquisition,
  rollback, and fencing tokens.
- Require a valid fencing token on every mutating agent operation.
- Reserve overlay identifiers atomically for the nodes on which they can
  appear; release reservations on failure or lease expiry.
- Make deployment generations compare-and-swap rather than last-writer-wins.

**Acceptance.** Repeatedly race two incompatible deployments of one lab and 100
concurrent 300-link labs. Exactly one incompatible deployment may commit, no
node may carry a mixed generation, no VNI may be shared, and no request may
report success for a partial cluster mutation.

### O5 - Bound overlay object growth and collect garbage automatically

**Problem.** Each cross-node link creates a bridge and VXLAN interface on both
ends. Concurrent grading multiplies those objects. Orphan cleanup was manual,
and prior interrupted grading/deployment runs left abandoned labs and hundreds
of host objects. An initial unauthenticated shell check in this audit
misclassified 28 node-0 overlays as orphaned; the authenticated ownership sweep
correctly proved they were active COS-461 links, and that correction is part of
the evidence.

**Required outcome.**

- Multiplex isolated links over a bounded set of tunnels per lab/node pair,
  using kernel-supported VLAN-to-VNI mapping, OVS, eBPF, or another measured
  design.
- Keep shaping at the container edge so local and remote links remain
  behaviorally identical.
- Persist ownership and last-use generation for every host object.
- Garbage-collect abandoned veths, bridges, tunnels, reservations, and lab
  records after a safe grace period, while refusing to remove anything an
  active operation can still use.
- Include host objects whose ownership record is missing rather than only those
  that still carry one. A bridge with a deterministic Twinet name, no alias and
  nothing enslaved to it is demonstrably abandoned; a bridge with a port, with
  an alias this build cannot read, or with an alias naming a live lab is not,
  and is preserved.
- Re-prove ownership under the reservation lock immediately before deleting an
  object, and hold a visible claim on it while deleting, so a deployment that
  claims the object mid-pass is refused a retryable conflict instead of being
  handed an overlay that is about to disappear. A grace window makes that race
  rarer; only mutual exclusion removes it.
- Give a lab that exists only for a running controller an explicit bounded
  lifetime, so an abandoned grading harness is reclaimed by the node rather
  than protected forever by the containers it is still running.

**Acceptance.** Overlay tunnel/bridge count grows with active lab/node pairs,
not cross-node links. Killing a controller halfway through deployment leaves no
objects after the lease/grace period. A deliberately abandoned synthetic lab is
detected and safely removed by the automatic path, while every active COS-461
overlay remains untouched.

### O6 - Remove front-node service bottlenecks

**Problem.** Shared services defaulted to one front node. In the scale
topology 64% of service links crossed the fabric, and the gateway, web tier, and
service containers were single failure and concentration points.

**Required outcome.**

- Support per-node or sharded replicas for DNS, RPKI RTR, matrix probes,
  measurement, and other attach-to-every-AS services.
- Place each AS's service attachment locally when possible.
- Give replicas stable anycast or generated service identities.
- Run gateway and web endpoints in active/standby or active/active form without
  weakening group authorization.

**Acceptance.** Losing the original front node does not remove student access,
DNS, RTR, or the web overview for ASes on surviving nodes. Service cross-links
are reduced to the minimum implied by replication.

### O7 - Preserve work through node loss and migration

**Problem.** Student snapshots and topology records were node-local. Node-loss
rescheduling was documented but not implemented. Export capture was best effort,
so a migration could transfer stale state and later strand the fresh snapshot on
the old node.

**Required outcome.**

- Maintain at least two failure-domain-separated copies of every current
  student snapshot and topology record.
- Capture periodically and on every destructive boundary.
- Make migration two-phase: fresh capture, replicated durable write,
  destination restore verification, then source removal.
- Fail closed on stale or unavailable state unless an operator explicitly
  chooses data loss.
- Implement node drain and `on_node_loss: reschedule` using the replicated
  state.

**Acceptance.** Change every supported kind, destroy the node that owns the AS,
reschedule it, and compare the restored configuration byte-for-byte and
semantically. No acknowledged configuration may be lost when any one node or
disk disappears.

#### O7 recovery-state contract

- Dynamic address, route, tunnel, and OVS snapshots use versioned typed,
  sorted facts rather than raw `ip`/OVS output. Kernel interface indexes,
  peer suffixes, link-local addresses, lifetimes, and route cache decorations
  do not change a snapshot digest; missing or extra student-significant facts
  do.
- A captured route is stored as portable, user-constructible semantics, not as
  the kernel printed it. The nexthop-object id a routing daemon's routes carry
  (`nhid <N>`), the protocol that installed them, IPv6 route preference, link
  state, and `ip -o`'s backslash line separator are dropped; destination, type,
  via/dev, metric, table, source, scope, `onlink`, locked metrics, weights, and
  encapsulation are kept. Multipath is stored and replayed as one
  `ip route replace P ... nexthop via A dev X weight 1 nexthop via B dev Y
  weight 1`. A route the kernel resolved only through a nexthop object it did
  not describe cannot be asked for by any command and is not stored; the kernel's
  own per-interface `fe80::/64` routes are not student state. Snapshots written
  in the kernel's spelling are re-canonicalised when they are read, so a lab
  with saved state never has to delete it to become deployable again.
- Restore clears stale dynamic facts before replay and fails on the first
  rejected command. Replay is in dependency order rather than stored order:
  tunnel, VLAN, and VRF devices are created and brought up first, then
  addresses, then the routes that name them, with the routes over a tunnel
  last. FRR/BIRD configuration is replayed only after its daemon is ready,
  after interfaces and tunnels have been restored.
- A persisted unfinished transaction gates event repair, sampled/full semantic
  audit, periodic capture/replication, and GC before their loops can mutate a
  rehydrated lab. Recovery cancels already scheduled periodic work and is the
  sole writer until it verifies and finalizes the terminal inventory.
- Exact rollback uses a small shared lifecycle worker budget, reuses an
  inspected matching/exited container, and resolves duplicate-name errors by
  re-inspection rather than blindly creating another container.
- Peer acknowledgement history survives restart as stale evidence; startup and
  recovery establish fresh mutual-TLS inventory handshakes independently of
  periodic capture. Peer inventory/read APIs remain read-only and available
  during recovery so simultaneous node restarts can authenticate, fetch an
  exact missing replica, and then restore.
- Kernel-created tunnel defaults (`sit0`, `tunl0`, GRE/GRETAP/ERSPAN, IP6
  tunnel, and VTI defaults) are excluded from captures and never deleted by
  restore; named student 6in4 tunnels remain durable facts.
- Renderer mode and harness `ungraded` are transaction state. A mode
  transition rewires and semantically verifies every local device, so a
  reference host address/default route cannot be skipped merely because its
  runtime spec was unchanged. Returning from solve resets reference state and
  restores only durable teaching state.
- Clustered transaction wires and journals require an explicit `platform` or
  `solve` mode plus `ungraded` value. Apply/commit/rollback consume the
  persisted transaction pair only; legacy empty records are audited during
  migration, never silently reinterpreted by a request-time default.
- Solve-to-platform removes exact reference addresses and routes only from
  student-owned interfaces; it preserves platform/link-local/kernel state.
  Routing reset is provider-aware: FRR reloads in its private control sidecar,
  while BIRD applies its own platform configuration and never invokes FRR
  lifecycle scripts.

### O8 - Implement true reconciliation and correct self-healing

**Problem.** Deploy was idempotent but computed no minimal change plan. The
repair loop performed a serial Docker inspect/exec survey every minute, treated
exited or unreadable containers as healthy, and stopped trying permanently after
three failed repairs. Agents now classify desired against observed and repair
from runtime events; deploy still computes no minimal cluster-wide change plan,
which [09](09_status.md#remaining-work) keeps as outstanding.

**Required outcome.**

- Implement desired/observed change classes: live, config, rewire, restart,
  recreate, and delete.
- Subscribe to runtime events for immediate lifecycle repair, with sampled
  audits as a backstop rather than a full minute-by-minute exec sweep.
- Represent healthy, broken, and unknown separately.
- Restart exited containers, repair partial wiring, and retry failures with
  bounded exponential backoff; recovery must clear failure history.
- Coordinate deliberate faults and grading through fenced exemptions/holds.

**Acceptance.** Changing one link delay touches only its qdisc. Restarting one
router causes no other AS flap. A device that fails repair three times and then
becomes repairable is recovered automatically.

### O9 - Add cluster-grade observability and bounded collection

**Problem.** Prometheus metrics and an event stream were designed but absent.
Node status omitted memory, disk, load, and operation pressure. One 82-AS matrix
refresh could issue up to 13,284 separate container execs.

**Required outcome.**

- Export Prometheus-compatible operation, queue, runtime, resource, overlay,
  convergence, repair, grading, and underlay metrics.
- Add a structured, bounded event stream with lab, node, generation, scope, and
  correlation identifiers.
- Report allocatable and used CPU, memory, disk, PIDs, file descriptors,
  netdevs, image cache, clock skew, and active work.
- Batch matrix and looking-glass collection agent-side; update incrementally
  from routing/runtime events where possible.

**Acceptance.** An 82-AS matrix refresh uses at most two container execs per
source AS, metrics explain every deployment phase, and a failed cross-node link
can be traced from controller request to both endpoint agents.

### O10 - Support heterogeneous NOSes and pluggable runtimes

**Problem.** The runtime interface had one Docker implementation and every
router was FRR. Containerlab supports Docker/Podman and more than 40 NOS kinds;
Kathara cleanly separates Docker and Kubernetes managers.

**Required outcome.**

- Add explicit NOS and runtime registries with capability declarations.
- Move rendering, apply, readiness, operational-state collection, and save
  semantics behind NOS interfaces.
- Introduce vendor-neutral route, protocol-session, interface, policy, and
  forwarding state consumed by grading and observability.
- Add a second open NOS image, initially BIRD or OpenBGPD, and a second runtime
  backend.
- Refuse unsupported device/feature combinations during validation.

**Acceptance.** Replace two routers in `examples/cos461` with the second NOS.
The unchanged rubric must award the unchanged reference score, while an
unsupported MPLS request is refused before deployment.

#### O10 implementation boundary

`examples/cos461/templates/transit_as.yaml` explicitly selects BIRD 2 for the
two staff-operated transit routers (AS 1 and AS 2). Student-owned routers
remain FRR: the COS-461 submission archive currently carries FRR command files,
so accepting BIRD for a student device would silently leave its submitted
configuration unapplied. Manifest validation rejects that combination before
deployment. The unchanged `examples/cos461/rubric/cos461.yaml` therefore
continues to assess FRR student work against BIRD reference peers.

The `bird` image pins Alpine by digest and BIRD to `2.15.1-r0`. It declares
IPv4/IPv6, OSPF, BGP, policy/community, and VLAN support; it does not declare
tunnels, RPKI, MPLS/LDP, VRF, multicast, or DHCP. `make nos-images`
builds both router images and starts both daemons; it fails when Docker is
unavailable instead of reporting a vacuous success.

**Runtime selection contract.** One selection, in four ordered layers:
`placement.runtime` is the lab's engine, `placement.nodes[].runtime` overrides
it for one node, `--runtime`/`TWINET_RUNTIME` overrides both for one invocation
and for every node at once, and `twinetd -runtime` is what the agent actually
runs — a mismatch is refused rather than reconciled. `runtime_socket` is an
optional node-local API endpoint; `docker`, `podman`, and `containerd` are the
registered backends.

Every bundled example declares `runtime: containerd`, the engine
[12](12_operator_guide.md) installs, so the whole bundle deploys unmodified on
one cluster. An omitted selection still means `docker`, for manifests written
before the registry existed, and validation now says so where it is authored
rather than leaving it to be discovered on a cluster that runs something else.
`TestEveryBundledExampleDeclaresTheClusterRuntime` and
`TestRuntimeOverrideMakesEveryExampleDeployableOnDockerOrPodman` are the gates.

Manifest validation checks the registered lifecycle/exec/copy/netns/event
capabilities before deployment, agents select through `runtime.NewRuntime`,
and status reports backend, engine version, and socket. `make
podman-integration` and `make containerd-integration` are explicit rootful
engine gates: they source-build the images, start an agent on that backend, run
a routed deploy/wire/configure/exec/save/destroy lifecycle, consume events, and
fail instead of skipping when the acknowledgement or prerequisite is absent.

### O11 - Generate and distribute intra-AS topology types

**Problem.** Inter-AS topology was generated, but AS interiors remained
explicit and AS-granular placement forbade distributing a large Clos.

**Required outcome.**

- Add one generator registry shared by inter-AS and interior generators.
- Implement `explicit`, `ring`, `two-tier`, and `clos`.
- Add role-derived scalable addressing and shape-aware rubric compatibility.
- Introduce placement groups so ordinary teaching ASes stay local while a
  declared fabric can split at a controlled boundary.

**Acceptance.** Existing labs represented as `kind: explicit` retain identical
topology hashes. A generated Clos deploys, converges, grades, and distributes
across three nodes with deterministic placement.

### O12 - Harden tenant and operator security

**Problem.** Student routers ran as root with `CAP_SYS_ADMIN`, label scoping
was not a kernel tenancy boundary, and one cluster-wide controller identity
could mutate every lab.

**Required outcome.**

- Remove `CAP_SYS_ADMIN` and every other unnecessary device capability.
- Apply no-new-privileges, explicit seccomp/AppArmor policy, read-only mounts
  where possible, and resource requests/limits to every device.
- Issue scoped operator/TA identities and enforce lab/action RBAC from the mTLS
  identity, not only a shared bearer token.
- Support a stronger sandbox or dedicated worker pool for hostile student and
  evaluated-agent code.
- Audit every privileged mutation.

**Acceptance.** A credential for one lab cannot list or mutate another; a
student container cannot reach the Docker socket, host namespaces, underlay, or
another lab; all course exercises still work without `CAP_SYS_ADMIN`.

**Shipped O12 enforcement contract.**

- Every agent route has a named action (`observe`, `exec`, `deploy`, `destroy`,
  `lifecycle`, `fault`, `state`, or `admin`) and a resolved lab target before
  its handler runs. TLS clients must present exactly one valid Twinet URI
  claim: controller is cluster-wildcard, operator/TA is named-lab and
  named-action, diagnostic is one-lab observe-only, and peer is
  `peer-state` only. The shared bearer remains a second factor; it cannot
  broaden a certificate claim. Plain HTTP is only `-insecure` on loopback.
- `twinet node pki` now creates separate `*_server_*` and `*_peer_*` keys.
  Peer keys are installed with `-peer-tls-cert`/`-peer-tls-key`, never used
  for controller routes. Existing clusters must issue peer material with
  `twinet node pki peer <node>` and roll it out. The only legacy bridge is an
  explicit, future `-legacy-peer-cert-until` deadline; expiry refuses
  replication rather than preserving broad fallback access. Scoped TA
  credentials use `twinet node pki credential`; replacement requires
  `--rotate` and records certificate serials without keys.
- Every expanded device uses `cap-drop ALL`, a minimal add set,
  no-new-privileges, named seccomp/AppArmor profiles, a read-only root
  filesystem, explicit tmpfs scratch paths plus per-device bind volumes for
  renderer-owned files, masked/read-only OCI paths, and no default Docker
  network. Docker API and CLI copies target those volumes; neither claims a
  shell bypass of a read-only root. Runtime class, user namespace, and worker-pool
  selection are typed manifest/placement fields. Unsafe values, host socket
  mounts, agent credential environment, and `SYS_ADMIN` topology devices are
  rejected; a named development override is auditable but never permits a
  privileged topology device.
- FRR runs in an internal, labelled control sidecar. The router keeps only its
  network namespace plus its own config/vty mounts; the sidecar has a private
  PID namespace, sidecar-only logs, and the sole `SYS_ADMIN` grant. API
  listing, attach, exec, lifecycle, reshape, and MPLS routes reject internal
  sidecars. Cross-node applies require fence-bound VNI reservations, and
  multiplex pairs include lab ownership in their kernel alias.
- The 84-AS topology has 2,020 primary devices and 644 FRR control sidecars:
  removing sidecars would reduce runtime objects by 24.2% and save about
  1.9 minutes at the measured three-node Podman rate. It is not currently a
  safe optimization: Alpine FRR 10 requires `SYS_ADMIN`, and merging the daemon
  back into the student router would grant that capability to student code.
- Privileged API mutations append immutable structured events containing
  identity, certificate serial, lab, action, deployment generation, fence,
  target, and result. Event text redacts bearer/token/secret/PEM material.
  The O12 unit suite covers certificate scope, stolen bearer resistance,
  peer impersonation, migration expiry, sidecar invisibility, hardening
  mapping, host-socket refusal, audit redaction, and two-lab overlay identity.

### O13 - Make documentation describe shipped behavior

**Problem.** Architecture documents claimed gRPC, two binaries, no state
store, minimal diff apply, Prometheus metrics, underlay health metrics, and
node-loss rescheduling, while the implementation used HTTP, built more binaries
than two, persisted file state, and lacked the latter features. The root README
carried stale course status.

**Required outcome.**

- Separate current architecture from target architecture.
- Generate command, schema, capability, fault-coverage, and benchmark tables
  from code or tests.
- Make CI fail when an implemented/remaining-work claim contradicts the
  corresponding executable capability.

**Acceptance.** Every feature claim in `README` and docs has an executable
evidence reference, and an intentionally stale claim fails a documentation
test.

### O14 - Make bootstrap, images, and upgrades reproducible

**Problem.** `twinet node bootstrap` emitted a non-loopback service with only
a bearer token, while `twinetd` correctly refused to start without mTLS or
`-insecure`. Examples used mutable image tags, and exact build matching
prevented rolling upgrades.

**Required outcome.**

- Provide one idempotent secure bootstrap that validates prerequisites,
  installs binaries and certificates, starts the agent, and verifies health,
  underlay reachability, MTU, and version.
- Pin released and grading images by digest and verify all nodes after pulling.
- Version the agent protocol and renderer contract separately from the binary;
  permit rolling upgrades only across declared-compatible versions.

**Acceptance.** Bootstrap fresh supported nodes without manual repair, deploy a
lab during a one-node-at-a-time compatible upgrade, and reproduce a grade using
only its recorded source revision and image digests.

**Shipped reproducibility contract.** `images.mode: development` remains an
explicit opt-in for mutable local tags. Every bundled example now uses
`images.mode: release` and a topology-bound `images.lock.json`; `release` and `grading` require
`images.lock`, a generated JSON lock whose entries are registry
`repository@sha256:...` manifests and whose topology hash must match the lab.
Each node checks the pulled digest before container creation and the
coordinator checks the node's post-pull evidence before commit. `twinet images
lock|verify` and `make image-lock`/`make image-verify` operate on that format;
the push target publishes and remotely inspects immutable
version/commit tags before writing it. `Version` remains exact source audit
data, while protocol, renderer, and state-schema version ranges gate rolling
upgrades.

### O15 - Continuously test scale and failure behavior

**Problem.** Cluster E2E was manual, there was no reproducible scale
benchmark script, and concurrent-controller, node-loss, migration, overlay-GC,
and 24-hour soak behavior were not release gates. The runners and the cluster
workflow now exist; a completed 24-hour soak is not recorded in
[09](09_status.md).

**Required outcome.**

- Add reproducible benchmark commands and machine-readable result artifacts.
- Add multi-node tests for concurrent deploys, VNI reservation, node reboot and
  disk loss, state migration, underlay flap, partial deployment, abandoned
  controller, overlay collection, and grading saturation.
- Run short chaos tests on every stable merge and scheduled scale/soak tests on
  `main`.
- Compare performance against stored budgets and fail on regression.

**Acceptance.** The full gate demonstrates O1-O14 and O16 from a clean cluster and
produces an auditable report tied to source and image digests.

**Shipped evidence contract.** `scripts/scale_benchmark.sh` writes
`schema_version: 2` evidence whose verdict is never rendered before the required
measurements have been attempted. A recorded failure -- including an acceptance
budget overrun -- no longer short-circuits the remaining collection: the
convergence probe, the full reference grade, and the post-deployment node status
are still measured, and a measurement that is deliberately not attempted is
named with its reason under `skipped_measurements` rather than silently absent.
`required_measurements.grade` is keyed to the operator's `--submissions`
request, not to a submission count a failing run never reached.

Cleanup is separated from a passing result. Recovery joins are recorded as
`cleanup.best_effort_attempts` with their real exit codes and are never on their
own accepted as proof that the lab is gone; a cleanup that cannot prove removal
fails the run and appears in `result.failures`, which lists every recorded
failure rather than only the first. When the evidence document itself cannot be
rendered, the raw per-phase captures are preserved next to the intended output
instead of being deleted, minus the copied manifest that carries controller
credentials. The `--allow-destructive` acknowledgement remains mandatory.

### O16 - Complete the NIKA substrate coverage

**Problem.** The former 45-of-60 registry could not serve as a general NIKA
RCA platform: the remaining types need P4/BMv2, Kubernetes, SDN/OpenFlow,
load-balancing/traffic generation, and a controllable MPLS label substrate.
Each must be a real substrate lifecycle, not an injector-shaped stub.

**Required outcome.**

- Add a P4/BMv2 device kind, pinned image, program/control-plane contract, and
  the six P4 fault implementations.
- Add an SDN controller/OpenFlow device and switch contract for the three
  southbound faults.
- Add load-balancer and deterministic traffic-generator services and implement
  `load_balancer_overload`.
- Add a controllable label-space implementation for
  `mpls_label_limit_exceeded` without weakening container isolation.
- Support the four Kubernetes faults through an explicit delegated NIKA
  backend, preserving one Twinet incident/result schema rather than pretending
  Linux containers reproduce Kubernetes behavior.
- Make runtime/substrate capabilities machine-readable so an unsupported
  scenario is refused before injection.

**Acceptance.** Diff Twinet's registry against the pinned NIKA taxonomy and
obtain 60 of 60 supported through either the native Twinet substrate or the
declared Kubernetes delegation. Every native fault injects, manifests,
verifies, resolves, and restores its baseline. NIKA runs unchanged scenarios
for every substrate and agrees with its reference backend. One hundred
concurrent mixed-substrate episodes remain isolated and reset cleanly.
The delegated Kubernetes gate uses a marked disposable multi-node cluster and
checks the same worker-scoped node filters, `NotReady` transition, stale-work
behavior, healthy surviving workload, and per-node ClusterIP contrast as
NIKA's reference implementations before accepting restoration.

## 5. Implementation order

1. **Protect correctness first:** O4, O7, O12.
2. **Remove scale bottlenecks:** O2, O3, O5, O6, O8, O9.
3. **Complete extensibility and RCA substrates:** O10, O11, O16.
4. **Make operation and evidence durable:** O13, O14, O15.
5. **Run O1 acceptance and optimize until every threshold is met.**

Each coherent milestone is developed on `dev`, tested, committed as
`Hongyu Hè <hhy@princeton.edu>`, and pushed. Only stable milestones move to
`main`.

## 6. Completion and review gate

After all objectives and acceptance tests pass:

1. Start a **fresh** reviewer with model **Claude Opus 5**, maximum reasoning
   effort, and long context.
2. Give it this document, the implementation diff, test/benchmark evidence, and
   instructions to be objective, adversarial, and constructive.
3. Treat any verdict other than exactly `PASS` as `FAIL`.
4. Record every finding, fix it, rerun the relevant acceptance evidence, and
   start a new reviewer with clean context.
5. Stop only after **two fresh review rounds in succession** return `PASS`.
