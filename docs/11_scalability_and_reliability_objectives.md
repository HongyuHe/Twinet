# 11 - Scalability, reliability, and extensibility objectives

## 1. Verdict

Twinet is already a materially better teaching and assessment platform than the
mini-Internet implementation it replaces. It has a typed topology model,
deterministic addressing, isolated grading, multi-node links, configuration
preservation, and a fault lifecycle that neither mini-Internet, containerlab,
nor Kathara provides as one coherent product.

It does **not** yet meet all of its own design goals.

The current three-node implementation proves that Twinet can distribute a
course lab. It does not yet prove that Twinet is a reliable cluster
orchestrator:

- the 84-AS deployment takes 22 minutes 38 seconds, against a target below 10
  minutes;
- fair grading of 100 submissions takes about 3 hours 15 minutes, against a
  target below 15 minutes;
- an eight-way grading run can saturate the cluster and quarantine correct
  submissions;
- cluster mutation, overlay allocation, capacity admission, node failover, and
  student-state replication are not transactional;
- every router still runs FRR and every AS interior is explicitly enumerated;
- the 24-hour scale soak and automated multi-node chaos gates have not run.

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

| Property | mini-Internet | containerlab | Kathara | Twinet now |
|---|---|---|---|---|
| Multi-node deployment | None; one Docker host | Core is single-host; manual VXLAN or separate Clabernetes for Kubernetes | Kubernetes backend distributes pods and collision domains | Native three-node placement and VXLAN, but no HA scheduler or automatic node-loss recovery |
| Topology model | Eight positional files and shell-derived state | Mature generic YAML and node-kind model | Simple Netkit-compatible `lab.conf` model | Strong typed course model, templates, IPAM, and inter-AS generation |
| Vendor breadth | FRR-centric | More than 40 NOS kinds, plus vrnetlab VMs | Generic image/backend abstraction | FRR only |
| Runtime breadth | Docker-specific scripts | Docker and Podman abstractions | Docker and Kubernetes managers | Docker only |
| Reconciliation | Teardown and rebuild | Real topology/link diff classes for supported changes | Kubernetes supplies declarative reconciliation in that backend | Idempotent ensure plus repair loop; no true desired/observed minimal diff |
| Distributed scheduling | None | None in core; Kubernetes in Clabernetes | Kubernetes scheduler | Static AS placement from manifest-declared nodes |
| Observability | Ad hoc containers and text files | Strong CLI plus external telemetry ecosystem | Runtime stats and Kubernetes tooling | Matrix and looking glass, but no metrics/event stream or resource telemetry |
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

| Evidence | Result |
|---|---:|
| 84 ASes / 2,012 devices / 2,927 links / three nodes | 22m38s deployment |
| Placement computation for that topology | 0.46s |
| Links crossing the fabric | 302 / 2,927 (10.3%) |
| Service links crossing the fabric | 204 / 320 (64%) |
| Fair reduced-harness grading at concurrency 8 | about 3h15m projected for 100; one observed infrastructure quarantine |
| VNI test, 100 concurrent 300-link labs | 23 collisions before sequential deconfliction |
| Authenticated cluster sweep after agent rollout | 0 orphan overlays; 28/24/14 active overlays on node-0/1/2 |
| Production Go | 57,234 lines |
| Core orchestration Go | 16,755 lines |
| Go tests | 26,690 lines |

The hardware was not saturated during the 84-AS deployment. Placement takes
less than a second. The dominant problems are orchestration, process creation,
global serialization, repeated observation, convergence strategy, and missing
admission control rather than graph partitioning or raw machine capacity.

## 4. Required objectives

Every objective is mandatory. An implementation is not complete because an
interface or design exists; it is complete only when its acceptance test has
run successfully.

### O1 - Meet the scale and grading targets

**Problem.** The two headline acceptance targets are missed: deployment by more
than 2x and grading by about 13x. The 24-hour stability claim is untested.

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

**Problem.** The runtime spawns the Docker CLI for lifecycle and exec calls,
all namespace work passes through one global mutex, deployment has whole-stage
barriers, and capture and teardown are sequential.

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

### O3 - Add real admission control and backpressure

**Problem.** `cpus` and `memory` are container limits but also act as placement
demand only when optional node capacities are present. Bundled cluster
manifests declare no capacities, so placement is effectively based on container
count. Different labs each create their own worker pool with no node-wide
limit.

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
more headroom but still needs Twinet's complete exec/copy/events/netns and
recovery contract rather than a benchmark-only `ctr` path.
Runtime-specific defaults use four create/start slots for Docker and eight for
Podman; both remain independently tunable.

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

**Problem.** Operation leases are local to each node. Concurrent controllers
can each win a different subset of nodes. Overlay deconfliction is a
query-then-apply operation, so concurrent labs can select the same apparently
free identifier.

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

**Acceptance.** Overlay tunnel/bridge count grows with active lab/node pairs,
not cross-node links. Killing a controller halfway through deployment leaves no
objects after the lease/grace period. A deliberately abandoned synthetic lab is
detected and safely removed by the automatic path, while every active COS-461
overlay remains untouched.

### O6 - Remove front-node service bottlenecks

**Problem.** Shared services default to one front node. In the scale topology,
64% of service links cross the fabric, and the gateway, web tier, and service
containers are single failure and concentration points.

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

**Problem.** Student snapshots and topology records are node-local. Node-loss
rescheduling is documented but not implemented. Export capture is best effort,
so a migration can transfer stale state and later strand the fresh snapshot on
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
- Restore clears stale dynamic facts before replay and fails on the first
  rejected command. FRR/BIRD configuration is replayed only after its daemon
  is ready, after interfaces and tunnels have been restored.
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

**Problem.** Deploy is idempotent but does not compute a minimal change plan.
The repair loop performs a serial Docker inspect/exec survey every minute,
treats exited or unreadable containers as healthy, and permanently stops
trying after three failed repairs.

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

**Problem.** Prometheus metrics and an event stream are designed but absent.
Node status omits memory, disk, load, and operation pressure. One 82-AS matrix
refresh can issue up to 13,284 separate container execs.

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

**Problem.** The runtime interface has one Docker implementation and every
router is FRR. Containerlab supports Docker/Podman and more than 40 NOS kinds;
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

**Runtime selection contract.** `placement.runtime` selects the lab default
(`docker` when omitted) and `placement.nodes[].runtime` may override it with
`docker` or `podman`; `runtime_socket` is an optional node-local API endpoint.
Manifest validation checks the registered lifecycle/exec/copy/netns/event
capabilities before deployment, agents select through `runtime.NewRuntime`,
and status reports backend, engine version, and socket. The controller refuses
to mutate when a node reports a backend different from its requested runtime.
`make podman-integration` is an explicit rootful Podman gate: it source-builds
the images, starts a Podman agent, runs a routed deploy/wire/configure/exec/
save/destroy lifecycle, consumes events, and fails instead of skipping when
the acknowledgement or prerequisite is absent.

### O11 - Generate and distribute intra-AS topology types

**Problem.** Inter-AS topology is generated, but AS interiors remain explicit
and AS-granular placement forbids distributing a large Clos.

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

**Problem.** Student routers run as root with `CAP_SYS_ADMIN`, label scoping is
not a kernel tenancy boundary, and one cluster-wide controller identity can
mutate every lab.

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

**Problem.** Architecture documents claim gRPC, two binaries, no state store,
minimal diff apply, Prometheus metrics, underlay health metrics, and node-loss
rescheduling. The implementation uses HTTP, builds five binaries, persists
file state, and lacks the latter features. The root README also contains stale
course status.

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

**Problem.** `twinet node bootstrap` emits a non-loopback service with only a
bearer token, while `twinetd` correctly refuses to start without mTLS or
`-insecure`. Examples use mutable image tags, and exact build matching prevents
rolling upgrades.

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

**Shipped reproducibility contract.** `images.mode: development` is the
explicit opt-in for mutable tags. `release` and `grading` require
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

**Problem.** Cluster E2E is manual, there is no reproducible scale benchmark
script, and concurrent-controller, node-loss, migration, overlay-GC, and
24-hour soak behavior are not release gates.

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

1. Start a **fresh** reviewer with model **GPT-5.6 Sol**, maximum reasoning
   effort, and long context.
2. Give it this document, the implementation diff, test/benchmark evidence, and
   instructions to be objective, adversarial, and constructive.
3. Treat any verdict other than exactly `PASS` as `FAIL`.
4. Record every finding, fix it, rerun the relevant acceptance evidence, and
   start a new reviewer with clean context.
5. Stop only after **two fresh review rounds in succession** return `PASS`.
