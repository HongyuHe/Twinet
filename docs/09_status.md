# 09 — Implementation status

This records what is built and verified, so the plan and the code cannot drift.
Measurements are from the three-node cluster (node-0/1/2, 56 cores and 251 GiB
each, 10 GbE private fabric).

Last updated after the sixth external code review.

Rows are written from evidence produced by a run, not from intent. Where a
number appears it came from the command named beside it; where a target was
missed it is recorded as a miss.

## Built and verified

| Area | State | Evidence |
|---|---|---|
| Typed model, manifest loading, aggregated positional validation | done | `internal/model`, `internal/manifest`; `twinet validate` reports every problem in one pass |
| Expression-based addressing plan | done | `internal/ipam`; tests assert the plan reproduces the COS-461 assignment text exactly |
| Deterministic allocation (VNI, MAC, interface names) | done | `internal/alloc`; tests assert order-independence, uniqueness across 5,000 links, and that names fit `IFNAMSIZ` |
| Template expansion, tiered-internet generator, post-expansion verifier | done | `internal/expand`; the verifier caught two real modelling defects (see below) |
| Netlink wiring: veth, netns, shaping, VXLAN | done | `internal/netx`; rate/time parsing tested against bit-vs-byte and binary-vs-decimal confusion |
| Container runtime abstraction | done | `internal/runtime` (docker) |
| Staged deployment DAG with per-scope failure isolation | done | `internal/plan`; tests assert stage ordering, real concurrency, and that one broken AS does not stop a class |
| Convergence predicates in place of sleeps | done | `internal/plan.Wait`, `internal/grade/converge.go` |
| Single-node deployment | done | 4-AS demo: 57 devices, 74 links, 64 s |
| Node agent and cluster fabric | done | 12-AS lab: 212 devices, 299 links across 3 nodes in **58 s**, zero failures |
| Cross-node VXLAN | done | 50.22 ms measured for a 25 ms configured delay, 9 µs jitter, no duplicates |
| AS-granular placement | done | 13.4 % of links cross the fabric; `twinet inspect --placement` |
| Underlay MTU verification | done | `twinet node check` refuses a lab that would not fit and names the MTU to use |
| Grading engine: rubric, 22 registered checks, structured reports | done | the COS-461 rubric uses 18 of them; 8 systems graded in **79 s**; JSON, text and CSV output |
| Reference solution (`--solve`) | done | scores **10.00 / 10.00** against its own rubric, verified end to end and re-checked by `make e2e` |
| Container images | done | `hyhe/twinet-{router,host,switch,svc}` |
| Reference solution | **10.00 / 10.00** | verified end to end on the live cluster; a rubric whose reference cannot score full marks is unfalsifiable, and every student who loses that mark loses it to the platform |
| RPKI | done | the lab is its own trust anchor: an RTR validator serves a payload derived from the topology, with declared discrepancies so an exercise can state exactly which announcement is invalid and which has no ROA |
| Mutual TLS | done | `twinet node pki` issues a cluster CA, a key per node and a controller certificate; the cluster now refuses plaintext and refuses TLS without a client certificate, verified against the live agents |
| SSH gateway | done | one credential per group, authenticated at the edge; device names resolve within the student own AS so another group router cannot be named at all. Legacy per-AS ports are served but do not authorise. Verified across the cluster |
| Save and restore | done | `twinet save` archives every group work with the topology hash and per-file checksums; restore refuses an archive from a different topology or one edited after it was taken |
| Per-submission grading harnesses | done | `twinet grade batch` gives each submission a private lab in which every AS but one is solved; verified with two submissions graded concurrently across three nodes |
| NIKA LabRuntime adapter | done, with one caveat | `TwinetRuntime` subclasses NIKA's `LabRuntime` and implements all ten abstract methods, so the ~50 semantic operations of `ExecSemanticOpsMixin` work; verified live on the three-node cluster, including driving an unmodified `LinkFailure` problem through inject and verify. The caveat: NIKA's problem classes select behaviour with a literal `match` on the backend name and refuse anything that is not `kathara` or `containerlab`, so the runtime must be constructed with `dialect="kathara"` — the arm that is correct for Linux/FRR/eth0 devices. Without it, every problem raises `RuntimeCapabilityError`. See `contrib/nika/README.md`. |
| Fault injection engine | partial | **42 registered, of which 40 are NIKA's** (NIKA publishes 60). Of the 20 not implemented, 15 need a substrate Twinet does not emulate — 6 P4/BMv2, 4 Kubernetes, 3 SDN-southbound, 2 others — and **5 are applicable and merely unbuilt**: the DHCP family. All 42 inject, verify, resolve, and are then checked to have left the device exactly as they found it; `make e2e` runs the full round trip in 54 s. See [10](10_fault_injection.md) §4.1 |
| Faults are reversible, and proved to be | done | The engine fingerprints a device before and after injecting and requires resolving to leave neither what it added nor a hole where something it removed used to be. Introducing the check immediately found five faults that satisfied their own predicate while leaving the device broken |
| Fault secrecy | verified | No fault writes a self-identifying path into the device under test. A test reads the fault sources and fails on any such path; it found one on its first run |
| Self-healing wiring | done | A container that restarts comes back with an empty network namespace. Each node now notices within a minute and rebuilds that device's links and configuration. Measured: `svc/matrix` went 10 interfaces → 2 → 10, repaired 0.8 s after detection, with no deploy run |
| Incident runner | done | `twinet incident run`; a two-fault scenario injects, holds and unwinds in 798 ms |
| Ground-truth isolation | verified | audited: 0 hits for the fault name, root cause or ground truth anywhere in a target container's files, environment or labels |
| DNS | done | zones are generated from the model, served by BIND in the service container, and every device points at the lab own resolver; verified end to end for forward and reverse lookups |
| Matrix, looking glass, policy analyzer | partial | the collectors and the analysis are implemented and tested, but nothing yet serves their output, so a student cannot open a looking glass. This is the largest remaining gap |
| _(collectors)_ | done | control-plane collectors; the analyzer reads structured paths and the declared relationships rather than scraping text |
| CI gates | done | `make ci` refuses to run without golangci-lint and shellcheck rather than reporting a pass it did not verify, and includes `go mod tidy -diff`. Turning the lint on found five real problems. The GitHub workflow is disabled on push by request; `make ci` runs the identical gates |
| Grading marks behaviour, not text | done | The exchange check requires the policy to be bound to the route server, the 6in4 check requires a tunnel that carried the packets rather than the kernel's own `sit0`, and the RPKI check requires a connected validator holding ROAs before an empty invalid table means anything |

## Defects found by the platform's own checks

Recording these because each is the kind of fault that would otherwise have
reached students, and each motivated a permanent test.

1. **Colliding interface names.** A reduced staff-run AS carries every external
   port on one router, so two links to the same peer both wanted `ext_3`.
   External interfaces are now named after the peer's *router*, with a
   deterministic uniquifying pass behind that. Caught by the post-expansion
   verifier.

2. **The internet exchange was not a shared LAN.** It was modelled as
   point-to-point cables that all carried the same `/24`, so every member would
   have believed the whole peering LAN was on-link while being unable to reach
   any of it. An exchange is now a real fabric switch, which is what the
   hardware is and what lets a member at `180.Z.0.<ASN>` reach the route server
   at `180.Z.0.Z` as the assignment promises. Caught by the prefix-overlap check.

3. **Duplicated packets on every cross-node link.** Creating a VXLAN device with
   a unicast remote already installs the all-zeros forwarding entry, so
   appending another produced two copies of every flooded frame. Students would
   have seen duplicate ICMP replies and inexplicable traceroutes and reasonably
   concluded they had misconfigured something. The entry is now reconciled
   rather than appended.

4. **A wrong reference answer.** Two keys in the OSPF cost map were written in
   the opposite order to the lookup, so their costs silently defaulted and one
   of the three prescribed load-balanced paths never appeared. Now the map is
   canonicalised at startup, and `TestReferenceECMPArithmetic` computes shortest
   paths through the real topology to assert that exactly the three prescribed
   paths tie and no fourth does.

5. **A stale agent.** A rollout used a binary built before the change it was
   meant to carry, which presented as a networking bug. `scripts/deploy_agents.sh`
   now verifies each node ends up with the checksum that was just built.

6. **Kubernetes-style memory quantities.** Docker rejects `512Mi`. Quantities are
   now normalised, and validated at author time rather than discovered one
   container at a time during a deployment.

7. **Six faults that did not work, or could not be undone.** Exercising all
   nineteen against the live cluster found: verify predicates too loose to tell
   an active fault from a repaired one; `pgrep -x` silently matching nothing on
   busybox, so a fault reported success without ever stopping the daemon;
   `pkill -f` matching the command line of the shell running it and killing
   itself half-way; `watchfrr` surviving a stop and holding its pid lock so the
   router never came back; `rm` failing on Docker's bind-mounted
   `/etc/resolv.conf`; and a fault that captured an empty file and would have
   guaranteed data loss on resolve. None of these were reachable by unit test.

8. **A fault that destroyed what it was meant to perturb.** `host_incorrect_gateway`
   pointed a host's default route at a dead neighbour and resolved by deleting
   the default route; where no prior route had been recorded it put nothing
   back. Its verifier asked whether the route went via the wrong gateway, the
   answer was no, and the resolve reported success — while the host was left
   unable to leave its own subnet. It surfaced a week later as a single
   unreachable host in a grading run, by which point nothing connected it to
   the cause. The mark it cost was very nearly attributed to the student. Every
   resolve is now checked against the state the injection found, which
   immediately found four more of the same shape: removing an address or
   downing an interface takes with it every route that resolved through it.

9. **A restart disconnected a device permanently.** A container that restarts
   comes back with an empty network namespace, and nothing noticed. The wiring
   was already idempotent and a deploy would have repaired it, but a deploy only
   runs when a person runs one, and nobody has a reason to until the symptom is
   reported. Each node now checks its own containers every minute.

10. **A release gate that answered yes without looking.** `make ci` printed
    "all CI gates passed" while skipping the lint and the shell check whenever
    their tools were absent, which on the development machine was always.
    Enabling them found five real problems, one of which mattered: the
    preservation replay treated an unreadable snapshot the same as no snapshot,
    so a corrupt capture was silently skipped and the device came back looking
    clean.

## Environment findings

- **Jumbo frames are unavailable.** Raising `eno2` to MTU 9000 dropped the
  carrier and made a node unreachable; it was reverted immediately. The lab MTU
  is therefore pinned to **1450** and applied to *every* link, local ones
  included, so a student's network behaves identically wherever their AS is
  scheduled. This was the documented fallback in
  [04](04_networking_and_scaleout.md) §1.3.

## Remaining work

Every row here is genuinely outstanding. An earlier revision of this table
listed save/restore, the NIKA adapter and RPKI as remaining while the table
above listed the same three as done, and that contradiction survived two
reviews. If a row appears in both, the row here is the one to believe until
someone has checked.

| Item | Milestone | Note |
|---|---|---|
| Serving the matrix, looking glass and web UI | M2 | The collectors and the analysis are implemented and tested; nothing yet serves their output, so a student cannot open a looking glass. This is the largest remaining gap in the student-facing workflow |
| Gateway `save` / SFTP | M2 | `goto`, `status` and `help` are there, and leaving a device shell now returns to the menu rather than dropping the connection. `save` from inside the gateway and SFTP file transfer are not; students collect work with `twinet save` from outside |
| Krill as a live RPKI publication point | M2 | The lab serves an RTR feed derived from the topology, which is what the exercise needs; a real publication point with per-AS validators is the fuller version |
| COS-461 Q2.6 stub-AS hijack scenarios | M7 | The RPKI machinery is in place and the check is honest; the scripted hijack scenarios are not written |
| Diff-and-converge `apply` | M4 | Deploy is idempotent and now self-healing, but does not compute a minimal change plan |
| Advanced-course exercises: multicast | M7 | MPLS and VRF are done -- `examples/advnet` is the ETH BGP-free-core and BGP/MPLS L3VPN exercise, verified end to end on the cluster: the two sites of each bank reach each other over a two-label stack, neither bank reaches the other, and the core router has no BGP instance and four operational LDP neighbours. Multicast has no exercise and no checks. It is graded: `examples/advnet/rubric/advnet.yaml` is worth 6 points across the BGP-free core, carrying each customer between its sites, and keeping the customers apart. Verified to discriminate on the cluster, not merely to be satisfiable -- the reference scores 6/6; putting BGP on the core scores 0.8/2 on that question alone; making both tables import both route targets scores 0/2 on isolation while reachability still passes |
| The 20 unimplemented NIKA fault types | M8 | 15 need a substrate Twinet does not emulate (6 P4/BMv2, 4 Kubernetes, 3 SDN-southbound, 2 others); adding them means adding that substrate. The other 5 are the DHCP family. See [10](10_fault_injection.md) §4.1, which explains why DHCP in particular is a design change rather than a fault to add |
| DHCP, web and load-balancer services, traffic generation | M8 | Prerequisites for nine of those |

### Addresses the assignment lets students choose

The COS-461 wiki leaves the layer-2 datacentre addresses and the inter-AS
peering addresses to the students, to be agreed with their neighbours. Twinet
allocates both from its own plan and grades against that plan, and the reference
neighbours are configured with those addresses.

So a group that picks its own DCS addressing, or negotiates different eBGP
addresses with a neighbour, is marked wrong for an answer the assignment
permits -- and in the eBGP case cannot bring the session up at all, because the
other end is a rendered reference that expects the planned address.

This is a real divergence from the assignment as written, not a bug in the
checks: making it right means discovering the addresses a submission actually
used and configuring its neighbours from them. Until it is done, a course using
Twinet has to prescribe the addressing, which the manifest already does.

### Grading checks that are narrower than their questions

Recorded here rather than implied to be complete:

- `tunnel.sixin4` tests one host in each datacentre and one direction. A
  submission that configures one VLAN and not another, or the forward path and
  not the reverse, can still score the point. It does now check that the tunnel
  is 6in4 rather than any encapsulation, and that its endpoints are the two
  gateways' loopbacks.
- `policy.ixp_communities` accepts any non-empty set of real member communities.
  It checks that the exchange relayed the announcement and that no in-region
  route was accepted, but not that the tagged set is exactly the members the
  assignment intends.
- The end-to-end discrimination suite covers q1.2, q2.1 and q2.3. The remaining
  questions are covered by unit tests and by the reference scoring 10/10, which
  is weaker: it shows the checks accept a correct answer, not that they reject
  every wrong one.

### Grading a hundred students is not yet practical in the fair mode

Measured: 4m 56s per submission, one at a time, almost all of it waiting for
OSPF and then BGP to settle -- twice, once for the submission and once for the
reference put back after it. A hundred students is therefore over eight hours.

That is a real limit and it is stated here rather than in a footnote. Three
things would move it, in the order they are worth doing:

1. **A per-submission harness with synthetic neighbours.** The convergence wait
   exists because a submission is graded inside the whole internet. A harness of
   the student's AS plus test doubles for its neighbours converges in seconds
   rather than minutes. It is designed (§4 of [06](06_grading.md)) and not built;
   the private-harness mode that does exist deploys a real neighbourhood and
   takes about twelve minutes a submission, which is worse, and eight at once
   saturates this cluster.
2. **Restoring only what the submission touched.** The reference is currently
   put back over the whole AS, which costs a second convergence. A submission
   names the devices it changed.
3. **`--per-wave`.** It exists and works, and batches submissions no two of
   which are within two systems of each other. It is off by default because that
   is a heuristic about the peering graph and not a proof of isolation, and
   marks are not the place to trade correctness for time without being asked.

## Measurements

| Metric | Value |
|---|---|
| 12-AS lab, 211 containers, 291 links, 3 nodes | 83 s |
| Same lab, single node | not attempted; 4-AS/57-container demo takes 64 s |
| Cross-node link RTT (25 ms configured) | 50.22 ms, σ 9 µs |
| Links kept local by AS-granular placement, 84-AS lab | **89.7 %** (302 of 2927 cross) |
| — of which inter-AS links crossing | **111 of 283 (39 %)**, against 201 (71 %) before the partitioner |
| — intra-AS links crossing | 0 of 2324, by construction |
| Placement cost, 84 ASes / 2012 containers | < 1 s |
| Grading, 3 submissions, 10 questions, 17 checks | 31 s |
| Grading a class of 8 in waves, all scoring 10/10 | **22m 11s in 4 waves**, measured when the conflict relation was adjacency and submissions were loaded onto the solved lab. Both have since changed and this number is not comparable to anything current |
| Waves needed for 8 student ASes / for 80, under `--per-wave 8` | **6 / 42** — the conflict relation is distance-two, so roughly one wave per two submissions. `--per-wave` is off by default; see [grading](06_grading.md) |
| **`grade class`, 8 submissions, one at a time, 5-minute convergence budget** | **39m 29s, 8 of 8 scored 10/10, none quarantined** -- 4m 56s per submission, of which the checks themselves are seconds; the rest is waiting for OSPF, then BGP sessions, then the BGP table to stop changing, twice per submission (once for the submission, once for the reference put back after it). Every archive was saved from the reference, so anything below 10/10 would have been a Twinet defect |
| Same 8 submissions, before the container-identity fix | 28m 12s, **7 of 8 quarantined**: grading recreated 89 of 212 containers, which empties their network namespaces, so loading failed on `Cannot find device port_BOS` |
| Containers recreated while grading, before / after that fix | **89 / 0** |
| Automatic repairs triggered on a lab while it was being graded, before / after the grading hold | **13 / 0** |
| Grading 1 submission in its own private harness | ~12 minutes; measured, and the reason waves exist |
| 8 private harnesses at once on 3 nodes | saturates the cluster; the failures are resource exhaustion, not marks |
| **Class-scale deployment: 84 ASes, 2012 devices, 2927 links across 3 nodes** | **22m 38s, zero failures** |
| Containers per node at that scale | 731 / 731 / 550 with `pack-by-as`, 660 / 675 / 677 with `spread-by-as` |
| Node utilisation at that scale | 22 GiB of 251, load average 13 of 56 cores |
| Emulated latency on a cross-node link at that scale | 20.07 ms for 20 ms configured |
