# 09 — Implementation status

This records what is built and verified, so the plan and the code cannot drift.
Measurements are from the three-node cluster (node-0/1/2, 56 cores and 251 GiB
each, 10 GbE private fabric).

Last updated after the grading milestone and the first external code review.

The fault-injection objective of [10](10_fault_injection.md) is recorded in the
plan but not yet implemented; it is milestone M8.

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
| Node agent and cluster fabric | done | 12-AS lab: 211 devices, 291 links across 3 nodes in **83 s**, zero failures |
| Cross-node VXLAN | done | 50.22 ms measured for a 25 ms configured delay, 9 µs jitter, no duplicates |
| AS-granular placement | done | 13.4 % of links cross the fabric; `twinet inspect --placement` |
| Underlay MTU verification | done | `twinet node check` refuses a lab that would not fit and names the MTU to use |
| Grading engine: rubric, 17 checks, structured reports | done | 3 submissions in **31 s**; JSON, text and CSV output |
| Reference solution (`--solve`) | partial | scores **7.33 / 10** against its own rubric |
| Container images | done | `hyhe/twinet-{router,host,switch,svc}` |
| Reference solution | **10.00 / 10.00** | verified end to end on the live cluster; a rubric whose reference cannot score full marks is unfalsifiable, and every student who loses that mark loses it to the platform |
| RPKI | done | the lab is its own trust anchor: an RTR validator serves a payload derived from the topology, with declared discrepancies so an exercise can state exactly which announcement is invalid and which has no ROA |
| SSH gateway | done | one credential per group, authenticated at the edge; device names resolve within the student own AS so another group router cannot be named at all. Legacy per-AS ports are served but do not authorise. Verified across the cluster |
| Save and restore | done | `twinet save` archives every group work with the topology hash and per-file checksums; restore refuses an archive from a different topology or one edited after it was taken |
| Per-submission grading harnesses | done | `twinet grade batch` gives each submission a private lab in which every AS but one is solved; verified with two submissions graded concurrently across three nodes |
| Fault injection engine | partial | 21 types across all six NIKA categories, out of the 47 that are in-substrate; **21/21 inject, verify and resolve** on the live cluster, re-checked by `make e2e` in 25 seconds |
| Incident runner | done | `twinet incident run`; a two-fault scenario injects, holds and unwinds in 798 ms |
| Ground-truth isolation | verified | audited: 0 hits for the fault name, root cause or ground truth anywhere in a target container's files, environment or labels |
| DNS | done | zones are generated from the model, served by BIND in the service container, and every device points at the lab own resolver; verified end to end for forward and reverse lookups |
| Matrix, looking glass, policy analyzer | partial | the collectors and the analysis are implemented and tested, but nothing yet serves their output, so a student cannot open a looking glass |
| _(collectors)_ | done | control-plane collectors; the analyzer reads structured paths and the declared relationships rather than scraping text |
| CI, Makefile, lint config | done | `.github/workflows/ci.yml` |

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

## Environment findings

- **Jumbo frames are unavailable.** Raising `eno2` to MTU 9000 dropped the
  carrier and made a node unreachable; it was reverted immediately. The lab MTU
  is therefore pinned to **1450** and applied to *every* link, local ones
  included, so a student's network behaves identically wherever their AS is
  scheduled. This was the documented fallback in
  [04](04_networking_and_scaleout.md) §1.3.

## Remaining work

| Item | Milestone | Note |
|---|---|---|
| Serving DNS, matrix, looking glass and the web UI | M2 | The data is generated and tested; the containers that should serve it still run `sleep infinity`. A student cannot yet resolve a name or open a looking glass |
| SSH gateway with label-based authorisation | M2 | The agent already enforces owner-scoped exec, which is the hard half |
| RPKI (Krill + Routinator) provisioning | M2 | Needed for the last point of the rubric |
| Reference answers for exchange communities, traffic engineering and RPKI | M7 | The remaining 2.67 points of `--solve` |
| Diff-and-converge `apply` | M4 | Deploy is idempotent, but does not yet compute a minimal change plan |
| `twinet save` / `restore` | M2 | |
| Advanced-course exercises (MPLS, VRF, multicast) | M7 | The agent already loads the MPLS modules |
| 80-AS scale run | M6 | The 12-AS run extrapolates to roughly 9 minutes |
| The remaining 28 in-substrate fault types | M8 | 19 of the 47 are implemented; the rest are mostly variants over the same primitives |
| DHCP, web and load-balancer services, traffic generation | M8 | Prerequisites for eleven of the remaining fault types |
| NIKA `LabRuntime` adapter | M8 | About fifty semantic operations, brokered through the existing agent exec API |

## Measurements

| Metric | Value |
|---|---|
| 12-AS lab, 211 containers, 291 links, 3 nodes | 83 s |
| Same lab, single node | not attempted; 4-AS/57-container demo takes 64 s |
| Cross-node link RTT (25 ms configured) | 50.22 ms, σ 9 µs |
| Links kept local by AS-granular placement | 86.6 % |
| Grading, 3 submissions, 10 questions, 17 checks | 31 s |
| Grading, 1 submission in its own full-breadth harness | 6 minutes |
| **Class-scale deployment: 84 ASes, 2012 devices, 2927 links across 3 nodes** | **22m 38s, zero failures** |
| Containers per node at that scale | 724 / 750 / 750 |
| Node utilisation at that scale | 22 GiB of 251, load average 13 of 56 cores |
| Emulated latency on a cross-node link at that scale | 20.07 ms for 20 ms configured |
