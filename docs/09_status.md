# 09 — Implementation status

This is the canonical ledger for implementation truthfulness.

| Label | Meaning |
|---|---|
| **Source-verified** | Implemented in this source tree and covered by an automated check. |
| **Measured** | Observed in the named environment/run. It is evidence, not a portability or release promise. |
| **Target** | A desired acceptance threshold; it is not evidence of completion. |
| **Historical** | Retained design or predecessor context, not a current implementation claim. |

Measurements below are from the named three-node cluster when stated. They must
not be generalized to another environment. A source capability with no named
live run is marked source-verified rather than “measured.”

## Source-generated capability facts

The JSON below is a machine-readable documentation surface. The
`TestDocumentationFactsMatchSource` gate derives it from `cmd/*`, the runtime,
NOS, interior, and fault registries, and `twinet validate --json` executed from
source for every bundled example. Do not edit a value to make prose look
complete: change the implementation or regenerate the facts through the test.

<!-- BEGIN SOURCE-GENERATED CAPABILITY FACTS -->
```json
{
  "binaries": [
    "twinet",
    "twinet-dhcpd",
    "twinet-init",
    "twinet-mcast",
    "twinet-openflow-controller",
    "twinet-rtr",
    "twinet-traffic",
    "twinetd"
  ],
  "runtime_backends": [
    "containerd",
    "docker",
    "podman"
  ],
  "runtime_backend_count": 3,
  "network_operating_systems": [
    "bird",
    "frr"
  ],
  "network_operating_system_count": 2,
  "interior_generators": [
    "clos",
    "explicit",
    "ring",
    "two-tier"
  ],
  "interior_generator_count": 4,
  "faults": {
    "total": 62,
    "nika": 60
  },
  "shipped_capabilities": [
    "agent-http-json-mtls",
    "persistent-state",
    "fenced-mutation-leases",
    "docker-engine-api-runtime",
    "selectable-runtime-backends",
    "reproducible-image-locks",
    "rolling-contract-upgrades",
    "shared-vxlan-overlays",
    "replicated-state-and-services",
    "generated-interiors",
    "bird-nos",
    "metrics-and-events",
    "strict-admission"
  ],
  "bundled_examples": {
    "advnet": {
      "ases": 5,
      "devices": 13,
      "links": 17
    },
    "clos": {
      "ases": 1,
      "devices": 11,
      "links": 12
    },
    "cos461": {
      "ases": 12,
      "devices": 212,
      "links": 299
    },
    "demo": {
      "ases": 4,
      "devices": 57,
      "links": 74
    },
    "mixed-substrate": {
      "ases": 1,
      "devices": 9,
      "links": 8
    },
    "multicast": {
      "ases": 1,
      "devices": 12,
      "links": 16
    },
    "scale": {
      "ases": 84,
      "devices": 2020,
      "links": 2927
    }
  }
}
```
<!-- END SOURCE-GENERATED CAPABILITY FACTS -->

The executable list is intentionally generated from the current tree rather
than summarized as “two binaries.” The source facts are not a live acceptance
claim.

## Current three-node acceptance (2026-08-26)

Fresh Claude Opus 5 review round 1 rebuilt the source and independently
deployed it on node-0/node-1/node-2. Its initial verdict was `FAIL`; the
remediation evidence below is from the same 56-core, 251 GiB-per-node,
containerd 2.3.3 cluster. Runtime source was `b86517a`; later commits through
`3d573eb` change tests, bundled placement, documentation, and release locks,
not the measured runtime path.

| Gate | Measured result |
|---|---|
| 84-AS scale run 1 | 472.438 s deploy + 84.694 s convergence = **557.181 s**; focused **1/1**, full reference **10/10** |
| 84-AS scale run 2 | 452.019 s deploy + 84.123 s convergence = **536.191 s**; focused **1/1**, full reference **10/10** |
| 84-AS scale run 3 | 461.108 s deploy + 84.439 s convergence = **545.595 s**; focused **1/1**, full reference **10/10** |
| Scale shape | 84 ASes, 2,020 primary devices, 2,927 links, 186 cross-node links; placement 556/731/733 |
| Healthy no-change deploy | 2,020-device plan verified with zero mutations in the reviewer run; canonical COS461 no-op measured **1.14 s** |
| Mixed FRR/BIRD canonical grade | **10.00/10.00**, no quarantine; BIRD alternate paths are retained by the normalized RIB provider |
| Abandoned grading controller | Controller killed after ephemeral harness commit; 60-second test lease expired and all three agents recorded `lease_reclaim: success`; zero harness containers remained |
| Unrelated work during reap | Canonical COS461 deployed successfully while the abandoned harness expired, remained at 278 managed containers, then graded **10.00/10.00** |
| Bundled generated Clos | 11 devices / 12 links / 6 cross-node endpoints: **19.98 s** deploy, **1/1** grade, clean teardown |
| Cleanup | Every run above ended at zero containers and zero `tw*` host links on all three nodes |
| Immutable release images | Seven `hyhe/twinet-*` images published as `0.1-e8d207d`; every bundled example carries a topology-bound `images.lock.json` with registry `sha256` manifests |

The repeated overlay loss found during remediation was not a failure of the
new agents: kernel probes identified an obsolete second
`twinetd-containerd-scale` fleet, still enabled on port 7300 since Aug 23, as
the process deleting active `twp*` veths. It used a different containerd
metadata namespace but the same root host network namespace. Those services
were stopped and disabled. Current agents hold `/run/twinet/agent.lock`, and
`scripts/deploy_agents.sh` refuses any alternate `twinetd*` process before
changing a node; a second agent start was live-tested and refused with the
current lock owner.

## Built and verified

| Area | State | Evidence |
|---|---|---|
| Typed model, manifest loading, aggregated positional validation | source-verified | `internal/model`, `internal/manifest`; `twinet validate` reports every problem in one pass |
| Expression-based addressing plan | source-verified | `internal/ipam`; tests assert the plan reproduces the COS-461 assignment text exactly |
| Deterministic allocation (VNI, MAC, interface names) | source-verified | `internal/alloc`; tests assert order-independence, uniqueness across 5,000 links, and that names fit `IFNAMSIZ` |
| HTTP/JSON agent API with mTLS | source-verified | `internal/agent.Server.Serve` requires TLS 1.3 client verification for non-loopback listeners; agent/client tests cover the authenticated API |
| Persistent state and replicated records | source-verified | `internal/state`, agent durability, and replica tests cover snapshots, topology/coordination records, acknowledgements, and fail-closed policy |
| Fenced mutation leases and transactions | source-verified | agent/client coordination tests cover fence generations, expiry, reservations, and prepare/commit/finalize recovery |
| Template expansion and generator registry | source-verified | `internal/expand` covers tiered peerings plus `explicit`, `ring`, `two-tier`, and `clos` interiors |
| Netlink wiring and shared overlays | source-verified | `internal/netx` tests cover veths, shaping, and one external VXLAN/bridge per lab/node pair with VLAN-to-VNI bindings |
| Docker Engine API runtime | source-verified | `internal/runtime` registers `docker`; API-client tests cover runtime operations and cancellation |
| Docker/Podman/containerd runtime selection | source-verified; measured, bounded | Typed `placement.runtime` plus per-node overrides select registered backends before mutation; `--runtime`/`TWINET_RUNTIME` overrides both for one invocation and every node; agents report backend/version/socket/namespace and controllers refuse a mismatch. Every bundled example declares `runtime: containerd`, so the bundle deploys unmodified on the cluster [12](12_operator_guide.md) builds; a manifest that declares nothing still means `docker` and validation says so. Node-0 ran the source-built Podman 4.9.3 routed lifecycle gate and the native containerd lifecycle/routed gate (`make podman-integration`, `make containerd-integration`): events, create/start/stop/remove, exec/stdin/output, copy, netns wiring, FRR control, and cleanup completed. |
| Image locks and rolling contracts | source-verified; measured | `twinet images lock|verify` records registry manifest digests; release/grading mode requires a checked lock and agents verify after pull before create. Seven immutable `0.1-e8d207d` images were remotely pushed/inspected, `make image-verify` passed, and every bundled example now pins that release with its own topology-bound lock. |
| BIRD NOS provider and capability validation | source-verified; measured | `internal/nos` registers FRR/BIRD and tests refuse unsupported requests. The live canonical and 84-AS reference grades both scored 10/10 with staff transit routers on BIRD; the normalized provider retains BIRD non-best alternate paths needed by traffic-engineering evidence. |
| Student-owned BIRD lifecycle | source-verified | The provider owns configuration capture/load/reload, the observation command list, and the BGP route refresh; `twinet save` records the NOS in the signed manifest and loading refuses a mismatched archive by name. `TestSaveAndRestoreOfABIRDStudentAS`, `TestSubmissionLoadingSelectsTheProvider`, `TestAnArchiveForAnotherNOSIsRefusedByName`, `TestNoFRRBinaryReachesABIRDDevice` and `TestBIRDStudentASGradesTheUnchangedRubricSubset` are the gates. No live student-AS BIRD deployment or grade has been measured. |
| Explicit NOS capability status in reports | source-verified | A check whose subject its NOS cannot express returns `unsupported`: excluded from the question's weighting, never scored zero, and always marking the question `needs_review` with a note naming the NOS. A verdict reached from fewer witnesses than designed carries `reduced_evidence` and marks the question for review when it awarded marks. |
| Service/state replication and endpoint policy | source-verified | model, expansion, placement, and durability tests cover replica identity, failure domains, and endpoint selection |
| Strict live-inventory admission | source-verified | `internal/place`, client, and CLI tests refuse unknown/overloaded capacity before mutation unless audited overcommit is requested |
| Staged deployment DAG with per-scope failure isolation | source-verified | `internal/plan`; tests assert stage ordering, real concurrency, and that one broken AS does not stop a class |
| Convergence predicates in place of sleeps | source-verified | `internal/plan.Wait`, `internal/grade/converge.go` |
| Single-node deployment | measured | 4-AS demo: 57 devices, 74 links, 64 s |
| Node agent and cluster fabric | measured | 12-AS lab: 212 devices, 299 links across 3 nodes in 44–58 s; see [Measurements](#measurements) |
| Cross-node shared VXLAN | measured | 50.22 ms for a 25 ms configured delay, 9 µs jitter; see [Measurements](#measurements) |
| AS-granular placement | measured | Current class-scale locality figures are recorded in [Measurements](#measurements), not as a timeless percentage |
| Underlay MTU verification | source-verified | `twinet node check` refuses a lab that would not fit and names the MTU to use |
| Grading engine, rubrics, checks, structured reports | source-verified; measured runs qualified below | `twinet grade checks`, JSON/text/CSV reports, and the named runs in [Measurements](#measurements) |
| Reference solution (`--solve`) | done | scores **10.00 / 10.00** against its own rubric, verified end to end and re-checked by `make e2e` |
| Buildable binaries and image inputs | source-verified | generated `cmd/*` facts above and the repository build manifest; no fixed two-binary or five-image claim |
| Reference solution | **10.00 / 10.00** | verified end to end on the live cluster; a rubric whose reference cannot score full marks is unfalsifiable, and every student who loses that mark loses it to the platform |
| RPKI | done | the lab is its own trust anchor: an RTR validator serves a payload derived from the topology, with declared discrepancies so an exercise can state exactly which announcement is invalid and which has no ROA |
| RPKI hijack behaviour | source-verified | `bgp-hijack` maps to the registered reversible `bgp_hijacking` fault; `twinet behaviour` controls declared teaching perturbations |
| Advanced MPLS/VRF example | measured, bounded | `examples/advnet` reference scored 6/6 in the recorded cluster discrimination run; this is example evidence, not course-wide acceptance |
| Multicast example | measured, bounded | `examples/multicast` reference scored 4/4 in the recorded cluster discrimination run; this is example evidence, not a claim about all multicast deployments |
| Mutual TLS | done | `twinet node pki` issues a cluster CA, a key per node and a controller certificate; the cluster now refuses plaintext and refuses TLS without a client certificate, verified against the live agents |
| SSH gateway | done | one credential per group, authenticated at the edge; device names resolve within the student own AS so another group router cannot be named at all. Legacy per-AS ports are served but do not authorise. Verified across the cluster |
| Save and restore | done | `twinet save` archives every group work with the topology hash and per-file checksums; restore refuses an archive from a different topology or one edited after it was taken |
| Per-submission grading harnesses | done | `twinet grade batch` gives each submission a private lab in which every AS but one is solved; verified with two submissions graded concurrently across three nodes |
| NIKA LabRuntime adapter | done, with one caveat | `TwinetRuntime` subclasses NIKA's `LabRuntime` and implements all ten abstract methods, so the ~50 semantic operations of `ExecSemanticOpsMixin` work; verified live on the three-node cluster, including driving an unmodified `LinkFailure` problem through inject and verify. The caveat: NIKA's problem classes select behaviour with a literal `match` on the backend name and refuse anything that is not `kathara` or `containerlab`, so the runtime must be constructed with `dialect="kathara"` — the arm that is correct for Linux/FRR/eth0 devices. Without it, every problem raises `RuntimeCapabilityError`. See `contrib/nika/README.md`. |
| Fault injection engine | source-verified; separately maintained coverage | The source-generated fault count above and the registry-backed coverage gate in [10](10_fault_injection.md) are authoritative; do not copy a stale count into this row |
| Faults are reversible, and proved to be | done | The engine fingerprints a device before and after injecting and requires resolving to leave neither what it added nor a hole where something it removed used to be. Introducing the check immediately found five faults that satisfied their own predicate while leaving the device broken |
| Fault secrecy | verified | No fault writes a self-identifying path into the device under test. A test reads the fault sources and fails on any such path; it found one on its first run |
| Event-driven self-healing | done | Agents subscribe to managed runtime lifecycle events and target only the affected device; sampled and low-frequency full audits are the backstop. Forwarding probes are model/NOS-capability-aware: IXP route servers prove BGP sessions/RIB but are not expected to reach every host. FRR sidecars are audited separately, must have exactly one enabled daemon and a working vty socket, and are repaired/recreated without replacing the primary namespace. Live three-node acceptance: all 66 controls healthy, AS3 reaches AS5/AS10, and AS3/AS5 both grade 10.00/10.00 |
| Automatic abandoned-object collection | done; measured | The agent applies a configurable grace period and generation/active-lab plus final runtime-container proof before collecting legacy or multiplexed overlays, stale host veths, expired reservations, and stale local control/replica records. Active, busy, held, and fenced labs are never candidates. A killed grading controller's harness self-reaped on all three live nodes while an unrelated COS461 lab deployed and remained intact. |
| Authenticated node sweep and overlay classification | measured, bounded | Upgraded agents returned zero orphans. The 28/24/14 observed overlays were active COS-461 links, correcting the earlier shell-only misclassification. |
| Incident runner | done | `twinet incident run`; a two-fault scenario injects, holds and unwinds in 798 ms. It also runs an agent and scores what it says against the ground truth: four parts (detection, devices as a Jaccard overlap, category, root-cause names), and the agent is given the brief and never the answer, which the end-to-end suite asserts. Measured with a small agent that greps for a router with too few OSPF adjacencies: 0.70 of 1.00, blaming the router that lost an adjacency as a consequence rather than the one the fault was injected at |
| Ground-truth isolation | verified | audited: 0 hits for the fault name, root cause or ground truth anywhere in a target container's files, environment or labels |
| DNS | done | zones are generated from the model, served by BIND in the service container, and every device points at the lab own resolver; verified end to end for forward and reverse lookups |
| Matrix, looking glass, policy analyzer | done | `twinet web` serves an overview, the connectivity matrix and a looking glass restricted to nine read-only commands. Matrix refresh batches reachability and path-policy probes source-side, using at most two container execs per source AS while preserving down/unknown/policy verdicts; runtime/repair events invalidate the cache. What it does not have, and the original had, is the time slider over historical snapshots, per-group VPN status and the Krill proxy |
| Agent metrics and event stream | done | `GET /metrics` emits bounded Prometheus text for operations, queues, runtime events, inventory, overlays, reservations, convergence, repairs, grading infrastructure, and underlay health. `GET /v1/events` is a durable bounded scoped stream; `twinet events [--json] [--follow]` merges node pages deterministically and diagnostic credentials remain confined to their lab |
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

   The wiring was the visible half. The restarted task also gets a *new* network
   namespace, and the private FRR control sidecar created against the previous
   task keeps running in the old one — a complete daemon set, a live vty socket,
   the right running configuration, and no cables. Every check that read the
   sidecar alone certified it: `node controls` printed `ok`, and `deploy` and
   reconcile reported success over a router with no control plane. Namespace
   identity is now proven between a router and its sidecar (inode identity where
   the backend can give it, the router's own interfaces either way), a split is
   reported as degraded rather than inferred from daemon counts, and reconcile
   rebuilds the sidecar in the router's current namespace without touching the
   student's container. The first version of that proof was itself defeated the
   same way: it resolved the backend capability by type assertion, so a runtime
   decorator satisfying only the core interface hid it, and every caller fell
   back to assuming the sidecar was where it had been put. Capability resolution
   now walks decorator chains, and a runtime that runs split sidecars without
   being able to place them stops the deployment instead of certifying it.

   Repairing the namespace turned out not to repair the router. A new namespace
   is empty, and an address a student configured lives only in their FRR
   configuration, so the repair depends on FRR re-applying that file. Applying
   `interface X` / `ip address A/B` belongs to `mgmtd`, which FRR's own init
   script starts whatever `/etc/frr/daemons` says; the containerd backend starts
   the daemons itself and started only what the file enabled, so `mgmtd` and
   `staticd` never ran on that backend. Every address line was refused with
   `mgmtd is not running` while the OSPF and BGP around them were accepted, and
   the cost was invisible for as long as the addresses an earlier deployment had
   put in the kernel survived. Once the namespace was replaced they did not: the
   router came back wired, supervised, holding a correct running configuration,
   with no address on any interface and no adjacency with anyone. FRR's
   mandatory daemons are now started on every backend and checked like any
   other, and the containerd lifecycle gate asserts the addresses and a Full
   OSPF neighbour after a restart repaired by an ordinary deploy.

   That was still the wrong boundary. On a teaching deployment most of a
   router's addresses are not in its FRR configuration and never were: where a
   course leaves the router interfaces and loopbacks to its students, the
   platform renders no `ip address` for them, so the running lab holds them
   only because somebody configured them and a save splits the router into a
   `.conf` of protocol configuration and a `.sh` of the `ip` commands that
   recreate the addressing. Repairing the namespace put the sidecar back and
   asked FRR to reload a file the addresses had never been in. The deployment
   had the work — in the state store, where the save had put it — and never
   looked, because nothing marked the router as owing a replay: its container
   was joinable, its specification hash matched, and the only thing that had
   changed was a namespace nobody was comparing. The gate could not have caught
   it either, since a lab it had just solved carries those addresses in its
   configuration. The namespace a device was last configured in is now recorded
   beside the hashes that decide whether it is current, a device found in a
   different one is rewired, reconfigured and replayed in that order, its
   neighbours on the node are replayed with it because a veth is rebuilt as a
   pair, and nothing captures over that state until the replay has happened --
   the pass that finds a restarted router used to be the pass that overwrote the
   snapshot it was about to restore. The gate now runs a restored submission
   rather than a solved lab, and fails without the replay.

   Three things that repair left behind. Noticing a restart is not the same as
   repairing it: a link is only rebuilt when one of its endpoints is being
   created, and a device with no control sidecar -- a host, a switch, a BIRD
   router -- had no sidecar to prove anything, so it was marked for a replay
   with none of its cables scheduled and its addresses were applied to
   interfaces that were not there. The comparison also needs something to
   compare against, and the first deployment after an upgrade has nothing
   recorded: a device that is healthy and never configures would never acquire a
   baseline, so an apply now records the namespace of every device whose
   semantic probe passes, a plan records nothing, and a device whose network
   state is already missing is neither blessed with a baseline nor captured from
   until it is healthy again. And prune, the one path nobody gets to undo,
   stored what it read straight into the store: a container that came back from
   a restart and had not been replayed into filed its empty namespace over the
   snapshot on the way to being deleted.

   What a baseline is allowed to be taken on. The paragraph above says "whose
   semantic probe passes", and that was the hole: in platform mode the probe
   skips every interface a student owns, a router is never asked for a default
   route, and a device the audit already believes healthy is not re-read at all,
   so a student's router that restarted into an empty namespace last term passes
   all three. Blessing it records the one place their work is *not* as the place
   it lives. A baseline is now taken only on a positive reading of the namespace
   -- every interface the wiring put there, every platform address on them, and
   every address the state store last saved for the device -- bracketed by the
   namespace identity before and after, so a device that restarts mid-proof is
   refused rather than credited. The reading covers the devices that are about
   to be *replaced* as well: a changed image turns the semantic probe off, and
   that is exactly the device whose empty namespace was being captured over the
   addressing its replacement would have restored.

   What a namespace holds, and who is told when it cannot be shown. The reading
   above compared addresses, and a namespace holds more than those: a VLAN
   sub-interface and a VRF master are objects in their own right, and a tunnel
   and a bridge port are the whole of what the other two snapshots are, so a
   switch whose ports had lost every VLAN and a router that came back without
   its 6in4 tunnel were still blessed. All of them are compared now, in the
   canonical form a capture writes, with routes excluded because a daemon churns
   them; each extra reading is made only where there is saved state to compare
   against, so no router is asked for bridge ports and no host for tunnels. A
   snapshot that could not be *read* -- a body that does not match its digest, a
   half-written pair of files -- also answered "nothing saved", which is the
   condition under which an empty namespace proves continuous; only a snapshot
   that was never taken counts as none now. And the refusal is finally visible:
   the node publishes `unproven_namespaces` in its apply response and `twinet
   deploy` prints a line per device and exits non-zero, because the devices are
   running, the audit does not look at student-owned state, and a lab that has
   quietly stopped being backed up is not something anybody can be expected to
   infer.

10. **A release gate that answered yes without looking.** `make ci` printed
    "all CI gates passed" while skipping the lint and the shell check whenever
    their tools were absent, which on the development machine was always.
    Enabling them found five real problems, one of which mattered: the
    preservation replay treated an unreadable snapshot the same as no snapshot,
    so a corrupt capture was silently skipped and the device came back looking
    clean.

11. **The benchmark could be answered from the internet.** Every scenario Twinet
    ships names its fault, its device and its interface, and the repository is
    public. The sandbox masked those files on this machine and left the agent
    the machine's network, so `curl` fetched the answer from GitHub and an agent
    that never queried a router scored 1.00. The agent now has a network
    namespace of its own permitting the node agents and nothing else, and the
    published scenarios no longer contain an answer to fetch: they say what kind
    of link or device to break and the run draws one, recording the seed.

12. **Withholding the internet from a paying customer was unassessed.** The
    export half of Gao-Rexford was graded in one direction only — nothing
    learned from a peer or a provider may go to a peer or a provider — because
    a customer may receive anything. "May receive anything" is not "need receive
    nothing": an AS could deny its providers' routes to every customer, leaving
    them able to reach nobody outside it, and keep full marks for business
    relationships. `policy.transit_for_customers` now requires every selected
    route to reach every customer, and the discrimination suite mutates for it.

13. **Reachability inside a VLAN was probed one way.** The same-VLAN half of the
    layer-2 question looped over `i<j` -- one probe per unordered pair -- while
    the cross-VLAN half deliberately probed every ordered pair. A host that
    dropped what it sent to its neighbour, while still answering that
    neighbour, kept whichever direction the loop happened to take, and full
    marks with it. Every ordered pair is probed now. Doubling the traffic
    through links the lab deliberately makes slow then cost a *correct*
    submission a mark to a dropped packet, so the probes send two per hop and
    retry three times: a mark that depends on the weather is worse than a
    missing check, because nobody re-reads a grade that looks plausible.

14. **A route-target leak that only went one way answered no probe.** Isolation
    between VPN customers was established by pinging every site pair in both
    directions. A ping needs a route home, and importing another customer's
    route target on one edge leaves their table alone -- so packets flow into
    the other bank's network, nothing comes back, every probe times out, and
    the check reports perfect isolation. One bank able to inject traffic into
    another's scored full marks. The tables are read as well as probed now.
    Found by the advanced course's new discrimination suite on its first run,
    which is what that suite is for.

15. **One multicast site was never tested as a receiver.** Delivery sent from
    one host and required every other one to receive; the sender was always the
    same host, so that site was never on the receiving end. One `iptables` rule
    on its own router -- a thing a student can write, because a student has root
    in their containers -- blocked the group to it for full marks. The
    no-flooding half had the mirror hole: the source and the single receiver
    were never bystanders, so a submission flooding to exactly those two passed.
    Both now run two rounds with the source moved, and a host covered by
    neither makes the check say it cannot give a verdict.

16. **The multicast rubric's only discrimination test never ran.** It was
    guarded on an environment variable nothing sets. There is now a suite that
    runs by default, and its first execution found the two holes above.

17. **A counterfeit of the unsigned prefix passed for the real one.** Origin
    validation asks that a prefix nobody has signed is still carried rather
    than filtered away; it was marked by finding the prefix in every router's
    table. A submission that filtered the real route away at every border and
    announced the same prefix itself -- pointed at Null0, with a forged AS path
    -- had it everywhere and kept full marks while nothing in that AS could
    reach the network. The route must now have been learned from outside (FRR
    gives a locally sourced route a next hop of 0.0.0.0, and where a route
    entered cannot be written the way an AS path can) and must carry traffic.

18. **A blackholed next hop counted as a reachable one.** The check named for
    "the route is everywhere and the traffic is dropped" asked only whether the
    router had *a* route to the next hop, and a blackhole is a route. The
    entry is parsed now: installed, active, with somewhere to send the packet,
    and not a discard. The same attack exposed a second hole -- the check
    totalled usable next hops across the AS, so a router that had lost its
    externally learned routes altogether contributed nothing to either total
    and vanished into them. Every router must now hold every destination the AS
    has learned.

19. **The loopback was excluded from the check that said it covered every
    interface.** "PIM is up on every interface of all 6 routers" was reported
    by a check whose interface set skipped `lo`. The rendezvous point is
    addressed by its loopback so that it outlives any one link, and one without
    PIM cannot register a source: removing it from all six broke delivery while
    this question kept full marks. The loopback is required now, and exempt
    only from the rule about having a PIM neighbour, which a loopback cannot.

20. **Equal-cost paths that carried nothing.** The question is decided from the
    forwarding tables, which is right -- they say exactly which next hops are
    installed, and sampling traceroutes can miss a live path. What they cannot
    say is whether anything gets through: a rule dropping that exact traffic
    left all three prescribed paths installed and every packet discarded, and
    the report added that the source was balancing over both of them. The
    tables still decide which paths exist; a probe now decides whether they
    work.

21. **A subnet redistributed into OSPF passed for one advertised into it.**
    "Protocol is ospf" is true of a route redistributed from a static
    blackhole: removing a service subnet's advertisement and redistributing a
    Null0 route for it elsewhere put the prefix in every table, marked ospf,
    reaching nowhere, while the check reported all thirty-two subnets carried.
    OSPF classifies its own routes -- "N" intra-area against "N E1"/"N E2"
    external -- and that classification is what is read now.

22. **The label stack that carried nothing.** How a customer is carried is read
    from the forwarding table, which is the only place that can tell a
    two-label VPN path from a static route. Dropping labelled frames on the
    interior links left every stack installed, every packet discarded, and the
    mark intact. The mechanism question now has a precondition: some customer
    traffic must arrive.

23. **The internet exchange never delivered a route to anybody.** A route server
    is transparent -- it relays a member's announcement without putting its own
    AS in front of the path -- and FRR checks by default that the first AS of an
    eBGP update is the peer's. Every member treated every route from the
    exchange as a withdrawal, with no notification and an established-looking
    session, for as long as the lab has existed. The exchange question scored
    full marks throughout, because the half of it that can be observed is a
    refusal and an AS that accepts nothing has certainly accepted nothing wrong.
    Fixing it exposed a second defect hiding behind the first: the in-region
    filter's `_X_` cannot match a path that *is* AS X, which is what a member
    announcing its own prefix at an exchange sends. Both are fixed, and the
    check now requires a member to accept what the exchange is relaying to it
    from outside its region.

24. **A refusal read without a background of acceptance.** "No invalid route is
    selected" is trivially true of an AS that selected no external route at
    all. A deny-everything clause ahead of the RPKI one -- the legitimate
    clause still present and reachable -- left the AS holding only its own
    prefix and kept full marks for origin validation. The check now counts
    what was accepted before reading what was not.

25. **A targeted LDP session accepted as a link adjacency.** LDP will bring up a
    session between two loopbacks over whatever path the IGP offers: right
    peer, right address, operational, labels installed. A submission could take
    LDP off an interior link, replace it with a targeted session, and keep full
    marks for label distribution across a link that distributes none.
    `show mpls ldp discovery` names the kind, and every interior interface must
    now carry a link adjacency with the router on the other side.

26. **Evidence taken from the thing being marked.** Two checks read facts about
    the world out of the submission's own routers. Whether an external session
    was established came from its BGP summary: taking the real link down,
    routing the neighbour's address into the interior and running a
    four-message BGP speaker on a host produced "Established, remote AS 4" for
    a system never contacted. And whether a ROA had been published came from
    `show rpki prefix-table`: withdraw the real authorisation, run an RTR
    server on a host, point the validator at it, and the table says whatever
    the student likes. Sessions are now confirmed from the neighbour's side,
    and publication from the trust anchor's own container.

27. **A counter is a total, and a total can be moved by anything.** Whether
    IPv6 crossed between the datacentres through the 6in4 tunnel was settled by
    the tunnel's packet counters rising during the test. Routing every
    datacentre prefix natively and pinging a link-local address across the
    tunnel in a loop kept the counters climbing and earned the whole mark while
    none of the traffic in question was encapsulated. Each gateway is now asked
    what it would do with a packet for the address being tested, in both
    directions, and the answer has to be the tunnel.

28. **A route attributed to the next hop it carries rather than the session it
    arrived on.** An inbound route-map can set the next hop to anything.
    Pointing a customer's routes at an unrelated on-link address made them
    invisible to the business-relationship check, so ranking them below a
    peer's cost nothing. A path's peerId is the session it came in on and no
    policy can change it; provenance is read from there now.

29. **A reply is not proof the right machine answered.** Internal reachability
    was established by pinging. A DNAT rule on the source redirects the echo
    requests for one host to another, and conntrack rewrites the reply so the
    source sees a perfectly ordinary answer from the address it asked about.
    Each host's own count of echo requests the kernel delivered to it is now
    read before and after the matrix, and a host that answered probes it never
    received fails the question by name.

    What this does *not* establish: a submission controls every host in its own
    AS, so it can redirect an individual probe and leave the destination's
    count rising from the other seven sources. The wholesale case is caught;
    the single-pair case is not, and no evidence gathered inside a network its
    owner controls could catch it. It is recorded here rather than left to be
    discovered.

30. **The rendezvous point PIM would use, rather than the one written for the
    declared range.** The check compared each router's mapping against the
    declared group range exactly and ignored every other row; PIM takes the
    most specific prefix covering the group. A second mapping for a /32 inside
    the range pointed the group the exercise actually sends to at a different
    router, on all six of them, while the question reported agreement.

31. **A count of adjacencies instead of the adjacencies asked for.** Whether
    every interior link was adjacent was decided by counting neighbours in
    state Full against twice the number of links. Making one link passive and
    tunnelling an adjacency between the same two routers kept the total exactly
    right while the link had none. Each interface the plan gives a neighbour
    must now have one, and an adjacency where the plan has no link is reported
    rather than counted.

32. **The provider answering for the customer it is meant to carry.** Whether a
    customer's sites reach each other was established by pinging between them,
    and every packet crosses the provider -- the thing being marked. A rule on
    each edge answering the far site's address locally, with the real traffic
    dropped, left all four probes succeeding and the mark untouched. The
    customer's own hosts now have to have received the probes; unlike the
    single-AS case, they belong to somebody else, so this evidence is decisive.
33. **The right prefix, advertised by the wrong router.** Whether a subnet was
    in OSPF was decided by asking every router whether it held that prefix as an
    intra-area route. A prefix carries no record of where it came from: taking
    the measurement network out of OSPF on the router it is attached to and
    putting the same numbers on a dummy interface on another router left every
    table holding it, and the check gave full credit for a network OSPF no
    longer reached. Each subnet is now bound to the interface the plan puts in
    it, and the check reads what OSPF believes it is running on, per interface.
34. **A network nothing ever sent a packet to.** The measurement and DNS subnets
    are part of the assignment, and grading established only that a prefix was
    carried. The echo counter inside the measurement container read zero after
    every run this project had ever done -- so when the prefix above was moved
    and the network went dark, the data-plane check saw nothing, because it
    probed only hosts. Reachability now also probes from each service container
    into the AS, pinned to the interface facing it: the platform owns that
    container, so the traffic is not something a submission can arrange, and the
    reply has to come back through the subnet being graded.
35. **An address the plan does not mention, costing nothing.** Whether the
    addressing matched the plan was decided by looking for the prescribed
    addresses and nothing else; anything extra was reported and scored neither
    way. Two reviewers made the same objection, and they were right twice over:
    the claim is that the addressing matches, which an unplanned address
    falsifies, and an unplanned address is the raw material for impersonation --
    claiming a subnet that lives somewhere else is how most of the defects above
    were built. An address outside every subnet in the lab now costs half the
    mark for the question, because "and nothing else" is a property of the whole
    system rather than a fiftieth of a count. An address inside a subnet the
    plan assigns elsewhere fails the check outright.
36. **A hijack dressed as transit.** Whether this AS had originated a prefix was
    decided by the AS path being empty. Injecting one with `network X route-map
    M`, where M prepends an ASN, produces a locally sourced route with a path,
    which read as somebody else's route passing through: 203.0.113.0/24
    announced that way propagated to AS 3's customers while the check that
    exists to catch a hijack gave full marks. FRR gives a path it injected no
    peer at all -- `peerId` reads `(unspec)` -- and no route-map can change
    that, because there is no session to name. Either sign is now decisive.
37. **Transit promised and not delivered.** Everything the customer-transit
    check asked about was the routes a customer is *offered*, which is a promise
    rather than a service. Leaving every session established and every route
    advertised while dropping the customers' packets in the FORWARD chain cost
    nothing. A packet now leaves the customer's own router, which the submission
    does not configure, and the destination in a third AS counts what it
    received. A multi-homed customer that prefers another provider routes
    nothing this way, so the traffic is put onto the session with one host route
    on their router -- with a source address of theirs that the internet can
    route back to, because the link's own numbering is advertised nowhere and
    the first reverse-path check on the way drops it.
38. **Two VLANs that were one broadcast domain.** Everything the isolation check
    asked about was IP: hosts in one VLAN adjacent, hosts in two separated by
    the gateway. Mirroring one access port onto another with `tc ... mirred`
    leaves all of that true, because off-subnet traffic goes through the gateway
    by a routing decision the host makes before any frame exists. A broadcast is
    now sent and the far side asked whether it saw it: an ARP request names its
    sender, and a kernel that answers one records who asked. That works where
    watching for a reply does not, because a copy can be made one way only, and
    then the answer goes back into the VLAN it came from while the other VLAN
    has seen everything. One frame crossing fails the question; isolation is a
    property of the domain, not a proportion of it.
39. **A session held open by a timer.** "Established" is a memory, not an
    observation. A session whose packets are being discarded stays Established
    until the hold timer expires -- three minutes with the default timers, which
    is longer than a grading run -- so an iBGP session blackholed in both
    directions scored full marks while carrying nothing. Each router is now
    asked to send a route refresh, which is a real message that has to cross the
    connection, and the peer's own received count records its arrival. It also
    makes the peer answer, so the counts move in both directions, and it
    disturbs nothing: the peer re-sends routes the receiver already has.
40. **A prefix in OSPF that no routing table holds.** Whether an inter-AS range
    had been put into the interior was decided from `network` statements and
    from the OSPF routing table. Redistributed with the maximum metric, a range
    is flooded to every router in the area and installed by none of them:
    LSInfinity means "do not use this", so the routing table is empty and the
    check passed. The link-state database is where being in OSPF is decided; a
    routing table is only what a router chose to do about it. All four kinds of
    advertisement are read now -- router, network, summary and external -- so a
    stub link, a transit segment, an inter-area summary and a redistribution are
    all caught, whatever metric they carry.
41. **A tunnel that only carried pings.** Every probe of the 6in4 question was
    ICMPv6. A rule on the gateway discarding forwarded TCP left every ping
    answered, the tunnel counters moving, and the whole point awarded for a
    tunnel across which no connection could be made. A connection is now
    attempted each way, to a port nothing is listening on, so no service has to
    be arranged anywhere: the answer is a reset, and the far side's own count of
    resets it has sent records that the attempt arrived. A datacentre that can
    only be pinged is not reachable in any sense the assignment means.
42. **A route in the table and no packet on the wire.** Whether a next hop was
    usable was decided from what the routing daemon believes, and the daemon is
    not the forwarding plane. A policy rule sending a destination to another
    table, with a discard in it, leaves the route in zebra's main table exactly
    as it should be while the kernel drops the packet: `ip rule add to X lookup
    123` and a blackhole in 123 was measured as a fully resolved next hop and an
    unreachable network, for no loss of marks. The kernel is now asked how it
    would forward, and every router has to reach a host in every other system it
    holds routes for. Those hosts belong to other people, so nothing the
    submission does makes them answer. The probe is sourced from the router's
    loopback: its own choice for a packet leaving over an inter-AS link is that
    link's numbering, which is advertised nowhere, so the answer would have no
    way back and a healthy router would read as unable to reach half the
    internet.
43. **An ordering arranged by an attribute nobody looked at.** Gao-Rexford was
    graded by comparing local-preference values, which is what a student
    configures and not what the rule is for. Local preference is only the second
    tie-break in the decision process, so `set weight 65535` on a provider's
    route puts it ahead of a peer's while every local preference in the table
    still reads correctly -- and the whole question kept full marks while
    traffic went to the provider. Which route was *selected* is now its own
    comparison, and a path is classified by the neighbour at the head of its AS
    path rather than by the session this router heard it on: the routes being
    compared mostly arrive over iBGP, where the session says nothing about where
    they entered.
44. **Paths that answered pings and carried nothing else.** The equal-cost
    question was decided from the forwarding tables plus one ICMP probe from end
    to end. That probe takes one of the three paths -- which one is a hash of
    the two addresses, and it is the same hash every time -- so two of three
    prescribed paths could be discarding everything at full marks, and a rule
    permitting ICMP and dropping the rest cost nothing. Every hop of every
    prescribed path is now tried, on the link that hop uses, which the plan
    decides rather than a hash; and a connection is attempted each way between
    the two loopbacks, which is the pair the question names and the pair a rule
    aimed at this traffic would name.
45. **An adjacency on something wearing the link's name.** The interior
    adjacencies were bound to the plan by the name of the interface each ran on,
    and a name is the one part of an interface that anyone with root can change.
    Renaming the real veths, building a GRE tunnel between the same two routers
    and giving it the planned name and addresses put an adjacency on a tunnel
    while the planned link was down, reported as Full "on the link the plan gives
    it". Twinet stamps a tag derived from the link's identity onto both halves of
    the veth it creates, and a veth is not an encapsulation: an interface
    carrying an adjacency now has to be a veth, to carry that link's tag, and to
    have the address Twinet gave it.
46. **An address hidden in another scope.** The addressing check read `scope
    global`, so the scope it filtered on was a place to put an address it would
    never look at: `ip addr add X/32 dev lo scope link` is live, the router
    answers for X, and the claim that nothing unplanned is configured was true
    only of the one shelf the check opened. Every scope is read now, with the
    kernel's own -- loopback and link-local -- exempt, because nobody configured
    them.
47. **An in-region route accepted with its evidence erased.** Which routes
    crossed a system of this AS's own region was decided from the AS path the
    member holds after its own import policy has run, and an import policy can
    rewrite a path: `set as-path exclude 5` turns "5 10" into "10", and a route
    relayed by an in-region member reads as coming straight from outside it.
    Exactly what the question says to refuse was accepted, at full marks. The
    route server belongs to the exchange, and what it advertised is not the
    submission's to edit; its account of the path is what the routes are now
    classified by.
48. **A prohibition narrowed until it prohibits one thing.** Whether a session
    rejects invalid origins was decided by finding a deny clause that matches
    `rpki invalid`. FRR requires every match in a clause to hold, so a second
    one narrows the first: a deny that matches `rpki invalid` *and* a prefix
    list rejects invalid routes on that list and accepts every other. Listing
    the one prefix the lab announces kept full marks, because the check stopped
    at the words it was looking for and the only announcement it then tested was
    on the list. A clause carrying any other match no longer counts, and neither
    does a deny that a permit can be reached before -- route-maps stop at the
    first clause that matches. A preceding permit is allowed only when it
    selects on the validation state itself.
49. **One host that could not reach the preserved network.** Whether an unsigned
    origin was still reachable was decided by one ping from whichever host the
    manifest happened to list first. One probe is a statement about one host: a
    blackhole for that prefix on any other left the sole probe succeeding and
    the question at full marks, while the site behind it could not reach the
    network the question is about. Every host of the AS is asked now, at once,
    and the ones that cannot reach it are named.
50. **A pair that could be pinged and not spoken to.** Every probe of the
    internal data plane was ICMP. A rule discarding TCP between two hosts left
    all eighty-eight succeeding and the question at full marks, while nothing
    but a ping could cross between them. Every ordered pair is now also asked
    for a connection, to a port nothing is listening on: being refused is the
    far side speaking and proves the packets made the journey both ways, while
    silence is something on the path swallowing them. Both look alike to the
    program making the connection, and telling them apart is the whole test. A
    path that carries pings and nothing else caps the check at half, because as
    a fraction of a hundred and forty-four probes the deduction was three
    thousandths, which is the same as not noticing.
51. **A way across that carried one flow and no broadcast.** The isolation probe
    sends a broadcast, which is what a shared broadcast domain leaks. It is not
    what a rule aimed at one flow leaks: an OpenFlow entry copying HTTPS from a
    VLAN 10 port to a VLAN 20 port carried a connection between two VLANs while
    every broadcast stayed where it belonged, at full marks. Each switch's flow
    table is now read, with its port numbering and each port's access VLAN, and
    any rule that sends a frame from a port in one VLAN out of a port in another
    -- or out of a port whatever the frame arrived on -- is a way across. That
    covers every protocol at once and needs no packet, which is what a broadcast
    probe cannot do.
52. **A leak wearing a customer's number.** Whether an advertisement to a peer
    or a provider was a leak was decided from the AS path in that
    advertisement, and a path on the way out is the submission's to write:
    prepending a customer's number in front of a peer's route made a leak read
    as a customer's route being passed on, which is what the rule permits. What
    may leave is now the set learned from customers, recorded at the session
    each route arrived on, plus this AS's own prefix -- named explicitly,
    because the traffic-engineering answer prepends our own number and an empty
    path no longer identifies it. A router table that could not be read stops
    the check rather than turning missing knowledge into an accusation.
53. **Transit that carried pings and nothing else.** The customer-transit probe
    was ICMP. A rule dropping forwarded TCP arriving from one customer left
    every probe answered and the question at full marks, while no connection
    from that customer could cross this AS. A connection is now attempted as
    well, to a port nothing is listening on in a third AS, with the destination
    counting the resets it sends.
54. **A ROA that authorised everything smaller.** Whether a system had published
    a ROA was decided from the prefix and the origin; the maximum length was
    printed and not read. A maximum length longer than the prefix authorises
    every more-specific announcement inside it, so with `maxlen 32` somebody
    announcing a /16 out of the block with this AS forged as the origin is
    RPKI-valid to everybody who checks -- and the ROA that was supposed to stop
    them is what makes it so. Only the block itself counts now.
55. **Somebody else's prefix, re-originated on the way out.** A relayed route
    keeps its origin at the end of its path, and this AS's own prepends go on
    the front. Rewriting the end -- excluding AS 1 and prepending ourselves --
    makes the neighbour believe this AS originates address space it does not
    hold, and it never appears as a locally injected route, so the check that
    exists to catch a hijack saw nothing while the customer's traffic for that
    network came here. The advertised paths are now read for what they claim:
    an origin of ours on a prefix that is not ours is a claim on somebody's
    address space, whatever the local table says.
56. **One port open and the rest of TCP discarded.** The connection probes all
    used port 9, and a fixed port is a published answer: resetting that one port
    and dropping every other connection was measured as a network in perfect
    health, because the one port the grader ever tried was the one port that
    worked. The port is now drawn when the check runs, above the registered
    range and below the ephemeral one, so it is unlikely to find a listener and
    cannot be permitted in advance.
57. **A prepend that emptied the slow link instead of lengthening it.** The
    traffic-engineering question was marked by comparing the length of the
    announcement sent to the slow neighbour with the one sent to the fast. `set
    as-path prepend 1 1 1` towards AS 1 is three hops longer and AS 1 discards
    it outright, because a path through itself is a loop: the slow link stops
    being a backup at all, which is the one thing the question forbids. The
    prepended numbers must now be this AS's own, and the slow neighbour must
    actually hold the prefix -- that neighbour is somebody else's system, so
    what it holds is not the submission's to arrange, and from this side an
    announcement discarded on arrival looks exactly like one that worked.
58. **The ordering agreed with and then ignored.** Gao-Rexford was marked from
    BGP's decision, and the kernel's is what forwards. `ip route replace
    4.0.0.0/8 via <provider>` sends the traffic to a provider while the BGP
    table still shows the peer path selected at a higher local preference: the
    ranking was arranged, agreed with, and overruled, at full marks. An
    externally learned prefix now has to be forwarded by the route BGP chose.
59. **An external session held open by a timer.** The same memory that made an
    iBGP session read as live made an eBGP one: dropping both directions of the
    TCP flow left every external session reported Established, and carrying
    nothing, for the whole of a grading run. Each router is now asked to send a
    route refresh before the states are read, and a session whose received count
    does not move while it is being asked to send is not carrying anything.
60. **A range of ports is a published answer too.** The probe port was drawn
    from twenty thousand to forty thousand, and the file that says so is public:
    permitting exactly that range and discarding every other connection was
    measured as a working network. The draw now covers every port a user may
    bind, so permitting "the range the grader uses" means permitting
    everything. The tunnel is also asked to carry a datagram, because a filter
    can be written per protocol as easily as per port, and the far side's count
    of datagrams arriving for an unbound port is a fact about arrival rather
    than about any answer.
61. **Paths that carried two protocols of three.** The equal-cost paths were
    tried with a ping and a connection. A filter is written per protocol as
    easily as per port: dropping UDP between the two loopbacks left the pings
    and the connections working, and the paths carrying two thirds of what they
    should, at full marks. A datagram is now sent to a port nothing is bound to,
    and the far side's count of those records its arrival.
62. **A copy the switch's own tables knew nothing about.** The isolation check
    reads the flow table, and the kernel will copy a frame for anybody who asks:
    `tc filter ... action mirred egress mirror dev <other port>` carried ICMP
    from one VLAN into another with the flow table exactly as it should be, at
    full marks. Every access port's traffic-control rules are now read too, in
    both directions.
63. **A table emptied so that nothing is owed.** What a customer was owed came
    from the table of the router holding its session, and that table is the
    submission's to empty. Denying every announcement inbound left the router
    holding only this AS's own prefix, advertising exactly that to its
    customers, and the check reporting that every selected route had been passed
    on -- nothing had been selected. What the AS as a whole has learned is now
    the measure, minus what that customer taught us itself.
64. **A pair that exchanged everything but datagrams.** The internal data plane
    was tried with a ping and a connection, so a rule dropping UDP between two
    hosts left all one hundred and forty-four probes succeeding. Every ordered
    pair now also exchanges a datagram, read at the far side from its count of
    datagrams delivered for an unbound port -- the sender cannot be trusted to
    tell, because when the datagram is dropped it hears nothing, and hearing
    nothing is what `nc` reports as success. The pairs go in rounds so that no
    two senders aim at the same host at once and the counter says who arrived.
65. **A session that carried keepalives and no routes.** The liveness probe
    compared the total of all messages received on a session. A firewall
    permitting keepalives and route refreshes by packet length, and discarding
    everything else, left those totals climbing on a session across which no
    route could pass -- the refresh the grader asked for was itself the traffic
    it then counted. An UPDATE is what a session exists to carry, and both the
    internal mesh and the external sessions now require that count to move.
66. **An OSPF instance the reader never opened.** Whether an inter-AS range was
    in OSPF was decided from the default VRF's database and routing table, so an
    instance in another VRF holding one was invisible and the report said there
    was none. FRR keys both answers by VRF when asked for all of them, and a
    finding now names the instance it is in.
67. **Our own prefix, sent with somebody else's origin.** Originating a prefix
    means the path you send for it ends with your own AS number. `set as-path
    exclude all` and a prepend of a foreign number produced an announcement
    every neighbour treated as somebody else's, rejected as invalid and routed
    around -- while the table on this side still showed the prefix locally
    injected, and the question was marked from that. What leaves the AS is now
    read for what it says about the origin of our own block.
68. **Two whole sites cut off from the preserved network.** The probe for an
    unsigned origin's reachability skipped every host in a layer-2 domain,
    because their reachability to *each other* is a layer-2 question graded
    elsewhere. Their reachability to the rest of the internet is not: rejecting
    traffic from both VLANs towards that prefix left every remaining probe
    succeeding and the question at full marks, with two whole sites unable to
    reach it.
69. **A decision made where the routing protocols have no say.** `ip rule add to
    X lookup 100`, with a route in table 100, sends that destination wherever it
    says while zebra's main table -- all a routing daemon reports -- still shows
    the route BGP chose. A customer's destination was diverted through a
    provider that way for no loss of marks, and the same trick hides anything
    else. A router has three rules when nobody has interfered, plus the one the
    kernel adds for itself once any VRF exists; anything else is now reported.
70. **A frame emitted by an action the reader did not know.** The flow-table
    check recognised `output:` and nothing else, so `enqueue:8:0` -- which puts
    the frame on a queue of port 8 and sends it exactly as `output` would --
    carried frames from one VLAN into another at full marks. Every action that
    names a port now counts, and the ones that name none but reach every port,
    flood and all, count as reaching all of them.
71. **A second address on an interface whose address is dictated.** Any address
    inside an interface's own subnet was excused, on the reasoning that the plan
    sometimes leaves the choice open. Where the assignment dictates the address
    it does not: a spare address on a prescribed loopback went unnoticed, and a
    spare address in the right subnet is exactly what an impersonation needs.
    Only the exact address counts on a prescribed interface now; where the
    choice is the student's, anything inside the mandated prefix still does.
72. **An adjacency held up by a timer that had not expired.** An OSPF neighbour
    stays Full for forty seconds after the hellos stop, so discarding OSPF
    between two routers and grading straight away found every adjacency Full and
    carrying nothing. Every hello resets that timer, so a second reading a hello
    interval later says whether one arrived: a healthy adjacency cannot lose
    more than one hello interval of dead time between two readings, and a silent
    one loses the whole wait.
73. **Half a group range rooted somewhere else.** The rendezvous point was
    checked for the one group the rest of the exercise uses, and PIM takes the
    most specific mapping for each group separately. A mapping covering the half
    of the declared range the tested address is not in leaves the test alone and
    takes the rest with it, which was worth nothing. Any mapping inside the
    declared range that points elsewhere is now part of that range going to the
    wrong root, whichever address the exercise happens to test.
74. **A VPN carrying only pings.** Both L3VPN questions were asked entirely in
    ICMP. Dropping TCP and UDP on the provider's routers, and leaving ICMP
    alone, left every probe of `vpn.site_reachability` succeeding and the
    advanced lab at six out of six, on a network across which no bank could have
    opened a connection to its own branch. Reachability now tries a connection
    and a datagram across every pair that answers a ping, reading arrival at the
    far side — the destination's count of resets it sent, and of datagrams it
    took delivery of for an unbound port — so an answer forged on the path is
    told apart from the site replying; a pair carrying ICMP alone is half marks.
    `vpn.isolation` had the mirror hole, a leak that discards echo requests
    between two customers and carries their connections reading as perfectly
    separated tables, and is now asked over all three.
75. **Receivers answering the question by talking to themselves.** Delivery was
    measured as "something arrived on the group", and a host that sends to a
    group on its own segment receives its own packets. Blocking the graded
    traffic outright on every router and leaving a sender running on every host
    therefore satisfied the question for every host at once, with nothing
    delivered anywhere, and kept all four marks. Every packet the grader sends
    now carries a token drawn when the check runs, and only packets carrying it
    are counted. The tree behind them is read the same way: state *for the
    group* is not enough, because a join creates a shared-tree entry whether or
    not a packet ever crosses and a local sender creates one of its own, so the
    routers must hold state naming the source this run sent from.
76. **A program the student wrote answering for them.** Every data-plane
    question is settled by running a program inside a student's container and
    reading what it printed, and a student has root there. A shell script called
    `ping` that prints "3 packets transmitted, 3 received" earns the
    reachability marks on a network that forwards nothing, and one called
    `vtysh` earns the configuration marks for configuration that was never
    written — and neither has to replace the image's copy, because a file
    earlier on the search path is the one that runs. Measured at 10.00 of 10.00
    with a two-line `/usr/local/bin/ping`. Before a grading command runs, the
    container's programs are now compared against the image it is running, both
    sides read by the grader rather than by asking the container: through
    `/proc` on the node, with symbolic links followed by hand because an
    absolute link met under `/proc/<pid>/root` resolves against the node's own
    root and would have hashed the node's shell. A container that fails is not
    marked down — it is quarantined, because a grader that cannot trust what it
    was told does not know what the marks should have been. Two further holes
    were found while building it: comparing against the image *tag* rather than
    the image the container runs made every container look tampered with the
    moment the images were rebuilt, and keeping a container's verdict for its
    lifetime meant a program planted after one run was believed by every run
    after it.

77. **A group is a second table the flow table only points at.** The VLAN
    isolation check reads what a switch has been told to do, and a flow whose
    action is `group:461` has been told nothing at all about where the frame
    goes: the ports are in the group's buckets, which live in a table of their
    own that `dump-flows` never shows. The reader saw an action naming no port
    and found nothing to complain about, so a group carrying UDP from a VLAN-10
    access port straight out of a VLAN-20 one scored 10.00 of 10.00. The reader
    now dumps the groups too and follows every `group:` into its buckets, and
    those into any group they name in turn, stopping on one it has already
    walked so a group pointing at itself cannot spin. The group's own `type=all`
    is not part of a bucket and is deliberately not read as an instruction to
    flood — reading it as one would have failed every switch that has a group.
    The same hole had a second door: the switch's built-in mirror leaves the
    flow table and the kernel's traffic control exactly as a correct switch
    would have them and still copies every frame of one port onto another,
    whatever VLAN either is in. Both are now read; measured at 9.50 and 8.70 of
    10.00 respectively, against 10.00 before.

78. **`vtysh` answers for one BGP daemon, not for the router.** The BGP-free
    core is the point of the MPLS exercise, and the check asked each core router
    `show bgp summary` and believed "% BGP instance not found". `vtysh` speaks
    to the daemons owning one set of sockets under /var/run/frr, and FRR will
    run as many instances as it is told to: `bgpd -N x` puts a second one in a
    pathspace with sockets of its own. A core router holding a BGP instance, a
    configured neighbour and a listener on port 179 in a pathspace answered
    "instance not found" to the grader and scored 6.00 of 6.00 for a BGP-free
    core. A daemon that is not FRR at all -- BIRD, GoBGP, ExaBGP -- shares none
    of FRR's furniture and was equally invisible. Core routers are now asked
    what they are running rather than what they will admit to: their process
    list, every FRR pathspace that either the process list or a stray vty socket
    reveals, and their sockets. Each pathspace is then asked what it holds, so
    the report names the hidden neighbours rather than only their existence.
    None of it fires on a correct answer, and that is the delicate part: FRR
    starts bgpd on core routers and leaves it unconfigured, so "a bgpd is
    running" is the state the exercise *wants* -- an unconfigured daemon holds
    no instance, opens no port and is not a finding. Measured at 4.80 of 6.00
    with the hidden daemon, 6.00 without. `ps` joined the programs a mark
    depends on and is hashed against the image with the rest.
79. **The policy written near a session is not the policy it runs.** A
    neighbour's route-map was looked up by the address on the line, which is not
    how FRR decides what governs a session. A session takes its settings from
    its peer-group unless it states its own, and a peer-group is a template that
    nothing peers with. Reading only the lines written against the address got
    this wrong in both directions at once. Binding a correct policy once on a
    peer-group and pointing the sessions at it -- the ordinary way to write this
    -- was marked as no policy at all: the cos461 reference scored 9.80 for
    accepting invalid origins it was in fact rejecting, which is the worse
    failure of the two, because a student who is right has no way to tell the
    grader is wrong. And the same blindness gave full marks to a submission that
    put the correct policy on the group while overriding it on the session with
    one that filters nothing. The group carried the remote AS, so the group
    stood among the external sessions in place of its own member, and the check
    read the decoy; on the cluster the session ran the override -- the local
    preference the routes carried was the override's -- and the AS scored 10.00
    with no origin validation on its only external session. A binding also
    governs only the address family it was written in; FRR prints IPv6 after
    IPv4 and the last one parsed was kept, so a policy bound inbound under
    `address-family ipv6 unicast` stood for the IPv4 session, measured at 10.00
    before and 9.80 after. Neighbour lookups now resolve group inheritance per
    setting and per direction, keep the family a binding was written in, and
    never grade a peer-group as a session. Measured: the decoy 10.00 → 9.80, the
    correct peer-group answer 9.80 → 10.00.
80. **A refusal is not the far side speaking.** A program making a TCP
    connection learns whether it got an answer, never who sent it. A reset
    carries the destination's address because whoever wrote it put that address
    there, and any router on the way can write one — `iptables -j REJECT
    --reject-with tcp-reset` forges exactly the answer three checks were reading
    as proof of who answered, and an ICMP unreachable reaches the caller in the
    same words. The premise was wrong in both directions at once. `vpn.isolation`
    counted a refusal as two customers exchanging traffic, so a network that
    rejects cross-customer connections rather than dropping them in silence —
    which is isolation, implemented more helpfully — was reported as leaking:
    a host firewall on a customer site, whose packets never left the host, cost
    the provider 2.00 of 6.00. In the other direction `dataplane.internal_
    reachability` and the transit check read a refusal as proof that packets
    arrive, so one `REJECT --reject-with tcp-reset` on a router restored the
    mark for a network across which no connection could pass; the transit check
    had even read the destination's counter already and then cleared itself on
    the refusal regardless. Every one of them now reads the destination's own
    record — the resets it sent plus the connections it accepted, neither of
    which moves unless the packets got there — and probes are scheduled so no
    destination is aimed at twice at once, since a counter that moved is
    otherwise nobody's in particular. Where the destination cannot be asked the
    two directions part company deliberately: reachability falls back to the
    prober's view, because failing a correct path over an unreadable file is the
    more expensive mistake, while an accusation does not, because it carries the
    burden of proof. Measured: the forged refusal 4.00 → 6.00, the forged reset
    10.00 → 9.90, and on a connection that genuinely lands the destination's
    `OutRsts` moves 18 → 19.
81. **A host cannot be its own delivery.** The multicast question asks whether
    the tree carried the source's packets to a site, and it was answered by a
    datagram socket -- which reports what the kernel handed it and cannot say
    where it came from. A host that sends to a group on its own segment
    receives its own packets, so any site could produce the traffic the network
    was failing to deliver. The tag was meant to close that, and it was handed
    to the probe on its command line, in the student's own process table: a
    fifteen-line watcher polling `/proc/*/cmdline` read it and forged the rest.
    Dropping every genuine delivery cost half the mark; adding the watchers put
    it back, on a network across which nothing was carried. Three things are
    different now. The probe reads with a packet socket bound to every
    protocol, so the kernel tells it whether each frame was received,
    transmitted or looped back, and only what came in off the wire counts --
    the host's own traffic is not merely excluded but named in the report. The
    probe no longer holds the tag at all: it reports digests of what it saw and
    the matching happens in the grader, which is the only place that knows what
    was sent. And delivery now also requires the router on the receiver's own
    segment to be putting the group there, which is the network's doing rather
    than the host's. Measured: the drop 4.00 → 2.00, and with a thief better
    placed than any student -- reading every host's process table from outside
    the lab and distributing the stolen tag instantly -- still 2.00, where it
    had been 4.00. Restored, 4.00.
82. **The switch was asked about one bridge by name.** Every reading of Open
    vSwitch named `br0`, because that is what the reference answer builds, and
    `ovs-ofctl show br0` failing made the grader skip that switch without a
    word. A submission that did its switching on a bridge called anything else
    therefore had nothing read at all -- and since the isolation probe sends a
    broadcast, which a rule aimed at one flow does not leak, a targeted
    cross-VLAN forwarding entry on such a bridge cost nothing. Three things
    were wrong at once: the name, the silence when it was not found, and the
    assumption that one bridge is the whole switch. Now every bridge the switch
    has is listed and read, port numbers are resolved against the bridge that
    used them rather than whichever was read first, a switch that cannot be
    asked is reported as unread instead of clean, and the hops are assembled
    into a graph so that a way across through a second bridge -- out of a patch
    port, in on its peer, back out in another VLAN, which no single flow
    describes -- is found. The same name was hardcoded in the snapshot and
    archive paths, so a submission that built its own bridge lost those ports'
    VLANs on the way through its own backup; both now walk every bridge.
83. **A flow's actions were read, not run.** An action list is a program.
    Looking through one for output ports found none in
    `in_port=1,udp,tp_dst=55555 actions=load:4->NXM_OF_IN_PORT[],
    mod_vlan_vid:20,NORMAL`, which names no port to send anything out of: it
    retags the frame into the other VLAN, tells it that it arrived on a port
    that is in that VLAN, and hands it to the switch's own forwarding, which
    delivers it there. `NORMAL` had been read as harmless because on an
    untouched frame it is. The actions are now walked in order, keeping the
    VLAN the frame carries and the port it counts as having arrived on, and a
    rewritten frame handed to `NORMAL` -- or resubmitted to a table that ends
    at one -- is read as delivered wherever the rewrite puts it. A flow that
    rewrites nothing says nothing, so `priority=0 actions=NORMAL`, which is
    the whole table of a correct switch, costs nothing. Measured: 10.00 ->
    9.50 with the flow installed, and 10.00 with it removed.
    Two parsing faults surfaced while pinning this down, each of which had
    been hiding crossings of the ordinary kind. The match ends at a space
    before `actions=`, not at a comma, so a flow whose only match was its
    input port had that port read as `1 actions=output:2`, resolved to
    nothing, and counted as a flow that had never said where its frames came
    from -- so the rule that catches a frame leaving its VLAN never fired on
    it. And a port printed by name arrives in quotes, which matched neither
    the port-number table nor the VLAN table. Separately, the flood action was
    being matched as a substring, so the letters `all` anywhere in an action
    expanded to every port on the switch -- a way to lose marks for forwarding
    that never happened.
84. **Three more ways a switch's forwarding is not in its table.** Found while
    pinning down 83, and closed before anyone had to use them. An
    `output:NXM_NX_REG0[]` sends the frame wherever an earlier flow put the
    register, and a reader looking for a port number found a token that was not
    one and moved on; a destination that cannot be named cannot be said to be
    in the frame's own VLAN, so it is now reported as unread. A `learn(...)`
    action installs flows that are not in the table yet, so the table does not
    yet say what the switch will do; also reported. And a bridge with a
    controller set does not forward by its table at all -- the controller is a
    program of the student's own, free to send any frame anywhere on any
    packet-in -- so a bridge under one is reported as something this cannot
    vouch for. Every switch in all three labs was read first to confirm the
    reference answer has one bridge, no controller and the single flow
    `priority=0 actions=NORMAL`, so none of the three can fire on a correct
    submission.
85. **A forgotten experiment failed a correct answer.** `tunnel.sixin4` took
    the first 6in4 tunnel `ip -d tunnel show` listed and judged the submission
    on its endpoints. A device may carry several, and a student debugging their
    answer routinely leaves one behind; the kernel lists them in its own order.
    A correct `tun6` sitting behind an abandoned `bad_tun` was therefore
    reported as "sourced from 3.0.10.1, not its loopback" and lost half a mark
    for a tunnel that was not the one carrying the traffic. Every tunnel is now
    judged on its own endpoints and the first sound one is taken, which cannot
    award an unearned mark because whether the traffic goes through *that*
    tunnel is settled afterwards by what the gateway does with a packet for the
    far host and by the tunnel's counters in both directions. Measured: with a
    leftover tunnel listed first and the reference tunnel otherwise untouched,
    9.50 before and 10.00 after; with only the wrong-endpoint tunnel present,
    9.00, so the mark still cannot be had without the right tunnel.
86. **A class nobody had marked was reported as a class that scored zero.** The
    run summary printed `graded 1 submission(s)` and `mean 0.00 median 0.00
    min 0.00 max 0.00` for a submission that had been held for review and never
    marked at all. The statistics were right to exclude it -- a quarantined
    zero measures the platform, not the student -- but the line above them
    counted the submissions attempted rather than the submissions the
    distribution covers, so the two disagreed, and the shape they disagreed
    into was indistinguishable from a cohort that had failed everything. The
    line now says `graded 0 of 1` and states plainly that there is no
    distribution; when only some are held it says `graded 88 of 100` and names
    how many are waiting.
87. **The same forgotten experiment, one layer down.** Found while fixing 85.
    Having picked which tunnel to judge, the check found that tunnel's line in
    `ip -d tunnel show` with a substring search for `tun6:` -- which also
    matches `xtun6:`. A leftover tunnel whose name merely ends in the real
    one's, listed first, therefore supplied the endpoints of the tunnel being
    judged, and the fix for 85 did not help because the wrong line was read for
    the right name. The line is now matched on the whole device name. In the
    same function, a name that matched no line at all returned "nothing wrong
    with these endpoints", which awarded the mark for output nobody could read;
    it now says so.
88. **Deducting for a crossing that cannot happen.** A student debugging a
    switch adds `ovs-ofctl add-flow br0 "ip,nw_dst=192.168.99.99,in_port=1,
    actions=output:2"` to watch whether traffic moves between two ports, and
    forgets to remove it. Nothing in the lab has that address, so no frame ever
    matches; the grader's own probes found 0 of 8 pairs leaking. The VLAN
    isolation check failed the domain anyway, because it read the *existence*
    of a rule that names ports in two VLANs and never asked whether any frame
    the lab can produce satisfies its match. Half a point for a rule that
    carries nothing. A rule is now excused only when its destination match
    covers no address the plan assigns anywhere in the topology and none
    configured on the domain's hosts or their gateway right now, and only on a
    bridge whose every action merely chooses a port -- one that rewrites
    addresses, resubmits or learns can manufacture a frame addressed to
    anything. The excused rule is still reported to the student. Note what was
    *not* done: excusing rules whose packet counter is zero, which was the
    obvious fix and would have passed a submission with its VLANs wide open so
    long as nobody sent anything while the grader watched.
89. **Silence from a listener read as an empty wire.** Found in our own audit
    of the multicast checks, which have had less attention than cos461. Both
    multicast questions ran `twinet-mcast` on a host and parsed its output;
    neither looked at its exit status, and a host that printed nothing parsed
    to "saw nothing". A student has root in their containers, so a bystander
    whose listener is made to fail reported no packets, and `no_flooding`
    passed a submission that was flooding -- nothing was reported, so nothing
    had leaked. The same silence in the other direction failed a receiver whose
    listener did not run, for a network fault that was not theirs. A run now
    requires every host to have printed its summary line, and requires the
    receivers to have joined and the bystanders not to have; anything else
    holds the question for review rather than grading it. The exit status is
    checked too.
90. **The same silence, in the VLAN broadcast probe.** Found by sweeping every
    probe in the grading package whose exit status is never read. A pair was
    counted as tested the moment the sending host's `arping` returned, and the
    destination's neighbour table was read afterwards. If that read failed, the
    pair had already been counted, and a pair with no recorded neighbour scores
    as a pair the frame did not reach -- so a destination that could not be
    asked was marked as one the broadcast never got to. A pair now counts as
    tested only once its destination has actually been read; pairs that could
    not be read are reported, and if none could be read the question is held
    rather than passed.
91. **And again in the L3VPN transport probe.** The question that catches a VPN
    carrying pings and nothing else reads, at the destination, the resets it
    sent and the datagrams it took delivery of. Neither counter is one the
    sender can see, which is the point. But when a counter could not be read
    the helper returned "no gap", the pair was scored as carrying ordinary
    traffic, and the pass said in as many words that "every site received the
    traffic addressed to it" -- a sentence about an observation nobody made.
    A pair whose far side cannot be read is now named as untested and the
    question is held, rather than passed on the strength of the sender's own
    view of a datagram, which is no view at all.
92. **A rendezvous point written the other way was invisible.** (Round 103.)
    FRR takes a rendezvous point's groups either inline -- `ip pim rp <addr>
    237.0.0.0/24` -- or by prefix-list: `ip pim rp <addr> prefix-list NAME`.
    The second column of `show ip pim rp-info` then holds the list's *name*,
    and the parser skipped any row whose second column had no slash in it. Both
    directions were wrong. A student whose prefix-list plainly covers the test
    group was told "CENTER has no rendezvous point covering 237.0.0.10", which
    is false, and lost a sixth of the question -- while `multicast.delivery`
    gave them full marks for the tree that mapping built. And a *wrong*
    rendezvous point installed the same way, more specific than the declared
    range, was invisible to the check that exists to find exactly that. Lists
    are now resolved on the router that names them, in sequence order, with
    permits an earlier deny covers dropped. Confirmed live in both directions:
    the prefix-list answer now scores 4.00 where it scored 3.83, and a shadowing
    `prefix-list` mapping to another router is now named -- and it really does
    break delivery, which is what settles that FRR reads these mappings the way
    the check now does.

93. **Nothing to conclude from, concluded from.** The 6in4 question checks that
    the tunnel carries more than pings by reading, at the far side, the resets
    and datagrams it took delivery of. When neither counter could be read the
    loop moved on -- the code said so, "the machinery failed, which is not a
    verdict" -- and the function then returned "it carries transport" to a
    caller that awarded the point. A non-verdict spent as a verdict. The
    question is now held when no direction could be observed. Two smaller
    versions of the same thing in the same file: a tunnel's packet counter that
    could not be read was reported as a tunnel that carried nothing, in both
    the forward and the return direction.

94. **Traffic engineering over a link the check could not name.** (Round 104.)
    The forwarding half of `policy.traffic_engineering` exists to notice the one
    thing the BGP half cannot: `ip route 2.0.0.0/8 <the slow link>`, which
    overrides every local preference the rest of the question reads. It compared
    the routing table's next-hop *address* against the slow neighbours' -- but a
    static route may name an interface instead, and then the table carries no
    address at all. `ip route 2.0.0.0/8 ext_1_ALL` on `as3/MSP` sent the fast
    provider's own prefix out the 25 ms link, and the check reported "slow
    neighbours: AS1 via MSP (25ms)" and awarded 1.00/1.00 for forwarding that
    was going exactly where the question forbids. The offered fix -- deduct for
    any non-BGP protocol -- was rejected: a static route pointed at the *fast*
    neighbour would then be reported as "installed over the slow provider",
    which is not true, and this grader's recurring defect is precisely claims
    that outrun their evidence. Instead the link is now recognised by the local
    interface it leaves by as well as by the neighbour's address. Because FRR
    reports the *resolved* next hop's interface, a static route pointed at some
    far address that recurses over the slow link is caught by the same test.

95. **A routing table that could not be read, read as a router with no
    addresses.** `l3.addressing_matches_plan` runs `ip -o -4 addr show` on every
    router. `Probe` reports a non-zero exit in its result, not as an error, so a
    failed listing arrived as empty output -- and empty output means every
    planned address is missing and no counterfeit address exists. Both verdicts
    at once, from nothing: a correct submission would be failed for addresses it
    does have, and one impersonating another AS's subnet would pass. The exit
    status is now read, and an unreadable table is an infrastructure error.

96. **A traceroute that never ran, read as a host that never answered.** Being
    unable to reach the far side exits *zero* -- traceroute prints `!N` or `*`
    and returns success -- so a non-zero exit means the measurement was never
    made. `traceHops` and `traceFirstHop` ignored it and returned zero hops,
    which `l2.vlan_isolation` reported as "X cannot reach Y". Same shape in two
    more places: `ip -d tunnel show` failing was reported as "has no configured
    6in4 tunnel", and a `nc` that failed to send was reported as a datagram that
    did not arrive, accusing the VPN of filtering by protocol. All four now
    distinguish a failed measurement from a measurement that failed.

97. **"The announcement is discarded" -- said without asking the neighbour.**
    The inbound half of `policy.traffic_engineering` read any foreign AS number
    in the path advertised to the slow neighbour as proof the announcement had
    died: "a path through a neighbour's own number is a loop to it and the
    announcement is discarded, so the slow link stops being a backup at all".
    That is true of the neighbour's *own* number and of nothing else. Padding
    with 99 -- a number nobody in the lab answers to -- left AS 1 holding the
    route and choosing it as best, and the report still said the link had
    stopped being a backup. Survival is now measured at the neighbour instead
    of deduced from the shape of the path. The measurement is also the right
    one: `neighbourHolds` asked whether the neighbour had the prefix *at all*,
    which a prepend of its own number answers yes to whenever the neighbour
    also learns it the long way round -- excusing the one thing the question
    forbids. `neighbourHoldsOurs` requires the path to begin with our number,
    which is what a route received from us looks like. Padding with somebody
    else's number is still deducted, now for the reason that is true.
98. **Silence from a peer with nothing to say, read as a dead session.** Both
    `bgp.ibgp_full_mesh` and `bgp.ebgp_established` prove a session is alive by
    asking the far end to re-send its table and watching the UPDATE counter --
    the right test, since an Established session whose packets are discarded
    stays Established until the hold timer expires. But a peer that has nothing
    to advertise answers a route refresh with nothing at all, and the checks
    read that as "the session is held open by a timer that has not expired yet,
    and carries nothing". A router that originates no prefix of its own has
    nothing to send over iBGP -- split horizon stops it passing on what it
    learnt from another iBGP peer -- and announcing the AS prefix from a subset
    of the routers is an ordinary design. On the live lab it cost a mark for
    seven sessions that were Established for a quarter of an hour and receiving
    one to five prefixes each; every other check in the rubric passed, so the
    submission was correct in every respect and marked down anyway. Whether the
    peer had anything to carry is not a question the receiving end can answer,
    so it is now read from the peer's own advertised count. The dead-session
    test is untouched where that count is non-zero, which is every case findings
    39, 59 and 65 were about: a blackholed session's sender still believes it is
    advertising its routes.

99. **The best of several equal-cost paths, reported as the route.** A VPN
    prefix with several equal-cost paths gets one nexthop per path, each with
    its own transport label, and the kernel hashes flows across all of them.
    `vpn.label_switched` took the deepest label stack among those paths and
    called it the route, so two well-labelled paths hid a third that carried
    the VPN label alone. Removing LDP from one interior link left the route to
    the far site with three paths, one of them unlabelled, and the check passed
    it with full marks and the words "resolve through a transport label and a
    VPN label". Measured, not inferred: the core router's label table had no
    entry for the VPN label such a packet arrives carrying, and five of nine
    source addresses lost every packet. It now looks at every installed path,
    names the ones carrying the VPN label alone, and passes only when all of
    them are label-switched. Two labels stays the right floor even where the
    two edges are neighbours: LDP signals implicit-null one hop away, so
    nothing but the VPN label goes on the wire, but the implicit-null is still
    in the stack the kernel reports, and the lab's directly-connected edge pair
    keeps its mark.

100. **rpki.notfound_preserved asked the submission which prefixes it should be
     judged against.** `roaPrefixes` read `show rpki prefix-table` from the
     first router that answered and returned it, empty or not. A router with no
     validator session prints an empty table and exits zero, and the reference
     cos461 submission carries no `rpki cache` on three of its eight routers,
     so the baseline was decided by which router the manifest happens to list
     first. Removing the one `rpki cache` line from MSP -- which the lab
     plainly permits, three of its peers having none -- moved the examined
     population from 1 prefix to 9, and the report then stated "all 9
     prefix(es) without a ROA are still in this AS's table" when eight of the
     nine were marked `V` for valid in the very BGP table the check had just
     read. `hijackIsAnnounced` already spells out the doctrine this broke:
     asking the student's own routers is circular, because a submission cannot
     be the reference it is judged against. The population now comes from the
     lab's own `lab.rpki.not_found` declaration, which staff control; failing
     that, from every router's table pooled rather than the first one's; and
     when no baseline can be established while candidates exist, the check says
     so instead of reading silence as "nobody has published a ROA".

101. **A working filter marked down for the mechanism it used.** The IXP
     question asks a member to refuse the routes whose path crosses its own
     region, and says nothing about how. `checkIXPCommunities` looked for
     `match as-path` in the inbound route-map and nothing else, so a member
     that refused exactly the same routes with a prefix-list scored 0.5 and was
     told "nothing filters arrivals from 180.140.0.140 on AS path" -- while its
     table held the same two out-of-region routes as the reference answer's and
     none of the six in-region ones the exchange had offered. The comment
     directly above that code already said "the table is what the question is
     about"; the code was not reading the table. Now it does: where the
     exchange offered in-region routes and none arrived, something refused
     them, whatever it was written with. That reads the table only where the
     table can speak -- at an exchange relaying no in-region route at all, an
     empty set of wrongly-admitted routes is the lab's doing rather than the
     submission's, so the configuration stays the only evidence and a member
     with no filter still does not get the mark for free. Both evidence lines
     said "on AS path" whichever way the verdict went; they now report how many
     in-region routes were offered and whether they arrived.

102. **A router accused of impersonating itself.** An address inside a subnet
     the plan assigns elsewhere fails the addressing check outright, which is
     right: that is how a submission stands in for a part of the network it is
     not. But "elsewhere" was read as "any interface other than this one", so a
     second address on a router's own prescribed loopback -- inside the router's
     own /24, advertised by the router itself, answering for nobody else -- was
     reported as "1 address(es) claim a subnet the plan puts on another
     interface", under a hint reading "an address from somebody else's subnet",
     with the detail naming as3/ATL:lo as both the offender and the victim. The
     check contradicted itself in its own evidence and took the whole mark for
     it. Standing in for something is a claim about a router, so the router now
     decides it: an address inside a subnet the plan gives to this router
     counterfeits nothing. It still costs, because the plan does not mention it
     and "and nothing else" is what that falsifies -- finding 71's spare address
     on a prescribed loopback is still caught, just no longer as an
     impersonation. The one case this must not swallow is the far end of a
     shared link, whose subnet really is partly ours: an address the plan hands
     to another router is a counterfeit wherever it is worn, whatever mask it is
     written with, and is now named as one.

103. **A prefix taken by attaching yourself to it.** The local-preference
     ordering is only worth marking if it decides where packets go, so the
     check looks for anything installed above BGP. Static routes, kernel routes
     and policy rules were all counted; connected routes were exempted
     outright. A connected route sits at distance 0, below every protocol, so
     `ip addr add 9.0.0.1/8 dev dummy0` made a customer's whole prefix directly
     attached and took its traffic, while the check still awarded the point for
     the ranking deciding where traffic goes -- a point for a property it had
     not established. The obvious repair, flagging any connected route for an
     externally learned prefix, was measured against the shipped labs first and
     is wrong: four correct border routers in the advanced-networks lab are
     directly attached to an eBGP link subnet that the far end redistributes,
     so the prefix is externally learned and the connected route rightly beats
     it. Worse, whether that happens depends on what the *neighbouring* AS
     advertises, which in a class is another student's submission. The plan
     decides instead: a router directly attached to a subnet the plan puts on
     it is where it belongs; one attached to a subnet the plan does not is
     answering for a part of the network it was never given. The data-plane
     check already noticed the blackhole this particular mutation caused, but
     it is the ranking's own claim that was false.

104. **A hello that was watched for less time than it takes to arrive.** The
     liveness test added for finding 72 watches an OSPF dead timer for twelve
     seconds and calls the adjacency dead if nothing reset it, which is right
     while hellos come every ten seconds. Ten is only the default: RFC 2328
     specifies thirty for non-broadcast networks and any interval is permitted.
     At thirty, two windows in three contained no hello at all, and an
     adjacency up for two and a half hours with nothing retransmitted was
     reported as "held by a timer that has not expired yet" -- on some runs and
     not others, so the same submission was worth 1.00 or 0.92 depending on
     when it was graded. The window is now taken from the interval each
     interface actually uses, and the threshold with it: over a window a live
     adjacency loses at most one interval less than the whole of it, a silent
     one loses all of it, and half an interval below the window separates the
     two whatever the interval is. An interval longer than the grader is
     willing to wait is reported as one whose liveness could not be
     established, rather than as silence.

105. **A host vouching for itself.** Reachability is not established by a
     reply, because a DNAT rule can divert the echo requests for one host to
     another and conntrack makes the answer look ordinary, so the check also
     reads the destination's own count of echo requests the kernel delivered to
     it. The comment on that read claimed nothing a submission configures could
     raise the counter without the packets arriving. A host pinging its own
     loopback address raises it one for one -- measured, five self-pings moved
     it from 1471 to 1476. With the echo requests for one host diverted away
     and a background `ping 127.0.0.1` left running on it, the DNAT rule
     counted 56 packets taken from the host during the graded run while the
     report said "every host received the traffic addressed to it", at full
     marks. The witness is now what arrived from off the machine: loopback
     packets are counted a second time on the loopback device, and a probe the
     grader sends never touches it, so the difference between the two counts
     cannot be raised by a host talking to itself. The second half of the same
     defect: the test was that the counter had moved at all, so one packet from
     anywhere stood as the witness for all eighteen probes sent to a host. It
     is now counted against the number of probes.

106. **The same counter, for connections and datagrams.** Reachability, transit,
     the VPN questions and the load-balancing question all ask whether something
     other than a ping gets through, and all of them read the destination's own
     kernel counters to find out: the resets it sent, the connections it
     accepted, the datagrams it took delivery of for a closed port. Those are
     global counters, and the destination is the submission's own machine. A
     loop connecting to 127.0.0.1 moved `OutRsts` thirty times in three seconds
     and `NoPorts` twenty-one times in two -- measured -- so with TCP and UDP
     dropped between two routers in both directions, no connection able to pass
     either way, `ospf.ecmp_paths` still reported "all 3 prescribed paths
     installed" at full marks. The loopback subtraction of finding 105 closes
     the self-inflation, and is applied to every one of these counters now; but
     a submission has more than one machine, and a connection to a closed port
     from any of them raises the counter without touching the loopback, so a
     counter alone cannot be the witness. Each probe now goes to a port drawn at
     random for it alone, and the destination watches its own interfaces for
     that flow while the probe is in flight: tcpdump names the interface each
     frame arrived on, and traffic a machine sends to itself names itself --
     even a connection to the machine's own routable address is delivered over
     `lo` and is reported as such. Both witnesses are required where both can be
     had, so a frame has to reach an interface from off the machine *and* the
     kernel has to take delivery of it; where the capture cannot run, the
     subtracted counter still decides, which is never weaker than what was there
     before. Measured: the attack 1.00 -> 0.00 on the load-balancing question,
     and the three shipped labs unchanged at 10.00, 6.00 and 4.00.

107. **A hop identified by a name instead of by where it leads.** The
     load-balancing question asks whether each router along a prescribed path
     forwards toward the next one, and decided it by looking for a next hop on
     an interface called `port_<next router>`. That is not a property of the
     network: it is how Twinet's own FRR renderer happens to name interfaces.
     A second link between the same pair is named differently, and so is every
     interface on a device configured by anything other than FRR -- both of
     which the topology supports and the heterogeneous-vendor goal requires --
     so a router forwarding perfectly well over such an interface was reported
     as not forwarding at all, and a path that was installed and carrying
     packets lost its mark. A route that names only the address it hands the
     packet to, with no interface at all, was invisible for the same reason.
     The plan already records which interface faces which neighbour and what
     address the neighbour holds on it, so that is what the check reads now:
     a hop is installed if any next hop leaves by an interface the plan says
     faces the neighbour or is handed to an address the neighbour owns. The
     same name was used to decide which links to probe and which next hops
     were unprescribed, and both now come from the plan too. A prescribed pair
     the topology does not join is reported as a rubric error rather than as a
     student one. Found as a dead branch: the code contained an `if !hops[want]`
     nested inside `if ... && !hops[want]`, with a comment describing a leniency
     for the final hop that the code did not implement.

108. **A grading width chosen without asking the machine underneath it.**
     `twinet grade run` with no `--as` grades every student system, and shipped
     a fixed default of eight concurrent submissions, each with its own
     eight-wide check pool. The canonical lab packs onto one node -- 212
     containers, one agent -- so all of it arrived at one exec budget of 56 as
     roughly 64 concurrent commands, plus a batched survey fan-out per grade
     and the tool-integrity read every grading exec carries. Every check
     exhausted its two-minute budget, and all eight reference reports came back
     quarantined at a provisional 7.00/10 -- against a lab deployed `--solve`,
     in which nothing was wrong, and which scored 10.00/10.00 when read one
     system at a time. Fail-closed marking held: no total was released. But the
     documented smoke test could not run at its own defaults, which is a
     capability defect in the diagnostic rather than in the marks.
     `--parallel` is now an override, and an omitted one is derived from the
     deployment: each target's device footprint and where the placer put it,
     the `exec_probe` budget each agent advertises minus what it is already
     serving (grading takes at most half), and how many targets converge on the
     same routers (at most two grades read one router's control plane at once,
     because that evidence is a full table dump served by one daemon in one
     container). Targets on independent nodes that share no router still run
     together; a node that cannot be asked is assumed to have room for one.
     The chosen width and the binding reason are printed and recorded in
     `summary.json`; an explicit width above the derived one is printed as an
     `AUDIT:` line and recorded with it. Canonical placement is unchanged:
     `pack-by-as` is a deliberate locality choice, and a grading command that
     only works on a spread lab would still be broken.




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
| The web UI's history: a time slider over past snapshots, per-group VPN status, the Krill proxy | M2 | The matrix, looking glass and overview are served by `twinet web`; the snapshots exist in the state store and nothing renders them |
| Gateway `save` / SFTP | M2 | `goto`, `status` and `help` are there, and leaving a device shell now returns to the menu rather than dropping the connection. `save` from inside the gateway and SFTP file transfer are not; students collect work with `twinet save` from outside |
| Outbound access for named devices (`egress:`) | M2 | Declared in the manifest and the schema and read by nothing. A manifest that uses it is now refused rather than deployed with the block ignored. Needs a per-device port into the node's namespace and masquerade on the node |
| A legacy `save_configs.sh` layout exporter | — | `twinet save` writes Twinet's own archive: a routing configuration and a replayable script per device. The legacy per-device directory layout is a state dump, which cannot be replayed, and is useful only for diffing against the old platform |
| Krill as a live RPKI publication point | M2 | The lab serves an RTR feed derived from the topology, which is what the exercise needs; a real publication point with per-AS validators is the fuller version |
| Real Krill certificate authority | M7 | ROAs are published through an interface of our own on the lab's trust anchor, not a Krill CA hierarchy. The exercise's observable behaviour is the same -- a student publishes a ROA for their own prefix and only their own -- and the lab stays self-contained |
| Diff-and-converge `apply` | M4 | Deploy is idempotent and now self-healing, but does not compute a minimal change plan |
| Course-wide acceptance beyond recorded advanced examples | M7 | MPLS/VRF and multicast examples have source support and the named measured discrimination evidence below this table. That is not an assertion that every course question, migration path, or live classroom workflow has completed acceptance. |
| NIKA coverage acceptance | M8 | This work is maintained in [10](10_fault_injection.md). Its registry-backed table, rather than a duplicated count here, states the current supported/gap set and any substrate limitations. |
| Load-balancer service, traffic generation | M8 | Prerequisites for two of those |
| Mixed-NOS live acceptance | M9 | FRR and BIRD providers, a vendor-neutral state path, capability validation, and the full provider-owned save/restore/submission-load path are source-verified. A live deployment and grade of a *student-owned* BIRD AS -- including `twinet save`, restore, and `grade batch` against its own archive -- has not been recorded as measured evidence. |
| Generated-interior live acceptance | M10 | `explicit`, `ring`, `two-tier`, and `clos` are source-verified generator kinds. A live three-node Clos deployment/convergence/grading acceptance run is not recorded here. |

### Addresses the assignment lets students choose

The COS-461 wiki leaves the layer-2 datacentre addresses and the inter-AS
peering addresses to the students, to be agreed with their neighbours. Twinet
plans both, and used to grade against its plan: a group that chose its own DCS
addressing was marked wrong for an answer the assignment permits, and a group
that agreed different eBGP addresses with a neighbour could not bring the
session up at all, because the other end was a rendered reference expecting the
planned address.

Both are now discovered rather than assumed.

- Every check reads the addresses off the devices. The datacentre checks ping
  what a host actually has; the session checks ask for the address the
  neighbour actually holds on its end of the link, in the subnet the group
  chose.
- Before a wave is graded, the reference side of each inter-AS link is adapted
  to whatever the submission configured: it is given an address in the group's
  subnet and a session to theirs, built by copying its own configuration for
  the planned address with the address substituted, so the relationship, the
  policies and the route-maps are exactly what the reference would have used.
  Everything is undone after the wave, and a failure to undo it quarantines the
  remaining waves rather than grading them against the last group's addressing.

Measured on the cluster with a signed submission that peers on 10.34.0.1/30
instead of the planned 179.3.4.1/24: 8.96/10 before, losing marks on
bgp.ebgp_established, policy.gao_rexford and policy.no_transit_for_peers;
10.00/10 after, with the run reporting `AS 3 configured 10.34.0.1/30 on
ext_4_BOS instead of the planned 179.3.4.1/24, so as4/BOS was given 10.34.0.2/30
and a session to 10.34.0.1`.

What is still prescribed: the exchange addressing, which is the exchange's own
and not a bilateral agreement, and the service subnets.

### Moving an autonomous system between machines is not atomic

`--rebalance` recomputes placement and now removes each system from the node it
left. The two halves are still independent: each node applies and prunes for
itself. If the destination fails and the source succeeds, the system is removed
from the node that had it; if the destination succeeds and the source fails for
some unrelated reason, the system runs on both and announces its prefix twice.

Both are recoverable by re-running the deployment, and neither can happen to a
lab nobody is rebalancing -- but a two-phase commit, creating and confirming
every destination before pruning any source, is what would make it safe, and it
is not built.

### The agent's listening address

`scripts/deploy_agents.sh --bind-underlay` narrows the agent from every
interface to the cluster fabric address it already announces as its own, taken
from the unit rather than from an argument so it cannot disagree with what the
rest of the cluster dials. The API is mutually authenticated either way -- a
stranger who reaches the port can do nothing with it -- but a port open to the
internet collects scans, and this one has no reason to answer anybody outside
the fabric. Verified on this cluster: `LISTEN 10.0.1.1:7200`.

The agent still runs as root with the host's network namespace and the Docker
socket, because creating network namespaces, moving interfaces between them and
building overlays is what it is for. The usual systemd sandboxing directives
would each have to be disabled again, so none are claimed.

### The web interface

`twinet web -m <lab>` serves three pages on the address the manifest's
`builtin.web` service declares: an overview of the lab and the machines hosting
it, the connectivity matrix between every pair of autonomous systems, and a
looking glass that runs a fixed list of nine read-only commands on any router.
Nothing on those pages can change a device.

Until this existed, `builtin.web` was declared in the manifests, accepted by the
schema, and served by nothing at all -- no container, no listener. Measured on
the cluster: 90 of 90 pairs reachable, matrix taken in 1.4 s, looking glass
answering from `as3/NYC`, and a command outside the list refused.

What it does not have, and the original had: the time slider over historical
snapshots, per-group VPN status, and the Krill proxy. The snapshots exist in the
state store; nothing renders them yet.

### Grading checks that are narrower than their questions

Recorded here rather than implied to be complete:

- `tunnel.sixin4` now tests every host of each datacentre against every host of
  the other, in both directions, as well as checking that the tunnel is 6in4
  rather than any encapsulation and that its endpoints are the two gateways'
  loopbacks. Measured: flushing the IPv6 address of one of AS 3's six
  datacentre hosts takes the system from 10.00 to 9.00.
- `policy.ixp_communities` now requires the announcement to be tagged for every
  member of the exchange, not merely for some real member. Measured: tagging
  one member of seven takes the system from 10.00 to 9.50.
- The end-to-end discrimination suite covers q1.2, q2.1 and q2.3. The rest rest
  on the reference scoring 10/10 and on the checks having been shown to
  discriminate by hand -- q2.4 against a forged community, q2.2 against
  next-hop-self removed across an AS, q1.3 against static routes. That is
  weaker than a suite: it shows the checks accept a correct answer and rejected
  one wrong one, not that they reject every wrong one, and nothing re-runs those
  demonstrations.

### Grading a hundred students: measured

Two modes, both fair, with different costs.

`twinet grade class` marks in the deployed lab, one submission at a time, with
everything else at the reference. Measured: **4m 56s per submission**, and it
holds the class lab for the duration -- a hundred students is over eight hours
during which nobody can use their own network.

`twinet grade batch --reduce` gives each submission its own disposable lab
containing every autonomous system but only the routers of each that face the
system under test, plus the services it is cabled to and the exchanges whole.
121 devices instead of 212. The class lab is not touched at all, and harnesses
run concurrently. Measured on this three-node cluster, with the class lab also
running:

| Concurrency | Submissions | Wall clock | Per submission |
|---|---|---|---|
| 1 | 1 | 6m 17s | 6m 17s |
| 4 | 4 | 9m 50s | 2m 27s |
| 8 | 8 | 15m 43s | 1m 58s |

At eight-wide that is a hundred students in about three and a quarter hours, on
three machines, without the class losing access to their lab. It scales with
nodes; the class mode does not.

The eight-wide run quarantined one submission of the eight: eight harnesses and
the class lab together saturated this cluster and one system's routing daemons
did not start. That is the honest capacity limit of three machines, and it is
reported as a quarantine rather than as a mark, which is the behaviour that
matters. On a cluster with room, or without the class lab running alongside, the
same eight complete.

### What would make the fair mode faster still

Most of a run is waiting for OSPF and then BGP to settle. Three things would
move it further, in the order they are worth doing:

1. **Neighbours reduced to a single synthetic router each.** Reduction keeps the
   routers of each neighbour that face the system under test, which on a tiered
   internet is still most of their borders: 121 devices where the ideal is
   perhaps 40. Replacing each neighbour with one router that originates its
   block would cut both the deployment and the convergence again.
2. **Restoring only what the submission touched.** In class mode the reference
   is put back over the whole AS, which costs a second convergence. A submission
   names the devices it changed.
3. **`--per-wave`.** It exists and works, and batches submissions no two of
   which are within two systems of each other. It is off by default because that
   is a heuristic about the peering graph and not a proof of isolation, and
   marks are not the place to trade correctness for time without being asked.

## Measurements

Every row is an observation from the named three-node environment. Re-running
any of them produces new evidence rather than reproducing these numbers, and
the machine-readable artifacts of a re-run are not kept in this tree:
`scripts/scale_benchmark.sh`, `scripts/chaos_e2e.sh`, and
`scripts/scale_soak.sh` write JSON under the untracked `reports/` path, which
the cluster workflow uploads as a build artifact. [12](12_operator_guide.md)
§11 is how they are run.

| Metric | Value |
|---|---|
| **84-AS current scale topology, three consecutive runs** | **557.181 s / 536.191 s / 545.595 s deploy+convergence**, each focused 1/1 and full reference 10/10 |
| Current 84-AS deploy phase | **472.438 s / 452.019 s / 461.108 s** |
| Current 84-AS focused convergence phase | **84.694 s / 84.123 s / 84.439 s** |
| Current 84-AS placement / cross-node links | **556 / 731 / 733 primary devices; 186 / 2,927 links cross-node** |
| Canonical 12-AS lab, 212 devices, 299 links, pack-by-AS | **133.64 s**, followed by 10/10 |
| Generated Clos, 11 devices / 12 links / 6 cross-node endpoints | **19.98 s**, followed by 1/1 |
| 12-AS lab at the earlier orchestration revision | **44-58 s** — historical; topology, runtime, readiness, and transaction proof are not comparable to the current gate |
| The same lab as it was measured earlier, at 211 containers and 291 links | 83 s -- superseded; the topology and the deployment path have both changed since |
| Same lab, single node | not attempted; 4-AS/57-container demo takes 64 s |
| Cross-node link RTT (25 ms configured) | 50.22 ms, σ 9 µs |
| Links kept local by AS-granular placement, 84-AS lab | **89.7 %** (302 of 2927 cross) |
| — of which inter-AS links crossing | **111 of 283 (39 %)**, against 201 (71 %) before the partitioner |
| — intra-AS links crossing | 0 of 2324, by construction |
| Placement cost, 84 ASes / 2012 containers (the shape of that run) | < 1 s |
| Grading, 3 submissions, 10 questions, 17 checks | 31 s |
| Grading a class of 8 in waves, all scoring 10/10 | **22m 11s in 4 waves**, measured when the conflict relation was adjacency and submissions were loaded onto the solved lab. Both have since changed and this number is not comparable to anything current |
| Waves needed for 8 student ASes / for 80, under `--per-wave 8` | **6 / 42** — the conflict relation is distance-two, so roughly one wave per two submissions. `--per-wave` is off by default; see [grading](06_grading.md) |
| **`grade class`, 8 submissions, one at a time, 5-minute convergence budget** | **39m 29s, 8 of 8 scored 10/10, none quarantined** -- 4m 56s per submission, of which the checks themselves are seconds; the rest is waiting for OSPF, then BGP sessions, then the BGP table to stop changing, twice per submission (once for the submission, once for the reference put back after it). Every archive was saved from the reference, so anything below 10/10 would have been a Twinet defect |
| Same 8 submissions, before the container-identity fix | 28m 12s, **7 of 8 quarantined**: grading recreated 89 of 212 containers, which empties their network namespaces, so loading failed on `Cannot find device port_BOS` |
| Containers recreated while grading, before / after that fix | **89 / 0** |
| Automatic repairs triggered on a lab while it was being graded, before / after the grading hold | **13 / 0** |
| Grading 1 submission in its own private harness | ~12 minutes; measured, and the reason waves exist |
| 8 private harnesses at once on 3 nodes | saturates the cluster; the failures are resource exhaustion, not marks |
| Historical class-scale deployment: 84 ASes, 2012 devices, 2927 links across 3 nodes | **22m 38s, zero failures** -- superseded by the three current 2,020-device runs above |
| Containers per node at that scale | 731 / 731 / 550 with `pack-by-as`, 660 / 675 / 677 with `spread-by-as` |
| Node utilisation at that scale | 22 GiB of 251, load average 13 of 56 cores |
| Emulated latency on a cross-node link at that scale | 20.07 ms for 20 ms configured |

### 108. A forwarding decision reported without reading the forwarding decision

`policy.traffic_engineering` asks whether a destination leaves by the slow
link. `installedVia` answered by reading `show ip route` -- and its own comment
claimed that this was where "a static route, a policy route or an
administrative distance shows up". A policy route does not show up there. An
`ip rule` diverts the lookup to a different table *before* the daemon's table
is consulted, and a route the daemon selected but failed to push is not in the
kernel at all. The daemon's opinion of its own table shows neither.

Measured on the live cos461 lab, on `as3/MSP`:

    ip route add 2.0.0.0/8 via 179.1.3.1 table 100
    ip rule  add to 2.0.0.0/8 lookup 100

    # ip route get 2.0.0.1
    2.0.0.1 via 179.1.3.1 dev ext_1_ALL table 100 src 179.1.3.2
    # vtysh -c 'show ip route 2.0.0.0/8'
      *   3.0.2.2, via port_CHI

The kernel forwards that destination over the slow provider link; the daemon
still shows the fast one. The check scored a full **1.00**, reporting that
nothing is forwarded over the slow link.

This was surfaced by review round 117 and dismissed there as unexploitable,
on the grounds that a student with a wrong local-preference would still have
the daemon pointing at the slow link, so the trick cannot turn a wrong answer
into a right one. That is true, and it is not the point: the check named a
forwarding decision it had never looked at. The same blindness hides an
injected fault -- a NIKA policy-routing fault would leave the grader reporting
the network healthy -- and it is exactly the defect class findings 97-107 are
about.

Each router is now also asked `ip route get` for one address inside every
prefix that has a fast alternative, batched into a single command per router
so the cost is one round trip rather than one per destination. The kernel's
answer is held to the same slow-link test as the table, and the two are a
union, so the new path can only fire where the daemon and the kernel disagree
-- which is never the case on a correct submission. Clean: cos461 10.00,
advnet 6.00, multicast 4.00. With the rule in place: 0.88, evidence
`2.0.0.0/8 on MSP (kernel)`.

Reading the kernel rather than the daemon also removes one more dependence on
FRR specifically, which the heterogeneous-vendor goal needs.

### 109. Asking the kernel about the wrong packet

Finding 108 added a kernel lookup to `policy.traffic_engineering`. Round 118
showed the lookup asked about the wrong packet. `ip route get <dst>` with no
source answers for a packet *the router originates itself*. A policy rule keyed
on the **source** -- which is exactly how transit traffic is singled out --
never fires under that lookup.

Measured on the live cos461 lab, on `as3/MSP`:

    ip route add default via 179.1.3.1 table 100
    ip rule  add from 4.0.0.0/8 table 100 priority 100

    # ip route get 1.0.0.1
    1.0.0.1 via 3.0.2.2 dev port_CHI                       <- fast, what the check saw
    # ip route get 1.0.0.1 from 4.100.0.1 iif port_CHI
    1.0.0.1 from 4.100.0.1 via 179.1.3.1 dev ext_1_ALL     <- slow, what actually happens

All transit traffic from AS4 leaves by the slow provider. The check scored a
full **1.00**.

The obvious repair -- guess a source, say this AS's own host prefix -- would
not have found it: the rule names AS4's space, not AS3's. There is no source
worth guessing, so the rules are read instead. Each rule the submission added
is asked about as a packet it would match: its own source prefix, its own
arrival interface, its own firewall mark. The kernel refuses a forwarding
lookup unless both a source and an arrival interface are given, so both are
supplied; a rule keyed only on a mark needs neither.

A rule keyed on something a route lookup cannot stand in for -- a port, a uid,
`oif`, a negation -- is **refused**, and the check reports that it could not
establish where traffic goes, rather than passing over it. Reporting that
nothing goes the slow way without having looked is the whole substance of
finding 108, and the repair must not reintroduce it in a narrower form.

A submission with no rules of its own is asked exactly what it was asked
before, so the cost is unchanged for every correct submission. Clean: cos461
10.00, advnet 6.00, multicast 4.00, and 1.00 on three consecutive isolated
runs. With the rule in place: 0.88, evidence
`1.0.0.0/8 on MSP (kernel, from 4.0.0.0/8)` -- naming the rule's own selector,
so the student is told which rule is at fault.

Two findings in a row now on the same few lines. That is worth stating plainly:
reading the kernel instead of the daemon was right, but "the kernel" is not one
answer -- it is an answer *per packet*, and a check has to say which packet it
means.

### 110. Failing a correct submission for the shape of its route-map

`rpki.invalid_rejected` will not credit a `deny` clause that sits behind a
`permit`, because route-maps stop at the first clause that matches and a permit
in front of the deny is usually a way in. That rule is right. The exception to
it was read too narrowly: a preceding permit was tolerated only when **every**
one of its match statements selected on some other validation state.

FRR requires *every* match in a clause to hold, so a single match the state
rules out is enough on its own. No invalid route matches `match rpki valid`,
however many prefix lists or communities sit beside it.

Round 119 measured it on the live cos461 lab, on `as3/MSP`:

    route-map LP-SLOW-PROVIDER permit 3
     match ip address prefix-list ALL-ROUTES
     match rpki valid
     set local-preference 50
    route-map LP-SLOW-PROVIDER deny 5
     match rpki invalid

`show route-map` reported the deny invoked 38 times and
`show bgp ipv4 unicast rpki invalid` was empty -- the router was rejecting
invalid origins exactly as asked. The check reported *"1 of 6 external
session(s) accept invalid origins"* and took half the marks; the full rubric
fell to 9.80.

Setting local-preference for valid routes on a prefix list is an ordinary thing
to write, so this was a correct submission being failed for not matching the
reference answer's shape -- the fairness direction, and the one students
actually feel.

The test now asks the question that decides it: *can a route in the denied
state match this clause at all?* It answers no as soon as any one match rules
it out, and yes otherwise. A clause naming the denied state itself is still a
way in, and so is one resting on a prefix list, an AS path or a community --
none of which the configuration can decide, since any of them can be true of an
invalid route as easily as of a valid one.

Measured both directions after the fix: the correct-but-unusual route-map above
scores **1.00**, and a genuine bypass (`permit 2: match ip address prefix-list
ALL-ROUTES` with no validation match, which really does hide the deny) still
scores **0.50**. Clean: cos461 10.00, advnet 6.00, multicast 4.00.

The lesson is one this ledger keeps relearning from the other side. Findings
97--109 were all checks that credited something they had not established.
This one is the mirror image: a check that *withheld* credit for something it
had not established either -- it never asked whether the permit clause could
match an invalid route, it asked what the clause was made of. Reading a
configuration for its shape rather than its consequence is the same mistake
whichever way the marks move.

### 111. Balancing over two links while every packet takes one

`ospf.ecmp_paths` read the routing table the daemon writes, at every router the
prescribed paths pass through, and awarded the marks when the equal-cost next
hops were all there. A policy rule is consulted *before* that table ever is, so
a submission could leave the route installed, untouched and plainly visible,
and still send every packet down one of its next hops:

    ip route add 3.153.0.1/32 via 3.0.10.1 dev port_BOS table 100
    ip rule add to 3.153.0.1/32 lookup 100 priority 100

`ip route show 3.153.0.1/32` still showed both next hops. `ip route get
3.153.0.1` answered `via 3.0.10.1 dev port_BOS table 100`, and a traceroute to
BOS was one hop. The check reported *"all 3 prescribed paths installed; ATL
balances over port_BOS (3.0.10.1), port_PHY (3.0.8.1)"* and gave full marks for
a question about which paths carry traffic.

The check's own comment, added when a firewall rule was found dropping the
traffic it had just called delivered, says this is the class of divergence it
exists to catch. The rule is the same trick without the packet loss.

Every router the paths pass through is now asked what it will really do with
the traffic. The comparison is between **two readings of the kernel**, not
between the kernel and the daemon: a rule pointing at a table that holds the
same next hops changes nothing, and a submission that writes one has answered
the question. What is reported is a table that carries the traffic differently
from the one OSPF wrote.

Measured, all four cases:

| state of `as3/ATL` | score |
| --- | --- |
| untouched (twice) | 1.00 |
| rule to a table pinning one hop | **0.50** |
| rule to a table holding *both* hops | 1.00 |
| rule to an empty table (falls through) | 1.00 |

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

Overriding the route in the main table instead -- `ip route replace 3.153.0.1/32
via 3.0.10.1 dev port_BOS` -- appeared to be caught already: zebra reads the
kernel back and reports such a route as learned by `kernel` rather than by
OSPF, which the protocol test rejects. Measured at 0.50 before this fix
existed. **That conclusion was too broad and finding 112 overturned it** -- it
holds only for the default protocol label. The paragraph is left standing
because drawing a general conclusion from one measurement is the mistake, and
it is the same mistake the findings themselves are about.

Findings 108, 109 and this one are the same sentence three times: *the routing
daemon's table is an opinion, and the kernel is the one that forwards.* 108 read
only the daemon; 109 asked the kernel the wrong question; this one never asked
it. The last check that reasons about forwarding from the daemon alone is worth
finding before a student does.

### 112. The daemon does not notice a route wearing its own name

Finding 111 asked whether a policy rule diverted the equal-cost traffic, and
recorded that overriding the route in the main table was caught already because
zebra reads such a route back and calls it `kernel` rather than `ospf`. That was
measured once, with the default protocol label, and stated as though it were
general. It is not. The label is an argument:

    ip route add 3.153.0.1/32 via 3.0.10.1 dev port_BOS proto ospf

The kernel now holds two routes for the destination. The added one has metric 0
and zebra's has metric 20, so the added one forwards. Zebra sees a route
carrying its own protocol label and leaves it alone; `show ip route` still says
`Known via "ospf", distance 110, metric 20, best` over both next hops. Nothing
in the daemon changed, no rule exists to find, and `ip route get 3.153.0.1`
answers `via 3.0.10.1 dev port_BOS`. Traceroute to BOS is one hop. The check
reported *"ATL balances over port_BOS, port_PHY"* and gave full marks; the full
rubric still totalled 10.00.

The reading was also wrong in a way no one had exploited: `ip route show
<target>` output was collapsed into one list of next hops, so two entries for
the same destination read as one route with all their hops. The route the
kernel prefers and the routes it ignores were indistinguishable.

Kernel output is now read as **entries** -- prefix, metric, type, next hops --
and the entry that answers for a destination is chosen the way the kernel
chooses it: longest prefix, then lowest metric. That entry is compared with
what the daemon claims, and a type that forwards nothing (`blackhole`,
`unreachable`, `prohibit`) is reported by name.

Reading entries fixed a second case that no reviewer had found. A policy rule
pointing at a table was checked with `ip route show table N <target>`, an exact
prefix match, so a table answering with a *less specific* route read as empty
and was treated as falling through to the daemon's table. Both lookups now use
`to match`, which is how the kernel itself resolves a destination.

Measured, every state of `as3/ATL`:

| state | score |
| --- | --- |
| untouched (twice) | 1.00 |
| `proto ospf` shadow route at a lower metric | **0.50** |
| rule to a table pinning one hop | **0.50** |
| rule to a table answering with a covering /24, one hop | **0.50** |
| `blackhole` for the destination | **0.00** |
| rule to a table holding *both* hops | 1.00 |
| rule to an empty table (falls through) | 1.00 |

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

The finding under the finding is about this ledger rather than the code. 111
closed a hole and, in the same breath, wrote down that the neighbouring hole was
shut -- on the strength of a single measurement of a single spelling. A reader
of the ledger would have skipped it. **A closed door recorded here should say
what was actually tried**, because the next reader will not retry it.

### 113. The tunnel gateway was asked about a packet it never sees

`tunnel.sixin4` establishes that traffic between the two IPv6 datacentres is
really encapsulated, by asking the gateway where it would send it:

    ip -6 route get <dst>

That describes a packet the gateway *originates*. It carries no source address
and no arrival interface, so an `ip -6 rule` keyed on either never fires and the
lookup falls through to the main table. A submission that put its tunnel routes
in a second table and pointed a rule at it -- an ordinary way to write the
answer, and the way an operator would write it -- got:

    ip -6 route get 3:200::1                 -> (nothing; network unreachable)
    ip -6 route get 3:200::1 from 3:201::1   -> dev tun6 table 100

The tunnel was working. `tun6`'s counters advanced by exactly the packets just
sent, pings crossed it, and the check reported *"BOS forwards traffic for
3:200::a over , not through tun6"* and took half the mark. The empty word in
that sentence is the whole finding: there was no interface to name because the
lookup had returned nothing at all, and "nothing" was rendered as "somewhere
else".

This is finding **109** again -- the same lookup, the same missing source -- in
the IPv6 path, which was never revisited when 109 was fixed for IPv4. Fixing a
defect in one place and not looking for its twin is its own kind of incomplete
claim.

The lookup now describes the real packet: from the sending host's address,
arriving on the interface facing it. Neither has to be guessed -- the interface
a reply to that host would leave by is the one its packets arrive on. And a
lookup that cannot be made returns an error rather than an empty interface
name, so "could not ask" and "answered natively" are no longer the same verdict.

Measured on `as3/BOS`, with the tunnel routes moved to table 100 behind
`ip -6 rule add from 3:201::/32 lookup 100`:

| | before | after |
| --- | --- | --- |
| routes in the main table (correct, ordinary) | 1.00 | 1.00 |
| routes in table 100 behind a rule (correct, unusual) | **0.50** | 1.00 (x3) |
| UDP filtered on the destination (genuinely broken) | 0.50 | 0.50 |

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

### 114. A capture that had already stopped, testifying to silence

Chasing 113 turned up a run that scored 0.50 with a *different* complaint --
*"a datagram from A_CHA to A_MGH never arrived -- no packet of it reached any
interface"* -- on a path that was working. Three runs either side of it scored
1.00, and sending the datagram by hand showed it arriving. A check that gives
two different verdicts on unchanged state is a finding in its own right.

The arrival witness from findings 105/106 runs `tcpdump` on the destination for
the exact flow, under `timeout 15`. Fifteen seconds was chosen to outlast the
probes it watches for: a connection attempt waits three seconds, a datagram two.
But between them are half a dozen round trips to a machine that may be on
another node, and on a loaded cluster -- or just after an agent redeploy -- the
capture's own timeout expired before the last probe was sent.

The reading then found the capture's start-up banner and an empty body, and
reported **a live witness that saw nothing**. `tapLive` answered "was tcpdump
ever running?" while the caller was asking "was anyone watching when the packet
went past?" Those are different questions, and only the second is evidence.

The window now covers the probes by construction rather than by estimate: the
capture is stopped explicitly when it is read, the timeout is demoted to a leak
guard for an interrupted run, and the capture records the moment it stops. A
capture that stopped before it was asked -- its own timeout, or its frame limit
-- is discarded, and the check falls back to the kernel counter or declines to
accuse.

The witness is not weakened by this. With `ip6tables -I INPUT -p udp -j DROP` on
the destination it still scores 0.50 and still distinguishes the two failures
precisely: *"it reached the interface but the kernel took no delivery of it"*,
which is exactly what an INPUT-chain drop looks like from the wire. No capture
files were left behind on any host.

The general shape, and the reason this one is worth writing down: **a timeout
picked to be "comfortably longer than" something is a claim about the
environment, not about the code.** Twinet's environment is a cluster whose
latency the grader does not control. Every such constant is a check that will
eventually report on a window it was not present for -- so the honest form is
not a bigger number, it is a mechanism that knows whether it was watching.

### 115. Marking the mechanism when the question asked for an outcome

`rpki.invalid_rejected` searched a session's inbound policy for a `deny`
clause naming the invalid state. A submission wrote no such clause:

    route-map LP-SLOW-PROVIDER permit 10
     match rpki notfound
    route-map LP-SLOW-PROVIDER permit 20
     match rpki valid

That admits the two states it names and drops everything else, because FRR
ends every route-map with an implicit deny. It is a perfectly ordinary way to
write the policy -- arguably the cleaner one, since it states what is allowed
rather than what is not -- and the router was doing exactly what the question
asked.

Measured on `as3/MSP`:

    show bgp ipv4 unicast rpki invalid   -> (empty)

Not one invalid route was selected. To be sure the implicit deny was what
stopped them, and not an absence of invalid routes to stop, a catch-all
`permit 30` was added at the bottom:

    I*> 10.128.0.0/9  179.1.3.1  ...  1 1 1 1 i

The invalid origin appeared immediately, and vanished again when the catch-all
was removed. The implicit deny was doing the whole job. The check reported
*"1 of 6 external session(s) accept invalid origins"* and took half the mark.

This is the third finding in this one check (110, 119, and now 115), and they
all have the same shape: the check knows what the reference answer looks like
and grades resemblance to it. A route-map is not a document to be searched for
a keyword; it is a program, and the question is what it does to a route in the
state being asked about. So that is what is now asked -- walk the clauses in
sequence order, and if none of them admits such a route, the implicit deny at
the bottom rejects it.

Reading a catch-all clause had the same flaw in miniature: any clause with no
match statements was treated as a way in, so an explicit `deny 30` at the
bottom -- the implicit deny written out longhand -- was also read as accepting
everything. Which direction the clause points is now the answer.

An empty body remains the one case that is not protection: no route-map bound
to the session, or a name that was never defined, leaves no clause list for an
implicit deny to sit at the end of, and nothing is filtered.

| | before | after |
| --- | --- | --- |
| explicit `deny 5: match rpki invalid` (reference) | 1.00 | 1.00 |
| permit-valid + permit-notfound, implicit deny | **0.50** | 1.00 |
| the same, plus a catch-all `permit 30` (a real hole) | 0.50 | 0.50 |
| no inbound route-map at all | 0.40 | 0.40 |

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

### 116. One probe answers for one path

`ospf.ecmp_paths` promises *"N equal-cost paths from X to Y, carrying
traffic"*. It established the paths from the forwarding tables and then, for
whether they carry anything, sent pings hop by hop and one connection end to
end. The hop-by-hop sweep covers every link of every path, but only with ICMP.
The connection covers every protocol the question cares about, but takes one
path -- and the same one every time, because the router picks by hashing the
flow.

So a router discarding forwarded connections in the middle of one of three
paths was invisible. On `as3/NYC`:

    iptables -A FORWARD -p tcp -d 3.153.0.1 -j DROP

Pings still went through, the end-to-end connection was hashed onto a path that
avoided NYC, and the question kept **1.00 / 1.00** across eight runs. Measured
directly, 40 connections from ATL to BOS with different source ports:

    30 of 40 arrived; NYC's DROP counter +15

A quarter of the traffic between the two routers was on the floor and the
question was reporting the pair as healthy.

The first instinct was to steer a flow deliberately onto the broken path. The
kernel will say where a flow is going:

    ip route get 3.153.0.1 from 3.156.0.1 ipproto tcp sport 2001 dport 8899
      -> via 3.0.8.1 dev port_PHY        (at ATL)
      -> via 3.0.4.1 dev port_NYC        (at PHY, iif port_ATL)

and then the packet went to BOS instead. For a forwarded packet the answer is
a prediction, and grading a prediction grades the wrong thing. So nothing is
predicted. The question the mark is for is asked directly: of the flows sent
between these two, did every one arrive? Thirty-two flows with different source
ports, spread over the paths by the same hash the routers use -- at every hop,
not only the first, which is what lets a three-router path be reached at all --
and a capture on the far side saying which source ports came in. A lost flow
means a path is discarding traffic, and the student is told how many.

Two mistakes made on the way to this, both worth keeping:

*Repeating only the failed flows is not a retry.* A source port is not a path.
Re-sending the lost ports hashes them afresh, so they mostly land on the paths
that work, and a real fault clears itself most of the time -- which is exactly
what happened: the first version of the fix scored the mutation 1.00. The whole
sweep is repeated instead, from fresh ports, and the fault has to survive both.
That still rejects a frame lost to a scheduler delay, which is what the retry
was for.

*A flow that could not be sent is not a flow that was lost.* A source port
already in use fails to bind, and counting that would blame a submission for
the grader's choice of port. The sender reports which ports it managed to use
and only those are looked for.

Both protocols alternate across the sweep, because a filter is written per
protocol as easily as per path.

| | before | after |
| --- | --- | --- |
| healthy (reference), five runs | 1.00 | 1.00, 1.00, 1.00, 1.00, 1.00 |
| TCP dropped mid-path on one of three | 1.00 | **0.50** -- *4 of 32 flows never arrived, and 28 did* |
| UDP dropped mid-path on one of three | 1.00 | **0.50 / 0.00 / 0.00** over three runs |

Full labs after the fix: cos461 10.00 in 4m14 (4m13 before), advnet 6.00,
multicast 4.00.

### 117. A rule like the one that was injected

`twinet fault verify` reports whether an injected fault is still doing what it
was injected to do. Scoring an agent's root-cause analysis rests on that
answer: if the fault has stopped biting, whatever the agent is being marked
against is not the problem it was given.

The two switch-fabric faults asked the flow table two independent questions --
does the string `priority=100` appear anywhere, and does the string
`actions=drop` appear anywhere -- and reported the fault in effect if both did.
Neither question mentions the port the fault recorded, and nothing requires the
two answers to come from the same rule.

Moving the drop rule from the port the fault names to a different port on the
same switch is enough:

```
$ twinet fault inject flow_rule_shadowing --as 3 --device DCS_S2
  verified: yes; observed ... priority=100,in_port=1 actions=drop

$ twinet exec as3/DCS_S2 -- sh -c \
    "ovs-ofctl --strict del-flows br0 'priority=100,in_port=1'; \
     ovs-ofctl add-flow br0 'priority=100,in_port=2,actions=drop'"

$ twinet fault verify
flow_rule_shadowing  as3/DCS_S2  yes  ... priority=100,in_port=2 actions=drop
```

The host the fault is about is reachable again, and the report says the fault
is still in effect -- quoting, as its evidence, a rule about a different host.

Flow lines are now split at ` actions=` into their match fields and their
actions, and the match fields are compared as whole terms. That is not
decoration over a longer needle: `in_port=1` is a prefix of `in_port=10`, so a
substring test lets a rule on port 10 answer for port 1, and `ovs-ofctl` makes
no promise about field order, so a fixed `priority=100,in_port=1` needle is a
guess about formatting rather than a reading of the rule.

The report now separates the two situations that matter to whoever reads it:

```
NO   no rule at priority=100 on port 1; a rule at that priority sits
     elsewhere: ... priority=100,in_port=2 actions=drop
NO   no rule at priority=100 on port 1
```

Sweeping the other faults for the same shape found a third instance the review
had not named. `host_static_blackhole` installs a blackhole route for a
recorded prefix and then asked `ip route show | grep blackhole` whether *any*
blackhole route existed. Deleting the route it installed and adding an
unrelated one elsewhere left it reporting "still in effect". It is now scoped
to the prefix it recorded, and refuses rather than guessing when no prefix was
recorded.

The remaining verifies were checked and are already scoped: the `tc` ones name
their device, `NOARP` names its interface, the ACL one asks `iptables -C` with
the exact rule, the wrong-gateway one reads `ip route show default` and names
the wrong gateway, and the DHCP ones reach their `Verified: true` only inside a
match on the recorded subnet.

| | before | after |
| --- | --- | --- |
| drop rule moved to another port | still in effect | **no longer in effect** |
| loop rule moved to another port | still in effect | **no longer in effect** |
| blackhole replaced by one for another prefix | still in effect | **no longer in effect** |
| fault injected and left alone (all three) | still in effect | still in effect |

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

### 118. Half a fault undone, reported as none

`link_detach` installs two independent things: a 100% loss netem on egress, and
a `u32` filter on the ingress qdisc that drops everything. Its verify read the
egress qdisc alone. Removing the netem -- `tc qdisc replace dev X root
pfifo_fast`, the ordinary way to take netem off an interface, and the first
thing anyone tries -- left the check reporting the link healthy:

```
link_detach  as3/SFO  NO   qdisc pfifo_fast 800e: root refcnt 57 bands 3 ...
```

while the filter was still installed and the link still carried nothing:

```
$ twinet exec as3/SFO -- tc filter show dev ext_7_MSP ingress
  match 00000000/00000000 at 0
	action order 1: gact action drop
$ twinet exec as7/MSP -- ping -c 3 -W 1 179.3.7.1
3 packets transmitted, 0 received, 100% packet loss
```

An agent that did half the repair was told it had done all of it, and the
ledger believed a lab was clean while a link on it was cut.

Sweeping for the shape -- *the fault installed more than one mechanism and the
check asks about one of them* -- found three more. All four were reproduced on
the running lab before being changed, and each was measured against the
mutation that exposes it.

**`link_flap`** counted running loops. The loop holds the link down for five
seconds of every fifteen, so killing it lands on a down cycle a third of the
time and leaves the interface down for good. `Resolve` had always known this
and set the link back up; `Verify` never asked. Killed mid-cycle, it reported
`NO -- 0 flap loop(s) running` on an interface that was down and losing every
packet.

**`host_incorrect_gateway`** reported `NO` -- with an empty observation, which
is the least useful way possible to be wrong -- after the bogus default route
was simply deleted. The host was then left with no default route at all and
answered `Network unreachable`: the symptom the fault exists to produce, fully
present, on a fault recorded as gone. `Resolve` already insisted the baseline
be back rather than merely the wrong gateway gone, and said so in a comment.
The check never learned it. It also compared the gateway with
`strings.Contains`, so `via 3.106.0.2` matched a route `via 3.106.0.254` -- and
the bogus neighbour this fault picks differs from the real gateway by one
digit, so the two addresses that must not be confused are exactly the two that
were.

**`dns_port_blocked`** installs a rule for udp and a rule for tcp, then counted
lines containing `--dport 53 -j DROP` anywhere in `INPUT` and reported `n > 0`.
Freeing udp -- the half that actually stops name resolution -- still read `yes,
1 rule(s) dropping port 53`, naming neither protocol. Its own `Inject` carries
a comment identifying this exact hazard and guards against it by refusing to
inject over a pre-existing rule; the guard was added to `Inject` and never
carried across to `Verify`.

Each now asks about everything it installed, and the evidence distinguishes
*partly undone* from *undone* and from *untouched*:

| mutation | before | after |
| --- | --- | --- |
| `link_detach`, egress netem removed | no longer in effect | **still in effect** -- "outbound is clear but every inbound packet is still dropped by the ingress filter" |
| `link_detach`, both halves removed | no longer in effect | no longer in effect |
| `link_flap`, loop killed on a down cycle | no longer in effect | **still in effect** -- "it stopped on a down cycle and ext_7_MSP is still down" |
| `host_incorrect_gateway`, bogus route deleted | no longer in effect (blank) | **still in effect** -- "no default route at all; the one this fault replaced (default via 3.106.0.2 dev ATLrouter) was never put back" |
| `dns_port_blocked`, udp rule removed | still in effect, "1 rule(s)" | still in effect, **"tcp dropped; udp reach the resolver"** |
| each fault injected and left alone | still in effect | still in effect |

Two things worth recording beyond the fix.

The first is that finding 117 swept for its own shape and reported, in this
document, that "the remaining verifies were checked and are already scoped ...
the wrong-gateway one reads `ip route show default` and names the wrong
gateway". That sweep was looking for one defect -- *is the check scoped to what
was injected?* -- and `host_incorrect_gateway` passed it while failing a
different one standing next to it. A sweep answers the question it asks. Saying
"the rest were checked" invites the reader to hear "the rest are correct", and
those are not the same claim.

The second is a limitation this fix does not remove. `dns_port_blocked` now
counts rules per protocol, but it still cannot tell its own rule from an
identical rule somebody added afterwards; nothing in `iptables -S` distinguishes
them. Injection refuses to run when such a rule is already present, so the
window is between inject and verify only. Tagging the rules with `-m comment`
would close it -- the module is present in the images, and this was checked --
but it would change helpers several ACL faults share, and that is not a change
to make in the same breath as a fix. It is recorded here rather than described
as done.

### 119. A link whose shaping could never be put back

Resolving `link_detach` reported:

```
resolve link_detach: the fault is gone but as3/SFO was not left as it was
found: not put back: qdisc netem 1: dev ext_7_MSP root limit 1000 delay 25ms
(the undo also reported: interface ext_7_MSP: add netem: file exists)
```

`ApplyShaping` clears the root qdisc and then adds netem there. `clearRootQdisc`
deliberately skips `pfifo_fast`, on the theory that it is the one the kernel
installs by default and "cannot be deleted, only replaced". That holds for the
implicit default. It does not hold for a `pfifo_fast` somebody installed on
purpose -- and installing one is precisely how a person takes netem off an
interface. After anyone did that, the root was occupied, `QdiscAdd` failed with
`EEXIST`, and the platform could never restore that link's delay or its rate
limit again. The link kept working, so nothing looked wrong; it simply no longer
had the 25ms and 1Mbit its own manifest describes, and every later episode over
it ran with different physics than the file says. For a benchmark whose episodes
must be comparable, a link that quietly stops matching its manifest is worse
than one that breaks.

The reviewer who found 118 hit this too, and reported resolving the fault "after
manual cleanup" -- the cleanup was this.

`QdiscReplace` installs at the root over whatever is there. Measured on the
wedged interface:

```
before:  qdisc pfifo_fast 800e: root refcnt 57 bands 3 priomap ...
resolve: resolved link_detach on as3/SFO
after:   qdisc netem 1: root refcnt 57 limit 1000 delay 25ms
         qdisc tbf a: parent 1:1 rate 1Mbit burst 14500b lat 50ms
```

The honest part of this one is that the failure was loud: resolve refused to
call the lab clean, printed what it could not put back, and exited non-zero.
The check that caught it was working. What was missing was the ability to act
on what it found.

Full labs after both fixes: cos461 10.00, advnet 6.00, multicast 4.00.

### 120. Half a leak, and the half that was checked was not the half that matters

`bgp_blackhole_route_leak` installs two things that can be removed
independently: a discard route (`ip route <prefix> Null0`) and the BGP
`network` statement that advertises the prefix so other networks' traffic comes
looking for it. Its verify read the forwarding table and nothing else.

Withdraw the announcement -- the repair that stops the internet-wide diversion,
and the one an agent that has correctly diagnosed a route leak would reach for
first -- and the check answered:

```
bgp_blackhole_route_leak  as3/SFO  yes   traffic for 7.0.0.0/8 is discarded here
```

a sentence about a leak that had stopped, offered as the ground truth an agent's
diagnosis is scored against. This is finding 118's shape, in a fault 118's sweep
did not reach: that sweep was a regex over the commands each `Inject` issues,
and this one builds both of its lines inside a single `VtyshConfig` call with
`fmt.Sprintf`, so it read as one mechanism. Re-run structurally -- parse each
registered fault, count the artifacts `Inject` leaves behind, print what
`Verify` probes -- it is the only remaining fault of the shape. The others that
install more than one thing (`bgp_asn_misconfig`, `dns_record_error`,
`ospf_area_misconfiguration`) all verify an *outcome*: no established sessions,
the name resolving to the wrong address, the adjacency down. **A verify that
asks about an outcome cannot have this defect. A verify that asks about a
mechanism has it whenever the fault installs more than one.** That is the rule
worth keeping.

The interesting part was deciding what "still in effect" should mean, because
the obvious answer is wrong. The reviewer who found this proposed requiring
*both* halves to be present. Measured on the lab, each half alone is an outage:

```
announcement withdrawn, discard route left:
  $ twinet exec as3/ATL_host -- ping -c 3 -W 2 7.152.0.1
  3 packets transmitted, 0 received, 100% packet loss

discard route removed, announcement left:
  $ twinet exec as3/SFO -- vtysh -c 'show ip route 7.0.0.0/8'
  % Network not in table
```

The first is plain. The second is worth spelling out: with the router
originating the prefix itself, its own path wins best-path selection on weight,
and a locally sourced path installs nothing in the forwarding table -- so the
router advertises a prefix it does not own to both of its external peers and
then has no route for the traffic that arrives. Requiring both halves would
have called each of those labs clean. It would have been finding 118 again,
written the other way round: a check that declares a lab repaired while packets
are on the floor. Either half surviving now reads as still in effect, which is
also what `Resolve` has always required.

The old code was already wrong in the second direction and nobody had looked:
with the discard route removed it reported **NO -- no longer in effect** on a
router that was still leaking.

| state | before | after |
| --- | --- | --- |
| fully injected | yes, "traffic is discarded here" | yes, "originates 7.0.0.0/8, which it does not own, and discards the traffic that follows it" |
| announcement withdrawn | yes, "traffic is discarded here" (silent about the leak) | yes, **"no longer originated into BGP, so the leak itself is gone, but the discard route is still installed and every packet ... is still dropped"** |
| discard route removed | **NO** | yes, **"the discard route is gone, but the router still originates 7.0.0.0/8 ... and this router has no route for what arrives"** |
| correctly resolved | not in effect | not in effect |

`blackholeFor` also scopes the discard to the recorded prefix. `show ip route
<prefix>` answers with whatever entry covers the prefix it is asked about, so a
discard route for a neighbouring network read as this fault still being in
place -- finding 117's shape, sitting inside the fault being repaired. The
locally-originated test reuses the existing `locallyOriginated` helper rather
than adding a second one; it already carries its own scar, having once matched
the "Local host:" line that every learned path prints.

Full labs after the fix: cos461 10.00, advnet 6.00, multicast 4.00.

### 121. A dry run that reported it had deployed the lab

```
$ twinet deploy --dry-run
twinet: docker 29.7.2, lab demo (topology a345547bd0b68597)

deployed 57 devices and 74 links in 1ms
$ echo $?
0
$ sudo docker ps -a --format '{{.Names}}' | grep -c '^demo'
0
```

Nothing was created. The word was "deployed", the exit status was zero, and an
operator scripting a preview -- or a TA gating the next step of a deployment
script on that exit code -- had no way to tell it apart from a real run.

The summary took its numbers from `top.Stats()`, the topology as written. That
figure is the same for every run of the same manifest, which makes it wrong in
three independent ways, only the first of which the reviewer had to trip over:

- `--dry-run`, which builds nothing, announced the whole lab;
- `--only as=1`, which built seven devices, announced all 57;
- a deploy that fell over half way announced the whole topology on the line
  immediately above the list of scopes that had failed.

The last is the one that would have cost somebody a night. The counts now come
from the execution report -- create and wire steps that actually ran and
returned no error -- so each of those runs reports what it did. The agent's
reply had the same shape: `Steps` was `p.Len()`, the planned length, so the
per-node table showed a full step count for a run that performed none of them.
It now sends completed and planned separately, and the table prints `0/333`
when they differ.

**The fix had the defect in it.** The per-node link totals double-count
cross-node links, which are wired from both ends, so the summary subtracted the
topology's cross-node count to get back to distinct links. That identity holds
only for a run covering the whole topology, and the first version applied it
unconditionally:

```
$ twinet deploy --dry-run --only as=3
dry run: 33 devices and 10 links would be deployed across 3 nodes
```

Forty-three endpoints, minus a whole lab's 33 cross-node links, reported as 10
-- a fix for a number that could not be supported, printing a number that could
not be supported. A restricted or partly answered run now reports endpoints and
says that is what they are. Caught only because the fix was re-run against the
mutation it was written for, which is the rule that keeps earning its place.

The check that matters for the class as a whole: **on a normal, complete deploy
the output is byte-for-byte what it was before** -- `212 devices, 299 links (33
cross-node) across 3 nodes` -- because on that run the intended number and the
achieved number agree. The fix is invisible exactly when the old code was right,
and speaks up exactly when it was lying.

An unreachable node turns out not to reach the degraded branch at all: the
pre-flight image check refuses first, non-zero and before anything is created.
Verified by stopping node-2's agent.

Swept the neighbours. `destroy` prints its node count only after checking every
node succeeded. `inspect`'s use of `Stats()` is correct -- it is describing the
manifest, which is what inspect is for. The remaining `p.Len()` uses are a
progress-bar denominator and an empty-plan guard.

Verified: dry run and `--only` on both the single-node and cluster paths, a
clean cluster deploy unchanged, node-2 stopped and restored, cos461 back to
10.00.

### 122. A restore that reported success on work it had not put back

Publishing a ROA is something a student *does*, not a line of configuration, so
it appears in no router's running-config. The save side knows this and writes
`roas.json` into the archive, with a comment recording that a re-mark in a
harness whose trust anchor starts empty had already cost a group the mark for
publishing, at 9.70 out of 10.

`restoreBundle` matched archive members by file extension. It handled `.conf`
and `.sh`. `roas.json` matched neither, so it was stepped over in silence:

```
$ twinet restore submissions/2026-08-19-234332/group3.tar.gz
restored group3 into AS 3 (33 device(s))
```

Reproduced end to end on the cluster. With AS 3's authorisation removed from
the trust anchor -- the state a rebuilt lab starts in -- the lab grades:

```
mean 9.70  median 9.70  min 9.70  max 9.70  (out of 10.00)
  rpki.roa_published                       1 of 1
```

the same 9.70 the save-side comment describes. The restore above then reported
success and left it at 9.70. It now reports

```
restored group3 into AS 3 (33 device(s) and its published authorisations)
```

and the lab grades 10.00 again.

**The twin was worse than the finding.** Two consumers read these archives:
`restoreBundle` and `bundleSubmission`, the one batch grading uses. Each
decided separately what an archive may contain, which is exactly how one came
to apply the authorisations while the other ignored them -- and the one that
ignored them at class scale would have marked every submission in a run on
partial work, silently. Both now call `classifyBundle`, which places every
member or refuses by name. An archive member this version cannot apply is not a
stray file to skip: it is part of a submission, and applying the rest while
reporting success is the defect the ledger keeps finding.

On the save side, a marshal failure dropped the authorisations from the archive
with `if err == nil`, three lines after the code had treated failing to *read*
them as worth aborting the whole save for.

### 123. A gate that refused the reference solution for passing

`twinet grade class` attests that the deployed lab is the reference solution
before it marks anybody against it -- the one thing standing between a class and
being graded against a broken internet. It refused:

```
$ twinet grade class -s submissions/2026-08-19-234332
twinet: this lab is not the reference solution, so nothing can be graded against it:
  AS 10 scores full marks, but policy.transit_for_customers did not pass (not_applicable)
  AS 7 scores full marks, but policy.transit_for_customers did not pass (not_applicable)
  AS 8 scores full marks, but policy.transit_for_customers did not pass (not_applicable)
  AS 9 scores full marks, but policy.transit_for_customers did not pass (not_applicable)
```

Read the sentence: *scores full marks, but did not pass*. `not_applicable` means
the question cannot arise -- a stub system that sells transit to nobody cannot
withhold transit from a customer -- and the scorer deliberately leaves such a
check out of the weighting, which is why those systems are standing there with
full marks. The gate counted it as a failure, so it was contradicting the
grader it exists to guard.

cos461 has four stub systems, so `grade class` could not be run on cos461 at
all. Neither remedy offered helps: `deploy --solve` had already been run and
cannot change a check's applicability, and `--skip-reference-check` disables the
gate itself -- working around a fault in a safety check by turning the safety
check off, for every future run.

The verdict is now a pure function, `referenceComplaint`, so the semantics are
pinned by tests rather than reachable only through a six-minute class run. It
still fires on every case it was built for: a failed check behind a full total,
a check the grader could not run, a total below full marks, and a report the
grader itself flagged for review.

### 124. Every submission in a class quarantined for a device the kernel owns

With 123 fixed, `grade class` ran and quarantined the only submission in it:

```
1 of 1 submission(s) could not be graded and are quarantined:
  group3   loading the submission: as3/ATL still carries the previous
           submission's work after being reset (tunnel gre0)
```

`gre0` is not the previous submission's work. It is the fallback device the
kernel creates when the `gre` module loads, and it cannot be removed:

```
$ twinet exec as3/ATL -- ip tunnel del gre0
delete tunnel "gre0" failed: Operation not permitted
```

The reset excluded `sit0` and nothing else, so on any router where a tunnel
module had ever been loaded -- in a course that teaches tunnelling, every router
a student has touched -- the wipe could not remove `gre0`, and the read-back
that follows it counted what the wipe had left as somebody's leftover answer.
Every submission in the run is quarantined. A whole class receives no marks:
honestly, which is the one thing that stops this being a marking scandal, and
uselessly.

Both the wipe and the read-back now share one list of the devices the kernel
owns, so they cannot drift apart. The exclusion is not a hiding place: `gre1`,
`tun6` and `sit01` are still reported, which is what the read-back is for. On
the router that produced the quarantine, the filter keeps exactly `tun6` -- the
student's tunnel -- and drops the kernel's `sit0` and `gre0`.

With 122, 123 and 124 fixed, `twinet grade class` completes on cos461 for the
first time:

```
wave 1/1: group3
  group3       10.00 / 10.00
graded 1 submission(s) against cos461-routing in 6m18.694s
```

Three defects in one command, all in the same direction: the platform's
class-scale marking path had never been run end to end against the reference
lab. Two of them made it refuse to work at all, which is the failure mode to be
grateful for. The first, in the restore it shares with that path, quietly
marked a group 9.70 for an answer worth 10.00.

### 125. A mark for label distribution, given without waiting for label distribution

Grading waits for the control plane to settle before it marks. The wait watched
OSPF, then BGP sessions, then the RIB. It never watched LDP -- in the course
whose entire subject is MPLS.

Graded in place, advnet scores 6.00. The same submission, through the path a
class run uses, scored 5.20:

```
graded 1 submission(s) against advnet-mpls-l3vpn in 2m57.365s
  mean 5.20  median 5.20  min 5.20  max 5.20  (out of 6.00)
most-missed checks:
  mpls.ldp_adjacencies                     1 of 1
```

with the evidence `R2 has no LDP session with R5`. Read back after the run:

```
$ twinet exec as1/R2 -- vtysh -c 'show mpls ldp neighbor'
ipv4 1.151.0.1       OPERATIONAL 1.151.0.1       00:00:15
ipv4 1.153.0.1       OPERATIONAL 1.153.0.1       00:00:10
```

Ten and fifteen seconds of uptime: the sessions came up *after* the mark was
recorded. The student's answer was right and the grader was early.

Grading in place hides this completely, because a lab that has been running for
minutes converged long ago. It appears only when grading follows a reset --
which is what `grade class` and `grade batch` do to every submission, one after
another. Every student in an advnet class run loses this mark, and the report
they receive says their LDP session does not exist.

The rubric's own question asks for `converge_scope: ospf` and then marks
`mpls.ldp_adjacencies` inside it, so the wait established one thing and the mark
was given on another -- the ledger's oldest shape, in the one place where it
costs marks rather than credibility.

The wait now reads each router's **configuration** to decide whether LDP belongs
to this lab, because "no session yet" and "this lab has no LDP" are the same
output from `show mpls ldp neighbor`, and a predicate that cannot tell them
apart returns instantly and declares the network settled. A lab that runs no
LDP passes straight through without a single query. A submission whose LDP is
genuinely broken times out, is recorded as a warning, and is still marked --
non-convergence is a mark, not an outage.

After the fix, the same submission through the same path:

```
graded 1 submission(s) against advnet-mpls-l3vpn in 4m15.616s
  mean 6.00  median 6.00  min 6.00  max 6.00  (out of 6.00)
```

### 126. One datagram, and a mark for the network that lost it

Four checks sent a single datagram and, if it did not arrive, told the student
that something on the path was filtering by protocol:

| where | what it says |
| --- | --- |
| `dataplane.internal_reachability` | *"a datagram from X to Y never arrived ... though pings and connections do: something on the path is filtering by protocol"* |
| the backbone loopback pair | *"answers pings and connections ... but no datagram from it arrives"* |
| `vpn.isolation` (`vpnUDPGap`) | *"though pings do: the VPN is filtering by protocol"* |
| the IPv6 tunnel | *"something on the path is filtering by protocol"* |

UDP has no retransmission under it. A datagram lost to a full socket buffer, to
a neighbour entry being resolved, or to a scheduler delay on a loaded node is
indistinguishable from a network that discards the protocol. The ping probes
have always sent two echo requests and asked for one, and the ledger's own
finding 13 says why: *a mark that depends on the weather is worse than a missing
check, because nobody re-reads a grade that looks plausible.* The datagram
probes never got the same treatment.

The cost is not proportional to one packet. `internal_reachability` scores in
proportion to the probes that arrived, but a TCP or UDP failure **caps the whole
check at 0.5** -- so one lost datagram out of 144 probes takes half the check,
which at weight 0.2 in a one-point question is 0.10 marks. Grading sixteen
copies of the reference solution through two class runs deducted exactly that
from two of them, on a different pair of hosts each time:

```
7 of 8 scored 10.00; group6 scored 9.90    (--per-wave 1)
7 of 8 scored 10.00; group3 scored 9.90    (--per-wave 4)
```

Three datagrams are sent now and one arriving is enough, through a single
sender all four checks share so they cannot drift apart again.

**Every attempt leaves from one source port**, not a fresh one, and that is the
whole difficulty. A source port is not a path: where equal-cost paths exist a
new port is hashed afresh and lands on whichever path works, so a fault that
discards one path would clear itself on the retry. That is finding 116, and it
is far easier to repeat here than it looks. Pinned, the attempts all take the
path the first one took, so a retry rescues a dropped packet without rescuing a
dropped path -- and the check becomes reproducible in *both* directions, where
before a per-path filter was caught or missed by chance.

A datagram that could not be sent is not a datagram that was lost, either. The
grader picks the source port, so a collision is the grader's fault: an attempt
that cannot bind is sent unbound instead, and a sender that got nothing away is
reported as such so the caller stays silent rather than accusing on no evidence.
Verified against the image's own netcat, which is OpenBSD's:

```
$ nc -u -w 1 -s 9.9.9.9 -p 34567 3.102.0.1 33456
nc: bind failed: Address not available          -> matches, falls back

$ ... three attempts from 3.103.0.1 to 3.102.0.1 ...
NoPorts on the far side: 139 -> 142             -> all three arrive
```

Ten consecutive gradings of the whole lab in place after the fix -- eight
systems each, about twelve hundred check results -- with no deduction of any
kind.

**It was not enough, and finding 128 is what was actually wrong.** Sending three
datagrams removes independent loss, and independent loss was not what this was.
The entry is kept as written because the reasoning it records is sound and the
change is worth having on its own; but a fix that is only tested where the
defect does not appear is not tested. The class path is where it appeared, and
it took an hour to run, and it was run afterwards.

### 127. A refusal whose stated reason denies itself

Chasing 126 turned up the reason it was so destructive. The gate that attests a
lab is the reference solution refused the *whole class run* on a single grading,
and on **any** shortfall at all -- including one too small to appear in the
number it printed. A single lost ping costs about a thousandth of a mark, and
`%.2f` rounds that away, so the operator was told:

```
this lab is not the reference solution, so nothing can be graded against it:
  AS 5 scores 10.00 of 10.00
Run `twinet deploy -m . --solve` and check it reported no problems.
Pass --skip-reference-check only for a lab you have just checked by hand
```

A refusal whose stated reason denies itself, naming no check, with a remedy that
cannot fix a dropped packet. Observed refusing 2 of 3 attempts. What is left is
`--skip-reference-check`, which turns off the one protection against marking a
whole class against a broken internet -- **finding 123 again, reached from the
other side**: when a safety check's only available remedy is to disable the
safety check, the check is the bug.

Two things were wrong. The total is now compared at the precision it is printed
to, so the complaint cannot contradict itself; a check that did not pass is
still named however little it cost, so tolerating the total never tolerates a
broken lab. And a complaint must survive being asked a second time before a
class is refused on it: a lab that really is not the reference solution fails
the second grading as surely as the first, and one that lost a probe does not.

Both fixes were mutated to prove the tests hold them. Reverting the precision
reproduces the original message verbatim -- `scores 10.00 of 10.00` -- and
reverting the retry lets a lab that grades clean the second time refuse a class.

### 128. One observation of a path, however many packets it took

Finding 126 sent three datagrams where one had been sent, and a class run of
eight copies of the reference solution still came back with one of them at 9.90:

```
wave 3/8: group4
  group4       9.90 / 10.00
```
```
a datagram from SFO_host to HOU_host (4.108.0.1) never arrived
-- no packet of it reached any interface -- though pings and
connections do: something on the path is filtering by protocol
```

So the pair was asked directly, afterwards, and the two possible causes were
separated:

| what was tested | result |
| --- | --- |
| 300 datagrams over that exact pair, counted at the far side | **300 of 300 arrived** |
| the capture started, three datagrams sent, capture read, 30 times | **30 of 30 recorded all three** |

Neither the path nor the witness loses packets. So the three datagrams were not
lost independently -- they were lost *together*, and the reason is in the
sending:

```
$ for k in 1 2 3; do echo twinet | nc -u -w 1 -p 31999 <dst> 33456; done
elapsed=0
```

`-w` is how long netcat waits for a reply, not a pause between sends. All three
datagrams leave in the same instant. Whatever takes a pair out for a moment --
and at roughly one probe in a thousand, on a lab that answers every one of 300
when asked again, it is a moment and not a filter -- takes all three with it.

**Three packets milliseconds apart are one observation of the path, not three.**
The retry has to repeat the *observation*. A round that finds something is now
run again, with fresh ports, fresh captures and fresh counters, and only the
pairs that fail both times are reported.

This is exactly the rule finding 116 arrived at for the load-balancing sweep --
*the whole sweep is repeated instead, from fresh ports, and the fault has to
survive both* -- applied to the check that never got it. The connection sweep
beside it has the same structure and the same cap on the score, so it is
repeated on the same terms. Nothing is repeated where nothing was found, so a
healthy submission costs exactly what it did before.

The lesson worth keeping is about the earlier fix, not this one. Finding 126 was
verified ten times over on the path where the defect does not appear, and passed
ten times, and was wrong. The defect lived in an hour-long class run, and only
running the hour-long class run could have said so.

| | before 126 | after 126 | after 128 |
| --- | --- | --- | --- |
| eight submissions, class path | 9.90 on one | 9.90 on one | **10.00 on all eight** |

### 129. One corrupt upload was the whole class's problem

Found by review round 134, which was otherwise a PASS. Every per-submission
failure came out of `readSubmissions` as an error, and both grading commands
returned it unchanged:

```
$ twinet grade class -s submissions
twinet: group6.tar.gz: group6.tar.gz is not a gzip archive: gzip: invalid header
$ echo $?
1
```

Nothing was graded. Not the corrupt submission, and not the ninety-nine
submissions beside it. A course with one truncated upload got no marks at all,
and the only remedy on offer was to go and find the bad file and take it out of
the directory by hand — which is also, exactly, how a student silently ends up
with no mark at all. The failure and its remedy were the same action.

The distinction that was missing is between **one submission being bad** and
**the set being ambiguous**. A directory that cannot be listed, or two archives
both claiming AS 5, still stops everything: there the question of who would be
silently skipped has no answer, and finding 111 already settled that guessing
between two submissions is a decision about late work that belongs to a course
and not to a grader. But one unreadable file answers that question by itself.

So an unreadable submission is now quarantined rather than fatal. It is named
at the *start* of the run, not the end — an operator who learns at minute one
can fix the upload and re-run, one who learns at minute sixty runs the hour
again. It becomes a `Report` with `NeedsReview` set, which is the same shape a
submission gets when its harness fails to deploy, so it travels the existing
summary, CSV, report-writing and release-guard path rather than a second one
invented beside it. It carries no total, it is excluded from the class
statistics, and the command still exits non-zero so no script mistakes a
partial class for a complete one.

Verified on the real thing — two solved submissions and two corrupt uploads:

```
2 submission(s) cannot be read and will not be graded:
  group6         group6.tar.gz: group6.tar.gz is not a gzip archive: gzip: invalid header
  group7         group7.tar.gz: group7.tar.gz is not a gzip archive: unexpected EOF
They are reported as needing review, and the other 2 are graded normally.
...
graded 2 of 4 submission(s) against cos461-routing in 14m50.587s
  mean 10.00  median 10.00  min 10.00  max 10.00  (out of 10.00, over the 2 graded; 2 need review)
```

Before this, that command graded nobody.

### 130. A report that was never completed printed a zero

Falling out of 129, in the artifact that actually reaches a student. Every
per-student `.txt` report opened with its score, including the ones that had no
score:

```
group6 (AS 0)
============================================================  0.00 / 10.00 (0%)

grading failed: this submission could not be read...
```

`0.00 / 10.00 (0%)` is what a student who did nothing looks like. A corrupt
upload, a harness that failed to deploy, and a genuinely empty submission were
typographically identical, and the number was in the largest type on the page
while the reason was a line of prose below it.

The CSV had been taught this lesson already — its comment says a report that
needs review "carries no total at all rather than a zero", so that a gradebook
import cannot silently award a zero the platform is responsible for. The
human-readable version had not, and it is the one anybody actually reads. It
now prints `not graded` where the score would be, and ends with a sentence
saying so in words: *this is not a score of zero: nothing about the work was
assessed.*

The lesson is the one behind finding 122 and finding 124, in a new place: when
two artifacts describe the same fact, they will drift, and the one that drifts
is the one without a test. Both are now tested against the same rule.

### 131. A full mark was overwritten by a quarantine report

Found by review round 135, and caused by the fix for finding 129 — which is
the honest way to say it. Reports are written to a file named after the
submission, and the ambiguity check only ever saw the submissions it could
*read*. Quarantine introduced a second set of names it never looked at, and
appended those reports after the graded ones. So:

```
$ ls submissions/
group3  group3.tar.gz          # an empty directory, and a real archive

$ twinet grade batch -s submissions -o reports
  [1/1] group3       10.00 / 10.00
$ cat reports/group3.txt
group3 (AS 3)
============================================================  not graded
```

A student who scored full marks was handed a report saying they had not been
graded at all, and the class CSV carried two contradictory rows for them — one
`graded,10.00`, one `needs-review`. An instructor importing that file would
either double-count the student or record nothing for someone who passed.

The reviewer proposed making this fatal, consistent with the existing rule.
That would have been consistent and wrong: it puts back exactly what finding
129 took out, one student's stray directory leaving a hundred others unmarked.

The rule that was actually missing is that **ambiguity is a property of a
name, not of the set**. Everything claiming a contested name or a contested AS
is now withdrawn from the marking and reported; the rest of the class is
graded. One contested name yields exactly one report, so two withdrawn entries
cannot collide with each other either. What justified stopping the whole run
was that somebody would otherwise be silently skipped — and nothing is silent
now: every withdrawn submission is named before the run starts, named in the
CSV with no total, named again by the release guard, and the command still
exits non-zero.

```
1 submission(s) will not be graded:
  group3         2 submissions claim to be "group3" (group3 (unreadable), group3.tar.gz), so none of them was graded. ...
grading 1 submission(s), 8 at a time, each in its own lab
  [1/1] group4       10.00 / 10.00
```

group4 is the point: an innocent bystander who now gets marked.

Two things were tightened alongside it. Writing the reports **refuses** two
reports for one name rather than resolving it — whatever produced them is a
defect, and quietly replacing one mark with another is the worst possible way
to find out about it. And the quarantine text no longer prefixes every reason
with "this submission could not be read", which was untrue of a submission
that read perfectly and was withdrawn because two entries claimed its name.
Telling a student something untrue about their own work is the whole of what
this project is trying not to do.

`refuseDuplicates` was deleted rather than kept beside its replacement. It had
three tests and no callers, which is how a function goes on being tested for a
year after it stopped being the one that runs.

The lesson is about the shape of the fix, not the bug. Finding 129 added a new
kind of thing — a submission that is named but not graded — and every existing
rule about names was written before that kind existed. A fix that introduces a
new state has to be checked against every invariant that was true without it.

### 132. A cleanup that reported success for a lab it could not see

`twinet destroy --lab NAME` was documented as the way to remove a lab whose
manifest is no longer available. With no manifest it had nothing to read a
runtime from, so it opened the compatibility default — Docker — asked it for
the lab's containers, and was told there were none. On the documented
containerd cluster that is not "the lab is gone"; it is "the wrong daemon was
asked". It then deleted the overlay objects this machine held for the lab,
printed a success, and exited zero, while a 212-container lab kept running on
three nodes with its cross-node cables cut.

Three separate assumptions failed together, and each was invisible:

- a lab name says nothing about which machines the lab is on;
- an engine that was never chosen says nothing about which engine created it;
- an empty answer to a question nobody could verify was treated as evidence.

Naming a lab without a manifest now refuses before touching anything, and says
what the three safe paths are: run it with the lab's manifest, sweep the
cluster through its agents, or clean up one machine explicitly. The explicit
path exists because it is genuinely needed on a node whose agent is gone, and
its scope is in its name:

```
$ twinet destroy --lab cos461 --yes
twinet: refusing to remove lab "cos461" from a name alone: no manifest was
loaded from ".", so nothing here can tell whether the lab is running on other
machines, which engine created it, or which overlay objects are still carrying
its traffic.
  - to remove the whole lab, run this with its manifest: twinet -m PATH destroy --lab cos461 --yes
  - to clean up abandoned objects across a cluster you can still reach, use: twinet -m PATH node sweep --remove
  - to remove only what this one machine holds, say so explicitly: twinet --runtime ENGINE destroy --lab cos461 --this-node-only --yes
```

`--this-node-only` requires `--runtime` for the same reason the default was
wrong: without a manifest, nothing else says which engine to ask, and an empty
answer from the wrong one is indistinguishable from an empty machine. It
reports what it did as this machine's alone.

Two rules were added underneath, which apply to every local removal and not
only to the manifest-less one. An overlay whose bridge still has an interface
attached is never removed — the same rule `twinet node sweep` already applied,
so a lab cannot be cleaned up more aggressively by naming it than by sweeping
for it — and it is reported rather than silently retained. And an overlay list
that could not be read is a reason to remove nothing and to refuse, rather than
a reason to print "nothing to remove": a conclusion drawn from a question that
failed is the same mistake in a smaller font.

The messages were the other half of the defect. "removed lab" and "nothing to
remove" mean different things on one machine and on a cluster, and nothing in
the output said which had happened. Every message now names the scope it can
actually speak for.

### 133. A bundle of examples with two runtime contracts

Six of the seven bundled labs declared no container runtime at all, which means
`docker` for compatibility with manifests written before the runtime registry
existed. The seventh, `examples/scale`, declared `containerd`. The operator
guide, the measured scale evidence, and the agent rollout all describe a
containerd cluster — on which six of the seven bundled labs were refused by the
backend check, one lab at a time, after the operator had built a cluster,
issued a PKI, and rolled out agents by following the same documentation.

The fallback was the problem, not the choice. A default that is invisible in
the manifest cannot be reviewed, cannot be diffed, and is discovered only when
something refuses it. Every bundled example now states `runtime: containerd`,
validation reports a manifest that declares nothing, and Docker or Podman is
selected by saying so — `--runtime` or `TWINET_RUNTIME`, which replaces the lab
default and every per-node selection at once and announces that it has. Two
tests keep the bundle coherent: one asserts every example declares the cluster
runtime, and one asserts every example still validates under an explicit
override to each registered backend.
