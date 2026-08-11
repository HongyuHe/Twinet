# 08 — Resources and decisions needed

Everything below is either something I cannot obtain myself, or a decision that
is yours to make. Items marked **blocking** stop a milestone; the rest have a
default I will proceed with if I do not hear otherwise.

## 1. Environment — what I already have (verified)

| | Status |
|---|---|
| Cluster | `node-0`, `node-1`, `node-2` — each 56 cores, 251 GiB RAM, 917 GB free disk, Ubuntu 24.04, kernel 6.8 |
| Networking | `eno1` 1 GbE public, `eno2` **10 GbE** private on `10.0.1.0/24` |
| Privileges | passwordless `sudo` on node-0; passwordless root SSH from node-0 to node-1 and node-2; permission to install anything needed |
| Docker | 29.7.2 on **all three nodes**, logged in to Docker Hub as `hyhe` |
| Cross-node VXLAN | **verified working**, 0.154–0.321 ms RTT (see doc 04 §1.2) |
| Git remote | `https://github.com/HongyuHe/Twinet` reachable, credentials stored |

All milestones are unblocked.

## 1a. Answers received

| # | Question | Answer |
|---|---|---|
| 2.1 | Docker on node-1/node-2 | **Done** — installed and logged in; free rein to install anything else |
| 2.2 | Cluster lifetime / size | Available indefinitely |
| 2.3 | Jumbo frames on `eno2` | **Approved** |
| 2.4 | Docker Hub namespace | `hyhe/twinet-*` approved |
| 2.5 | Real submissions for grader validation | Approved — to be supplied |
| — | Budget / schedule | **Not a constraint.** Optimise solely for the best outcome. |


## 2. Things I need

### 2.1 Docker on node-1 and node-2 — *blocking M3*
Neither has Docker installed. They have public IPs on `eno1`, so I expect to be
able to install it directly. **May I install Docker (and a `twinetd` systemd
unit) on node-1 and node-2?** Default if I hear nothing: yes, I will install
via the official apt repo.

### 2.2 Cluster lifetime and node count
- **How long do I have these three nodes?** This determines whether M6's
  80-AS scale test is a one-shot or something I can iterate on.
- **Can I get more nodes?** Three is enough to *prove* scale-out and to run an
  80-AS class, but 5–6 would let me demonstrate 112 ASes with headroom and
  test placement/rebalancing more convincingly. Not blocking.

### 2.3 Jumbo frames on the private fabric
I would like to set `eno2` MTU to 9000 on all three nodes so VXLAN
encapsulation is free and every lab link can stay at MTU 1500 (see doc 04 §1.3).
This is a change to shared infrastructure. **OK to change `eno2` MTU?** Default
if I hear nothing: I will test it non-destructively first and fall back to a
uniform 1450 lab MTU if it does not work.

### 2.4 Docker Hub namespace
I will publish images as `hyhe/twinet-router`, `hyhe/twinet-host`,
`hyhe/twinet-switch`, `hyhe/twinet-ixp`, `hyhe/twinet-svc`. **Do you want an
organisation namespace (e.g. `twinet/…`) instead?** If so I need it created and
the `hyhe` account added. Not blocking (I will start with `hyhe/`).

### 2.5 Real student submissions for grader validation — *helps M5*
To validate the grading engine against ground truth I would like:
- a handful of **real, anonymised** COS-461 submissions (the `configs_*` dumps),
  ideally spanning the score range, and
- their **human-assigned scores**.

Failing that, I will synthesise submissions by mutating a reference solution,
which validates mechanics but not fidelity to how students actually fail. If
there is anything usable in the `cos-461` GitHub org, read access to it would
help. *(There is one usable artifact already in-tree: `golden-configs/`, but it
is a mid-assignment snapshot of a single AS with no eBGP or RPKI, so it only
covers Q1.1–Q2.1.)*

### 2.6 The 2025 grader, for cross-checking
The report on the current autograder is based on
`communication_networks_course/2025_assignment_eth/config_2025/autograder-25/`.
If there is a **newer or Princeton-specific grader** with the actual point
weights used for COS-461 grading, I want it — the rubric weights should match
what you actually award.

### 2.7 Public hostname and ports — *only for a student-facing deployment*
If Twinet is to be reachable by students this term, I need:
- a DNS name and which node it points at (the equivalent of `hecate`),
- ports opened: web (9000 or 80/443), SSH gateway (2022), optionally the
  legacy `2000+N` range, WireGuard UDP (51820), Krill (4000).

Not needed for development or for any milestone through M7.

## 3. Decisions I would like from you

Each has a default; tell me only if you disagree.

| # | Decision | Default |
|---|---|---|
| D1 | **Implementation language: Go.** Single static binary, native netlink/netns, real parallelism, no runtime deps on 20 machines. Rationale in doc 02 §2. | Go |
| D2 | **No Kubernetes.** Purpose-built agent instead; a K8s backend stays possible behind the `Runtime` interface. Rationale in doc 04 §7. | No K8s |
| D3 | **Licence.** The upstream mini-Internet is MIT (since 2025-03-25); Kathará is GPLv3 (so I will take ideas, not code); containerlab is BSD-3. Twinet as MIT keeps it compatible and reusable. | MIT |
| D4 | **Course material compatibility.** I keep the `save_configs.sh` dump layout and the `ssh -p 2000+X` path so the existing COS-461 wiki needs no rewrite beyond hostnames. | Keep compatibility |
| D5 | **Primary target course.** I optimise the examples, rubric and docs for COS-461 first, with the ETH advanced course (MPLS/VPN/multicast) ported in M7. | COS-461 first |
| D6 | **Scope of the advanced course.** MPLS/LDP, BGP-free core, BGP/MPLS VPN with VRF, and PIM-SM/IGMP multicast are all in scope but late (M7). Say if any should move earlier or be dropped. | All in scope, M7 |
| D7 | **Features I propose to drop or replace.** ① the per-group SSH proxy container (→ gateway); ② `wg_observer` in every router (→ read WireGuard state centrally); ③ the history container + headless-Chrome GIF pipeline (→ snapshots + a time slider in the web UI); ④ the forked Krill image (→ upstream image, provisioned by a typed client). Object to any of these? | Drop/replace all four |
| D8 | **VPN priority.** WireGuard matters (2025's Q2.7 grades a VPN-delivered secret), but it is the most operationally fiddly piece. I have it in M2; it can slip to M7 if you would rather have grading sooner. | Keep in M2 |
| D9 | **IPv6 depth.** The course needs IPv6 addressing in the L2 domains plus 6in4 tunnels — not full dual-stack routing. I will implement exactly that. | Course-level IPv6 |
| D10 | **Repo hygiene.** I will keep `main` always green (CI must pass), commit per logical change with `Hongyu Hè` as sole author and no Copilot trailer, and push after each milestone. | As stated |

## 3a. Resources the fault-injection objective adds

Recorded here because [10](10_fault_injection.md) was added to the plan after
the original list.

| # | Item | Why |
|---|---|---|
| A | **Confirmation that NIKA integration is two-way.** I plan both a native Twinet fault API *and* a NIKA `LabRuntime` adapter, so NIKA's existing fault implementations run unmodified against a Twinet lab. If you only want one direction, the adapter is the one to keep. | Scope |
| B | **A decision on the 13 out-of-substrate fault types.** My recommendation: build P4/BMv2 and SDN-controller device kinds (9 types), and delegate the 4 Kubernetes types to NIKA's existing backend rather than duplicating a container orchestrator's failure modes inside a network emulator. | Scope |
| C | **Whether Twinet should be upstreamed to NIKA as a backend**, or kept as an adapter in this repository. Upstreaming means matching their release cadence and review; an adapter here means tracking their interface. | Process |
| D | **An agent endpoint to test against.** To validate the evaluation loop end to end I need at least one agent I can point `twinet incident run` at. NIKA's mock agent would do for mechanics; a real one is needed to know the task is neither trivial nor impossible. | Validation |
| E | **Any NIKA scenarios you consider canonical**, so M8's acceptance test ("NIKA agrees with containerlab's verdict for the same fault") compares against cases you care about rather than ones I pick. | Validation |

None of these block starting M8, and none change anything before it.

## 4. What I do *not* need

- Access to the live `hecate` deployment — I would rather build and validate
  independently, then migrate.
- Any external framework as a dependency — Twinet is self-contained; Kathará
  and containerlab informed the design (see doc 04 §7) but neither is a runtime
  dependency.
- Cloud resources — the cluster is sufficient.

## 5. Immediate next step

Unless you redirect me, I will start on **M0 + M1**: repo scaffolding, the typed
model with generated schema and aggregated validation, the Docker runtime and
`netx` wiring layer, the staged deployment DAG, and the three base images —
targeting a working 12-AS mini-Internet on node-0 that a person can SSH into and
configure by hand.
