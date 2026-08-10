# Twinet

**Twinet** is a ground-up redesign and reimplementation of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project):
a container-based network *twin* for teaching, at class scale, how the Internet
practically works.

> **Twin** + **net**: every student group operates a real AS — real FRR, real
> BGP, real OSPF, real RPKI — inside a faithful, reproducible, horizontally
> scalable digital twin of the Internet.

---

## Why a redesign?

The current platform works and has taught thousands of students, but it has
accumulated ~35,000 lines of ad-hoc bash and Python with no schema, no tests,
no state model, and a hard single-machine ceiling. See
[01-assessment.md](01-assessment.md) for the full critique.

Twinet keeps everything that makes the mini-Internet pedagogically excellent
and replaces the machinery underneath it.

| | mini-Internet | Twinet |
|---|---|---|
| Implementation | ~17.8k lines bash + ~17.4k lines Python, 20 top-level scripts run serially | One statically-linked Go binary + one node agent |
| Topology input | 8 positional whitespace-separated `.txt` files with `N/A` sentinels | One validated, schema-checked, templated YAML manifest |
| Addressing | `subnet_config.sh`: hardcoded bash functions with magic offsets | Declarative, expression-based IPAM plan; deterministic and inspectable |
| State | `groups/` dir + `docker_pid.map` sourced as bash (stale after reboot) | Derived from container labels + deterministic allocation; no database to corrupt |
| Deploy | `startup.sh` → 20 scripts, two hardcoded `sleep 60`s | Dependency DAG, parallel workers, active convergence detection |
| Scale | Single beefy server, ~1.5–2k containers | Scales out across a cluster; AS-granular placement over a VXLAN fabric |
| Restart one device | `restart_container.sh` (1,011 lines of bash) | `twinet redeploy --node <x>`, diff-and-converge |
| Grading | Serial, `sleep(20)`-driven, mutates the live class network, hours per class | Parallel ephemeral per-student labs, convergence-triggered, minutes per class |
| Tests | none | Unit + integration + e2e in CI |

---

## Documents

| # | Document | Contents |
|---|---|---|
| 01 | [Assessment](01-assessment.md) | Critical review of the current implementation; what to keep, what to kill |
| 02 | [Architecture](02-architecture.md) | Components, control/data plane split, state model, runtime abstraction |
| 03 | [Topology model](03-topology-model.md) | The Twinet manifest, AS templates, IPAM, the provisioned/student config split |
| 04 | [Networking & scale-out](04-networking-and-scaleout.md) | Link realization, VXLAN fabric, placement, shaping, MTU, measured results |
| 05 | [Services](05-services.md) | DNS, matrix, looking glass, RPKI, IXP, measurement, VPN, web, access/SSH |
| 06 | [Grading](06-grading.md) | The autograding engine: ephemeral labs, probes, rubrics, parallelism |
| 07 | [Roadmap](07-roadmap.md) | Milestones, deliverables, acceptance criteria, risks |
| 08 | [Resources needed](08-resources-needed.md) | What I need from you to execute this plan |
| 09 | [Implementation status](09-status.md) | What is built and verified, with measurements |

## Design principles

1. **One binary, no runtime dependencies.** `twinet` is a static Go binary.
   Deploying Twinet on a fresh machine is: install Docker, drop two binaries,
   `twinet up`. No pip, no venv, no OVS on the host, no sourcing bash libraries.
2. **The manifest is the truth; everything else is derived.** Addressing, VNIs,
   ports, container names, DNS zones, IXP configs, the website, and the grading
   topology are all *computed* from one validated document. Nothing is
   hand-maintained in two places.
3. **Deterministic allocation, so there is no state to lose.** Every allocated
   resource (subnet, VNI, port, MAC) is a pure function of the manifest. A
   controller restart, a node reboot, or a partial failure changes nothing.
4. **Incomplete-by-design is a first-class concept.** A teaching network is
   *deliberately* unfinished. Twinet distinguishes operator-provisioned config
   from student-owned config at the model level, rather than by convention.
5. **Everything is parallel.** Deployment, probing, and grading are all
   embarrassingly parallel; nothing may be serialized by a `sleep`.
6. **Scale out, not up.** The unit of placement is an AS. Adding a machine adds
   capacity; no single node is special except by choice.
7. **Grading is a first-class product, not a script.** Reproducible, isolated,
   parallel, rubric-driven, with structured output and a re-runnable artifact.
