# Twinet

A container-based network **twin** for teaching how the Internet practically
works — at class scale, across a cluster.

Twinet is a ground-up redesign and reimplementation of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project).
Every student group operates a real Autonomous System — real FRR, real OSPF,
real BGP, real RPKI, real Open vSwitch — and must cooperate with every other
group for the Internet to work.

> **Status: under construction.** The design is in [`docs/`](docs/); what is
> built and measured so far is in [`docs/09_status.md`](docs/09_status.md).
>
> A twelve-AS lab of 211 containers and 291 links currently deploys across three
> machines in 83 seconds, and a rubric-driven grading run completes a submission
> in about ten seconds.

## What it is for

- **Courses.** Supports the Princeton [COS-461 routing project](https://github.com/cos-461/routing/wiki)
  and the ETH advanced-networks exercises (MPLS/LDP, BGP-free core, BGP/MPLS
  VPN with VRFs, multicast).
- **Autograding.** Hundreds of submissions graded in parallel, in isolated
  reproducible labs, in minutes.
- **Scale-out.** The unit of placement is an AS; adding a machine adds capacity.
- **Agent evaluation.** The same twin, broken in a known and reversible way, is
  a reproducible benchmark for whether an AI agent can perform root-cause
  analysis. Twinet targets the [NIKA](https://github.com/sands-lab/nika) fault
  taxonomy and aims to serve as a NIKA backend.

## Design in one page

| | |
|---|---|
| **One binary to deploy** | `twinet` (control plane, stateless) + `twinetd` (node agent). No Python, no OVS on the host, no bash libraries to source. |
| **One document to edit** | A validated, templated YAML manifest. Addressing, VNIs, DNS zones, IXP configs, the website and the grading topology are all derived from it. |
| **No state to corrupt** | Every allocated resource is a pure function of the manifest; observed state comes from container labels. |
| **Incomplete by design** | The model distinguishes operator-*provisioned* config, *student*-owned config, and the *expected* answer — so the grader and the assignment text come from the same source. |
| **No sleeps** | Readiness and convergence are predicates, not `sleep 60`. |
| **Scales out** | veth for same-node links, point-to-point VXLAN for cross-node links (measured 0.16 ms on 10 GbE — invisible under a 2.5 ms emulated delay). |

## Documentation

| Document | Contents |
|---|---|
| [Assessment](docs/01_assessment.md) | Critical review of the current mini-Internet implementation |
| [Architecture](docs/02_architecture.md) | Components, state model, runtime abstraction, deployment pipeline |
| [Topology model](docs/03_topology_model.md) | Manifest, AS templates, IPAM, the provisioning contract |
| [Networking & scale-out](docs/04_networking_and_scaleout.md) | Link realization, VXLAN fabric, placement, capacity |
| [Services](docs/05_services.md) | DNS, matrix, looking glass, RPKI, IXP, VPN, web, SSH access |
| [Grading](docs/06_grading.md) | Ephemeral labs, test doubles, checks, rubrics, reports |
| [Roadmap](docs/07_roadmap.md) | Milestones, acceptance criteria, risks |
| [Resources needed](docs/08_resources_needed.md) | Open decisions and required resources |
| [Implementation status](docs/09_status.md) | What is built and verified, with measurements |
| [Fault injection and RCA](docs/10_fault_injection.md) | Injecting the NIKA fault taxonomy to assess AI agents at root-cause analysis |

## Credits

Twinet builds on the ideas of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project) by
the Networked Systems Group at ETH Zürich, and takes design inspiration from
[containerlab](https://containerlab.dev) and
[Kathará](https://www.kathara.org). It shares no code with any of them.
