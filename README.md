# Twinet

A container-based network **twin** for teaching how the Internet practically
works — at class scale, across a cluster.

Twinet is a ground-up redesign and reimplementation of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project).
Every student group operates a real Autonomous System — real FRR, real OSPF,
real BGP, real RPKI, real Open vSwitch — and must cooperate with every other
group for the Internet to work.

> **Status: design.** The implementation plan is in [`docs/`](docs/).
> Start with [`docs/README.md`](docs/README.md).

## What it is for

- **Courses.** Supports the Princeton [COS-461 routing project](https://github.com/cos-461/routing/wiki)
  and the ETH advanced-networks exercises (MPLS/LDP, BGP-free core, BGP/MPLS
  VPN with VRFs, multicast).
- **Autograding.** Hundreds of submissions graded in parallel, in isolated
  reproducible labs, in minutes.
- **Scale-out.** The unit of placement is an AS; adding a machine adds capacity.

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
| [Assessment](docs/01-assessment.md) | Critical review of the current mini-Internet implementation |
| [Architecture](docs/02-architecture.md) | Components, state model, runtime abstraction, deployment pipeline |
| [Topology model](docs/03-topology-model.md) | Manifest, AS templates, IPAM, the provisioning contract |
| [Networking & scale-out](docs/04-networking-and-scaleout.md) | Link realization, VXLAN fabric, placement, capacity |
| [Services](docs/05-services.md) | DNS, matrix, looking glass, RPKI, IXP, VPN, web, SSH access |
| [Grading](docs/06-grading.md) | Ephemeral labs, test doubles, checks, rubrics, reports |
| [Roadmap](docs/07-roadmap.md) | Milestones, acceptance criteria, risks |
| [Resources needed](docs/08-resources-needed.md) | Open decisions and required resources |

## Credits

Twinet builds on the ideas of the
[mini-Internet project](https://github.com/nsg-ethz/mini_internet_project) by
the Networked Systems Group at ETH Zürich, and takes design inspiration from
[containerlab](https://containerlab.dev) and
[Kathará](https://www.kathara.org). It shares no code with any of them.
