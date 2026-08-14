# 04 — Networking and scale-out

## 1. Link realization

A Twinet link is a point-to-point L2 segment between two device interfaces. It
is realized in one of three ways, chosen automatically by the planner:

| Case | Mechanism |
|---|---|
| Both endpoints on the **same node** | `veth` pair; each end moved into the target netns, renamed, MAC/MTU set, brought up |
| Endpoints on **different nodes** | `veth` into each container + a per-link **VXLAN** netdev, joined by a link-local bridge on each node |
| Endpoint is a **switch** (OVS) | `veth` into the switch container, added as an OVS port with the declared VLAN tag/trunk |

Everything happens through `vishvananda/netlink` and
`containernetworking/plugins/pkg/ns` inside `twinetd`. Notably, Twinet does
**not** need Open vSwitch on the host (the current platform requires
`ovs-vsctl` on the host and creates host bridges); OVS lives only inside switch
containers, where the course actually wants it.

### 1.1 Same-node veth (the common case)

```
netlink.LinkAdd(&netlink.Veth{LinkAttrs{Name: rndA, MTU: mtu}, PeerName: rndB})
netlink.LinkSetNsFd(a, nsFdOf(containerA))      // move
ns.WithNetNSPath(nsA, func() { rename→ifaceA; setMAC; setMTU; setUp; txoff })
… same for b …
```

Both halves are created once, in the root namespace, with random names, then
moved — this avoids the name collisions the current platform works around by
hashing an identifier through `uuidgen -s --namespace @url` to produce a
13-character port name. Each veth gets an `altname` of `twinet-<linkID-hash>`
so orphans are identifiable and removable after a crash.

### 1.2 Cross-node VXLAN

```
container A ──veth──▶ br-tw<vni> ──▶ vxlan<vni> (id=VNI, local=nodeA, remote=nodeB,
                                                  dstport=4789, nolearning)
                                          ≈ 10 GbE underlay ≈
container B ──veth──▶ br-tw<vni> ──▶ vxlan<vni> (id=VNI, local=nodeB, remote=nodeA)
```

- **Unicast, point-to-point, `nolearning`** with a static FDB entry per peer.
  No multicast (unavailable in most clusters/clouds) and no EVPN control plane
  needed, because every Twinet link has exactly **two** endpoints. This is
  strictly simpler than Kathará's Megalos CNI (which needs BGP-EVPN precisely
  because its collision domains are multi-access) and than containerlab's
  manual `clab tools vxlan create` runbook.
- **VNI is deterministic** (`fnv1a64(lab‖linkID)` folded into the 4096..2^24
  range), so both agents compute the same value independently and there is no
  allocation registry to keep consistent.
- A future optimization, if per-link netdev count becomes a problem, is a single
  VXLAN device in `external`/collect-metadata mode with per-link VLAN mapping;
  the interface between the planner and `netx` is designed so this is a
  drop-in change.

**Measured on this cluster (node-0 ↔ node-1, 10 GbE `eno2`, 10.0.1.0/24):**

```
$ ip netns exec vxns ping -c3 192.168.77.2
64 bytes from 192.168.77.2: icmp_seq=1 ttl=64 time=0.321 ms
64 bytes from 192.168.77.2: icmp_seq=2 ttl=64 time=0.158 ms
64 bytes from 192.168.77.2: icmp_seq=3 ttl=64 time=0.154 ms
rtt min/avg/max/mdev = 0.154/0.211/0.321/0.077 ms
```

**This is the key feasibility result.** The overlay adds ~0.16 ms, while the
*smallest* emulated inter-AS delay in the course is 2.5 ms and the smallest
link delay anywhere is 1 ms. Cross-node links are therefore
pedagogically indistinguishable from same-node links — the underlay noise is
6% of the smallest quantity a student can observe, and is dwarfed by the
`netem` jitter already present.

### 1.3 MTU

VXLAN adds 50 bytes of encapsulation. If cross-node links had MTU 1450 while
same-node links had 1500, students would hit path-MTU artifacts that depend on
*where the platform happened to schedule their AS* — an unacceptable
observable difference.

Twinet enforces a **uniform overlay MTU** across every link in the lab:

1. Preferred: raise the underlay MTU (`eno2`) to 9000 and keep all lab links at
   1500. Jumbo frames on the private 10 GbE fabric make encapsulation free.
2. Fallback: if the underlay cannot exceed 1500, set every lab link to
   `mtu: 1450` (declared once in `link_defaults`, applied everywhere), so the
   behaviour is uniform and explicit rather than placement-dependent.

`twinet validate` fails if the requested link MTU plus VXLAN overhead exceeds
the discovered underlay MTU on any node pair. *(Validation task M3-1: confirm
`eno2` accepts MTU 9000 on all three nodes.)*

### 1.4 Shaping

Bandwidth, delay and queue come from the manifest and are applied per-interface
inside the container's netns:

```
tc qdisc add dev <if> root handle 1:0 netem delay <delay>
tc qdisc add dev <if> parent 1:1 handle 10: tbf rate <bw> burst <burst> latency <queue>
```

Burst is computed as 10% of one second of the configured rate, floored at 10
MTU — the same rule the current platform uses (`compute_burstsize`, ~60 lines
of bash unit conversion), reimplemented as ~20 lines of typed Go with tests.
Shaping is applied on **both** ends, as today, so the emulated delay is
symmetric and independent of which end is on which node.

Because shaping lives on the container-side veth, it is identical for local and
cross-node links — the VXLAN hop is inside the shaped path, not outside it.

## 2. Placement

The unit of placement is the **AS**, not the container. This is the single
decision that makes scale-out cheap:

- Intra-AS links (12 router-router links, 8 router-host links, 2 L2 fabrics)
  are the numerous, low-latency, high-fan-out ones → keep them **local veths**.
- Inter-AS links are few (typically 5–7 per AS), already throttled to `1mbit`
  with 2.5–25 ms of emulated delay → **perfect VXLAN candidates**.

For an 80-AS class: ~2,000 intra-AS links stay local; only ~250 inter-AS links
plus service links cross the fabric.

```yaml
placement:
  strategy: pack-by-as
  nodes: [node-0, node-1, node-2]
  reserve: {node-0: {cpus: 8, memory: 32Gi}}   # leave headroom for services
  pin:
    - {match: {service: "*"},  node: node-0}
    - {match: {as: 1},         node: node-0}   # Krill/RPKI near the web tier
```

### The partitioner

Placement is a **balanced graph partition of the peering graph**, in three
steps (`internal/place`):

1. **Order.** ASes are visited by growing outwards from the highest-degree
   seed, so that each AS is placed while its neighbours are already known.
   Weight-descending order — the natural one for bin-packing — walks the graph
   arbitrarily, so most neighbours are still unplaced when a decision is made
   and there is no locality to exploit.
2. **Greedy assignment.** Each AS goes to the node that keeps the most of its
   links local, among the nodes that would still be *balanced* after taking
   it. The balance bound is expressed against the least-loaded option at that
   moment, not as a fixed ceiling, so the candidate set is never empty and no
   fallback is needed that would abandon balance altogether.
3. **Local search.** Moves and pairwise swaps that keep more links inside a
   node, and leave the load no less even, are applied until nothing improves
   (capped at eight rounds). The greedy pass commits early to choices later
   ASes make bad; this repairs them.

Cost is a fraction of a second for eighty ASes and two thousand containers.

`strategy` chooses how much imbalance is traded for locality:

| Strategy | Trades | Use for |
|---|---|---|
| `pack-by-as` *(default)* | up to a tenth of a node's share | normal class deployment |
| `spread-by-as` | nothing; locality breaks exact ties only | uniform hardware, maximum headroom |
| `single-node` | everything onto the front node | development, CI, a one-machine course |

Measured on the 80-AS lab across three nodes (`twinet inspect --placement`):

| | inter-AS links crossing | node load |
|---|---|---|
| least-loaded assignment (what this replaced) | 201 / 283 (71%) | 662..675 |
| `pack-by-as` | **111 / 283 (39%)** | 550..731 |
| `spread-by-as` | **110 / 283 (39%)** | 660..677 |

An **intra-AS link never crosses a node**, by construction: the AS is the unit
of placement. `twinet inspect --placement` reports the three classes
separately and warns if an AS is ever split, because a single aggregate
percentage cannot distinguish a good partition from a topology that happens to
have few inter-AS links.

Service links are the remaining cost (≈64% cross at 80 ASes). A service that
attaches to every AS is a star, and no assignment of one container can keep
more than one node's share of a star local; the fix is more service replicas,
not better placement.

### Stability

Placement is **deterministic for a given manifest** — every tie is broken by AS
number or node name, and the local search only takes strictly improving moves
(`TestPlacementIsIdenticalOnEveryRun`).

Determinism alone is not enough, because the manifest changes. Every command
that has to find a device — `exec`, `grade`, `save`, `restore`, the gateway —
recomputes placement, so if the answer ever changed they would look for
containers on nodes that do not have them and report "no such container" while
the container runs perfectly well one node over. Adding a single student to a
term already under way moved seven of the other ten ASes; so does any
improvement to the placer itself.

So the assignment is **written down**, in `<lab>/.twinet/placement.json`, and
read back by everything that places:

- `twinet deploy` writes the record before creating anything, so a deploy that
  fails half way still leaves a record matching the containers that came up.
- Any AS named in the record stays where the record says, even where the
  placer would now choose otherwise. New ASes are placed around them.
- If the record is missing but the lab is running — deployed by an earlier
  version, or the record lost — `deploy` **adopts** the placement from the
  running containers' `twinet.node` labels. What is running is the authority;
  the record only remembers it.
- A node removed from the manifest is the one case where an AS must move. It
  is reported as a warning, because it costs that group their containers.
- `twinet deploy --rebalance` recomputes from scratch. It warns first: every AS
  that moves is destroyed and rebuilt.
- `twinet destroy` clears the record, so the next deployment is free to place
  the lab afresh and pick up any improvement to the placer.
- A record that is corrupt, or belongs to another lab, is a **hard error**, not
  a missing record. Treating it as absent would recompute a placement that
  disagrees with the running containers — precisely what the record prevents.

`twinet inspect --placement` prints the assignment.

## 3. Capacity model

Current cluster: 3 × (56 cores, 251 GiB RAM, 917 GB disk, 10 GbE private).

| Per-AS (full template) | Count |
|---|---|
| routers | 8 |
| L3 hosts | 8 |
| switches | 3 |
| L2 hosts | 6 |
| **containers per AS** | **25** |

(No per-group SSH proxy container — the gateway replaces 1 container per group;
see doc 05.)

| Class size | Containers | Nodes needed @ ~600/node |
|---|---|---|
| 30 ASes | ~760 | 2 |
| 80 ASes | ~2,010 | 4 |
| 112 ASes | ~2,810 | 5 |

An idle FRR router container is ~30–60 MiB RSS; 600 containers/node ≈ 36 GiB,
well inside 251 GiB. The binding constraint is more likely CPU during
convergence bursts and the kernel's netdev/ARP tables, for which `twinetd`
applies the required sysctls automatically at startup (`neigh.gc_thresh*`,
`pid_max`, `inotify.max_user_instances`, `nf_conntrack_max`) instead of asking
the operator to remember them.

**Twinet targets ~600 containers per node as a conservative default**, so the
3-node cluster comfortably runs the historical 80-AS class, and adding a fourth
machine is a one-line manifest change.

## 4. Bootstrapping a node

```bash
twinet node bootstrap node-1        # from the control machine, over SSH
```
installs Docker if absent, drops `twinetd`, installs a systemd unit, applies
sysctls and modules (`mpls_router`, `mpls_gso`, `mpls_iptunnel` for the
advanced course), issues an mTLS certificate, and verifies underlay reachability
and MTU to every other node. `twinet node status` reports version skew, clock
skew, capacity, and image cache state.

Images are pulled by agents in parallel; `make push` pre-seeds a
node from a local tarball for air-gapped or slow-link environments.

## 5. External connectivity

- **Students**: SSH to the gateway on the front node (doc 05). No per-group
  port mapping is required, though `legacy_ports` reproduces `ssh -p 2000+X`.
- **Web UI / Krill**: published on the front node only.
- **VPN**: WireGuard endpoint on the front node; peer traffic is routed into
  the overlay, so a student's laptop can reach devices on any cluster node.
- **Lab → Internet**: *(planned, not implemented)* off by default; an explicit
  `egress:` block would enable masquerade for named devices (e.g. a validator
  fetching real trust anchors), rather than the legacy platform's blanket
  `nat_setup.sh` + `iptables/filters.sh`. Today a device reaches only the lab,
  and a manifest that declares `egress:` is **refused** rather than deployed
  with the block silently ignored. The lab is self-contained by construction:
  the trust anchor is derived from the topology, the resolver is authoritative
  for the lab's own zones, and nothing else needs to leave.

## 6. Failure handling

| Failure | Behaviour |
|---|---|
| Agent restarts | Containers keep running (they are not children of the agent). On reconnect the agent re-inventories from labels and repairs missing wiring. |
| Node reboots | `twinet deploy` recreates that node's ASes; other nodes untouched. Optionally `placement.on_node_loss: reschedule` moves the ASes elsewhere. |
| Container dies | Docker `restart: unless-stopped` brings it back; the agent notices the new netns and re-wires its links (this is what `restart_container.sh`'s 1,011 lines do today, done automatically). |
| Underlay link flap | VXLAN is stateless; links recover with the underlay. Agents export a `twinet_underlay_up` metric per peer. |
| Partial deploy failure | Per-AS status; re-running converges only the gap. |

## 7. What we borrow, and from where

| Idea | Source | Note |
|---|---|---|
| veth-into-netns wiring, altname ownership tags, TX-offload disable | containerlab `links/`, `nodes/default_node.go` | Reimplemented; same primitives, same correctness edge cases |
| labels-as-state, `defaults→kind→node` inheritance, stages/`wait-for` DAG, diff-and-apply | containerlab `core/`, `types/` | Adopted as design patterns |
| VXLAN as the cross-host L2 primitive | Kathará Megalos CNI | Simplified: point-to-point unicast, no EVPN, because Twinet links are strictly 2-endpoint |
| Namespace-per-lab tenancy | Kathará Kubernetes backend | Realized as label-scoped tenancy + agent-side authz instead of K8s namespaces |
| config-tree-overlaid-into-device | Kathará `lab.conf` device folders | Kept as one of two config input modes |
| per-link bandwidth/delay/queue as pedagogy | mini-Internet | Kept verbatim, including the `compute_burstsize` rule |
| `save_configs` dump layout | mini-Internet | Kept as the submission interchange format |

**Deliberately not adopted:** Kubernetes. It would add an enormous operational
dependency (control plane, CNI, Multus, a custom CNI plugin) for a workload that
is a static, long-lived, hand-placed topology. Kathará's own Megalos notes that
its CNI "does not work on managed clusters" and that volumes land on whichever
worker the pod is scheduled to — both disqualifying for this use case. Twinet's
agent is a few thousand lines and has exactly the semantics we need. (A
Kubernetes backend remains possible later behind the same `Runtime` interface
if someone wants it.)
