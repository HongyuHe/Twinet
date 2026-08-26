# 03 — Topology model

> **Documentation status: shipped model surface.** Examples in this document
> describe fields validated and expanded by the current source. They are not a
> claim that every example has passed a live-cluster acceptance run; measured
> evidence is limited to [09](09_status.md).

## One authored model, expanded graph

A lab is authored as YAML (`Lab` plus `ASTemplate` documents) and expanded into
concrete devices, interfaces, links, service replicas, placement groups, and
rendering inputs. `twinet validate --json` validates a lab and reports the
expanded statistics; the documentation gate runs that source-built command for
every bundled example.

The model owns:

- defaults, kinds, resource **requests**, and runtime limits;
- deterministic addressing and link identifiers;
- AS templates, peerings, services, access, placement, and state policy;
- the provisioning contract that distinguishes platform-owned configuration
  from student-owned configuration; and
- the expected/reference configuration used by rendering and grading.

`requests` reserve a host scheduling share; `cpus`, `memory`, and `pids`
remain hard container burst limits. FRR routers have a primary shell and an
internal control sidecar, so capacity reporting and admission count both
explicitly. `placement.convergence.max_concurrent` queues control-plane start
bursts instead of treating peak startup CPU as an idle reservation.

Deterministic derivation avoids duplicate allocation ledgers. It does not erase
durable state: student snapshots, topology records, lease/fence data, event
journals, and replica acknowledgements are persisted by the node state store.

## Interior generators

The model's shared generator registry contains:

| Kind | Meaning |
|---|---|
| `explicit` | Legacy routers and links written in the template |
| `ring` | Generated ring, optionally with a hub |
| `two-tier` | Generated core/edge graph |
| `clos` | Generated spine/leaf graph, optionally with leaf hosts |

An omitted `interior:` is `explicit` for compatibility. Generated interiors
become ordinary devices and links after expansion. A `distributable: true`
Clos can expose a spine group and leaf-with-host groups to placement; ordinary
ASes remain atomic. Rubrics can declare supported interior kinds and reject a
mismatch before grading.

The exact registry values are source-generated in [09](09_status.md). A
generated interior being available in the model is **not** a measured
three-node deployment acceptance claim.

## Network operating systems

Routers default to FRR when no `nos:` is selected. FRR and BIRD are registered
providers, and a provider owns rendering, apply/readiness, state collection,
configuration capture and load, save, restore, and the BGP route refresh used
as a session-liveness witness.

Validation derives requested capabilities from the topology and refuses a
provider that does not declare them. The BIRD provider deliberately supports a
smaller feature set than FRR: it does not claim Twinet support for BIRD
MPLS/LDP, VRF, multicast, DHCP, RPKI, or tunnels. Treat a manifest using BIRD
as source-supported only unless a specific measured result is recorded in
[09](09_status.md).

### BIRD in a student-owned AS

A student AS may declare `nos: bird`. `twinet save` captures BIRD's own
configuration file, the archive manifest records `bird` for that member and the
signature covers it, and `grade batch`/`restore` install it with
`birdc configure` rather than FRR's reload tool. An archive whose recorded NOS
does not match the device is refused by name; an archive that records no NOS at
all is accepted only for FRR, which is what every archive written before the
field existed contains.

What a BIRD student AS is graded on is narrower, and the report says so per
question rather than quietly shrinking a denominator:

| Rubric area | BIRD student AS |
| --- | --- |
| `l3.addressing_matches_plan`, `l2.vlan_isolation`, `dataplane.*`, `tunnel.sixin4` | assessed; kernel and probe evidence is vendor-neutral |
| `ospf.full_adjacency` | assessed, including the dead-timer liveness witness, which BIRD publishes in `show ospf neighbors` |
| `ospf.ecmp_paths` | assessed; the provider attributes each kernel route to the BIRD protocol that produced it, because Linux records only `proto bird` |
| `bgp.*`, `policy.gao_rexford`, `policy.no_transit_for_peers`, `policy.transit_for_customers` | assessed; BIRD's per-channel `Routes:` and route-change statistics supply the prefix and update counters, and `birdc reload in all` is the route refresh |
| `policy.traffic_engineering` | assessed from the kernel probe; the daemon-table second opinion is recorded as reduced evidence and marks the question for review |
| `ospf.subnets_advertised`, `config.no_forbidden_ospf`, `policy.ixp_communities` | reported `unsupported`: each concludes from FRR configuration text or FRR's OSPF route classes |
| `rpki.*`, `multicast.*`, `mpls.*`, `vpn.*` | reported `unsupported`: the BIRD provider declares none of those features |

An `unsupported` check is excluded from the question's weighting, exactly like a
check that could not run, and always marks the question `needs_review` with a
note naming the NOS. It is never a zero and never silently absent.

## Services, endpoints, and state policy

Services can declare a replication policy. The current model supports
`singleton`, `per-node`, fixed `replicas`, and `sharded` modes; replica identity
and attachment selection are deterministic. Endpoint policies support
multi-endpoint access/web arrangements rather than treating a front node as a
required singleton.

`state:` controls durable capture, replication factor, failure domains, and
fail-closed behavior. Clustered defaults and validation make a one-copy
configuration explicit rather than silently equating it with replicated state.
The runtime verifies state/replica evidence at destructive and migration
boundaries; operational acceptance remains scoped by the evidence in
[09](09_status.md).

## Behaviours, hijacks, and multicast

`behaviours:` is an implemented, reversible teaching-perturbation surface.
The model maps `bgp-hijack` to the `bgp_hijacking` fault implementation and
`link-down` to `link_down`. An instructor can inspect and control declarations
with:

```sh
twinet behaviour list
twinet behaviour start NAME
twinet behaviour stop NAME
twinet behaviour status
```

The RPKI/hijack path is therefore not described as an unimplemented scripted
scenario. Its actual exercise and fault coverage are separately documented in
[09](09_status.md) and [10](10_fault_injection.md).

Multicast is also modeled explicitly: an AS can request the PIM sparse-mode
exercise, and the FRR renderer/check registry has multicast support. The
bundled `examples/multicast` fixture is source-validated by the documentation
gate. Only the measured discrimination evidence stated in [09](09_status.md)
is a live result.

## Compatibility boundary

`twinet save` and `twinet restore` use Twinet's archive format: configuration
and replayable device scripts plus integrity/topology metadata. A legacy
`save_configs.sh` directory-layout exporter is not claimed as shipped.

Likewise, no importer from the predecessor platform's positional text files is
claimed here. Historical proposals for an importer, a third NOS, or additional
topology forms are targets only when labelled as such in
[07 — Roadmap](07_roadmap.md).
