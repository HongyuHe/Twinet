# 02 — Architecture

## 1. Overview

Twinet is two Go binaries and nothing else.

```
                     ┌──────────────────────────────────────────────┐
   operator ────────▶│  twinet   (CLI / control plane, stateless)   │
   TA / autograder   │  parse → validate → expand → IPAM → place    │
                     │  → plan (DAG) → dispatch → reconcile         │
                     └───────┬──────────────┬──────────────┬────────┘
                             │ gRPC/mTLS    │              │
              ┌──────────────▼───┐  ┌───────▼──────┐  ┌────▼─────────┐
              │ twinetd @ node-0 │  │ twinetd @ .1 │  │ twinetd @ .2 │
              │  runtime (docker)│  │              │  │              │
              │  netns / veth    │  │              │  │              │
              │  vxlan / tc      │  │              │  │              │
              │  exec broker     │  │              │  │              │
              │  probe engine    │  │              │  │              │
              └──────────────────┘  └──────────────┘  └──────────────┘
                       │                    │                 │
                  containers           containers        containers
                       └──────── VXLAN overlay (10 GbE) ──────┘

   students ──ssh──▶ twinet-gateway (a mode of twinetd) ──exec──▶ any device
```

- **`twinet`** — the CLI and the entire control plane. Stateless: every
  invocation re-derives the desired state from the manifest and the observed
  state from the agents. Also embeds the optional web server and the grader.
- **`twinetd`** — the node agent. The only long-running privileged process.
  Owns containers, network namespaces, veths, VXLAN tunnels, `tc` qdiscs, the
  exec broker (for `twinet attach`/`exec` and student SSH), and a local probe
  engine (ping/traceroute/BGP-state collection executed near the containers
  rather than centrally).

There is deliberately **no database and no message broker**. See §4.

## 2. Why Go

| Requirement | Consequence |
|---|---|
| "Easy to deploy" | One static binary per role; `scp` + `systemd` unit. No pip/venv/conda on 20 machines. Compare: the current platform needs Python, bash 4+, OVS on the host, `uuidgen`, `bc`, `lsb_release`, and a specific `ip` version. |
| "Easy to maintain" | A typed model with a compiler; refactors are mechanical instead of `grep`-and-pray across 225 shell files. |
| Massive parallelism | Goroutines + `errgroup`; deploying 2,000 containers and grading 100 students are both fan-out problems. Python's GIL and bash's `&` are why the current system is slow. |
| Netns/netlink/tc/VXLAN | `vishvananda/netlink` and `containernetworking/plugins/pkg/ns` give first-class, race-free access. The current `_connect_utils.sh` shells out to `ip`, and needs a `trap` to remove `/var/run/netns` symlinks on 6 signals. |
| Precedent | containerlab is exactly this design and is production-proven. We adopt its low-level wiring approach (see [04](04_networking_and_scaleout.md)). |

Python remains welcome for *course content* (grading rubrics can call out to
scripts), but not for infrastructure.

## 3. Package layout

```
cmd/
  twinet/            # CLI (cobra): up, down, deploy, destroy, redeploy, inspect,
                     #   exec, attach, save, restore, graph, validate, gen,
                     #   grade, serve, node
  twinetd/           # node agent
internal/
  model/             # typed topology: Lab, AS, Device, Iface, Link, Service…
  manifest/          # YAML load, merge, schema validation, error aggregation
  expand/            # template instantiation: AS templates → concrete devices
  ipam/              # addressing-plan evaluation, CIDR helpers, conflict checks
  alloc/             # deterministic allocation: VNI, MAC, port, container name
  place/             # placement of ASes onto nodes (bin-pack + constraints)
  plan/              # deployment DAG, stages, wait-for, workers
  reconcile/         # observed vs desired diff → minimal apply plan
  runtime/           # ContainerRuntime iface + docker impl (+ fake for tests)
  netx/              # veth, netns, vxlan, tc/netem, bridge, MTU, altnames
  agent/             # twinetd server: gRPC handlers over runtime + netx
  client/            # typed gRPC client used by CLI, web, grader
  svc/               # built-in services: dns, matrix, lg, rpki, ixp, meas, vpn
  access/            # SSH gateway, identities, authz, session audit
  grade/             # grading engine: probes, checks, rubric, reporting
  web/               # embedded web UI (Go templates, no Node build step)
  obs/               # slog setup, Prometheus metrics, event stream
api/twinet/v1/       # protobuf definitions
images/              # Dockerfiles for twinet-router/host/switch/ixp/…
examples/            # cos461/, advnet-mpls-vpn/, advnet-multicast/, demo/
test/e2e/            # end-to-end suites
docs/
```

Target: **under 15,000 lines of Go for the core** (excluding generated
protobuf, tests and images) — less than half the current platform's glue, while
doing strictly more.

## 4. State model: deterministic derivation, not a database

The single most important architectural decision. Twinet has **no state store**
because every allocated resource is a pure function of the manifest.

```
desired state   := f(manifest)                       # pure, reproducible
observed state  := g(container labels across agents) # queried live
apply plan      := diff(desired, observed)           # minimal convergence
```

**Deterministic allocation.** For each resource class there is a total function:

| Resource | Derivation |
|---|---|
| Container name | `twinet-{lab}-{as}-{device}` (also the hostname) |
| Interface name | declared in the template, e.g. `ATL-L2.10`, `port_HOU`, `host` |
| Link subnet | evaluated from the `addressing:` plan expressions |
| VXLAN VNI | `fnv1a64(lab ‖ linkID) mod (2^24 − 4096) + 4096`, with an explicit collision-resolution probe order recorded in the plan |
| MAC | `02:00:` ‖ first 4 bytes of `fnv1a(lab ‖ device ‖ iface)` (locally administered) |
| SSH/service ports | `basePort + ASN` (configurable), or gateway-only mode with none |
| Netns name | the container's PID is looked up live, never cached |

**Labels as observed state.** Every object Twinet creates is labelled:

```
twinet.lab=cos461-f25      twinet.as=12         twinet.device=ATL
twinet.kind=router         twinet.owner=group12 twinet.node=node-1
twinet.manifest-hash=9f3c… twinet.role=student  twinet.link-id=…
```

`twinet inspect` is a label query fanned out across agents — it needs no local
files and works from any machine with the manifest. Orphaned veths carry an
`altname` derived from the link ID so cleanup is possible even if a container
died.

**Consequences.** A controller crash is a no-op. `twinet deploy` is idempotent.
A node that reboots is repaired by re-running deploy, which recreates only that
node's objects. There is no `docker_pid.map` to go stale and no `groups/`
directory to drift.

The only durable on-disk artifacts are the **lab directory** (per-device
rendered configs, saved student configs, TLS material, DNS zones) — which is
data the operator or student owns, not control-plane bookkeeping — and an
optional append-only event log for auditing.

## 5. Runtime abstraction

```go
type Runtime interface {
    PullImage(ctx, ref string, policy PullPolicy) error
    Create(ctx, spec *ContainerSpec) (id string, err error)
    Start(ctx, id string) error
    Stop(ctx, id string, sig Signal) error
    Remove(ctx, id string) error
    List(ctx, filter LabelFilter) ([]Container, error)
    NSPath(ctx, id string) (string, error)   // /proc/<pid>/ns/net
    Exec(ctx, id string, cmd *ExecCmd) (*ExecResult, error)
    CopyTo(ctx, id, dst string, r io.Reader) error
    Events(ctx, filter LabelFilter) (<-chan Event, error)
    Health(ctx, id string) (Health, error)
}
```

Implementations: `docker` (default), `fake` (in-memory, for unit tests and for
running the full planner in CI without root). The interface is deliberately
narrow — wiring is *not* a runtime concern, it is `netx`'s job, so a future
`podman`/`containerd` backend is ~300 lines.

## 6. Deployment pipeline

```
manifest ──▶ load+merge ──▶ validate ──▶ expand ──▶ ipam ──▶ alloc ──▶ place
                             (all errors        (templates→
                              at once)           devices)
                                                                       │
   ┌───────────────────────────────────────────────────────────────────┘
   ▼
plan (DAG)  ──▶  reconcile(observed)  ──▶  dispatch to agents  ──▶  verify
```

**Stages** (borrowed from containerlab, generalised): each device passes through
`image → create → wire → configure → healthy → ready`. Dependency edges come
from three sources: explicit `wait-for` in the manifest, implicit ordering
(a link needs both endpoints created; an IXP route server before its peers'
sessions are checked), and service dependencies (Krill CA up before per-AS
child CAs are provisioned).

**No sleeps.** Where the current platform writes `sleep 60`, Twinet defines a
*readiness predicate* and polls it with backoff:

| Instead of | Twinet waits for |
|---|---|
| `sleep 60` after Krill | Krill `/api/v1/authorized` returns 200 **and** the root CA is published |
| `sleep 60` for BGP | every configured session in `show bgp summary json` is `Established` **and** the RIB has been stable for `N` consecutive polls |
| `sleep 1` before `tc qdisc add` | the interface exists in the target netns (netlink confirms) |

This is also the mechanism the grader reuses for convergence detection, which
is where the ~10× grading speedup comes from.

**Failure semantics.** A failure in one AS marks that AS `degraded` and does not
abort the run; `twinet deploy` reports a per-AS status table and exits non-zero.
Re-running converges only what is missing.

## 7. Diff and converge

`twinet deploy` on an already-running lab computes a minimal apply plan rather
than recreating everything (the current platform's only option is
`cleanup.sh` + full rebuild, or the 1,011-line `restart_container.sh`).

Change classes, in increasing order of disruption:

| Class | Example | Action |
|---|---|---|
| `live` | link delay/bandwidth change | re-apply `tc` in place |
| `config` | service config template changed | rewrite file, reload daemon |
| `rewire` | link added/removed | create/delete veth or VXLAN only |
| `restart` | env/sysctl change | stop+start container, re-wire |
| `recreate` | image or kind change | remove + create |

`--dry-run` prints the plan; `--only as=12` scopes it. This makes "restart one
student's router without touching the other 99 groups" a one-liner, and makes
mid-semester topology tweaks safe.

## 8. Security and privilege separation

The current platform runs everything as root and gives students root in a
container that shares a host bridge with 99 other groups.

Twinet:

- `twinetd` is the only privileged component (needs `CAP_NET_ADMIN`,
  `CAP_SYS_ADMIN` for netns, and the Docker socket). It runs under systemd with
  a hardened unit.
- `twinet` (CLI) is unprivileged; it authenticates to agents over **mTLS** with
  a lab-scoped certificate. TAs get a cert scoped to their labs.
- Students never touch the Docker socket or the host. They reach a **gateway**
  (a mode of `twinetd`) over SSH, authenticate with a per-group key or password,
  and are dropped into a restricted menu/shell that can only `exec` into devices
  carrying `twinet.owner=<their group>`. Authorization is enforced agent-side,
  not by network segmentation.
- Every exec is audit-logged (who, when, which device, argv).
- Per-AS resource quotas (CPU shares, memory, pids) are declared in the
  manifest and enforced by the runtime, so one group cannot starve the class.

## 9. Observability

- **Structured logging** (`log/slog`, JSON) from both binaries.
- **Prometheus metrics** from agents: container states, link states, deploy
  durations, probe results, per-AS BGP session counts, matrix cell states.
- **Event stream**: `twinet events` tails a merged event feed (container
  lifecycle, link up/down, BGP session flaps, student logins) — replaces
  `setup_network_logging.sh` and the "history" container.
- **Time-series snapshots**: the matrix and looking-glass history are just
  periodic structured snapshots on disk, which the web UI replays. This
  subsumes the `history` container and `make_gif.py` (headless Chrome +
  gifsicle) with a few hundred lines of Go.

## 10. Testing strategy

| Level | Scope | Runs |
|---|---|---|
| Unit | model, manifest validation, IPAM expressions, allocation determinism, placement, DAG scheduling, reconcile diffs | `go test`, no root, seconds |
| Integration | full planner against the `fake` runtime; asserts the exact set of containers/links/tc rules that *would* be created for the COS-461 manifest | `go test`, no root |
| E2E (single node) | deploy the 12-AS demo on one machine, assert OSPF/BGP converge, run the grader against a golden config, destroy | CI with Docker |
| E2E (cluster) | 2-node deploy, assert cross-node links pass traffic with correct shaping | nightly / manual on the cluster |
| Scale | 100-AS deploy across 3 nodes, measure wall-clock and resource use | milestone gate |

Golden-file tests over the *rendered* FRR configs, DNS zones and IXP configs
protect against regressions in template changes — this is the class of bug that
currently reaches students.
