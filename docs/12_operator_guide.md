# 12 — Operator guide: a teaching cluster from three clean machines

> **Documentation status: shipped commands only.** Every command in this guide
> exists in this source tree and is checked by
> `TestEveryDocumentedCommandExists` and `TestEveryDocumentedFlagExists`. This
> is a runbook, not evidence: no timing, capacity, or success claim is made
> here. Measured results live only in
> [09 — Measurements](09_status.md#measurements).
>
> **Nothing in this guide prints a secret.** No step echoes a token, a private
> key, or a student credential, and none is written into a systemd unit, a
> shell history, or a command line. Where a secret has to exist, it is created
> directly into a root-only file.

This guide takes an operator from three clean Linux machines to a running,
graded, and safely removed COS-461 mini-Internet. Read it in order the first
time: each section states what it verifies before the next one depends on it.

## 1. What you will end up with

- Three nodes — `node-0`, `node-1`, `node-2` — each running containerd and one
  `twinetd` node agent, mutually authenticated with TLS 1.3.
- A controller machine (a laptop or `node-0` itself) holding the manifest, the
  cluster PKI, and the `twinet` binary.
- The bundled [`examples/cos461`](../examples/cos461) lab deployed across the
  three nodes, graded against its rubric, and removed without leaving overlay
  objects behind.

Roles are separate on purpose: the controller holds the CA and the manifest,
and the nodes hold only what an agent needs. The controller may be one of the
nodes; nothing in the design assumes it is.

## 2. Prerequisites

| Requirement | Where | Why it is required |
|---|---|---|
| Linux with systemd, root or passwordless `sudo` | every node | The agent creates network namespaces, moves interfaces between them, and builds overlays |
| containerd with its socket at `/run/containerd/containerd.sock` | every node | The runtime the bundled labs declare; see [§9](#9-the-runtime-contract) for Docker or Podman |
| One routed underlay address per node, reachable from every other node | every node | VXLAN tunnels are sourced from it |
| Underlay MTU at least the lab MTU + 50 bytes | every node | VXLAN encapsulation; [`twinet node check`](#6-check-the-cluster-before-you-deploy) refuses a lab that would not fit |
| TCP port 7200 reachable between controller and nodes | every node | The agent API |
| `ssh` and `scp` to each node as root | controller | Bootstrap copies binaries and certificates |
| `curl` and `python3` | controller | The generated bootstrap script verifies agent health with them |
| Go 1.25 and `make` | controller | Builds the binaries that are rolled out |

Most bundled labs set a 1450-byte link MTU, which needs a 1500-byte underlay;
`examples/demo` asks for 1500 because it is a single-node lab with no tunnels
to encapsulate. The reason the cluster labs say 1450 rather than 9000 is an
environment finding on the documented cluster, recorded in
[09 — Environment findings](09_status.md#environment-findings). `twinet node
check` is what tells you whether yours fits, and it names the MTU to use when
it does not.

Two facts are worth knowing before you start, because they contradict the usual
expectation of a single static binary:

- Twinet has host dependencies. It needs a container engine, a kernel that
  supports VXLAN and VLAN-filtering bridges, and container images.
- The agent runs as root with the host network namespace. That is what it is
  for; [09](09_status.md) records exactly what is and is not claimed about it.

## 3. Build the binaries

On the controller:

```sh
git clone <this repository> twinet && cd twinet
make build
```

`make build` produces `bin/twinet` (the controller CLI), `bin/twinetd` (the
node agent), and `bin/twinet-init` (the PID 1 used by the containerd backend).
The bootstrap in [§5](#5-install-the-agents) copies `bin/twinetd` and
`bin/twinet-init` to the nodes, so build before you bootstrap.

The build is byte-reproducible: the same source and toolchain produce the same
binaries, whatever the clock says. The embedded date is the source's, taken
from `SOURCE_DATE_EPOCH` or the commit, not the moment of the build, so
provenance can be checked rather than only asserted — `twinet version` prints
the version, the commit, and the content-addressed source digest that
identifies exactly what was compiled. `bash scripts/test_reproducible_build.sh`
builds twice and compares.

Container images are pulled from a registry by each node when a lab is
deployed. Build them yourself only if you are changing them:

```sh
make images
```

Every bundled example is already in `release` mode and carries a
topology-bound `images.lock.json`, so the documented deployment pulls the
published registry digests rather than whatever a mutable tag means that day.
After changing an image, publish one immutable commit tag and regenerate every
affected lock with `twinet images lock`; verify it with `twinet images verify`
before deployment. The format and grading provenance are described in
[09](09_status.md) and [`docs/06_grading.md`](06_grading.md).

## 4. Describe the cluster in the manifest

The manifest is the only place that says which machines a lab uses. Edit
`placement` in [`examples/cos461/twinet.yaml`](../examples/cos461/twinet.yaml)
so the node names, agent addresses, and underlay addresses are yours:

```yaml
placement:
  strategy: spread-by-as
  runtime: containerd
  nodes:
    - {name: node-0, addr: "10.0.1.1:7200", underlay_ip: 10.0.1.1, front: true}
    - {name: node-1, addr: "10.0.1.2:7200", underlay_ip: 10.0.1.2}
    - {name: node-2, addr: "10.0.1.3:7200", underlay_ip: 10.0.1.3}
```

- `name` must match the `-node` value the agent is started with.
- `underlay_ip` is the VTEP source address. Add `underlay_dev` when a node has
  more than one candidate interface and you want the choice pinned.
- `front: true` marks the node that publishes the web UI, the SSH gateway, and
  the shared services.
- `runtime` states the engine. It is declared rather than inherited; see
  [§9](#9-the-runtime-contract).
- `strategy` decides how autonomous systems are distributed. Both `pack-by-as`
  and `spread-by-as` keep each autonomous system whole on one node, so no
  internal link becomes a tunnel; they differ in how much imbalance they will
  accept to keep peering neighbours together. The canonical lab ships
  `spread-by-as` because this walkthrough promises a lab deployed across the
  three nodes: under `pack-by-as` a cluster with plenty of headroom put all
  twelve autonomous systems on `node-0`, which exercises no overlay path and
  queues every graded `exec` behind one agent. Confirm with
  `twinet -m examples/cos461 inspect --placement`. Changing the strategy of a
  lab that is already running does not move anything by itself: the placement
  record is honoured so a redeploy never rebuilds the containers a student is
  working in. `twinet -m examples/cos461 deploy --rebalance` is the explicit
  way to recompute, and it does rebuild them.

Check the file before it is used for anything:

```sh
twinet -m examples/cos461 validate
```

Validation reports every problem in one pass, including a runtime selection the
registry cannot run and a manifest that declares no runtime at all.

## 5. Install the agents

### 5.1 The controller token

Every agent requires a shared controller token *in addition to* its client
certificate. Create it directly into a root-only file, without printing it:

```sh
sudo install -d -m 0700 /etc/twinet
umask 077
printf 'TWINET_TOKEN=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/twinet/agent.env >/dev/null
sudo chmod 0600 /etc/twinet/agent.env
```

Any source of 32 random bytes will do; the point is that the value goes
straight into a root-only file and is never printed.

Bootstrap reads the token from that file and copies the file itself to each
node. It is never embedded in the generated script or in the systemd unit,
because a unit is world-readable and every account on the node could then act
as the controller.

For interactive commands, export it from the file rather than typing it:

```sh
export TWINET_TOKEN=$(sudo sed -n 's/^TWINET_TOKEN=//p' /etc/twinet/agent.env)
```

Prefer `TWINET_TOKEN` over `--token` on every command: an argument is visible
in the process table to every user on the machine.

### 5.2 The cluster PKI

```sh
export TWINET_PKI="$HOME/.twinet/pki/cos461"
install -d -m 0700 "$TWINET_PKI"
twinet -m examples/cos461 node pki --dir "$TWINET_PKI"
twinet -m examples/cos461 node pki peer node-0 --pki "$TWINET_PKI"
twinet -m examples/cos461 node pki peer node-1 --pki "$TWINET_PKI"
twinet -m examples/cos461 node pki peer node-2 --pki "$TWINET_PKI"
```

This issues a cluster CA, one server certificate and key per node, one
controller certificate, and one replication-only peer certificate per node. Keep
that directory off any shared filesystem: the CA key alone lets an attacker mint
a controller certificate for the cluster. Omitting `--dir` writes it into the
lab's own `.twinet/pki/` instead, which [`.gitignore`](../.gitignore) excludes
from version control for the same reason.

Peer certificates are deliberately separate from server certificates: a peer
identity may only replicate state, so a stolen one cannot deploy or destroy.
Rotate either with `--rotate`, and replace a whole CA with `--force`, which
invalidates every certificate already deployed.

Teaching assistants get their own scoped identity rather than the controller's:

```sh
twinet -m examples/cos461 node pki credential ta-alice \
  --pki "$TWINET_PKI" --lab cos461 --action observe --action exec
```

The certificate carries the lab and the actions it may perform. The shared
token cannot broaden it.

### 5.3 Bootstrap

`twinet node bootstrap` prints an idempotent script instead of running one, so
you can read exactly what will execute as root on your machines:

```sh
export TWINET_TOKEN_FILE=/etc/twinet/agent.env
twinet -m examples/cos461 node bootstrap \
  --pki "$TWINET_PKI" --token-file "$TWINET_TOKEN_FILE" > bootstrap.sh
less bootstrap.sh
bash bootstrap.sh
```

For each node the script installs the runtime if it is missing, installs
`twinetd` and `twinet-init`, copies the certificates with restrictive
permissions, writes a systemd unit that reads the token from
`/etc/twinet/agent.env`, starts the agent, and then verifies it: the reported
backend, engine version and socket, the protocol/renderer/state contracts, the
image cache, the state store, the underlay address and MTU, and reachability of
every underlay peer. It refuses to generate a remotely reachable agent that has
only a bearer token.

To roll out a rebuilt agent later — an upgrade rather than a first install —
use the rollout script, which verifies that each node ends up running exactly
the binary that was just built:

```sh
./scripts/deploy_agents.sh --pki "$TWINET_PKI" --bind-underlay \
  --runtime containerd node-0 node-1 node-2
```

`--bind-underlay` narrows the agent from every interface to the fabric address
it already announces as its own.

Exactly one `twinetd` may own a host network namespace. A second process on
another API port or in another containerd metadata namespace is **not**
isolated: both still create and remove root-namespace veths, bridges and
VXLANs. Ownership is claimed from the kernel's own identity for the namespace —
the inode behind `/proc/self/ns/net` — so two agents in one namespace always
contend and two agents in genuinely separate namespaces never do. There is no
path to override: an agent that is refused is told which namespace it lost and
which process holds it. An agent in the host's root namespace also holds
`/run/twinet/agent.lock`, the fixed path older builds used, so a stale one of
those is refused too, and the rollout script refuses any alternate `twinetd*`
process before changing a node. `-host-lock-dir` moves only the directory
holding that record, for a host whose `/run` is unusual; it cannot change who
contends with whom.

## 6. Check the cluster before you deploy

```sh
twinet -m examples/cos461 node status
twinet -m examples/cos461 node check
```

`node status` prints one row per node: state, source build, runtime and engine
version, contract versions, socket, allocatable and reserved inventory, load,
back-pressure, image cache, underlay address, peer replication, container
counts, the lab it is holding, and any recovery in progress. It exits non-zero
when a node is unreachable *or* merely degraded — a version-skewed agent, a
grading hold, or a busy node are each something the next command will refuse,
and being told afterwards is not the same as being told.

The inventory columns distinguish three states, because collapsing them
misleads in opposite directions. A number is a measured budget. `unknown` means
the agent could not read that dimension, and strict admission refuses it rather
than guess. A term such as `unlimited-fd` means the kernel imposes no ceiling
at all — a host with `fs.file-max` at `LONG_MAX` was once reported as having
8301034833169298227 allocatable file descriptors — and that dimension simply
does not constrain admission. Declare a `placement.nodes[].capacity` if you
want an unbounded dimension bounded by policy.

`node check` compares the underlay MTU against the lab's link MTU plus VXLAN
overhead and names the MTU to use if it does not fit. Run it whenever the
underlay changes, not only once.

Both accept `--json` for scripting.

## 7. Deploy the canonical COS-461 lab

```sh
twinet -m examples/cos461 deploy
```

Deploy is idempotent: it compares the manifest against what is running and
creates only what is missing, so it is safe to re-run after a partial failure,
a reboot, or a topology edit. Strict admission runs first — an assignment that
does not fit the live allocatable inventory is refused before anything is
created, and `--overcommit` is the audited exception rather than a silent
fallback.

On a first deployment, each assigned node pulls the images it needs. If only
some of the nodes assigned the same **mutable tag** already cache it, Twinet
refuses: the missing nodes could otherwise pull a newer build under the same
name. Preload that image through the selected runtime on the nodes named by the
error, or use a digest-pinned image lock. A cache on a node that will not run
that image is intentionally outside the coherence boundary.

A **digest-pinned** reference — what `images.mode: release` produces, and what
every bundled example deploys — is not subject to that refusal. The reference
names one manifest, so a node that is missing it can only pull that manifest or
fail, and unequal caches after a partial run are safe. The proof is taken after
the pull rather than before it: every assigned node reports the digest it
actually has, and the deployment refuses to commit — and rolls back — unless
each one is the locked manifest. A reference that claims a digest but does not
carry a well-formed one (64 lower-case hexadecimal characters), and a node whose
cache answers a pinned reference with a different manifest, are both refused
before anything is created; clear that image on the node named and re-run.

Useful variations:

```sh
twinet -m examples/cos461 deploy --dry-run    # plan only, no mutation
twinet -m examples/cos461 deploy --solve      # also apply the reference solution
twinet -m examples/cos461 deploy --prune      # remove what the topology no longer wants
```

`--solve` is the platform smoke test: the reference solution should score full
marks against its own rubric, and anything less is a Twinet defect rather than
a student's.

Look at what you deployed:

```sh
twinet -m examples/cos461 inspect --placement
twinet -m examples/cos461 exec as3/ATL -- ip -br addr
twinet -m examples/cos461 web
```

Students reach their own devices through the SSH gateway. Create one credential
per student AS, then serve:

```sh
twinet -m examples/cos461 gateway roster init
twinet -m examples/cos461 gateway roster list
twinet -m examples/cos461 gateway run
```

`roster init` stores only a salted verifier and writes the passwords once, to a
separate file, for distribution. Neither file belongs in version control, and
[`.gitignore`](../.gitignore) excludes both. `roster list` shows who is
enrolled, not what their password is.

## 8. Grade

Check the rubric first, then grade:

```sh
twinet grade validate examples/cos461/rubric/cos461.yaml
twinet -m examples/cos461 grade run --as 3 --out reports
```

`grade run` is a diagnostic: it reads the lab exactly as it is. Given no `--as`
it reads every student system, and it chooses for itself how many to read at
once:

```
$ twinet -m examples/cos461 grade run --out reports
grading 8 system(s), at most 3 at a time: node node-0 admits 28 concurrent
grading exec(s) and each grade needs up to 8 there
```

Every grade reads its own devices and its neighbours' through the node agent
that holds them, so the safe width depends on where the lab is placed, on the
exec budget each node advertises, and on how many systems converge on the same
staff routers and exchange route servers. The canonical lab packs onto one node
(`inspect --placement` shows it), so its eight systems are read a few at a time;
systems on independent nodes that share no router are read together. A node
that cannot be asked what it admits is assumed to have room for one system, and
the run says so.

`--parallel` overrides the derived width. It is an operator's decision to make,
and a value above what the cluster advertises is recorded next to the marks it
produced:

```
$ twinet -m examples/cos461 grade run --parallel 8 --out reports
AUDIT: grading 8 system(s) at --parallel 8, above the capacity-safe width of 3 …
```

Checks that then run out of time are still quarantined rather than marked:
overriding the width can waste a run, but it cannot turn an overloaded cluster
into a student's zero.

To mark a class, use one of the two fair modes:

```sh
twinet -m examples/cos461 grade class --out reports          # one submission at a time, in the class lab
twinet -m examples/cos461 grade batch --submissions submissions --out reports
```

`grade class` needs the lab deployed with `--solve`; it loads one submission at
a time and puts the reference back afterwards. `grade batch` gives each
submission its own disposable harness and does not touch the class lab. Both
hold the lab against automatic repair while a mark is being produced, and both
report a quarantine rather than a mark when the infrastructure — not the
submission — failed. Their relative costs are recorded in
[09](09_status.md#measurements); do not infer them from this guide.

Collect and replay student work with `twinet save` and `twinet restore`. Every
archive carries the topology hash it was written against, and an archive from a
different topology is refused rather than silently replayed against addresses
that have moved.

## 9. The runtime contract

One selection, stated in one place, overridable in one way:

| Layer | What it says | Wins over |
|---|---|---|
| `placement.runtime` | the lab's engine | the compatibility default |
| `placement.nodes[].runtime` | one node's engine | the lab's |
| `--runtime` / `TWINET_RUNTIME` | this invocation's engine, for every node | both of the above |
| `twinetd -runtime` | what the agent actually runs | nothing: a mismatch is refused |

Every bundled example declares `runtime: containerd`, so each one deploys
unmodified on the cluster this guide builds. A manifest that declares nothing
means `docker`, kept for manifests written before the runtime registry existed;
validation says so rather than leaving it to be discovered on a cluster that
does not run Docker.

To run any bundled lab on a Docker or Podman machine, state the engine instead
of editing the lab:

```sh
twinet --runtime docker -m examples/demo deploy
TWINET_RUNTIME=podman twinet -m examples/demo deploy
```

The override replaces the lab default *and* every per-node selection, so a lab
cannot end up half on one engine, and it is announced on standard error rather
than applied quietly. The controller still refuses to mutate a node whose agent
reports a different backend, so an override that does not match the cluster
fails before it creates anything.

### containerd namespace and socket

The containerd backend uses the native gRPC API in a metadata namespace of its
own, so Twinet's containers never share a namespace with anything else on the
host:

```text
twinetd -runtime containerd \
        -runtime-socket unix:///run/containerd/containerd.sock \
        -runtime-namespace twinet-<node>
```

Bootstrap and `scripts/deploy_agents.sh` write exactly those flags, defaulting
the namespace to `twinet-<node>`. Two consequences are worth remembering:

- Images pulled by Twinet live in that namespace. `ctr --namespace twinet-node-0
  images ls` sees them; a plain `ctr images ls` and `docker images` do not.
- `twinet-init` must be installed on the node, at `/usr/local/bin/twinet-init`
  unless `TWINET_INIT_BINARY` names another path. It is the PID 1 inside each
  container on this backend, and creating a container fails outright when it is
  missing or not executable. Bootstrap and the rollout script install it; a
  hand-written unit is the way to forget it.

## 10. Reconcile, repair, and recover

Agents subscribe to runtime lifecycle events and repair the affected device;
sampled audits are the backstop. When you want to drive that from outside:

```sh
twinet -m examples/cos461 node reconcile                      # bounded desired/observed pass
twinet -m examples/cos461 node reconcile --device as3/ATL     # one device
twinet -m examples/cos461 node controls --repair              # private FRR control sidecars
twinet -m examples/cos461 events --follow                     # what the cluster is doing, as it happens
```

`node controls` audits the private FRR control sidecar of every FRR router.
Its `NETNS` column is the one to read first:

| `NETNS` | What it means |
|---|---|
| `same` | the sidecar is provably in its router's network namespace |
| `SPLIT` | the sidecar is running in a **different** namespace from its router — the router has no control plane at all, whatever its daemon counts say |
| `UNKNOWN` | the namespace identity could not be read; the sidecar is reported degraded rather than assumed well |
| `wired`/`unproven` | the backend cannot prove inode identity, so only the interface evidence applies |

`SPLIT` is what a router looks like after its PID 1 has been killed and the
runtime has brought the task back: the container gets a **new** network
namespace, the sidecar that was created against the old task keeps running in
the old one, and every question asked inside that sidecar — how many daemons,
is the vty socket alive, what is the running configuration — is answered
correctly about a namespace holding a loopback and no cables. `--repair`
rebuilds the sidecar in the router's current namespace, restarts its daemons
from the shared `/etc/frr`, and re-proves both identities. The student's router
container, and everything in it, is never touched. Event-driven and periodic
reconcile do the same thing without being asked, and an ordinary `deploy`
refuses to report a no-op while a sidecar is split or unprovable.

Rebuilding the sidecar restores the addresses too, and that is worth stating
because it depends on a daemon that is easy to overlook. A new namespace is
empty: the platform re-creates the cables, but an address a student configured
lives only in `/etc/frr/frr.conf`, and it comes back when FRR reloads that file.
Applying `interface X` / `ip address A/B` is `mgmtd`'s work, so a router without
`mgmtd` accepts the OSPF and BGP around those lines and refuses the addresses
with `mgmtd is not running` — leaving a router with every cable, every routing
daemon, a correct running configuration and no adjacency to anyone. `mgmtd` and
`staticd` are therefore started and checked like any other daemon, on every
backend; `twinet node controls` reports a router missing either of them as
degraded.

That covers the addresses a router's own configuration carries. On a teaching
deployment most of them are not in it. Where a course leaves `router_interfaces`
and `loopbacks` to the students — COS-461 does — the platform renders no
`ip address` line for those interfaces at all: the model carries the addresses
so the grader and `--solve` agree on what they should be, and the running lab
has them only because somebody configured them. Saving such a router splits it
in two, a `.conf` of protocol configuration and a `.sh` of the `ip` commands
that recreate the addressing, and that is exactly how it comes back from a
restore.

A namespace replacement is therefore not only a control-plane repair. The
namespace a device was last configured in is recorded beside the hashes that
decide whether it is current, and a device found in a different one is not
current: it is rewired, reconfigured, and then has its saved state replayed on
top, in that order, because an address cannot be put on an interface that does
not exist yet. Its links are rebuilt with it, because an address cannot be
replayed onto an interface that went with the namespace. Its neighbours on the
same node are replayed too — a veth is a pair and is rebuilt as one, so a
restarted router takes its neighbours' interfaces with it and they come back
bare — but only replayed: nothing restarted them, so their containers and their
other cables are left alone. Nothing captures over that state until the replay
has happened, so the pass that finds a restarted router cannot overwrite the
snapshot it is about to restore, and neither can a prune that is about to delete
an unreplayed container. A backend that cannot prove namespace identity is not
asked to: its containers are replaced rather than restarted when a task dies,
which the ordinary create path already restores through.

Automatic repair does the same, and for a while it did not. It does not run
through the deployment planner — an event-driven repair, a semantic-drift
repair, an operator's `node reconcile --force` and solved-reference recovery all
rewire one device directly — and rewiring one device deletes its neighbours'
ends of the cables between them. On a live three-node lab holding a restored
group submission, killing one router's PID 1 rebuilt that router, replayed its
addressing, rebound its sidecar, and left the three routers on the far ends of
its cables with interfaces that were up, carried no address, and formed no
adjacency; the repaired router had zero OSPF neighbours and the agent logged
`device repaired and its configuration put back`. Every automatic rewire now:

- **saves first.** Every affected device holding a student's work — the target
  and each same-node neighbour whose end of a cable is about to be deleted — is
  captured through the guarded capture funnel *before* anything is unplugged.
  The periodic snapshot may be an hour old, which is long enough for somebody to
  have addressed the interface that is about to go.
- **refuses rather than guesses.** A capture that fails, or a neighbour whose
  namespace this node cannot vouch for, stops the repair before any mutation and
  names the device and the reason. A namespace that is *provably* a replacement
  is a known loss, not an open question, so the device that was reported broken
  is never refused for the fault it was reported for.
- **puts the neighbours back.** After the wiring, each rebuilt neighbour's
  rendered contract is reapplied and its saved state replayed, after the
  target's. Their containers and their other cables are left alone.
- **asks each device's own mode.** A private grading harness is solved
  everywhere except the system under evaluation, so that system's work is saved
  and replayed and the solved routers around it are neither read nor written.
- **accounts for the device it was called about, too.** "Cannot be vouched for"
  means nothing on this node can say whether the namespace holds work that was
  never captured or an empty room somebody's name is still on. Having been
  reported broken is not evidence about what is inside, so the target is held to
  the same rule as its neighbours. Only a namespace that is provably a
  replacement — recorded identity, different live identity — is exempt.
- **copies what it saved off the node first.** The reading is the only record of
  interfaces that are about to stop existing, and the lab's replication factor
  decides how many nodes it has to be on. If it cannot get there, nothing is
  unplugged.
- **leaves a durable mark on everything it is about to empty.** The repair is
  not the only thing on the node that captures: periodic durability builds its
  own engine every few minutes, the CLI builds one, a second agent process
  builds one, and none of them knows a repair is halfway through. A neighbour's
  container never restarted, so its namespace identity is exactly what was
  recorded and every identity check calls a reading of it trustworthy — but what
  was in it has just been deleted. So every affected device is marked as owing
  its saved state back, inside the device, *before* the first interface goes;
  any other engine sees the marker and withholds that device's addresses,
  tunnels and bridge ports. A device that cannot be marked stops the repair
  before it starts.
- **writes down where it put the device back.** The namespace a replaced task
  landed in is one nobody recorded. The record is updated after the state is
  replayed and before the device is let go of; without that, every later capture
  would find a mismatch, call the namespace replaced and withhold the device's
  state indefinitely — repaired, reported repaired, and never backed up again.
  That the record can be *written* is proven before the repair starts, not
  assumed: the check republishes it exactly as it already stands, so a
  filesystem that has gone read-only or filled up since it was last written
  refuses the repair while every device is still working, rather than after the
  interfaces are gone and there is nowhere left to record where they came back.
  Each device's marker is cleared only after both of those have happened, so a
  repair that fails partway leaves the devices it did not finish withheld rather
  than overwritten.

A repair that refuses names the device and the reason, records it as a node
event, and reports it as a repair failure rather than as a rewire that broke
something — nothing was unplugged. A refusal that had already marked some
devices takes those marks back, and if one of them will not come back off it
names that device too: a container left carrying a stale mark is withheld from
every capture until something clears it, which is the same quiet, permanent
stop-being-backed-up the mark exists to prevent. A repair that failed partway
leaves the devices it did not finish marked as owing a restore, which withholds
their namespace-backed snapshots until a later repair or deploy replays them;
that is deliberate, and is why the failure is loud.

The comparison needs something to compare against, and the first deployment
after an upgrade has nothing recorded for any device. A device that is healthy
and stays healthy never configures, so it would never acquire a baseline and its
first restart would be invisible for ever. An apply therefore records the
namespace of every device whose namespace it can read and show to be *continuous*
with what the device is supposed to hold: every interface the platform's own
wiring put there is present, every address the platform renders onto them is on
them, and every stable object the state store last saved for the device is still
there. That last part is more than addresses. A VLAN sub-interface and a VRF
master are namespace objects in their own right — they are captured alongside the
addressing precisely because the addressing depends on them — and a tunnel and a
bridge port are the whole of what the other two snapshots are, so a switch whose
ports had lost every VLAN and a router that came back without its 6in4 tunnel are
refused as well. Routes are deliberately excluded: a routing daemon installs and
withdraws them constantly, and a route cannot exist without the interface,
address, or tunnel it runs over. Each further reading is made only when there is
something saved to compare it against and only on the kind of device it belongs
to, so no router is asked for its bridge ports and no host is asked for its
tunnels.

A snapshot that cannot be *read* is not a device with nothing saved. A body
whose digest does not match what was recorded beside it, a half-written pair of
files, a disk that is refusing reads — every one of those used to answer "no
saved state", which is the condition under which an empty namespace proves
continuous, so the one circumstance where the stored copy of a student's work is
already in question was the circumstance that let an empty namespace be recorded
as theirs. Only a snapshot that has genuinely never been taken counts as none;
anything else refuses.

Passing a semantic probe is deliberately **not** enough on its own. In platform
mode that probe skips every interface a student owns — the model carries their
addresses so grading and `--solve` agree about the answer, not because the
running lab is supposed to have them yet — a router is never asked for a default
route, and a device the audit already believes healthy is not re-read at all. A
student's router that restarted into an empty namespace last term passes all
three, and blessing that namespace would record the one place their work is *not*
as the place it lives. The proof is bracketed by the namespace identity read from
the backend before and after it, so a device that restarts while it is being read
is refused rather than credited with a reading of a namespace it had already
left. A plan records nothing — it decided nothing.

A device with no baseline whose namespace cannot be shown continuous is the
dangerous one, since it may have restarted weeks ago and its student's addressing
may exist only in the state store. It is repaired like any other drift, but it is
not given a baseline and its namespace-backed state is withheld from the store
until continuity can be shown again, so the emptiness is never filed over the
work. That withholding covers the device being *replaced* as well as the device
being left alone: a changed image or rendered file turns the semantic probe off,
and that is exactly the device about to be captured and destroyed. The one
exemption is a container this pass rebuilt from its image and replayed the store
into, where the namespace is new and its contents are known because the
deployment just put them there.

**This is established by the capture itself, not only by a deployment.** A
deployment is one of several things that write to the state store. The
durability timer captures every student-owned device every capture interval; a
destructive apply captures before it replaces anything; a destroy captures
before it removes the containers; a fresh state export captures before handing a
device to another node; recovery captures after a rollback. Each of those builds
an engine for the purpose, so none of them has observed anything and none of
them holds a deployment's findings — and on a live node it is usually the timer,
not a deployment, that reaches a restarted router first. Every capture therefore
establishes the same two facts before it writes: the namespace the device was
last configured in, read from the node's own record, and the identity of the one
it is in now. A namespace that is demonstrably not the recorded one, an identity
that cannot be read, and a container that is not running are all treated the
same way, because none of them is evidence that the namespace survived. A device
with no baseline has to prove continuity against what is saved before it may
overwrite it, which is also what happens if the record itself cannot be read —
losing the record is not a way through. The identity is resolved *after* the
namespace has been read, so a task replaced during the reading invalidates it
rather than being credited with it. Configuration files are captured either
way: they are on a filesystem, they survived, and withholding them would be a
different way of losing the same work.

Two paths used to write a capture without going through that API at all, and
both were paths where the container is about to stop existing. A device whose
specification changed is captured and then replaced; a device that left the
manifest, or moved to another node, is captured and then deleted. Both now go
through the same guarded write. The consequence for the second is worth stating
plainly, because it changes what a prune does: an orphan whose namespace was
*proven* to have been replaced is still removed — what is in it now demonstrably
is not the student's work, the saved copy was left alone, and leaving a moved
device running would have it announcing its prefixes from two places — while an
orphan whose namespace could *not* be accounted for is refused, named, and left
where it is, because this pass deliberately did not save what is in it and
removing it would destroy the only thing that could still answer the question.
Both keep the routing configuration. `twinet destroy` remains the way to say
that a lab is genuinely disposable.

The same policy now governs the first of those two paths, for the same reason:
the container is deleted immediately afterwards, so it is the last object that
could say what was in it. A device whose namespace was proven replaced is
rebuilt as before — that is what the guard exists to make safe — but a device
whose namespace could not be accounted for has its replacement refused, after
whatever was safe to keep has been kept. A capture that skips one doubtful
snapshot costs a deferred backup of state the store already holds; a
replacement that skips one destroys the evidence and then replays a copy that
may be older than the work, unreadable, or absent. A container that is stopped
when the replacement reaches it is a case of the first kind, not the second:
starting it to read its filesystem is what empties its namespace, so the loss
is recorded as one this pass caused rather than left as an open question, and
the device is rebuilt.

A prune reads the container in front of it. An orphan almost always still has
the name the manifest gave it — a device that moves to another node keeps its
container — so resolving one through the model looked right, and was not when
the two disagreed: a manifest that renames a device's container, or an older
container still running under the same identifier, sent the reading to the
*live* container and then deleted the leftover without ever looking inside it.

More than one container can claim one device, and there is one slot in the
store to hold it. A rename leaves the old container running under the same
identifier; an interrupted deployment leaves two; a moved device keeps its name
here while the manifest points elsewhere. Letting each of them write the slot in
turn files a dead container's reading as a live device's work. Letting none of
them write it and deleting them all is the same loss more quietly, because a
container that is not the authority may still hold the newest thing anybody
did, and two of them cannot be merged.

So the authority writes, and **every other claimant has to prove it has nothing
to lose before it is removed**. Authority comes from the topology and from
container identity, never from preference: a device the manifest still places
somewhere has exactly one container name, and the container carrying that name
is the authority for it. Where nothing establishes one — two containers for a
device the manifest has forgotten — there is no canonical source and every
claimant is held to the same proof rather than chosen between.

The proof is that the claimant's complete reading is the state already held for
the device: every kind, filesystem-backed routing configuration as much as
namespace-backed addressing, tunnels and ports, compared in the form a capture
writes and compared for presence as well as content. A claimant holding
something the store has nothing for, a claimant missing something the store
holds, any difference in any kind, a saved snapshot that cannot be read, and a
capture that only partly succeeded all refuse the removal, name the container,
the device and the difference, and leave the container where it is. Its reading
is never written over the authority's. An exact duplicate has nothing to lose
and is removed. `twinet destroy` remains the way to say that a lab is genuinely
disposable.

The same boundary refuses before reading when there is nowhere trustworthy to
put the result. A teaching-mode replacement or prune without a state store is
an error, not permission to delete the container, and a prune candidate without
a canonical device identifier is left alone because it cannot be assigned a
snapshot slot without risking another device's saved state. Internal FRR
control sidecars remain exempt: they own no independent student state and share
their routing files with the primary container.

### A solve is a transition, and both of its halves are destructive

On a single machine `deploy --solve` writes the reference answer over the
devices the manifest still places here, and, when it was asked to prune, removes
the containers the manifest no longer wants. The first half was preserved before
it ran and the second was not, because the prune is the deployment's last step:
a stale container that a course had dropped, still holding the group's
configuration, was captured by nothing at all until the moment it was deleted.

Both halves are therefore preserved before either of them runs. A
platform-to-solve deployment on one node captures every device the manifest
still wants **and** every container a requested `--prune` could later remove,
through the same guarded funnel and the same namespace and claimant checks, and
only then marks the lab as one that may hold the answer. Anything that cannot be
preserved refuses the deployment while the lab is still exactly as the students
left it: no reference command has run, no marker has been written, and the
containers are all where they were. The prune itself still happens after a
successful deployment, so `--prune` means what it has always meant.

What was preserved is written down beside the mode marker, in
`<manifest>/.twinet/solve-transition.json`, because the process that preserves a
container is not necessarily the process that removes it. If the reference plan
fails part way, the retry finds the lab marked `solve-pending` — a lab whose
containers must never be read as student work again, since some of them now hold
the answer — and removes exactly the containers that record covers, and nothing
else. The record names the lab, the node, the manifest hash it was taken
against, and each container with the device identifier it carried.

Everything else about that retry is a refusal, before it changes anything:

| What the retry finds | What it does |
| --- | --- |
| No record, or one that cannot be read | Refuses the prune and names the remedy |
| A first attempt that was not asked to prune | Refuses: nothing was preserved for these containers |
| A manifest edited since the record was written | Refuses: which containers are stale was decided against a different lab |
| A container the record does not cover | Refuses, names the container, removes nothing |
| A container now carrying a different device identifier | Refuses, names both identifiers |

One unprovable candidate stops the whole prune, as it does everywhere else on
this boundary: a lab with one stale container is a nuisance, and a lab that has
quietly eaten a group's configuration is not something an apology fixes. The way
out of any of them is to return the lab to teaching mode with `twinet deploy`,
which replays the preserved student state, and then to run the solve and its
prune again; or to finish the solve without `--prune` and leave the stale
containers where they are. `twinet destroy` remains the way to say that a lab is
genuinely disposable, and it goes on treating `solve-pending` as a lab that
holds the reference solution.

The mode is recorded only after every requested mutation has succeeded, and the
record of what was preserved is forgotten only after that. A crash in between
leaves a record describing a transition that has finished, which the next
deployment ignores; the other order would leave a pending marker with nothing to
prove what may be removed, and refuse a prune that had every right to run. A
prune of a lab that is already solved reads nothing and writes nothing, so a
repeated `deploy --solve --prune` never files the answer as anybody's work, and
`--only` is unaffected: a scope cannot say what the rest of the lab no longer
wants, so a scoped deployment does not prune at all.

Every device left in that state is reported. The node publishes them in its
apply response as `unproven_namespaces`, keyed by device with the reason for
each, and `twinet deploy` prints one `UNPROVEN NAMESPACE:` line per device and
exits non-zero:

```
  UNPROVEN NAMESPACE: node-1/as3/ATL: the saved address it was last seen with is not in it (addr inet lo 3.156.0.1/24)
```

This is a failure of the command rather than a note in the output, because
nothing else in a deployment's summary shows it. The devices are running, the
inventory matches, and the audited health that would otherwise raise the alarm
does not look at student-owned state at all — so a lab can quietly stop being
backed up while every other number says it is fine. Look at each device: if its
namespace is empty because it restarted, replay the stored snapshot with
`twinet restore`; if what is in the namespace is the work and the snapshot is
stale, capture it deliberately; if the deployment was repairing that device,
re-run it once the device has converged and it will be baselined on the next
pass. A dry run prints the same lines without failing, since it changed
nothing.

If a cluster mutation was interrupted — a controller killed halfway, a node
rebooted mid-apply — the transaction is persisted and resumable:

```sh
twinet -m examples/cos461 recover                     # roll back to the last committed generation
twinet -m examples/cos461 recover --strategy forward  # finish the desired transaction instead
```

Rollback is the default because it is the strategy that cannot lose
acknowledged work. `--strategy forward` resumes the intended transaction, and
requires `--acknowledge-forward-data-loss` when the historical replicas it
would need are unavailable.

### The same transition across a cluster

`deploy --solve --prune` is the same two destructive halves on a cluster, and
the clustered path did not need an interruption to lose the second one. Prepare
captures and replicates every dirty student-owned device the manifest still
places on a node; a container the manifest has forgotten is not in the topology
to be enumerated, so it is in no such set. Commit's prune runs on an engine that
installs the reference solution, which is exactly the engine that reads nothing
— so the container was removed having been read by nobody, on an uninterrupted
run where every node reported success.

Each node therefore preserves the other half during its own prepare, before the
apply phase writes a line of the reference solution. It reads every container a
requested `--prune` will later remove, through the same guarded funnel and the
same claimant and namespace checks as any other capture, and replicates the
copies to the peer failure domains the lab's state policy asks for. What it
preserved is journalled into that node's prepared transaction — lab, node,
generation, fence, manifest hash, mode, prune intent, and each container with
the device identifier it carried. Nothing about `--prune` changes: a successful
deployment still prunes, at the end, as it always has.

The record is what a later process is entitled to act on, and the node fails
closed without it:

| What the node finds | What it does |
| --- | --- |
| A pruning solve with no preservation record | Refuses to apply — the reference solution is never written |
| A prune candidate the record does not cover | Refuses, names the container, removes nothing |
| A candidate now carrying a different device identifier | Refuses, names both identifiers |
| A record for another lab, node, generation or fence | Refuses and names whose record it is |
| A manifest edited since the record was written | Refuses: which containers are stale was decided against a different lab |
| Peers the state policy requires but cannot reach | Refuses the solve before anything is written, unless the manifest sets `fail_closed: false`, which is audited |

One unprovable candidate stops the whole prune, and a commit that reports a
prune failure is a transaction to be recovered rather than a success. The way
out of any of them is to return the lab to teaching mode by deploying it without
`--solve`, which replays the preserved student state, and then to run the solve
and its prune again; or to re-run the deployment without `--prune` and leave the
stale containers where they are. `twinet destroy` remains the way to say that a
lab is genuinely disposable.

Two consequences are worth knowing before you meet them. A node that is already
inside an unfinished solve transaction refuses to prepare another generation,
and refuses it *before* reading anything, because the devices on that node may
already hold the answer and prepare's first act is to capture what it is about
to destroy — recover or abort that transaction first, with `twinet recover`. And
a rollback of a failed solve does not read the containers the forward half wrote
to: it removes those without capturing them, which loses nothing because either
the transaction created them or the state they replaced is what prepare captured
and proved durable, and it reads and preserves the containers that transaction
never touched exactly as an ordinary prune does. A rollback whose prepared state
was never proven durable keeps what it cannot account for and names it.

To empty a node for maintenance while the lab keeps running:

```sh
twinet -m examples/cos461 node drain node-2 --dry-run
twinet -m examples/cos461 node drain node-2
```

Drain is two-phase and fenced: fresh capture, replicated durable write,
destination restore verification, and only then removal from the source. It
refuses rather than proceeding when no verified durable replica exists;
`--allow-stale-state` and `--allow-data-loss` exist for the case where an
operator knowingly accepts the loss, and both are audited.

## 11. Benchmark and soak

The cluster evidence commands are deliberately destructive and deliberately
explicit. They are never part of ordinary CI:

```sh
TWINET_BENCHMARK_ALLOW_DESTRUCTIVE=1 make benchmark
TWINET_CHAOS_ALLOW_DESTRUCTIVE=1 make chaos
TWINET_SOAK_ALLOW_DESTRUCTIVE=1 make soak-short
```

Each refuses to run without its acknowledgement rather than turning a
destructive gate into a silent no-op. They drive
[`scripts/scale_benchmark.sh`](../scripts/scale_benchmark.sh),
[`scripts/chaos_e2e.sh`](../scripts/chaos_e2e.sh), and
[`scripts/scale_soak.sh`](../scripts/scale_soak.sh) against
[`examples/scale`](../examples/scale), and write machine-readable evidence
under `reports/` — an untracked directory, because a result belongs with the
run that produced it and not in the source tree. The scale workflow uploads
those files as build artifacts.

Numbers from previous runs are recorded, with the environment they came from,
in [09 — Measurements](09_status.md#measurements). Re-running these commands on
your cluster produces your own evidence; it does not reproduce that ledger.

## 12. Remove a lab safely

With the manifest, which is what says where the lab is:

```sh
twinet -m examples/cos461 destroy --yes
```

Destroy captures every student-owned configuration before removing anything,
removes containers on every node the manifest names, removes the lab's overlay
objects, and clears the placement record so the next deployment is not pinned
to an arrangement chosen for a lab that no longer exists.

A grading harness, or any lab whose name you know, is removed by naming it —
still with a manifest, because the manifest is what says which machines to
reach:

```sh
twinet -m examples/cos461 destroy --lab cos461-grade-g07 --yes
```

Leftovers from an interrupted teardown are found and removed cluster-wide:

```sh
twinet -m examples/cos461 node sweep            # report only
twinet -m examples/cos461 node sweep --remove
```

An overlay whose bridge still has something attached is never removed by a
sweep, whatever its ownership record says: it is carrying a cable for
something.

A removing sweep is refused outright while anything on the node owns its
objects — an operation in flight, a fenced cluster mutation, a transaction
being rolled forward or back by recovery, a grading hold, or a prepared
generation — and the refusal names which. That fence is re-proved before every
single deletion rather than once for the batch, and each object is claimed
through the same lock a deployment reserves it with, so an overlay a deploy
claims part-way through a long sweep is left in place and counted under
`FENCED` instead of being deleted out from under it. Reporting is never
refused: run the sweep without `--remove` to see what is there while the node
is busy.

### When there is no manifest

`twinet destroy --lab NAME` with no loadable manifest refuses and changes
nothing. A name is not evidence about where a lab is running: the same command
once selected the default Docker backend on a containerd cluster, saw no
containers, deleted the overlay objects that machine held, and reported success
while a 212-container lab kept running on three nodes with its cross-node
cables cut.

Two safe ways forward, in order of preference:

1. Get the manifest — any manifest that names the same nodes will do — and use
   the commands above.
2. Clean up one machine, explicitly, when you accept that scope:

```sh
twinet --runtime containerd destroy --lab cos461 --this-node-only --yes
```

That removes only the containers lab `cos461` has on the machine you run it on
and the overlay objects it owns there that no longer carry a cable. No other
node is contacted or changed, and the output says so. `--runtime` is required
because without a manifest nothing says which engine created the lab, and an
empty answer from the wrong daemon is indistinguishable from an empty machine.

### When a device's saved configuration will not replay

`twinet destroy` captures every student-owned device before removing anything,
and the next `deploy` replays it. If a replay is refused you see it during
configure, and the deployment stops there:

```
node-0/as7: configure as7/BOS: as7/BOS was recreated but its saved
configuration could not be replayed (the snapshot is safe in the state store,
and the device is still marked as needing one): restore as7/BOS addrs
command "ip route replace ..." exited 2: ...
```

Nothing was lost. The snapshot is on the node that owns the device, under
`/var/lib/twinet/state/<lab>/<as>_<device>/`, and the device carries
`/etc/twinet/restore-pending` so any later deploy looks for it again. Re-run
`twinet -m <manifest> deploy`: routes are canonicalised on the way out of the
store as well as on the way in, so a snapshot written by an older build is
repaired as it is read and does not need to be deleted.

Deleting `/var/lib/twinet/state/<lab>` is the one action to avoid. It is not a
cache: it is the only copy of the work captured from devices that no longer
exist, and removing it is silent and permanent. If a replay is still refused
after a re-run, quote the rejected command — it is printed in full — rather
than clearing the store.

## 13. When something is refused

| What you see | What it means | What to do |
|---|---|---|
| `N of M node(s) are not in a state this controller can safely act on` | version skew, a grading hold, or a busy node | read the last column of `twinet node status` |
| an underlay problem naming an MTU | the underlay cannot carry the lab MTU plus VXLAN overhead | raise the underlay MTU, or lower `link_defaults.mtu` |
| a node reports a backend different from its requested runtime | manifest and agent disagree about the engine | fix `placement.runtime`, or re-roll the agent with `deploy_agents.sh --runtime` |
| an admission refusal naming a resource | requests exceed live allocatable inventory | reduce the lab, add capacity, or use the audited `--overcommit` |
| an admission refusal saying a resource is *unknown* | the agent could not read that dimension at all; it is neither zero nor unlimited | fix the node, declare a safe `placement.nodes[].capacity`, or use the audited `--overcommit`. A dimension the kernel simply does not bound is reported as `unlimited-` and never refused |
| `refusing to remove lab ... from a name alone` | destroy has no manifest and cannot prove the scope | [§12](#when-there-is-no-manifest) |
| `refusing to install the reference solution ... asked to prune, and there is no record` | a node reached the apply phase of a pruning solve with nothing preserved for the containers it would remove | prepare the generation again, or re-run the deployment without `--prune` ([§10](#the-same-transition-across-a-cluster)) |
| `refusing to prune ... could be neither read as a student's work nor told apart from the answer` | a prune candidate is not covered by what that node preserved before it wrote the reference solution | deploy the lab without `--solve` to replay the preserved state, then solve and prune again; never delete the container by hand until you have compared it ([§10](#the-same-transition-across-a-cluster)) |
| `refusing to prepare generation ... was installing the reference solution here and has not finished` | a second deployment met an unfinished solve on that node; capturing now would file the answer as student work | `twinet recover` that transaction first, then redeploy ([§10](#10-reconcile-repair-and-recover)) |
| `its saved configuration could not be replayed` | a captured command was rejected by the device | [§12](#when-a-devices-saved-configuration-will-not-replay) — re-run `deploy`; never delete `/var/lib/twinet/state` |
| `this node is not idle, so sweeping now could remove an overlay that is being built or recovered` | a removing sweep met an operation, mutation lease, transaction, hold, or prepared generation | wait for the named owner, or sweep without `--remove` to report only |
| a sweep that reports objects under `FENCED` | a deployment claimed those overlays between the scan and the deletion | nothing: they belong to a live lab. Re-run the sweep later if they are still orphaned |
| `another Twinet agent already owns network namespace ...` | two agents are in one network namespace; a separate lock directory, API port, or runtime namespace is not isolation | stop the process the refusal names; there is no override ([§5.3](#53-bootstrap)) |
| `the cluster mutation is committed and durable ... but finalization ... did not complete` | every node committed and nothing was rolled back; only cleanup or the post-commit inventory proof failed | the lab is live: check `node status`, then resume with `twinet recover --strategy forward` if a node still reports an incomplete generation ([§10](#10-reconcile-repair-and-recover)). Do not redeploy |
| a quarantine instead of a mark | the infrastructure failed, not the submission | re-grade after `twinet node status` is clean |
| a deploy that will not report a no-op, naming a control sidecar | a router's FRR sidecar is in a different network namespace from the router, or its namespace cannot be read | let the deployment run; it rebuilds the sidecar. `twinet node controls` names the device, and `--repair` does it on its own |
| `manages split FRR control sidecars but cannot prove network namespace identity` | the runtime backend in use runs FRR routers as a router plus a private sidecar but cannot say which namespace either is in | this is a defect in the build, not a cluster fault: report it. Deploy refuses rather than certify a control plane it never located |

## 14. What this guide does not claim

It does not claim a duration for any step, a class size, or a success rate.
Those are properties of a specific cluster and a specific run, and the only
place they are recorded is [09](09_status.md). It does not claim that following
it end to end has been re-run on a clean cluster since the last change to this
tree; where that matters, the ledger says what has been observed and what has
not.
