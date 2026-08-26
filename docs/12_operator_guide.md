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
  strategy: pack-by-as
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
VXLANs. The agent holds `/run/twinet/agent.lock` for its process lifetime, and
the rollout script refuses any alternate `twinetd*` process before changing a
node. A deliberately network-namespace-isolated test agent may use a distinct
`-host-lock` path inside that isolated environment; never use that override to
run two agents in the same root network namespace.

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
| `refusing to remove lab ... from a name alone` | destroy has no manifest and cannot prove the scope | [§12](#when-there-is-no-manifest) |
| `its saved configuration could not be replayed` | a captured command was rejected by the device | [§12](#when-a-devices-saved-configuration-will-not-replay) — re-run `deploy`; never delete `/var/lib/twinet/state` |
| a quarantine instead of a mark | the infrastructure failed, not the submission | re-grade after `twinet node status` is clean |
| a deploy that will not report a no-op, naming a control sidecar | a router's FRR sidecar is in a different network namespace from the router, or its namespace cannot be read | let the deployment run; it rebuilds the sidecar. `twinet node controls` names the device, and `--repair` does it on its own |

## 14. What this guide does not claim

It does not claim a duration for any step, a class size, or a success rate.
Those are properties of a specific cluster and a specific run, and the only
place they are recorded is [09](09_status.md). It does not claim that following
it end to end has been re-run on a clean cluster since the last change to this
tree; where that matters, the ledger says what has been observed and what has
not.
