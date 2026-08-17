# 06 — Autograding

## 1. The problem with the current approach

Both existing generations grade **against the live, shared class network**:

- Legacy (`platform/utils/autograder/bgp/`): `ovs-vsctl del-port` a student's AS
  out of the running mini-Internet, splice in an ExaBGP container, probe, then
  reconnect. Parallel (Go runner, N workers) but destructive and root-heavy.
- Current (`autograder-25/grader.py`, 1,747 lines): builds a "shadow AS" of
  containers and veths next to the live network, one AS at a time, in a plain
  `for` loop, with `BGP_CONV_WAIT = 20` invoked more than eight times per AS
  plus per-AS bootstrap sleeps. Realistically **hours** for one class.

Both share four defects:

1. **Serial or coarsely parallel**, bounded by wall-clock sleeps.
2. **Destructive**: grading perturbs the network other students are using.
3. **Not reproducible**: the result depends on the state of the live class
   network at that moment. Regrades and appeals cannot be replayed.
4. **Unstructured output**: text logs or raw SQLite blobs, with no rubric,
   aggregation, or export.

## 2. The core idea: grade in an ephemeral private lab

Twinet grades a submission, not a running AS.

```
submission (configs_*.tar.gz, the save_configs layout)
        │
        ▼
  twinet grade --rubric rubric/cos461.yaml --submissions ./subs --parallel 24
        │
        ├─ for each student, on any cluster node, in parallel:
        │     1. synthesize a *grading lab*: the student's AS
        │        + synthetic neighbours generated from the class manifest
        │        + a scriptable BGP speaker at each external port
        │        + a Routinator seeded with a fixed RPKI snapshot
        │     2. restore the student's saved config into it
        │     3. wait for convergence (predicate, not sleep)
        │     4. run the rubric's checks
        │     5. tear the lab down
        │
        ▼
  reports/  <netid>.json  <netid>.html   summary.csv   summary.html
```

Why this is strictly better:

- **Embarrassingly parallel.** A grading lab is ~10 routers plus a handful of
  synthetic peers — roughly 20 containers. At 600 containers/node that is ~30
  concurrent students per node, ~90 across the cluster. A 100-student class
  becomes two waves.
- **Non-destructive.** The class network is never touched; grading can run
  during the assignment, nightly, for formative feedback.
- **Reproducible.** A grading lab is a pure function of (submission, class
  manifest, rubric, RPKI snapshot). Regrades and appeals replay bit-for-bit,
  and a student can be handed the exact lab that failed.
- **Runs without the class network at all** — including after the semester, on
  a laptop, in CI.

The live-network mode is kept as `twinet grade --live` for spot checks and for
checks that are inherently about the real class (e.g. "did you actually peer
with your real neighbour during the hackathon"), but it is no longer the
primary path.

## 3. Convergence detection instead of sleeps

The single biggest speedup. Every wait is a predicate polled at 250 ms with a
deadline:

| Predicate | Definition |
|---|---|
| `bgp.sessions_established(as)` | every configured neighbour in `show bgp summary json` is `Established` |
| `bgp.rib_stable(as, 3)` | the RIB hash is unchanged for 3 consecutive polls |
| `ospf.adjacencies_full(as)` | every OSPF neighbour is `Full` |
| `route.present(dev, prefix, via)` | a specific route exists with a given next hop / AS path |
| `probe.reachable(src, dst)` | ping succeeds |

`BGP_CONV_WAIT = 20` seconds × 8 per AS = 160 s of pure sleeping becomes
typically 2–6 s of actual convergence. Combined with parallelism, expected
class-wide grading time goes from hours to **single-digit minutes**.

## 4. Test doubles — target design, not built

Everything in this section describes what the grading harness is meant to
become. **None of it exists yet.** Grading today deploys the real neighbourhood
and waits for it to converge, which is why a submission costs about five
minutes; see [09](09_status.md) for the measurement and for what would change
it. The section is kept because it is the design the convergence cost argues
for, not because it describes the code.


The reusable primitive both existing generations converged on — *attach a
scriptable BGP speaker where a real neighbour would be, inject benign and
adversarial routes, then observe both the control plane and the data plane* —
is promoted to a first-class Twinet object.

```yaml
doubles:
  peer:                          # attaches at an external_port
    kind: bgp-speaker            # GoBGP-based; scriptable over gRPC
    asn: "{{ .Neighbor.asn }}"
    relationship: "{{ .Neighbor.rel }}"
  ixp:
    kind: ixp-route-server
    community_gated: true
```

Capabilities: announce/withdraw arbitrary prefixes with crafted AS-paths,
communities and origins (valid / invalid / not-found under the seeded RPKI
snapshot); read the RIB-in (what the student exported); measure export/import
timing; and emit marker packets for data-plane verification.

Using **GoBGP as a library** rather than ExaBGP + `exabgpcli` + Scapy removes a
Python runtime, a CLI-scraping layer and a packet-crafting dependency from the
grading path, and makes announcements synchronous and assertable.

## 5. Checks

Checks are typed Go functions registered by name, each returning a structured
`Result{Pass, Score, Evidence, Detail}`. `Evidence` is machine-readable (the
RIB entry, the traceroute, the parsed config stanza) so feedback can quote
exactly what was observed.

Library, mapped to the COS-461 questions:

| Check | Verifies |
|---|---|
| `l2.vlan_isolation` | admin↔admin and patient↔patient reachable; admin↔patient only via the L3 gateway (assert the traceroute has the gateway hop) |
| `l2.gateway_configured` | hosts' default gateway is the prescribed router |
| `l3.addressing_matches_plan` | every interface matches the manifest's `expected` addressing, and no router carries an address the plan does not mention (Q1.2) |
| `ospf.full_adjacency` | all OSPF neighbours `Full` |
| `ospf.subnets_advertised` | every required subnet, incl. DNS/measurement/matrix, in the OSPF LSDB |
| `ospf.ecmp_paths` | compute the shortest-path DAG from `show ip ospf … json` **and** confirm empirically (repeated traceroutes / marker packets) that exactly the three prescribed `ATL`↔`BOS` paths carry traffic (Q1.3) |
| `tunnel.sixin4` | IPv6 DCN↔DCS reachability *and* that it traverses the 6in4 tunnel, not native routing (Q1.4) |
| `bgp.ibgp_full_mesh` | a session between every router pair, sourced from loopbacks |
| `bgp.next_hop_self` | eBGP-learned routes carry a reachable next hop internally |
| `bgp.own_prefix_only` | the AS originates exactly its /8 |
| `policy.gao_rexford` | inject from each relationship class via doubles; assert local-pref ordering and that provider/peer routes are not re-exported to provider/peer (Q2.3) |
| `policy.no_transit_for_peers` | nothing learned from a peer or a provider is advertised to a peer or a provider, and your own and your customers' prefixes are (Q2.3) |
| `policy.transit_for_customers` | every route the AS selected reaches every customer — the transit half of the export rule, and the opposite error from a leak (Q2.3) |
| `policy.ixp_communities` | announcements are relayed only to out-of-region members and in-region announcements from the IXP are filtered (Q2.4) |
| `policy.traffic_engineering` | the slow provider/customer is deprioritised outbound (local-pref) and made less attractive inbound (AS-path prepend), **without** any deny (Q2.5) |
| `rpki.roa_published` | the AS's ROA exists in the RPKI snapshot and covers its /8 |
| `rpki.invalid_rejected` | an invalid-origin announcement from a double is not selected |
| `rpki.notfound_preserved` | not-found routes are still usable (no over-filtering) |
| `dataplane.reachability_matrix` | pairwise reachability with correct paths |
| `config.no_forbidden` | e.g. `179.*`/`180.*` not in OSPF; `ATL-L2` (no suffix) untouched |

Each check is independent and has a timeout, so a broken AS produces a partial
score rather than aborting the run — a defect in both current generations.

## 6. Rubrics

```yaml
apiVersion: twinet.dev/v1
kind: Rubric
metadata: {name: cos461-routing, total: 10}
questions:
  - id: q1.1
    title: L2 connectivity and VLANs
    points: 1
    checks:
      - {check: l2.vlan_isolation,     weight: 0.6}
      - {check: l2.gateway_configured, weight: 0.4}
  - id: q1.3
    title: OSPF load balancing
    points: 1
    checks:
      - {check: ospf.ecmp_paths, weight: 1.0,
         args: {a: ATL, b: BOS,
                paths: [[ATL,BOS], [ATL,PHY,NYC,BOS], [ATL,PHY,BOS]],
                exclusive: true}}
  - id: q2.5
    title: Traffic engineering
    points: 1
    depends_on: [q2.3]
    checks:
      - {check: policy.traffic_engineering, weight: 1.0}
```

Rubrics are versioned with the course material, are diffable, and — importantly
— **the point weights live in one place** instead of being scattered as
`points += check_rpki_invalid(asn) * 0.5` across a 1,747-line script.

`depends_on` lets the engine skip (and explain) checks that cannot meaningfully
run, instead of reporting cascading failures.

## 7. Output

What is written today:

- `<group>.json` — every check, score, evidence, timings, lab fingerprint and
  the version of Twinet that produced it. Self-contained, so an appeal is
  answered by reading it.
- `<group>.txt` — the same thing as human-readable feedback, with the evidence
  inline: the table entry that was wrong, the address that could not be
  reached, the command that produced it.
- `summary.csv` — one row per student, one column per question; drops straight
  into Canvas or Gradescope.

Not written, and previously listed here as though they were: an HTML report per
student, an HTML class dashboard, and a `.twinetlab` replay bundle. The JSON and
text carry the same evidence, and the CSV is what an LMS ingests, so nothing is
unusable without them -- but they were described in the present tense and did
not exist, which is the kind of claim this document exists not to make.

## 8. Formative use

Because grading is non-destructive and fast, the same engine powers a
**self-check** students can run themselves:

```
group12@gateway$ check q1.3
q1.3 OSPF load balancing ......................... FAIL (0.0 / 1.0)
  ✗ ospf.ecmp_paths: expected 3 equal-cost paths ATL→BOS, observed 2.
      observed: ATL→BOS, ATL→PHY→BOS
      missing:  ATL→PHY→NYC→BOS
      hint: cost(PHY→NYC) + cost(NYC→BOS) must equal cost(PHY→BOS).
```

This is the highest-leverage pedagogical addition in the whole redesign: it
turns the connectivity matrix (a coarse red/green signal, updated every few
minutes) into precise, immediate, per-question feedback — while the rubric
still keeps hidden checks for the graded run.

## 9. Integrity

- Every submission's `manifest.json` is checked against the class manifest hash.
- Config dumps are compared across groups for near-duplicate detection
  (normalised token similarity), replacing the anecdotal use of the history GIF.
- The event log records whether the graded AS's config matches what was live in
  the class network at the deadline.

### The programs a mark rests on

A student has root in their own containers — that is the exercise. It also means
every program the grader runs there is theirs to replace. A shell script called
`ping` that prints `3 packets transmitted, 3 received` earns the reachability
marks on a network that forwards nothing, and one called `vtysh` earns the
configuration marks for configuration that was never written. Neither has to
overwrite the image's copy: a file earlier on the search path is the one that
runs.

So before a grading command executes in a container, its programs are compared
against the image it is running. Both sides are read by the grader, never by
asking the container: the container's through `/proc` on its node, the image's
out of a container of that image created and never started. Resolution follows
the search path, so a `ping` planted in `/usr/local/bin` is found while the
image's copy sits untouched below it, and a program the image does not ship at
all is a plant. A program the student *removed* is not a finding — it cannot
answer anything either.

A container that fails this is **not marked down**. The run is quarantined and
says which container and which program, because a grader that cannot trust what
it was told does not know what the marks should have been.

Two consequences worth knowing:

- Rebuilding the images under a tag that already has containers leaves those
  containers running bytes the node may no longer have. Grading then stops with
  "this container is running an image that is no longer on this node"; redeploy
  the lab.
- `twinet grade batch` is unaffected either way: it rebuilds every container
  from the image and loads only the submitted configuration, so nothing a
  student did to their container's filesystem is present at all.

What this does not cover is stated plainly: a shared library replaced underneath
an untouched program, and a program replaced in the twenty seconds between one
check and the next. Both are narrower than what it does cover, and neither is
reachable by editing a configuration file.

### Where a switch has been told to send a frame

`l2.vlan_isolation` does not only send probes. A broadcast finds two VLANs that
share a broadcast domain, but it does not find a rule aimed at one flow, so the
check also reads what each switch has actually been told to do and calls any
instruction that carries a frame from a port in one VLAN out of a port in
another a way across.

"What it has been told" is larger than the flow table, and each place it turned
out to be larger cost a mark:

- **Actions that name a port in an unfamiliar way.** `enqueue:8:0` puts the
  frame on a queue of port 8 and sends it exactly as `output:8` would. Every
  action naming a port is read, and `flood` and `all`, which name none and reach
  every port, count as reaching all of them.
- **Actions that name no port at all.** `actions=group:461` says only that the
  frame goes wherever group 461 says; the ports are in the group's buckets,
  which `dump-flows` never shows. The groups are dumped as well and every
  `group:` is followed into its buckets, and those into any group they name in
  turn — stopping at one already walked, so a group pointing at itself cannot
  spin. A group's own `type=all` is not part of a bucket and is deliberately not
  read as flooding; reading it as flooding would fail every switch that has a
  group at all.
- **Copies made outside the switch's tables.** `tc filter … action mirred egress
  mirror dev <other>` has the kernel copy the frames of an access port into
  another VLAN with the flow table exactly as it should be, and the switch's own
  `ovs-vsctl` mirror does the same with neither the flow table nor traffic
  control touched. Both are read.

The pattern is worth naming, because it is the one that keeps recurring: a check
that reads one table and concludes from its silence. Silence in a table that
only points at another table says nothing.

### Asking a router what it runs, not what it will admit to

The same shape, one layer down. `vtysh` is not the router; it is a client that
connects to whichever daemons own the sockets in `/var/run/frr`. Asking it
whether a core router runs BGP asks only about those, and FRR will happily run a
second `bgpd` in a pathspace of its own — `bgpd -N x` — holding an instance, a
neighbour and the BGP port while `vtysh -c 'show bgp summary'` reports `% BGP
instance not found`. A daemon that is not FRR at all shares none of FRR's
furniture and is invisible in the same way.

`mpls.bgp_free_core` therefore reads three things about each core router, none
of which the router gets to narrate:

- **its processes**, for a second `bgpd` — started with `-N`, `--pathspace` or
  its own `--vty_socket`, or simply a second copy — and for BIRD, GoBGP, ExaBGP
  or OpenBGPD under their own names;
- **its FRR pathspaces**, from the process list and from any `.vty` socket in a
  subdirectory of `/var/run/frr`, each then asked what it holds so the evidence
  names the hidden neighbours;
- **its sockets**, for the BGP port in any state — which is what catches a BGP
  speaker that has been renamed, since the name it runs under is its to choose
  and the port its peers connect to is not.

The delicate half is the false positive. FRR *does* start `bgpd` on a correct
core router and leaves it unconfigured, and that is the state the exercise asks
for: no instance, no table, no listener. "A bgpd is running" is therefore not a
finding, and a check that made it one would fail every correct answer — the more
expensive of the two mistakes. What remains uncovered is a BGP speaker that has
been renamed *and* moved off port 179, which is stated here rather than papered
over.

### Which policy governs a session

A route-map is judged by what it does to the session it is on, so the grader has
to work out which route-map that is — and the answer is not "the one written on
a line with this address in it".

FRR resolves it in two steps the reader has to follow. A session takes each
setting from its peer-group unless it states that setting itself, per setting
and per direction; and a binding governs only the address family it was written
in. A peer-group is a template: nothing peers with it, and it has no marks of
its own.

Skipping either step is wrong in both directions at once, which is what makes it
worth spelling out:

- **The correct answer loses marks.** Binding an import policy once on a
  peer-group and pointing every session at it is how this is written in
  practice. Read literally, each of those sessions has no policy — so the
  reference lost the origin-validation mark for filtering it was performing.
  This is the more serious of the two failures. A student who is right has no
  way to discover that the grader is wrong, and no evidence to argue with.
- **The wrong answer keeps them.** Put the correct policy on the group, then
  override it on the session with one that filters nothing. The clause the
  grader searches for is still in the configuration, and the router never runs
  it. If the group also carries the `remote-as` — which it usually will, since
  that is half the point of a group — then the group itself appears in the list
  of external sessions in place of its own members, and the sessions are never
  examined at all.

The same applies across families: FRR prints `address-family ipv6 unicast` after
`ipv4`, so a reader that keeps the last binding it saw will report an IPv6
policy as the policy on an IPv4 session.

The rule this comes down to is that a configuration is a program with scoping
rules, and grepping it is not reading it. Wherever a check asks what a
configuration says about one object, it has to resolve the same inheritance the
daemon does, or it is reading a different program from the one that runs.

### Who answered a connection

A program making a TCP connection learns whether it got an answer. It does not
learn who sent it, and it cannot. A reset carries the destination's address
because whoever wrote it put that address there: `iptables -j REJECT
--reject-with tcp-reset` on any router along the way forges one, an ICMP
unreachable from a router reaches the caller in the same words, and a host
firewall on the sender produces it without a packet ever leaving.

Three checks read "refused" as the far side speaking, and the premise is wrong
in both directions at once:

- **Isolation.** A refusal was counted as two customers exchanging traffic. A
  network that rejects cross-customer connections rather than dropping them in
  silence is isolating — more helpfully than one that leaves the sender waiting
  for a timeout — and it was marked as leaking.
- **Reachability.** A refusal was counted as proof that packets arrive. One
  `REJECT` rule on a router restored full marks for a network across which no
  connection could pass.

What settles it is the destination's own record: the resets it sent plus the
connections it accepted, read before and after the attempt. Neither counter
moves unless the packets got there, and nothing on the path can raise either.
Probes are scheduled so that no destination is aimed at twice at once — a
counter that moved while two attempts were in flight is nobody's in particular.

The two directions part company where the destination cannot be asked, and the
asymmetry is deliberate. Reachability falls back to the prober's view: failing a
correct path because a file could not be read is the more expensive mistake. An
accusation does not, because it carries the burden of proof, and isolation has
two further witnesses — the routing tables and the datagram counters — so
nothing rests on this one alone.

## Grading a class

Two modes, and the difference is what they cost.

`twinet grade batch` gives every submission a private lab. It is the strongest
isolation available and it was measured: a full-breadth harness is the whole
class topology, so a hundred submissions means deploying the class a hundred
times, and eight concurrent harnesses already saturate three nodes. One
submission takes about twelve minutes. It remains the right tool for a single
disputed mark, where isolation matters more than throughput.

`twinet grade class` is the one to use for a class. It exploits the fact that a
harness differs from the class lab in exactly one way — every autonomous system
but one is the reference solution — so a submission graded on its own in that
lab sees exactly what it would see in a private harness, at the cost of
resetting one system rather than deploying a lab.

That is what it does by default: one submission at a time. Nothing else in the
lab is anything but the reference while a submission is being marked, so no
student's mistake can reach another's marks. It is a property of the
construction, not an argument about topology.

### Loading the submission onto a blank system, not onto the answer

Before a submission is loaded, its autonomous system is returned to the state a
student is given: the platform's own addressing, the starting FRR
configuration, and none of the tunnels, hand-written routes or VLAN assignments
a previous submission installed.

This matters more than it sounds. A submission is the set of files a student
wrote. A router they never touched has no file in the archive. Loaded onto a lab
deployed at the reference, that router keeps the model answer — and the student
is marked correct for work they did not do, with nothing in the report able to
say so, because a correct router looks identical however it came to be correct.
Blanking first makes an omission read as an omission.

### Nothing else may touch the lab while it is being graded

Each node runs a loop that repairs devices which have lost their wiring, and
grading is indistinguishable from that fault while it is working: it blanks an
autonomous system back to the state its owner started from, which is a device
with no addresses and no routing configuration, and then loads somebody's work
onto it.

The loop believed what it saw. In one recorded run it rewired thirteen devices
of the lab being graded; rewiring removes an interface and adds it back, so the
submission being loaded at that moment failed with `Cannot find device
port_BOS`, and seven of eight students were held for review. The marks that
survive that are worse than the ones that do not, because in a lab deployed at
the reference a repair also re-renders configuration -- the model answer written
over a student's work while it is being marked.

`grade class` therefore asks every node to leave the lab alone, and keeps
asking. It is a lease with a deadline, not a switch: a grader that is killed
stops renewing, and the nodes resume looking after the lab by themselves within
three minutes. Nobody has to remember to turn repairs back on, and no crash can
leave them off.

Every node must agree, and grading refuses to start if one will not hold. A
hold on two nodes of three is not a hold: the devices of a lab this size are
spread across all of them, and the third node's repair loop rewires its share
regardless. If the hold lapses partway through a run -- two renewals failing in
a row -- the wave being graded and everything after it is held for review rather
than marked, because from that moment nothing can say whether a mark measures
the student's work or the reference being written back over it.

Loading also waits, briefly, for the interfaces the lab says a device has. Any
deploy rewires by removing an interface and adding it back, so the condition is
temporary by construction -- but the wait is bounded, because a genuinely absent
interface produces the same symptom and a run that hangs silently is worse than
one that stops and names the device.

### Trading isolation for speed, deliberately

`--per-wave N` loads several submissions at once, batched so that no two members
of a wave are within two hops of each other in the peering graph.

Two hops, not one. Adjacency alone is not enough: with A — B — C, a route A
originates reaches C through B, so a mistake in A can change what C is marked
on even though they never peer. Widening the conflict relation costs waves, and
this is what it costs, measured rather than assumed:

| Class | Waves | Submissions per wave |
|---|---:|---:|
| 8 student ASes | 6 | 1.3 |
| 80 student ASes | 42 | 1.9 |

So the speed-up is under a factor of two, and it is bought with a heuristic. A
route can travel further than two hops through reference systems, so a
sufficiently long path can still carry one submission's mistake into another's
marks. In the COS-461 topology the reference systems between any two students
filter and re-originate enough that this has not been observed, but it is not
excluded by construction — which is why it is off by default. Use it for a dry
run over a class, not for marks that are final.

`twinet grade batch` deploys a private lab per submission, at about twelve
minutes each. Default `grade class` gives the same isolation far more cheaply,
so `batch` is for the case where the deployed lab itself is in doubt — a
disputed mark, or a re-run that must not share anything with the class run,
including the containers.
