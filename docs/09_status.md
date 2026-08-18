# 09 — Implementation status

This records what is built and verified, so the plan and the code cannot drift.
Measurements are from the three-node cluster (node-0/1/2, 56 cores and 251 GiB
each, 10 GbE private fabric).

Last updated after the sixth external code review.

Rows are written from evidence produced by a run, not from intent. Where a
number appears it came from the command named beside it; where a target was
missed it is recorded as a miss.

## Built and verified

| Area | State | Evidence |
|---|---|---|
| Typed model, manifest loading, aggregated positional validation | done | `internal/model`, `internal/manifest`; `twinet validate` reports every problem in one pass |
| Expression-based addressing plan | done | `internal/ipam`; tests assert the plan reproduces the COS-461 assignment text exactly |
| Deterministic allocation (VNI, MAC, interface names) | done | `internal/alloc`; tests assert order-independence, uniqueness across 5,000 links, and that names fit `IFNAMSIZ` |
| Template expansion, tiered-internet generator, post-expansion verifier | done | `internal/expand`; the verifier caught two real modelling defects (see below) |
| Netlink wiring: veth, netns, shaping, VXLAN | done | `internal/netx`; rate/time parsing tested against bit-vs-byte and binary-vs-decimal confusion |
| Container runtime abstraction | done | `internal/runtime` (docker) |
| Staged deployment DAG with per-scope failure isolation | done | `internal/plan`; tests assert stage ordering, real concurrency, and that one broken AS does not stop a class |
| Convergence predicates in place of sleeps | done | `internal/plan.Wait`, `internal/grade/converge.go` |
| Single-node deployment | done | 4-AS demo: 57 devices, 74 links, 64 s |
| Node agent and cluster fabric | done | 12-AS lab: 212 devices, 299 links across 3 nodes in **58 s**, zero failures |
| Cross-node VXLAN | done | 50.22 ms measured for a 25 ms configured delay, 9 µs jitter, no duplicates |
| AS-granular placement | done | 13.4 % of links cross the fabric; `twinet inspect --placement` |
| Underlay MTU verification | done | `twinet node check` refuses a lab that would not fit and names the MTU to use |
| Grading engine: rubric, 23 registered checks, structured reports | done | the COS-461 rubric uses 20 of them; 8 systems graded in **79 s**; JSON, text and CSV output |
| Reference solution (`--solve`) | done | scores **10.00 / 10.00** against its own rubric, verified end to end and re-checked by `make e2e` |
| Container images | done | `hyhe/twinet-{router,host,switch,svc}` |
| Reference solution | **10.00 / 10.00** | verified end to end on the live cluster; a rubric whose reference cannot score full marks is unfalsifiable, and every student who loses that mark loses it to the platform |
| RPKI | done | the lab is its own trust anchor: an RTR validator serves a payload derived from the topology, with declared discrepancies so an exercise can state exactly which announcement is invalid and which has no ROA |
| Mutual TLS | done | `twinet node pki` issues a cluster CA, a key per node and a controller certificate; the cluster now refuses plaintext and refuses TLS without a client certificate, verified against the live agents |
| SSH gateway | done | one credential per group, authenticated at the edge; device names resolve within the student own AS so another group router cannot be named at all. Legacy per-AS ports are served but do not authorise. Verified across the cluster |
| Save and restore | done | `twinet save` archives every group work with the topology hash and per-file checksums; restore refuses an archive from a different topology or one edited after it was taken |
| Per-submission grading harnesses | done | `twinet grade batch` gives each submission a private lab in which every AS but one is solved; verified with two submissions graded concurrently across three nodes |
| NIKA LabRuntime adapter | done, with one caveat | `TwinetRuntime` subclasses NIKA's `LabRuntime` and implements all ten abstract methods, so the ~50 semantic operations of `ExecSemanticOpsMixin` work; verified live on the three-node cluster, including driving an unmodified `LinkFailure` problem through inject and verify. The caveat: NIKA's problem classes select behaviour with a literal `match` on the backend name and refuse anything that is not `kathara` or `containerlab`, so the runtime must be constructed with `dialect="kathara"` — the arm that is correct for Linux/FRR/eth0 devices. Without it, every problem raises `RuntimeCapabilityError`. See `contrib/nika/README.md`. |
| Fault injection engine | partial | **47 registered, of which 45 are NIKA's** (NIKA publishes 60). The 15 not implemented each need a substrate Twinet does not emulate — 6 P4/BMv2, 4 Kubernetes, 3 SDN-southbound, 2 others. 45 of the 47 inject, verify, resolve, and are then checked to have left the device exactly as they found it, in about 88 s of `make e2e`; the other two are skipped by name with reasons (one needs a lab with VRFs, one cannot measurably overwhelm the resolver from a single container). The DHCP family was the last applicable gap and is now built, with each fault checked against a real client asking for a lease rather than against the server's configuration file. See [10](10_fault_injection.md) |
| Faults are reversible, and proved to be | done | The engine fingerprints a device before and after injecting and requires resolving to leave neither what it added nor a hole where something it removed used to be. Introducing the check immediately found five faults that satisfied their own predicate while leaving the device broken |
| Fault secrecy | verified | No fault writes a self-identifying path into the device under test. A test reads the fault sources and fails on any such path; it found one on its first run |
| Self-healing wiring | done | A container that restarts comes back with an empty network namespace. Each node now notices within a minute and rebuilds that device's links and configuration. Measured: `svc/matrix` went 10 interfaces → 2 → 10, repaired 0.8 s after detection, with no deploy run |
| Incident runner | done | `twinet incident run`; a two-fault scenario injects, holds and unwinds in 798 ms. It also runs an agent and scores what it says against the ground truth: four parts (detection, devices as a Jaccard overlap, category, root-cause names), and the agent is given the brief and never the answer, which the end-to-end suite asserts. Measured with a small agent that greps for a router with too few OSPF adjacencies: 0.70 of 1.00, blaming the router that lost an adjacency as a consequence rather than the one the fault was injected at |
| Ground-truth isolation | verified | audited: 0 hits for the fault name, root cause or ground truth anywhere in a target container's files, environment or labels |
| DNS | done | zones are generated from the model, served by BIND in the service container, and every device points at the lab own resolver; verified end to end for forward and reverse lookups |
| Matrix, looking glass, policy analyzer | done | `twinet web` serves an overview, the connectivity matrix and a looking glass restricted to nine read-only commands. Measured on the cluster: 90 of 90 pairs reachable, the matrix taken in 1.4 s, the looking glass answering from `as3/NYC`, and a command outside the list refused. What it does not have, and the original had, is the time slider over historical snapshots, per-group VPN status and the Krill proxy |
| _(collectors)_ | done | control-plane collectors; the analyzer reads structured paths and the declared relationships rather than scraping text |
| CI gates | done | `make ci` refuses to run without golangci-lint and shellcheck rather than reporting a pass it did not verify, and includes `go mod tidy -diff`. Turning the lint on found five real problems. The GitHub workflow is disabled on push by request; `make ci` runs the identical gates |
| Grading marks behaviour, not text | done | The exchange check requires the policy to be bound to the route server, the 6in4 check requires a tunnel that carried the packets rather than the kernel's own `sit0`, and the RPKI check requires a connected validator holding ROAs before an empty invalid table means anything |

## Defects found by the platform's own checks

Recording these because each is the kind of fault that would otherwise have
reached students, and each motivated a permanent test.

1. **Colliding interface names.** A reduced staff-run AS carries every external
   port on one router, so two links to the same peer both wanted `ext_3`.
   External interfaces are now named after the peer's *router*, with a
   deterministic uniquifying pass behind that. Caught by the post-expansion
   verifier.

2. **The internet exchange was not a shared LAN.** It was modelled as
   point-to-point cables that all carried the same `/24`, so every member would
   have believed the whole peering LAN was on-link while being unable to reach
   any of it. An exchange is now a real fabric switch, which is what the
   hardware is and what lets a member at `180.Z.0.<ASN>` reach the route server
   at `180.Z.0.Z` as the assignment promises. Caught by the prefix-overlap check.

3. **Duplicated packets on every cross-node link.** Creating a VXLAN device with
   a unicast remote already installs the all-zeros forwarding entry, so
   appending another produced two copies of every flooded frame. Students would
   have seen duplicate ICMP replies and inexplicable traceroutes and reasonably
   concluded they had misconfigured something. The entry is now reconciled
   rather than appended.

4. **A wrong reference answer.** Two keys in the OSPF cost map were written in
   the opposite order to the lookup, so their costs silently defaulted and one
   of the three prescribed load-balanced paths never appeared. Now the map is
   canonicalised at startup, and `TestReferenceECMPArithmetic` computes shortest
   paths through the real topology to assert that exactly the three prescribed
   paths tie and no fourth does.

5. **A stale agent.** A rollout used a binary built before the change it was
   meant to carry, which presented as a networking bug. `scripts/deploy_agents.sh`
   now verifies each node ends up with the checksum that was just built.

6. **Kubernetes-style memory quantities.** Docker rejects `512Mi`. Quantities are
   now normalised, and validated at author time rather than discovered one
   container at a time during a deployment.

7. **Six faults that did not work, or could not be undone.** Exercising all
   nineteen against the live cluster found: verify predicates too loose to tell
   an active fault from a repaired one; `pgrep -x` silently matching nothing on
   busybox, so a fault reported success without ever stopping the daemon;
   `pkill -f` matching the command line of the shell running it and killing
   itself half-way; `watchfrr` surviving a stop and holding its pid lock so the
   router never came back; `rm` failing on Docker's bind-mounted
   `/etc/resolv.conf`; and a fault that captured an empty file and would have
   guaranteed data loss on resolve. None of these were reachable by unit test.

8. **A fault that destroyed what it was meant to perturb.** `host_incorrect_gateway`
   pointed a host's default route at a dead neighbour and resolved by deleting
   the default route; where no prior route had been recorded it put nothing
   back. Its verifier asked whether the route went via the wrong gateway, the
   answer was no, and the resolve reported success — while the host was left
   unable to leave its own subnet. It surfaced a week later as a single
   unreachable host in a grading run, by which point nothing connected it to
   the cause. The mark it cost was very nearly attributed to the student. Every
   resolve is now checked against the state the injection found, which
   immediately found four more of the same shape: removing an address or
   downing an interface takes with it every route that resolved through it.

9. **A restart disconnected a device permanently.** A container that restarts
   comes back with an empty network namespace, and nothing noticed. The wiring
   was already idempotent and a deploy would have repaired it, but a deploy only
   runs when a person runs one, and nobody has a reason to until the symptom is
   reported. Each node now checks its own containers every minute.

10. **A release gate that answered yes without looking.** `make ci` printed
    "all CI gates passed" while skipping the lint and the shell check whenever
    their tools were absent, which on the development machine was always.
    Enabling them found five real problems, one of which mattered: the
    preservation replay treated an unreadable snapshot the same as no snapshot,
    so a corrupt capture was silently skipped and the device came back looking
    clean.

11. **The benchmark could be answered from the internet.** Every scenario Twinet
    ships names its fault, its device and its interface, and the repository is
    public. The sandbox masked those files on this machine and left the agent
    the machine's network, so `curl` fetched the answer from GitHub and an agent
    that never queried a router scored 1.00. The agent now has a network
    namespace of its own permitting the node agents and nothing else, and the
    published scenarios no longer contain an answer to fetch: they say what kind
    of link or device to break and the run draws one, recording the seed.

12. **Withholding the internet from a paying customer was unassessed.** The
    export half of Gao-Rexford was graded in one direction only — nothing
    learned from a peer or a provider may go to a peer or a provider — because
    a customer may receive anything. "May receive anything" is not "need receive
    nothing": an AS could deny its providers' routes to every customer, leaving
    them able to reach nobody outside it, and keep full marks for business
    relationships. `policy.transit_for_customers` now requires every selected
    route to reach every customer, and the discrimination suite mutates for it.

13. **Reachability inside a VLAN was probed one way.** The same-VLAN half of the
    layer-2 question looped over `i<j` -- one probe per unordered pair -- while
    the cross-VLAN half deliberately probed every ordered pair. A host that
    dropped what it sent to its neighbour, while still answering that
    neighbour, kept whichever direction the loop happened to take, and full
    marks with it. Every ordered pair is probed now. Doubling the traffic
    through links the lab deliberately makes slow then cost a *correct*
    submission a mark to a dropped packet, so the probes send two per hop and
    retry three times: a mark that depends on the weather is worse than a
    missing check, because nobody re-reads a grade that looks plausible.

14. **A route-target leak that only went one way answered no probe.** Isolation
    between VPN customers was established by pinging every site pair in both
    directions. A ping needs a route home, and importing another customer's
    route target on one edge leaves their table alone -- so packets flow into
    the other bank's network, nothing comes back, every probe times out, and
    the check reports perfect isolation. One bank able to inject traffic into
    another's scored full marks. The tables are read as well as probed now.
    Found by the advanced course's new discrimination suite on its first run,
    which is what that suite is for.

15. **One multicast site was never tested as a receiver.** Delivery sent from
    one host and required every other one to receive; the sender was always the
    same host, so that site was never on the receiving end. One `iptables` rule
    on its own router -- a thing a student can write, because a student has root
    in their containers -- blocked the group to it for full marks. The
    no-flooding half had the mirror hole: the source and the single receiver
    were never bystanders, so a submission flooding to exactly those two passed.
    Both now run two rounds with the source moved, and a host covered by
    neither makes the check say it cannot give a verdict.

16. **The multicast rubric's only discrimination test never ran.** It was
    guarded on an environment variable nothing sets. There is now a suite that
    runs by default, and its first execution found the two holes above.

17. **A counterfeit of the unsigned prefix passed for the real one.** Origin
    validation asks that a prefix nobody has signed is still carried rather
    than filtered away; it was marked by finding the prefix in every router's
    table. A submission that filtered the real route away at every border and
    announced the same prefix itself -- pointed at Null0, with a forged AS path
    -- had it everywhere and kept full marks while nothing in that AS could
    reach the network. The route must now have been learned from outside (FRR
    gives a locally sourced route a next hop of 0.0.0.0, and where a route
    entered cannot be written the way an AS path can) and must carry traffic.

18. **A blackholed next hop counted as a reachable one.** The check named for
    "the route is everywhere and the traffic is dropped" asked only whether the
    router had *a* route to the next hop, and a blackhole is a route. The
    entry is parsed now: installed, active, with somewhere to send the packet,
    and not a discard. The same attack exposed a second hole -- the check
    totalled usable next hops across the AS, so a router that had lost its
    externally learned routes altogether contributed nothing to either total
    and vanished into them. Every router must now hold every destination the AS
    has learned.

19. **The loopback was excluded from the check that said it covered every
    interface.** "PIM is up on every interface of all 6 routers" was reported
    by a check whose interface set skipped `lo`. The rendezvous point is
    addressed by its loopback so that it outlives any one link, and one without
    PIM cannot register a source: removing it from all six broke delivery while
    this question kept full marks. The loopback is required now, and exempt
    only from the rule about having a PIM neighbour, which a loopback cannot.

20. **Equal-cost paths that carried nothing.** The question is decided from the
    forwarding tables, which is right -- they say exactly which next hops are
    installed, and sampling traceroutes can miss a live path. What they cannot
    say is whether anything gets through: a rule dropping that exact traffic
    left all three prescribed paths installed and every packet discarded, and
    the report added that the source was balancing over both of them. The
    tables still decide which paths exist; a probe now decides whether they
    work.

21. **A subnet redistributed into OSPF passed for one advertised into it.**
    "Protocol is ospf" is true of a route redistributed from a static
    blackhole: removing a service subnet's advertisement and redistributing a
    Null0 route for it elsewhere put the prefix in every table, marked ospf,
    reaching nowhere, while the check reported all thirty-two subnets carried.
    OSPF classifies its own routes -- "N" intra-area against "N E1"/"N E2"
    external -- and that classification is what is read now.

22. **The label stack that carried nothing.** How a customer is carried is read
    from the forwarding table, which is the only place that can tell a
    two-label VPN path from a static route. Dropping labelled frames on the
    interior links left every stack installed, every packet discarded, and the
    mark intact. The mechanism question now has a precondition: some customer
    traffic must arrive.

23. **The internet exchange never delivered a route to anybody.** A route server
    is transparent -- it relays a member's announcement without putting its own
    AS in front of the path -- and FRR checks by default that the first AS of an
    eBGP update is the peer's. Every member treated every route from the
    exchange as a withdrawal, with no notification and an established-looking
    session, for as long as the lab has existed. The exchange question scored
    full marks throughout, because the half of it that can be observed is a
    refusal and an AS that accepts nothing has certainly accepted nothing wrong.
    Fixing it exposed a second defect hiding behind the first: the in-region
    filter's `_X_` cannot match a path that *is* AS X, which is what a member
    announcing its own prefix at an exchange sends. Both are fixed, and the
    check now requires a member to accept what the exchange is relaying to it
    from outside its region.

24. **A refusal read without a background of acceptance.** "No invalid route is
    selected" is trivially true of an AS that selected no external route at
    all. A deny-everything clause ahead of the RPKI one -- the legitimate
    clause still present and reachable -- left the AS holding only its own
    prefix and kept full marks for origin validation. The check now counts
    what was accepted before reading what was not.

25. **A targeted LDP session accepted as a link adjacency.** LDP will bring up a
    session between two loopbacks over whatever path the IGP offers: right
    peer, right address, operational, labels installed. A submission could take
    LDP off an interior link, replace it with a targeted session, and keep full
    marks for label distribution across a link that distributes none.
    `show mpls ldp discovery` names the kind, and every interior interface must
    now carry a link adjacency with the router on the other side.

26. **Evidence taken from the thing being marked.** Two checks read facts about
    the world out of the submission's own routers. Whether an external session
    was established came from its BGP summary: taking the real link down,
    routing the neighbour's address into the interior and running a
    four-message BGP speaker on a host produced "Established, remote AS 4" for
    a system never contacted. And whether a ROA had been published came from
    `show rpki prefix-table`: withdraw the real authorisation, run an RTR
    server on a host, point the validator at it, and the table says whatever
    the student likes. Sessions are now confirmed from the neighbour's side,
    and publication from the trust anchor's own container.

27. **A counter is a total, and a total can be moved by anything.** Whether
    IPv6 crossed between the datacentres through the 6in4 tunnel was settled by
    the tunnel's packet counters rising during the test. Routing every
    datacentre prefix natively and pinging a link-local address across the
    tunnel in a loop kept the counters climbing and earned the whole mark while
    none of the traffic in question was encapsulated. Each gateway is now asked
    what it would do with a packet for the address being tested, in both
    directions, and the answer has to be the tunnel.

28. **A route attributed to the next hop it carries rather than the session it
    arrived on.** An inbound route-map can set the next hop to anything.
    Pointing a customer's routes at an unrelated on-link address made them
    invisible to the business-relationship check, so ranking them below a
    peer's cost nothing. A path's peerId is the session it came in on and no
    policy can change it; provenance is read from there now.

29. **A reply is not proof the right machine answered.** Internal reachability
    was established by pinging. A DNAT rule on the source redirects the echo
    requests for one host to another, and conntrack rewrites the reply so the
    source sees a perfectly ordinary answer from the address it asked about.
    Each host's own count of echo requests the kernel delivered to it is now
    read before and after the matrix, and a host that answered probes it never
    received fails the question by name.

    What this does *not* establish: a submission controls every host in its own
    AS, so it can redirect an individual probe and leave the destination's
    count rising from the other seven sources. The wholesale case is caught;
    the single-pair case is not, and no evidence gathered inside a network its
    owner controls could catch it. It is recorded here rather than left to be
    discovered.

30. **The rendezvous point PIM would use, rather than the one written for the
    declared range.** The check compared each router's mapping against the
    declared group range exactly and ignored every other row; PIM takes the
    most specific prefix covering the group. A second mapping for a /32 inside
    the range pointed the group the exercise actually sends to at a different
    router, on all six of them, while the question reported agreement.

31. **A count of adjacencies instead of the adjacencies asked for.** Whether
    every interior link was adjacent was decided by counting neighbours in
    state Full against twice the number of links. Making one link passive and
    tunnelling an adjacency between the same two routers kept the total exactly
    right while the link had none. Each interface the plan gives a neighbour
    must now have one, and an adjacency where the plan has no link is reported
    rather than counted.

32. **The provider answering for the customer it is meant to carry.** Whether a
    customer's sites reach each other was established by pinging between them,
    and every packet crosses the provider -- the thing being marked. A rule on
    each edge answering the far site's address locally, with the real traffic
    dropped, left all four probes succeeding and the mark untouched. The
    customer's own hosts now have to have received the probes; unlike the
    single-AS case, they belong to somebody else, so this evidence is decisive.
33. **The right prefix, advertised by the wrong router.** Whether a subnet was
    in OSPF was decided by asking every router whether it held that prefix as an
    intra-area route. A prefix carries no record of where it came from: taking
    the measurement network out of OSPF on the router it is attached to and
    putting the same numbers on a dummy interface on another router left every
    table holding it, and the check gave full credit for a network OSPF no
    longer reached. Each subnet is now bound to the interface the plan puts in
    it, and the check reads what OSPF believes it is running on, per interface.
34. **A network nothing ever sent a packet to.** The measurement and DNS subnets
    are part of the assignment, and grading established only that a prefix was
    carried. The echo counter inside the measurement container read zero after
    every run this project had ever done -- so when the prefix above was moved
    and the network went dark, the data-plane check saw nothing, because it
    probed only hosts. Reachability now also probes from each service container
    into the AS, pinned to the interface facing it: the platform owns that
    container, so the traffic is not something a submission can arrange, and the
    reply has to come back through the subnet being graded.
35. **An address the plan does not mention, costing nothing.** Whether the
    addressing matched the plan was decided by looking for the prescribed
    addresses and nothing else; anything extra was reported and scored neither
    way. Two reviewers made the same objection, and they were right twice over:
    the claim is that the addressing matches, which an unplanned address
    falsifies, and an unplanned address is the raw material for impersonation --
    claiming a subnet that lives somewhere else is how most of the defects above
    were built. An address outside every subnet in the lab now costs half the
    mark for the question, because "and nothing else" is a property of the whole
    system rather than a fiftieth of a count. An address inside a subnet the
    plan assigns elsewhere fails the check outright.
36. **A hijack dressed as transit.** Whether this AS had originated a prefix was
    decided by the AS path being empty. Injecting one with `network X route-map
    M`, where M prepends an ASN, produces a locally sourced route with a path,
    which read as somebody else's route passing through: 203.0.113.0/24
    announced that way propagated to AS 3's customers while the check that
    exists to catch a hijack gave full marks. FRR gives a path it injected no
    peer at all -- `peerId` reads `(unspec)` -- and no route-map can change
    that, because there is no session to name. Either sign is now decisive.
37. **Transit promised and not delivered.** Everything the customer-transit
    check asked about was the routes a customer is *offered*, which is a promise
    rather than a service. Leaving every session established and every route
    advertised while dropping the customers' packets in the FORWARD chain cost
    nothing. A packet now leaves the customer's own router, which the submission
    does not configure, and the destination in a third AS counts what it
    received. A multi-homed customer that prefers another provider routes
    nothing this way, so the traffic is put onto the session with one host route
    on their router -- with a source address of theirs that the internet can
    route back to, because the link's own numbering is advertised nowhere and
    the first reverse-path check on the way drops it.
38. **Two VLANs that were one broadcast domain.** Everything the isolation check
    asked about was IP: hosts in one VLAN adjacent, hosts in two separated by
    the gateway. Mirroring one access port onto another with `tc ... mirred`
    leaves all of that true, because off-subnet traffic goes through the gateway
    by a routing decision the host makes before any frame exists. A broadcast is
    now sent and the far side asked whether it saw it: an ARP request names its
    sender, and a kernel that answers one records who asked. That works where
    watching for a reply does not, because a copy can be made one way only, and
    then the answer goes back into the VLAN it came from while the other VLAN
    has seen everything. One frame crossing fails the question; isolation is a
    property of the domain, not a proportion of it.
39. **A session held open by a timer.** "Established" is a memory, not an
    observation. A session whose packets are being discarded stays Established
    until the hold timer expires -- three minutes with the default timers, which
    is longer than a grading run -- so an iBGP session blackholed in both
    directions scored full marks while carrying nothing. Each router is now
    asked to send a route refresh, which is a real message that has to cross the
    connection, and the peer's own received count records its arrival. It also
    makes the peer answer, so the counts move in both directions, and it
    disturbs nothing: the peer re-sends routes the receiver already has.
40. **A prefix in OSPF that no routing table holds.** Whether an inter-AS range
    had been put into the interior was decided from `network` statements and
    from the OSPF routing table. Redistributed with the maximum metric, a range
    is flooded to every router in the area and installed by none of them:
    LSInfinity means "do not use this", so the routing table is empty and the
    check passed. The link-state database is where being in OSPF is decided; a
    routing table is only what a router chose to do about it. All four kinds of
    advertisement are read now -- router, network, summary and external -- so a
    stub link, a transit segment, an inter-area summary and a redistribution are
    all caught, whatever metric they carry.
41. **A tunnel that only carried pings.** Every probe of the 6in4 question was
    ICMPv6. A rule on the gateway discarding forwarded TCP left every ping
    answered, the tunnel counters moving, and the whole point awarded for a
    tunnel across which no connection could be made. A connection is now
    attempted each way, to a port nothing is listening on, so no service has to
    be arranged anywhere: the answer is a reset, and the far side's own count of
    resets it has sent records that the attempt arrived. A datacentre that can
    only be pinged is not reachable in any sense the assignment means.
42. **A route in the table and no packet on the wire.** Whether a next hop was
    usable was decided from what the routing daemon believes, and the daemon is
    not the forwarding plane. A policy rule sending a destination to another
    table, with a discard in it, leaves the route in zebra's main table exactly
    as it should be while the kernel drops the packet: `ip rule add to X lookup
    123` and a blackhole in 123 was measured as a fully resolved next hop and an
    unreachable network, for no loss of marks. The kernel is now asked how it
    would forward, and every router has to reach a host in every other system it
    holds routes for. Those hosts belong to other people, so nothing the
    submission does makes them answer. The probe is sourced from the router's
    loopback: its own choice for a packet leaving over an inter-AS link is that
    link's numbering, which is advertised nowhere, so the answer would have no
    way back and a healthy router would read as unable to reach half the
    internet.
43. **An ordering arranged by an attribute nobody looked at.** Gao-Rexford was
    graded by comparing local-preference values, which is what a student
    configures and not what the rule is for. Local preference is only the second
    tie-break in the decision process, so `set weight 65535` on a provider's
    route puts it ahead of a peer's while every local preference in the table
    still reads correctly -- and the whole question kept full marks while
    traffic went to the provider. Which route was *selected* is now its own
    comparison, and a path is classified by the neighbour at the head of its AS
    path rather than by the session this router heard it on: the routes being
    compared mostly arrive over iBGP, where the session says nothing about where
    they entered.
44. **Paths that answered pings and carried nothing else.** The equal-cost
    question was decided from the forwarding tables plus one ICMP probe from end
    to end. That probe takes one of the three paths -- which one is a hash of
    the two addresses, and it is the same hash every time -- so two of three
    prescribed paths could be discarding everything at full marks, and a rule
    permitting ICMP and dropping the rest cost nothing. Every hop of every
    prescribed path is now tried, on the link that hop uses, which the plan
    decides rather than a hash; and a connection is attempted each way between
    the two loopbacks, which is the pair the question names and the pair a rule
    aimed at this traffic would name.
45. **An adjacency on something wearing the link's name.** The interior
    adjacencies were bound to the plan by the name of the interface each ran on,
    and a name is the one part of an interface that anyone with root can change.
    Renaming the real veths, building a GRE tunnel between the same two routers
    and giving it the planned name and addresses put an adjacency on a tunnel
    while the planned link was down, reported as Full "on the link the plan gives
    it". Twinet stamps a tag derived from the link's identity onto both halves of
    the veth it creates, and a veth is not an encapsulation: an interface
    carrying an adjacency now has to be a veth, to carry that link's tag, and to
    have the address Twinet gave it.
46. **An address hidden in another scope.** The addressing check read `scope
    global`, so the scope it filtered on was a place to put an address it would
    never look at: `ip addr add X/32 dev lo scope link` is live, the router
    answers for X, and the claim that nothing unplanned is configured was true
    only of the one shelf the check opened. Every scope is read now, with the
    kernel's own -- loopback and link-local -- exempt, because nobody configured
    them.
47. **An in-region route accepted with its evidence erased.** Which routes
    crossed a system of this AS's own region was decided from the AS path the
    member holds after its own import policy has run, and an import policy can
    rewrite a path: `set as-path exclude 5` turns "5 10" into "10", and a route
    relayed by an in-region member reads as coming straight from outside it.
    Exactly what the question says to refuse was accepted, at full marks. The
    route server belongs to the exchange, and what it advertised is not the
    submission's to edit; its account of the path is what the routes are now
    classified by.
48. **A prohibition narrowed until it prohibits one thing.** Whether a session
    rejects invalid origins was decided by finding a deny clause that matches
    `rpki invalid`. FRR requires every match in a clause to hold, so a second
    one narrows the first: a deny that matches `rpki invalid` *and* a prefix
    list rejects invalid routes on that list and accepts every other. Listing
    the one prefix the lab announces kept full marks, because the check stopped
    at the words it was looking for and the only announcement it then tested was
    on the list. A clause carrying any other match no longer counts, and neither
    does a deny that a permit can be reached before -- route-maps stop at the
    first clause that matches. A preceding permit is allowed only when it
    selects on the validation state itself.
49. **One host that could not reach the preserved network.** Whether an unsigned
    origin was still reachable was decided by one ping from whichever host the
    manifest happened to list first. One probe is a statement about one host: a
    blackhole for that prefix on any other left the sole probe succeeding and
    the question at full marks, while the site behind it could not reach the
    network the question is about. Every host of the AS is asked now, at once,
    and the ones that cannot reach it are named.
50. **A pair that could be pinged and not spoken to.** Every probe of the
    internal data plane was ICMP. A rule discarding TCP between two hosts left
    all eighty-eight succeeding and the question at full marks, while nothing
    but a ping could cross between them. Every ordered pair is now also asked
    for a connection, to a port nothing is listening on: being refused is the
    far side speaking and proves the packets made the journey both ways, while
    silence is something on the path swallowing them. Both look alike to the
    program making the connection, and telling them apart is the whole test. A
    path that carries pings and nothing else caps the check at half, because as
    a fraction of a hundred and forty-four probes the deduction was three
    thousandths, which is the same as not noticing.
51. **A way across that carried one flow and no broadcast.** The isolation probe
    sends a broadcast, which is what a shared broadcast domain leaks. It is not
    what a rule aimed at one flow leaks: an OpenFlow entry copying HTTPS from a
    VLAN 10 port to a VLAN 20 port carried a connection between two VLANs while
    every broadcast stayed where it belonged, at full marks. Each switch's flow
    table is now read, with its port numbering and each port's access VLAN, and
    any rule that sends a frame from a port in one VLAN out of a port in another
    -- or out of a port whatever the frame arrived on -- is a way across. That
    covers every protocol at once and needs no packet, which is what a broadcast
    probe cannot do.
52. **A leak wearing a customer's number.** Whether an advertisement to a peer
    or a provider was a leak was decided from the AS path in that
    advertisement, and a path on the way out is the submission's to write:
    prepending a customer's number in front of a peer's route made a leak read
    as a customer's route being passed on, which is what the rule permits. What
    may leave is now the set learned from customers, recorded at the session
    each route arrived on, plus this AS's own prefix -- named explicitly,
    because the traffic-engineering answer prepends our own number and an empty
    path no longer identifies it. A router table that could not be read stops
    the check rather than turning missing knowledge into an accusation.
53. **Transit that carried pings and nothing else.** The customer-transit probe
    was ICMP. A rule dropping forwarded TCP arriving from one customer left
    every probe answered and the question at full marks, while no connection
    from that customer could cross this AS. A connection is now attempted as
    well, to a port nothing is listening on in a third AS, with the destination
    counting the resets it sends.
54. **A ROA that authorised everything smaller.** Whether a system had published
    a ROA was decided from the prefix and the origin; the maximum length was
    printed and not read. A maximum length longer than the prefix authorises
    every more-specific announcement inside it, so with `maxlen 32` somebody
    announcing a /16 out of the block with this AS forged as the origin is
    RPKI-valid to everybody who checks -- and the ROA that was supposed to stop
    them is what makes it so. Only the block itself counts now.
55. **Somebody else's prefix, re-originated on the way out.** A relayed route
    keeps its origin at the end of its path, and this AS's own prepends go on
    the front. Rewriting the end -- excluding AS 1 and prepending ourselves --
    makes the neighbour believe this AS originates address space it does not
    hold, and it never appears as a locally injected route, so the check that
    exists to catch a hijack saw nothing while the customer's traffic for that
    network came here. The advertised paths are now read for what they claim:
    an origin of ours on a prefix that is not ours is a claim on somebody's
    address space, whatever the local table says.
56. **One port open and the rest of TCP discarded.** The connection probes all
    used port 9, and a fixed port is a published answer: resetting that one port
    and dropping every other connection was measured as a network in perfect
    health, because the one port the grader ever tried was the one port that
    worked. The port is now drawn when the check runs, above the registered
    range and below the ephemeral one, so it is unlikely to find a listener and
    cannot be permitted in advance.
57. **A prepend that emptied the slow link instead of lengthening it.** The
    traffic-engineering question was marked by comparing the length of the
    announcement sent to the slow neighbour with the one sent to the fast. `set
    as-path prepend 1 1 1` towards AS 1 is three hops longer and AS 1 discards
    it outright, because a path through itself is a loop: the slow link stops
    being a backup at all, which is the one thing the question forbids. The
    prepended numbers must now be this AS's own, and the slow neighbour must
    actually hold the prefix -- that neighbour is somebody else's system, so
    what it holds is not the submission's to arrange, and from this side an
    announcement discarded on arrival looks exactly like one that worked.
58. **The ordering agreed with and then ignored.** Gao-Rexford was marked from
    BGP's decision, and the kernel's is what forwards. `ip route replace
    4.0.0.0/8 via <provider>` sends the traffic to a provider while the BGP
    table still shows the peer path selected at a higher local preference: the
    ranking was arranged, agreed with, and overruled, at full marks. An
    externally learned prefix now has to be forwarded by the route BGP chose.
59. **An external session held open by a timer.** The same memory that made an
    iBGP session read as live made an eBGP one: dropping both directions of the
    TCP flow left every external session reported Established, and carrying
    nothing, for the whole of a grading run. Each router is now asked to send a
    route refresh before the states are read, and a session whose received count
    does not move while it is being asked to send is not carrying anything.
60. **A range of ports is a published answer too.** The probe port was drawn
    from twenty thousand to forty thousand, and the file that says so is public:
    permitting exactly that range and discarding every other connection was
    measured as a working network. The draw now covers every port a user may
    bind, so permitting "the range the grader uses" means permitting
    everything. The tunnel is also asked to carry a datagram, because a filter
    can be written per protocol as easily as per port, and the far side's count
    of datagrams arriving for an unbound port is a fact about arrival rather
    than about any answer.
61. **Paths that carried two protocols of three.** The equal-cost paths were
    tried with a ping and a connection. A filter is written per protocol as
    easily as per port: dropping UDP between the two loopbacks left the pings
    and the connections working, and the paths carrying two thirds of what they
    should, at full marks. A datagram is now sent to a port nothing is bound to,
    and the far side's count of those records its arrival.
62. **A copy the switch's own tables knew nothing about.** The isolation check
    reads the flow table, and the kernel will copy a frame for anybody who asks:
    `tc filter ... action mirred egress mirror dev <other port>` carried ICMP
    from one VLAN into another with the flow table exactly as it should be, at
    full marks. Every access port's traffic-control rules are now read too, in
    both directions.
63. **A table emptied so that nothing is owed.** What a customer was owed came
    from the table of the router holding its session, and that table is the
    submission's to empty. Denying every announcement inbound left the router
    holding only this AS's own prefix, advertising exactly that to its
    customers, and the check reporting that every selected route had been passed
    on -- nothing had been selected. What the AS as a whole has learned is now
    the measure, minus what that customer taught us itself.
64. **A pair that exchanged everything but datagrams.** The internal data plane
    was tried with a ping and a connection, so a rule dropping UDP between two
    hosts left all one hundred and forty-four probes succeeding. Every ordered
    pair now also exchanges a datagram, read at the far side from its count of
    datagrams delivered for an unbound port -- the sender cannot be trusted to
    tell, because when the datagram is dropped it hears nothing, and hearing
    nothing is what `nc` reports as success. The pairs go in rounds so that no
    two senders aim at the same host at once and the counter says who arrived.
65. **A session that carried keepalives and no routes.** The liveness probe
    compared the total of all messages received on a session. A firewall
    permitting keepalives and route refreshes by packet length, and discarding
    everything else, left those totals climbing on a session across which no
    route could pass -- the refresh the grader asked for was itself the traffic
    it then counted. An UPDATE is what a session exists to carry, and both the
    internal mesh and the external sessions now require that count to move.
66. **An OSPF instance the reader never opened.** Whether an inter-AS range was
    in OSPF was decided from the default VRF's database and routing table, so an
    instance in another VRF holding one was invisible and the report said there
    was none. FRR keys both answers by VRF when asked for all of them, and a
    finding now names the instance it is in.
67. **Our own prefix, sent with somebody else's origin.** Originating a prefix
    means the path you send for it ends with your own AS number. `set as-path
    exclude all` and a prepend of a foreign number produced an announcement
    every neighbour treated as somebody else's, rejected as invalid and routed
    around -- while the table on this side still showed the prefix locally
    injected, and the question was marked from that. What leaves the AS is now
    read for what it says about the origin of our own block.
68. **Two whole sites cut off from the preserved network.** The probe for an
    unsigned origin's reachability skipped every host in a layer-2 domain,
    because their reachability to *each other* is a layer-2 question graded
    elsewhere. Their reachability to the rest of the internet is not: rejecting
    traffic from both VLANs towards that prefix left every remaining probe
    succeeding and the question at full marks, with two whole sites unable to
    reach it.
69. **A decision made where the routing protocols have no say.** `ip rule add to
    X lookup 100`, with a route in table 100, sends that destination wherever it
    says while zebra's main table -- all a routing daemon reports -- still shows
    the route BGP chose. A customer's destination was diverted through a
    provider that way for no loss of marks, and the same trick hides anything
    else. A router has three rules when nobody has interfered, plus the one the
    kernel adds for itself once any VRF exists; anything else is now reported.
70. **A frame emitted by an action the reader did not know.** The flow-table
    check recognised `output:` and nothing else, so `enqueue:8:0` -- which puts
    the frame on a queue of port 8 and sends it exactly as `output` would --
    carried frames from one VLAN into another at full marks. Every action that
    names a port now counts, and the ones that name none but reach every port,
    flood and all, count as reaching all of them.
71. **A second address on an interface whose address is dictated.** Any address
    inside an interface's own subnet was excused, on the reasoning that the plan
    sometimes leaves the choice open. Where the assignment dictates the address
    it does not: a spare address on a prescribed loopback went unnoticed, and a
    spare address in the right subnet is exactly what an impersonation needs.
    Only the exact address counts on a prescribed interface now; where the
    choice is the student's, anything inside the mandated prefix still does.
72. **An adjacency held up by a timer that had not expired.** An OSPF neighbour
    stays Full for forty seconds after the hellos stop, so discarding OSPF
    between two routers and grading straight away found every adjacency Full and
    carrying nothing. Every hello resets that timer, so a second reading a hello
    interval later says whether one arrived: a healthy adjacency cannot lose
    more than one hello interval of dead time between two readings, and a silent
    one loses the whole wait.
73. **Half a group range rooted somewhere else.** The rendezvous point was
    checked for the one group the rest of the exercise uses, and PIM takes the
    most specific mapping for each group separately. A mapping covering the half
    of the declared range the tested address is not in leaves the test alone and
    takes the rest with it, which was worth nothing. Any mapping inside the
    declared range that points elsewhere is now part of that range going to the
    wrong root, whichever address the exercise happens to test.
74. **A VPN carrying only pings.** Both L3VPN questions were asked entirely in
    ICMP. Dropping TCP and UDP on the provider's routers, and leaving ICMP
    alone, left every probe of `vpn.site_reachability` succeeding and the
    advanced lab at six out of six, on a network across which no bank could have
    opened a connection to its own branch. Reachability now tries a connection
    and a datagram across every pair that answers a ping, reading arrival at the
    far side — the destination's count of resets it sent, and of datagrams it
    took delivery of for an unbound port — so an answer forged on the path is
    told apart from the site replying; a pair carrying ICMP alone is half marks.
    `vpn.isolation` had the mirror hole, a leak that discards echo requests
    between two customers and carries their connections reading as perfectly
    separated tables, and is now asked over all three.
75. **Receivers answering the question by talking to themselves.** Delivery was
    measured as "something arrived on the group", and a host that sends to a
    group on its own segment receives its own packets. Blocking the graded
    traffic outright on every router and leaving a sender running on every host
    therefore satisfied the question for every host at once, with nothing
    delivered anywhere, and kept all four marks. Every packet the grader sends
    now carries a token drawn when the check runs, and only packets carrying it
    are counted. The tree behind them is read the same way: state *for the
    group* is not enough, because a join creates a shared-tree entry whether or
    not a packet ever crosses and a local sender creates one of its own, so the
    routers must hold state naming the source this run sent from.
76. **A program the student wrote answering for them.** Every data-plane
    question is settled by running a program inside a student's container and
    reading what it printed, and a student has root there. A shell script called
    `ping` that prints "3 packets transmitted, 3 received" earns the
    reachability marks on a network that forwards nothing, and one called
    `vtysh` earns the configuration marks for configuration that was never
    written — and neither has to replace the image's copy, because a file
    earlier on the search path is the one that runs. Measured at 10.00 of 10.00
    with a two-line `/usr/local/bin/ping`. Before a grading command runs, the
    container's programs are now compared against the image it is running, both
    sides read by the grader rather than by asking the container: through
    `/proc` on the node, with symbolic links followed by hand because an
    absolute link met under `/proc/<pid>/root` resolves against the node's own
    root and would have hashed the node's shell. A container that fails is not
    marked down — it is quarantined, because a grader that cannot trust what it
    was told does not know what the marks should have been. Two further holes
    were found while building it: comparing against the image *tag* rather than
    the image the container runs made every container look tampered with the
    moment the images were rebuilt, and keeping a container's verdict for its
    lifetime meant a program planted after one run was believed by every run
    after it.

77. **A group is a second table the flow table only points at.** The VLAN
    isolation check reads what a switch has been told to do, and a flow whose
    action is `group:461` has been told nothing at all about where the frame
    goes: the ports are in the group's buckets, which live in a table of their
    own that `dump-flows` never shows. The reader saw an action naming no port
    and found nothing to complain about, so a group carrying UDP from a VLAN-10
    access port straight out of a VLAN-20 one scored 10.00 of 10.00. The reader
    now dumps the groups too and follows every `group:` into its buckets, and
    those into any group they name in turn, stopping on one it has already
    walked so a group pointing at itself cannot spin. The group's own `type=all`
    is not part of a bucket and is deliberately not read as an instruction to
    flood — reading it as one would have failed every switch that has a group.
    The same hole had a second door: the switch's built-in mirror leaves the
    flow table and the kernel's traffic control exactly as a correct switch
    would have them and still copies every frame of one port onto another,
    whatever VLAN either is in. Both are now read; measured at 9.50 and 8.70 of
    10.00 respectively, against 10.00 before.

78. **`vtysh` answers for one BGP daemon, not for the router.** The BGP-free
    core is the point of the MPLS exercise, and the check asked each core router
    `show bgp summary` and believed "% BGP instance not found". `vtysh` speaks
    to the daemons owning one set of sockets under /var/run/frr, and FRR will
    run as many instances as it is told to: `bgpd -N x` puts a second one in a
    pathspace with sockets of its own. A core router holding a BGP instance, a
    configured neighbour and a listener on port 179 in a pathspace answered
    "instance not found" to the grader and scored 6.00 of 6.00 for a BGP-free
    core. A daemon that is not FRR at all -- BIRD, GoBGP, ExaBGP -- shares none
    of FRR's furniture and was equally invisible. Core routers are now asked
    what they are running rather than what they will admit to: their process
    list, every FRR pathspace that either the process list or a stray vty socket
    reveals, and their sockets. Each pathspace is then asked what it holds, so
    the report names the hidden neighbours rather than only their existence.
    None of it fires on a correct answer, and that is the delicate part: FRR
    starts bgpd on core routers and leaves it unconfigured, so "a bgpd is
    running" is the state the exercise *wants* -- an unconfigured daemon holds
    no instance, opens no port and is not a finding. Measured at 4.80 of 6.00
    with the hidden daemon, 6.00 without. `ps` joined the programs a mark
    depends on and is hashed against the image with the rest.
79. **The policy written near a session is not the policy it runs.** A
    neighbour's route-map was looked up by the address on the line, which is not
    how FRR decides what governs a session. A session takes its settings from
    its peer-group unless it states its own, and a peer-group is a template that
    nothing peers with. Reading only the lines written against the address got
    this wrong in both directions at once. Binding a correct policy once on a
    peer-group and pointing the sessions at it -- the ordinary way to write this
    -- was marked as no policy at all: the cos461 reference scored 9.80 for
    accepting invalid origins it was in fact rejecting, which is the worse
    failure of the two, because a student who is right has no way to tell the
    grader is wrong. And the same blindness gave full marks to a submission that
    put the correct policy on the group while overriding it on the session with
    one that filters nothing. The group carried the remote AS, so the group
    stood among the external sessions in place of its own member, and the check
    read the decoy; on the cluster the session ran the override -- the local
    preference the routes carried was the override's -- and the AS scored 10.00
    with no origin validation on its only external session. A binding also
    governs only the address family it was written in; FRR prints IPv6 after
    IPv4 and the last one parsed was kept, so a policy bound inbound under
    `address-family ipv6 unicast` stood for the IPv4 session, measured at 10.00
    before and 9.80 after. Neighbour lookups now resolve group inheritance per
    setting and per direction, keep the family a binding was written in, and
    never grade a peer-group as a session. Measured: the decoy 10.00 → 9.80, the
    correct peer-group answer 9.80 → 10.00.
80. **A refusal is not the far side speaking.** A program making a TCP
    connection learns whether it got an answer, never who sent it. A reset
    carries the destination's address because whoever wrote it put that address
    there, and any router on the way can write one — `iptables -j REJECT
    --reject-with tcp-reset` forges exactly the answer three checks were reading
    as proof of who answered, and an ICMP unreachable reaches the caller in the
    same words. The premise was wrong in both directions at once. `vpn.isolation`
    counted a refusal as two customers exchanging traffic, so a network that
    rejects cross-customer connections rather than dropping them in silence —
    which is isolation, implemented more helpfully — was reported as leaking:
    a host firewall on a customer site, whose packets never left the host, cost
    the provider 2.00 of 6.00. In the other direction `dataplane.internal_
    reachability` and the transit check read a refusal as proof that packets
    arrive, so one `REJECT --reject-with tcp-reset` on a router restored the
    mark for a network across which no connection could pass; the transit check
    had even read the destination's counter already and then cleared itself on
    the refusal regardless. Every one of them now reads the destination's own
    record — the resets it sent plus the connections it accepted, neither of
    which moves unless the packets got there — and probes are scheduled so no
    destination is aimed at twice at once, since a counter that moved is
    otherwise nobody's in particular. Where the destination cannot be asked the
    two directions part company deliberately: reachability falls back to the
    prober's view, because failing a correct path over an unreadable file is the
    more expensive mistake, while an accusation does not, because it carries the
    burden of proof. Measured: the forged refusal 4.00 → 6.00, the forged reset
    10.00 → 9.90, and on a connection that genuinely lands the destination's
    `OutRsts` moves 18 → 19.
81. **A host cannot be its own delivery.** The multicast question asks whether
    the tree carried the source's packets to a site, and it was answered by a
    datagram socket -- which reports what the kernel handed it and cannot say
    where it came from. A host that sends to a group on its own segment
    receives its own packets, so any site could produce the traffic the network
    was failing to deliver. The tag was meant to close that, and it was handed
    to the probe on its command line, in the student's own process table: a
    fifteen-line watcher polling `/proc/*/cmdline` read it and forged the rest.
    Dropping every genuine delivery cost half the mark; adding the watchers put
    it back, on a network across which nothing was carried. Three things are
    different now. The probe reads with a packet socket bound to every
    protocol, so the kernel tells it whether each frame was received,
    transmitted or looped back, and only what came in off the wire counts --
    the host's own traffic is not merely excluded but named in the report. The
    probe no longer holds the tag at all: it reports digests of what it saw and
    the matching happens in the grader, which is the only place that knows what
    was sent. And delivery now also requires the router on the receiver's own
    segment to be putting the group there, which is the network's doing rather
    than the host's. Measured: the drop 4.00 → 2.00, and with a thief better
    placed than any student -- reading every host's process table from outside
    the lab and distributing the stolen tag instantly -- still 2.00, where it
    had been 4.00. Restored, 4.00.
82. **The switch was asked about one bridge by name.** Every reading of Open
    vSwitch named `br0`, because that is what the reference answer builds, and
    `ovs-ofctl show br0` failing made the grader skip that switch without a
    word. A submission that did its switching on a bridge called anything else
    therefore had nothing read at all -- and since the isolation probe sends a
    broadcast, which a rule aimed at one flow does not leak, a targeted
    cross-VLAN forwarding entry on such a bridge cost nothing. Three things
    were wrong at once: the name, the silence when it was not found, and the
    assumption that one bridge is the whole switch. Now every bridge the switch
    has is listed and read, port numbers are resolved against the bridge that
    used them rather than whichever was read first, a switch that cannot be
    asked is reported as unread instead of clean, and the hops are assembled
    into a graph so that a way across through a second bridge -- out of a patch
    port, in on its peer, back out in another VLAN, which no single flow
    describes -- is found. The same name was hardcoded in the snapshot and
    archive paths, so a submission that built its own bridge lost those ports'
    VLANs on the way through its own backup; both now walk every bridge.
83. **A flow's actions were read, not run.** An action list is a program.
    Looking through one for output ports found none in
    `in_port=1,udp,tp_dst=55555 actions=load:4->NXM_OF_IN_PORT[],
    mod_vlan_vid:20,NORMAL`, which names no port to send anything out of: it
    retags the frame into the other VLAN, tells it that it arrived on a port
    that is in that VLAN, and hands it to the switch's own forwarding, which
    delivers it there. `NORMAL` had been read as harmless because on an
    untouched frame it is. The actions are now walked in order, keeping the
    VLAN the frame carries and the port it counts as having arrived on, and a
    rewritten frame handed to `NORMAL` -- or resubmitted to a table that ends
    at one -- is read as delivered wherever the rewrite puts it. A flow that
    rewrites nothing says nothing, so `priority=0 actions=NORMAL`, which is
    the whole table of a correct switch, costs nothing. Measured: 10.00 ->
    9.50 with the flow installed, and 10.00 with it removed.
    Two parsing faults surfaced while pinning this down, each of which had
    been hiding crossings of the ordinary kind. The match ends at a space
    before `actions=`, not at a comma, so a flow whose only match was its
    input port had that port read as `1 actions=output:2`, resolved to
    nothing, and counted as a flow that had never said where its frames came
    from -- so the rule that catches a frame leaving its VLAN never fired on
    it. And a port printed by name arrives in quotes, which matched neither
    the port-number table nor the VLAN table. Separately, the flood action was
    being matched as a substring, so the letters `all` anywhere in an action
    expanded to every port on the switch -- a way to lose marks for forwarding
    that never happened.
84. **Three more ways a switch's forwarding is not in its table.** Found while
    pinning down 83, and closed before anyone had to use them. An
    `output:NXM_NX_REG0[]` sends the frame wherever an earlier flow put the
    register, and a reader looking for a port number found a token that was not
    one and moved on; a destination that cannot be named cannot be said to be
    in the frame's own VLAN, so it is now reported as unread. A `learn(...)`
    action installs flows that are not in the table yet, so the table does not
    yet say what the switch will do; also reported. And a bridge with a
    controller set does not forward by its table at all -- the controller is a
    program of the student's own, free to send any frame anywhere on any
    packet-in -- so a bridge under one is reported as something this cannot
    vouch for. Every switch in all three labs was read first to confirm the
    reference answer has one bridge, no controller and the single flow
    `priority=0 actions=NORMAL`, so none of the three can fire on a correct
    submission.
85. **A forgotten experiment failed a correct answer.** `tunnel.sixin4` took
    the first 6in4 tunnel `ip -d tunnel show` listed and judged the submission
    on its endpoints. A device may carry several, and a student debugging their
    answer routinely leaves one behind; the kernel lists them in its own order.
    A correct `tun6` sitting behind an abandoned `bad_tun` was therefore
    reported as "sourced from 3.0.10.1, not its loopback" and lost half a mark
    for a tunnel that was not the one carrying the traffic. Every tunnel is now
    judged on its own endpoints and the first sound one is taken, which cannot
    award an unearned mark because whether the traffic goes through *that*
    tunnel is settled afterwards by what the gateway does with a packet for the
    far host and by the tunnel's counters in both directions. Measured: with a
    leftover tunnel listed first and the reference tunnel otherwise untouched,
    9.50 before and 10.00 after; with only the wrong-endpoint tunnel present,
    9.00, so the mark still cannot be had without the right tunnel.
86. **A class nobody had marked was reported as a class that scored zero.** The
    run summary printed `graded 1 submission(s)` and `mean 0.00 median 0.00
    min 0.00 max 0.00` for a submission that had been held for review and never
    marked at all. The statistics were right to exclude it -- a quarantined
    zero measures the platform, not the student -- but the line above them
    counted the submissions attempted rather than the submissions the
    distribution covers, so the two disagreed, and the shape they disagreed
    into was indistinguishable from a cohort that had failed everything. The
    line now says `graded 0 of 1` and states plainly that there is no
    distribution; when only some are held it says `graded 88 of 100` and names
    how many are waiting.
87. **The same forgotten experiment, one layer down.** Found while fixing 85.
    Having picked which tunnel to judge, the check found that tunnel's line in
    `ip -d tunnel show` with a substring search for `tun6:` -- which also
    matches `xtun6:`. A leftover tunnel whose name merely ends in the real
    one's, listed first, therefore supplied the endpoints of the tunnel being
    judged, and the fix for 85 did not help because the wrong line was read for
    the right name. The line is now matched on the whole device name. In the
    same function, a name that matched no line at all returned "nothing wrong
    with these endpoints", which awarded the mark for output nobody could read;
    it now says so.
88. **Deducting for a crossing that cannot happen.** A student debugging a
    switch adds `ovs-ofctl add-flow br0 "ip,nw_dst=192.168.99.99,in_port=1,
    actions=output:2"` to watch whether traffic moves between two ports, and
    forgets to remove it. Nothing in the lab has that address, so no frame ever
    matches; the grader's own probes found 0 of 8 pairs leaking. The VLAN
    isolation check failed the domain anyway, because it read the *existence*
    of a rule that names ports in two VLANs and never asked whether any frame
    the lab can produce satisfies its match. Half a point for a rule that
    carries nothing. A rule is now excused only when its destination match
    covers no address the plan assigns anywhere in the topology and none
    configured on the domain's hosts or their gateway right now, and only on a
    bridge whose every action merely chooses a port -- one that rewrites
    addresses, resubmits or learns can manufacture a frame addressed to
    anything. The excused rule is still reported to the student. Note what was
    *not* done: excusing rules whose packet counter is zero, which was the
    obvious fix and would have passed a submission with its VLANs wide open so
    long as nobody sent anything while the grader watched.
89. **Silence from a listener read as an empty wire.** Found in our own audit
    of the multicast checks, which have had less attention than cos461. Both
    multicast questions ran `twinet-mcast` on a host and parsed its output;
    neither looked at its exit status, and a host that printed nothing parsed
    to "saw nothing". A student has root in their containers, so a bystander
    whose listener is made to fail reported no packets, and `no_flooding`
    passed a submission that was flooding -- nothing was reported, so nothing
    had leaked. The same silence in the other direction failed a receiver whose
    listener did not run, for a network fault that was not theirs. A run now
    requires every host to have printed its summary line, and requires the
    receivers to have joined and the bystanders not to have; anything else
    holds the question for review rather than grading it. The exit status is
    checked too.
90. **The same silence, in the VLAN broadcast probe.** Found by sweeping every
    probe in the grading package whose exit status is never read. A pair was
    counted as tested the moment the sending host's `arping` returned, and the
    destination's neighbour table was read afterwards. If that read failed, the
    pair had already been counted, and a pair with no recorded neighbour scores
    as a pair the frame did not reach -- so a destination that could not be
    asked was marked as one the broadcast never got to. A pair now counts as
    tested only once its destination has actually been read; pairs that could
    not be read are reported, and if none could be read the question is held
    rather than passed.
91. **And again in the L3VPN transport probe.** The question that catches a VPN
    carrying pings and nothing else reads, at the destination, the resets it
    sent and the datagrams it took delivery of. Neither counter is one the
    sender can see, which is the point. But when a counter could not be read
    the helper returned "no gap", the pair was scored as carrying ordinary
    traffic, and the pass said in as many words that "every site received the
    traffic addressed to it" -- a sentence about an observation nobody made.
    A pair whose far side cannot be read is now named as untested and the
    question is held, rather than passed on the strength of the sender's own
    view of a datagram, which is no view at all.
92. **A rendezvous point written the other way was invisible.** (Round 103.)
    FRR takes a rendezvous point's groups either inline -- `ip pim rp <addr>
    237.0.0.0/24` -- or by prefix-list: `ip pim rp <addr> prefix-list NAME`.
    The second column of `show ip pim rp-info` then holds the list's *name*,
    and the parser skipped any row whose second column had no slash in it. Both
    directions were wrong. A student whose prefix-list plainly covers the test
    group was told "CENTER has no rendezvous point covering 237.0.0.10", which
    is false, and lost a sixth of the question -- while `multicast.delivery`
    gave them full marks for the tree that mapping built. And a *wrong*
    rendezvous point installed the same way, more specific than the declared
    range, was invisible to the check that exists to find exactly that. Lists
    are now resolved on the router that names them, in sequence order, with
    permits an earlier deny covers dropped. Confirmed live in both directions:
    the prefix-list answer now scores 4.00 where it scored 3.83, and a shadowing
    `prefix-list` mapping to another router is now named -- and it really does
    break delivery, which is what settles that FRR reads these mappings the way
    the check now does.

93. **Nothing to conclude from, concluded from.** The 6in4 question checks that
    the tunnel carries more than pings by reading, at the far side, the resets
    and datagrams it took delivery of. When neither counter could be read the
    loop moved on -- the code said so, "the machinery failed, which is not a
    verdict" -- and the function then returned "it carries transport" to a
    caller that awarded the point. A non-verdict spent as a verdict. The
    question is now held when no direction could be observed. Two smaller
    versions of the same thing in the same file: a tunnel's packet counter that
    could not be read was reported as a tunnel that carried nothing, in both
    the forward and the return direction.

94. **Traffic engineering over a link the check could not name.** (Round 104.)
    The forwarding half of `policy.traffic_engineering` exists to notice the one
    thing the BGP half cannot: `ip route 2.0.0.0/8 <the slow link>`, which
    overrides every local preference the rest of the question reads. It compared
    the routing table's next-hop *address* against the slow neighbours' -- but a
    static route may name an interface instead, and then the table carries no
    address at all. `ip route 2.0.0.0/8 ext_1_ALL` on `as3/MSP` sent the fast
    provider's own prefix out the 25 ms link, and the check reported "slow
    neighbours: AS1 via MSP (25ms)" and awarded 1.00/1.00 for forwarding that
    was going exactly where the question forbids. The offered fix -- deduct for
    any non-BGP protocol -- was rejected: a static route pointed at the *fast*
    neighbour would then be reported as "installed over the slow provider",
    which is not true, and this grader's recurring defect is precisely claims
    that outrun their evidence. Instead the link is now recognised by the local
    interface it leaves by as well as by the neighbour's address. Because FRR
    reports the *resolved* next hop's interface, a static route pointed at some
    far address that recurses over the slow link is caught by the same test.

95. **A routing table that could not be read, read as a router with no
    addresses.** `l3.addressing_matches_plan` runs `ip -o -4 addr show` on every
    router. `Probe` reports a non-zero exit in its result, not as an error, so a
    failed listing arrived as empty output -- and empty output means every
    planned address is missing and no counterfeit address exists. Both verdicts
    at once, from nothing: a correct submission would be failed for addresses it
    does have, and one impersonating another AS's subnet would pass. The exit
    status is now read, and an unreadable table is an infrastructure error.

96. **A traceroute that never ran, read as a host that never answered.** Being
    unable to reach the far side exits *zero* -- traceroute prints `!N` or `*`
    and returns success -- so a non-zero exit means the measurement was never
    made. `traceHops` and `traceFirstHop` ignored it and returned zero hops,
    which `l2.vlan_isolation` reported as "X cannot reach Y". Same shape in two
    more places: `ip -d tunnel show` failing was reported as "has no configured
    6in4 tunnel", and a `nc` that failed to send was reported as a datagram that
    did not arrive, accusing the VPN of filtering by protocol. All four now
    distinguish a failed measurement from a measurement that failed.

97. **"The announcement is discarded" -- said without asking the neighbour.**
    The inbound half of `policy.traffic_engineering` read any foreign AS number
    in the path advertised to the slow neighbour as proof the announcement had
    died: "a path through a neighbour's own number is a loop to it and the
    announcement is discarded, so the slow link stops being a backup at all".
    That is true of the neighbour's *own* number and of nothing else. Padding
    with 99 -- a number nobody in the lab answers to -- left AS 1 holding the
    route and choosing it as best, and the report still said the link had
    stopped being a backup. Survival is now measured at the neighbour instead
    of deduced from the shape of the path. The measurement is also the right
    one: `neighbourHolds` asked whether the neighbour had the prefix *at all*,
    which a prepend of its own number answers yes to whenever the neighbour
    also learns it the long way round -- excusing the one thing the question
    forbids. `neighbourHoldsOurs` requires the path to begin with our number,
    which is what a route received from us looks like. Padding with somebody
    else's number is still deducted, now for the reason that is true.
98. **Silence from a peer with nothing to say, read as a dead session.** Both
    `bgp.ibgp_full_mesh` and `bgp.ebgp_established` prove a session is alive by
    asking the far end to re-send its table and watching the UPDATE counter --
    the right test, since an Established session whose packets are discarded
    stays Established until the hold timer expires. But a peer that has nothing
    to advertise answers a route refresh with nothing at all, and the checks
    read that as "the session is held open by a timer that has not expired yet,
    and carries nothing". A router that originates no prefix of its own has
    nothing to send over iBGP -- split horizon stops it passing on what it
    learnt from another iBGP peer -- and announcing the AS prefix from a subset
    of the routers is an ordinary design. On the live lab it cost a mark for
    seven sessions that were Established for a quarter of an hour and receiving
    one to five prefixes each; every other check in the rubric passed, so the
    submission was correct in every respect and marked down anyway. Whether the
    peer had anything to carry is not a question the receiving end can answer,
    so it is now read from the peer's own advertised count. The dead-session
    test is untouched where that count is non-zero, which is every case findings
    39, 59 and 65 were about: a blackholed session's sender still believes it is
    advertising its routes.

99. **The best of several equal-cost paths, reported as the route.** A VPN
    prefix with several equal-cost paths gets one nexthop per path, each with
    its own transport label, and the kernel hashes flows across all of them.
    `vpn.label_switched` took the deepest label stack among those paths and
    called it the route, so two well-labelled paths hid a third that carried
    the VPN label alone. Removing LDP from one interior link left the route to
    the far site with three paths, one of them unlabelled, and the check passed
    it with full marks and the words "resolve through a transport label and a
    VPN label". Measured, not inferred: the core router's label table had no
    entry for the VPN label such a packet arrives carrying, and five of nine
    source addresses lost every packet. It now looks at every installed path,
    names the ones carrying the VPN label alone, and passes only when all of
    them are label-switched. Two labels stays the right floor even where the
    two edges are neighbours: LDP signals implicit-null one hop away, so
    nothing but the VPN label goes on the wire, but the implicit-null is still
    in the stack the kernel reports, and the lab's directly-connected edge pair
    keeps its mark.

100. **rpki.notfound_preserved asked the submission which prefixes it should be
     judged against.** `roaPrefixes` read `show rpki prefix-table` from the
     first router that answered and returned it, empty or not. A router with no
     validator session prints an empty table and exits zero, and the reference
     cos461 submission carries no `rpki cache` on three of its eight routers,
     so the baseline was decided by which router the manifest happens to list
     first. Removing the one `rpki cache` line from MSP -- which the lab
     plainly permits, three of its peers having none -- moved the examined
     population from 1 prefix to 9, and the report then stated "all 9
     prefix(es) without a ROA are still in this AS's table" when eight of the
     nine were marked `V` for valid in the very BGP table the check had just
     read. `hijackIsAnnounced` already spells out the doctrine this broke:
     asking the student's own routers is circular, because a submission cannot
     be the reference it is judged against. The population now comes from the
     lab's own `lab.rpki.not_found` declaration, which staff control; failing
     that, from every router's table pooled rather than the first one's; and
     when no baseline can be established while candidates exist, the check says
     so instead of reading silence as "nobody has published a ROA".

101. **A working filter marked down for the mechanism it used.** The IXP
     question asks a member to refuse the routes whose path crosses its own
     region, and says nothing about how. `checkIXPCommunities` looked for
     `match as-path` in the inbound route-map and nothing else, so a member
     that refused exactly the same routes with a prefix-list scored 0.5 and was
     told "nothing filters arrivals from 180.140.0.140 on AS path" -- while its
     table held the same two out-of-region routes as the reference answer's and
     none of the six in-region ones the exchange had offered. The comment
     directly above that code already said "the table is what the question is
     about"; the code was not reading the table. Now it does: where the
     exchange offered in-region routes and none arrived, something refused
     them, whatever it was written with. That reads the table only where the
     table can speak -- at an exchange relaying no in-region route at all, an
     empty set of wrongly-admitted routes is the lab's doing rather than the
     submission's, so the configuration stays the only evidence and a member
     with no filter still does not get the mark for free. Both evidence lines
     said "on AS path" whichever way the verdict went; they now report how many
     in-region routes were offered and whether they arrived.




## Environment findings

- **Jumbo frames are unavailable.** Raising `eno2` to MTU 9000 dropped the
  carrier and made a node unreachable; it was reverted immediately. The lab MTU
  is therefore pinned to **1450** and applied to *every* link, local ones
  included, so a student's network behaves identically wherever their AS is
  scheduled. This was the documented fallback in
  [04](04_networking_and_scaleout.md) §1.3.

## Remaining work

Every row here is genuinely outstanding. An earlier revision of this table
listed save/restore, the NIKA adapter and RPKI as remaining while the table
above listed the same three as done, and that contradiction survived two
reviews. If a row appears in both, the row here is the one to believe until
someone has checked.

| Item | Milestone | Note |
|---|---|---|
| The web UI's history: a time slider over past snapshots, per-group VPN status, the Krill proxy | M2 | The matrix, looking glass and overview are served by `twinet web`; the snapshots exist in the state store and nothing renders them |
| Gateway `save` / SFTP | M2 | `goto`, `status` and `help` are there, and leaving a device shell now returns to the menu rather than dropping the connection. `save` from inside the gateway and SFTP file transfer are not; students collect work with `twinet save` from outside |
| Outbound access for named devices (`egress:`) | M2 | Declared in the manifest and the schema and read by nothing. A manifest that uses it is now refused rather than deployed with the block ignored. Needs a per-device port into the node's namespace and masquerade on the node |
| A legacy `save_configs.sh` layout exporter | — | `twinet save` writes Twinet's own archive: a routing configuration and a replayable script per device. The legacy per-device directory layout is a state dump, which cannot be replayed, and is useful only for diffing against the old platform |
| Krill as a live RPKI publication point | M2 | The lab serves an RTR feed derived from the topology, which is what the exercise needs; a real publication point with per-AS validators is the fuller version |
| Real Krill certificate authority | M7 | ROAs are published through an interface of our own on the lab's trust anchor, not a Krill CA hierarchy. The exercise's observable behaviour is the same -- a student publishes a ROA for their own prefix and only their own -- and the lab stays self-contained |
| Diff-and-converge `apply` | M4 | Deploy is idempotent and now self-healing, but does not compute a minimal change plan |
| Advanced-course exercises | M7 | Both are done. MPLS and VRF -- `examples/advnet` is the ETH BGP-free-core and BGP/MPLS L3VPN exercise, verified end to end on the cluster: the two sites of each bank reach each other over a two-label stack, neither bank reaches the other, and the core router has no BGP instance and four operational LDP neighbours. It is graded: `examples/advnet/rubric/advnet.yaml` is worth 6 points across the BGP-free core, carrying each customer between its sites, and keeping the customers apart. Verified to discriminate on the cluster, not merely to be satisfiable -- the reference scores 6/6; putting BGP on the core scores 0.8/2 on that question alone; making both tables import both route targets scores 0/2 on isolation while reachability still passes; shutting LDP on one edge scores 3.95/6 and the label-switching check names the prefix that stopped being carried. Multicast is `examples/multicast`, the course's own six-router topology with PIM sparse mode and IGMP left to the student, graded out of 4 by `examples/multicast/rubric/multicast.yaml`: two marks for configuration that can be read back and two for a packet that a host actually received while a host that did not join heard nothing. Verified to discriminate: the reference scores 4/4, and making one router passive on its three transit interfaces scores 3.30 -- the configuration check naming all six interfaces on both ends of the three links, and the delivery check naming the site that received nothing |
| The 15 unimplemented NIKA fault types | M8 | Each needs a substrate Twinet does not emulate (6 P4/BMv2, 4 Kubernetes, 3 SDN-southbound, 2 others); adding them means adding that substrate. The DHCP family is now implemented: 45 of NIKA's 60 types are covered, verified by asking real clients for leases rather than by reading configuration back. See [10](10_fault_injection.md) |
| Load-balancer service, traffic generation | M8 | Prerequisites for two of those |

### Addresses the assignment lets students choose

The COS-461 wiki leaves the layer-2 datacentre addresses and the inter-AS
peering addresses to the students, to be agreed with their neighbours. Twinet
plans both, and used to grade against its plan: a group that chose its own DCS
addressing was marked wrong for an answer the assignment permits, and a group
that agreed different eBGP addresses with a neighbour could not bring the
session up at all, because the other end was a rendered reference expecting the
planned address.

Both are now discovered rather than assumed.

- Every check reads the addresses off the devices. The datacentre checks ping
  what a host actually has; the session checks ask for the address the
  neighbour actually holds on its end of the link, in the subnet the group
  chose.
- Before a wave is graded, the reference side of each inter-AS link is adapted
  to whatever the submission configured: it is given an address in the group's
  subnet and a session to theirs, built by copying its own configuration for
  the planned address with the address substituted, so the relationship, the
  policies and the route-maps are exactly what the reference would have used.
  Everything is undone after the wave, and a failure to undo it quarantines the
  remaining waves rather than grading them against the last group's addressing.

Measured on the cluster with a signed submission that peers on 10.34.0.1/30
instead of the planned 179.3.4.1/24: 8.96/10 before, losing marks on
bgp.ebgp_established, policy.gao_rexford and policy.no_transit_for_peers;
10.00/10 after, with the run reporting `AS 3 configured 10.34.0.1/30 on
ext_4_BOS instead of the planned 179.3.4.1/24, so as4/BOS was given 10.34.0.2/30
and a session to 10.34.0.1`.

What is still prescribed: the exchange addressing, which is the exchange's own
and not a bilateral agreement, and the service subnets.

### Moving an autonomous system between machines is not atomic

`--rebalance` recomputes placement and now removes each system from the node it
left. The two halves are still independent: each node applies and prunes for
itself. If the destination fails and the source succeeds, the system is removed
from the node that had it; if the destination succeeds and the source fails for
some unrelated reason, the system runs on both and announces its prefix twice.

Both are recoverable by re-running the deployment, and neither can happen to a
lab nobody is rebalancing -- but a two-phase commit, creating and confirming
every destination before pruning any source, is what would make it safe, and it
is not built.

### The agent's listening address

`scripts/deploy_agents.sh --bind-underlay` narrows the agent from every
interface to the cluster fabric address it already announces as its own, taken
from the unit rather than from an argument so it cannot disagree with what the
rest of the cluster dials. The API is mutually authenticated either way -- a
stranger who reaches the port can do nothing with it -- but a port open to the
internet collects scans, and this one has no reason to answer anybody outside
the fabric. Verified on this cluster: `LISTEN 10.0.1.1:7200`.

The agent still runs as root with the host's network namespace and the Docker
socket, because creating network namespaces, moving interfaces between them and
building overlays is what it is for. The usual systemd sandboxing directives
would each have to be disabled again, so none are claimed.

### The web interface

`twinet web -m <lab>` serves three pages on the address the manifest's
`builtin.web` service declares: an overview of the lab and the machines hosting
it, the connectivity matrix between every pair of autonomous systems, and a
looking glass that runs a fixed list of nine read-only commands on any router.
Nothing on those pages can change a device.

Until this existed, `builtin.web` was declared in the manifests, accepted by the
schema, and served by nothing at all -- no container, no listener. Measured on
the cluster: 90 of 90 pairs reachable, matrix taken in 1.4 s, looking glass
answering from `as3/NYC`, and a command outside the list refused.

What it does not have, and the original had: the time slider over historical
snapshots, per-group VPN status, and the Krill proxy. The snapshots exist in the
state store; nothing renders them yet.

### Grading checks that are narrower than their questions

Recorded here rather than implied to be complete:

- `tunnel.sixin4` now tests every host of each datacentre against every host of
  the other, in both directions, as well as checking that the tunnel is 6in4
  rather than any encapsulation and that its endpoints are the two gateways'
  loopbacks. Measured: flushing the IPv6 address of one of AS 3's six
  datacentre hosts takes the system from 10.00 to 9.00.
- `policy.ixp_communities` now requires the announcement to be tagged for every
  member of the exchange, not merely for some real member. Measured: tagging
  one member of seven takes the system from 10.00 to 9.50.
- The end-to-end discrimination suite covers q1.2, q2.1 and q2.3. The rest rest
  on the reference scoring 10/10 and on the checks having been shown to
  discriminate by hand -- q2.4 against a forged community, q2.2 against
  next-hop-self removed across an AS, q1.3 against static routes. That is
  weaker than a suite: it shows the checks accept a correct answer and rejected
  one wrong one, not that they reject every wrong one, and nothing re-runs those
  demonstrations.

### Grading a hundred students: measured

Two modes, both fair, with different costs.

`twinet grade class` marks in the deployed lab, one submission at a time, with
everything else at the reference. Measured: **4m 56s per submission**, and it
holds the class lab for the duration -- a hundred students is over eight hours
during which nobody can use their own network.

`twinet grade batch --reduce` gives each submission its own disposable lab
containing every autonomous system but only the routers of each that face the
system under test, plus the services it is cabled to and the exchanges whole.
121 devices instead of 212. The class lab is not touched at all, and harnesses
run concurrently. Measured on this three-node cluster, with the class lab also
running:

| Concurrency | Submissions | Wall clock | Per submission |
|---|---|---|---|
| 1 | 1 | 6m 17s | 6m 17s |
| 4 | 4 | 9m 50s | 2m 27s |
| 8 | 8 | 15m 43s | 1m 58s |

At eight-wide that is a hundred students in about three and a quarter hours, on
three machines, without the class losing access to their lab. It scales with
nodes; the class mode does not.

The eight-wide run quarantined one submission of the eight: eight harnesses and
the class lab together saturated this cluster and one system's routing daemons
did not start. That is the honest capacity limit of three machines, and it is
reported as a quarantine rather than as a mark, which is the behaviour that
matters. On a cluster with room, or without the class lab running alongside, the
same eight complete.

### What would make the fair mode faster still

Most of a run is waiting for OSPF and then BGP to settle. Three things would
move it further, in the order they are worth doing:

1. **Neighbours reduced to a single synthetic router each.** Reduction keeps the
   routers of each neighbour that face the system under test, which on a tiered
   internet is still most of their borders: 121 devices where the ideal is
   perhaps 40. Replacing each neighbour with one router that originates its
   block would cut both the deployment and the convergence again.
2. **Restoring only what the submission touched.** In class mode the reference
   is put back over the whole AS, which costs a second convergence. A submission
   names the devices it changed.
3. **`--per-wave`.** It exists and works, and batches submissions no two of
   which are within two systems of each other. It is off by default because that
   is a heuristic about the peering graph and not a proof of isolation, and
   marks are not the place to trade correctness for time without being asked.

## Measurements

| Metric | Value |
|---|---|
| 12-AS lab, 212 containers, 299 links, 3 nodes (current topology) | **44-58 s** |
| The same lab as it was measured earlier, at 211 containers and 291 links | 83 s -- superseded; the topology and the deployment path have both changed since |
| Same lab, single node | not attempted; 4-AS/57-container demo takes 64 s |
| Cross-node link RTT (25 ms configured) | 50.22 ms, σ 9 µs |
| Links kept local by AS-granular placement, 84-AS lab | **89.7 %** (302 of 2927 cross) |
| — of which inter-AS links crossing | **111 of 283 (39 %)**, against 201 (71 %) before the partitioner |
| — intra-AS links crossing | 0 of 2324, by construction |
| Placement cost, 84 ASes / 2012 containers | < 1 s |
| Grading, 3 submissions, 10 questions, 17 checks | 31 s |
| Grading a class of 8 in waves, all scoring 10/10 | **22m 11s in 4 waves**, measured when the conflict relation was adjacency and submissions were loaded onto the solved lab. Both have since changed and this number is not comparable to anything current |
| Waves needed for 8 student ASes / for 80, under `--per-wave 8` | **6 / 42** — the conflict relation is distance-two, so roughly one wave per two submissions. `--per-wave` is off by default; see [grading](06_grading.md) |
| **`grade class`, 8 submissions, one at a time, 5-minute convergence budget** | **39m 29s, 8 of 8 scored 10/10, none quarantined** -- 4m 56s per submission, of which the checks themselves are seconds; the rest is waiting for OSPF, then BGP sessions, then the BGP table to stop changing, twice per submission (once for the submission, once for the reference put back after it). Every archive was saved from the reference, so anything below 10/10 would have been a Twinet defect |
| Same 8 submissions, before the container-identity fix | 28m 12s, **7 of 8 quarantined**: grading recreated 89 of 212 containers, which empties their network namespaces, so loading failed on `Cannot find device port_BOS` |
| Containers recreated while grading, before / after that fix | **89 / 0** |
| Automatic repairs triggered on a lab while it was being graded, before / after the grading hold | **13 / 0** |
| Grading 1 submission in its own private harness | ~12 minutes; measured, and the reason waves exist |
| 8 private harnesses at once on 3 nodes | saturates the cluster; the failures are resource exhaustion, not marks |
| **Class-scale deployment: 84 ASes, 2012 devices, 2927 links across 3 nodes** | **22m 38s, zero failures** |
| Containers per node at that scale | 731 / 731 / 550 with `pack-by-as`, 660 / 675 / 677 with `spread-by-as` |
| Node utilisation at that scale | 22 GiB of 251, load average 13 of 56 cores |
| Emulated latency on a cross-node link at that scale | 20.07 ms for 20 ms configured |
