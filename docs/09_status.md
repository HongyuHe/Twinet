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
