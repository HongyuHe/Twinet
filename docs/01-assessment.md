# 01 — Assessment of the current mini-Internet implementation

Reviewed at `/users/hy/mini-internet` @ `c2e8827` ("Modify topo for typonet poc").
This is the Princeton COS-461 fork of the ETH `nsg-ethz/mini_internet_project`.

## 1. What the platform does (and does very well)

The mini-Internet gives every student group a full Autonomous System — 8 FRR
routers across US cities, L2 datacenters with Open vSwitch and VLANs, hosts,
and eBGP links to other groups' ASes and to IXP route servers. Students SSH
into a per-group proxy and configure everything themselves. Auxiliary services
(connectivity matrix, looking glass, DNS, RPKI, measurement vantage point,
website) close the feedback loop.

**The pedagogy is excellent and must be preserved verbatim.** Concretely, the
COS-461 assignment (`https://github.com/cos-461/routing/wiki`) requires:

| Q | Task | Platform capability required |
|---|---|---|
| 1.1 | L2 connectivity, VLAN 10 (admin) / 20 (patient), tagged + trunk ports | OVS switches, sub-interfaces `ATL-L2.10`/`.20` on the gateway router, per-host L2 attachment with VLAN id |
| 1.2 | IPv4 addressing + OSPF network-wide, advertise all subnets | FRR `ospfd`, deterministic prescribed subnets (`X.0.N.0/24` links, `X.[150+Y].0.1/24` loopbacks, `X.[100+Y].0.0/24` router–host) that students must type in themselves |
| 1.3 | OSPF weights so `ATL`↔`BOS` load-balances over exactly 3 paths | ECMP, `fib_multipath_hash_policy`, traceroute observability |
| 1.4 | IPv6 addressing in both DCs + 6in4 tunnels `ATL`↔`BOS` | IPv6 on OVS/VLAN, and **raw shell access inside the router container** (6in4 cannot be done from vtysh) |
| 2.1 | iBGP full mesh on loopbacks, `update-source`, `next-hop-self` | FRR `bgpd` |
| 2.2 | eBGP with neighbouring student ASes and IXPs; advertise own /8 | Inter-AS links with published subnets, IXP route servers, a website page listing each group's neighbours |
| 2.3 | Gao-Rexford business relationships via local-pref + export route-maps + communities | Provider/peer/customer relationship as *topology metadata*, BGP policy analyzer for feedback |
| 2.4 | Community-gated peering through IXPs (`N:X`), region-aware filtering | IXP route server that only relays on community match; region attribute per AS |
| 2.5 | Detect the high-delay provider/customer link and traffic-engineer around it | **Per-link delay is load-bearing pedagogy**: `1mbit 2.5ms 50ms` vs `1mbit 25ms 50ms` |
| 2.6 | Diagnose stub-AS hijacks; issue ROAs in Krill; RPKI-based route filtering | Krill CA hierarchy with per-AS child CA, per-AS Routinator RTR, scripted hijack injection |

The advanced course adds MPLS/LDP, BGP-free core, BGP/MPLS VPN with VRFs, and
PIM-SM/IGMP multicast — all of which need the same substrate plus kernel MPLS.

## 2. Where it breaks down

### 2.1 Sheer volume of untyped glue

```
225 shell files   17,764 lines
 91 python files  17,425 lines
 20 Dockerfiles
 79 TODO/FIXME/HACK markers
```

`platform/setup/` alone is **6,887 lines of bash**, including:

| File | Lines | Role |
|---|---|---|
| `_connect_utils.sh` | 1,138 | veth/netns/tc plumbing library |
| `restart_container.sh` | 1,011 | restart *one* device and re-wire it |
| `router_config.sh` | 600 | generate + push FRR configs |
| `rpki_setup.sh` | 369 | drive the Krill REST API from bash |
| `container_setup.sh` | 365 | `docker run` every container |
| `save_configs.sh` | 336 | **generates a bash script per group** that itself saves configs |

`save_configs.sh` is emblematic: a bash script that writes a bash script into
each group's directory, which is then bind-mounted into a container and run by
students. There is no way to test, type-check, or refactor this.

### 2.2 The configuration format has no schema

An AS is described across **eight** whitespace-separated positional files:

```
# AS_config.txt  — note the literal padding "Config  " to align columns
3	AS	NoConfig	l3_routers.txt	l3_links.txt	l2_switches.txt	l2_hosts.txt	l2_links.txt
140	IXP	Config  	N/A	N/A	N/A	N/A	N/A

# l3_routers.txt — column 2 overloads "service attached here"; "N/A" = none
ATL   MATRIX        L2-DCS:miniinterneteth/d_host           linux
PHY   N/A           routinator:miniinterneteth/d_routinator  vtysh

# aslevel_links.txt — column 10 is either a subnet OR a comma list of ASNs
1	PHY	Provider	3	MSP	Customer	1mbit	2.5ms	50ms	179.1.3.0/24
1	PHY	Peer    	140	None	Peer    	1mbit	2.5ms	50ms	1,2,11,12,21,22
```

Problems: positional columns with no header; `N/A` sentinels; alignment
whitespace that is semantically meaningful to `readarray` splitting; a field
whose *type* depends on the peer's kind; CRLF line endings in
`as_nicknames.csv`; and cross-file referential integrity (does
`l2_hosts.txt` reference a switch that exists in `l2_switches.txt`?) that is
never checked. A typo produces a container that silently fails to wire.

### 2.3 Addressing is a bash library of magic numbers

`config/subnet_config.sh` (191 lines) is the single source of the addressing
plan, expressed as bash functions:

```bash
subnet_host_router() {   # → X.(R+101).0.1/24 for host, .0.2/24 for router
  echo "${n_grp}"".""$(($n_router + 101))"".0.1/24"
}
subnet_router() {        # → loopback X.(R+151).0.1/24
  echo "${n_grp}"".""$(($n_router + 151))"".0.1/24"
}
```

Every consumer must `source` this file. The offsets (`+101`, `+151`, `+200`,
`158.X.`, `157.0.0.`, `198.X.`, `180.IXP.`) are undocumented, unvalidated, and
appear again as hardcoded literals in the assignment wiki, the DNS generator,
the website, and the autograder. Changing the plan means editing five places.

### 2.4 State is implicit, and goes stale

There is no state model. "What is deployed" is answered by:
- the presence of directories under `groups/`,
- `groups/docker_containers.txt`, and
- `groups/docker_pid.map` — **container PIDs cached in a file that is `source`d
  as bash**, and is wrong the moment any container restarts.

`_connect_utils.sh:get_container_pid()` has an explicit `use_cache` flag whose
"True" branch exists solely to look up the *old* PID of a stopped container.
This is a workaround for not having a state model.

### 2.5 Startup is a 20-step serial pipeline with sleeps

`startup.sh` runs `cleanup → folder_setup → dns_config → rpki_config →
goto_scripts → save_configs → container_setup → vpn_config →
connect_l3_host_router → connect_l2_network → connect_internal_routers →
connect_external_routers → configure_ssh → connect_services → layer2_config →
router_config → mpls_setup → rpki_setup → website_setup → webserver_links →
history_setup → hijack_config → bgp_clear`, with

```bash
echo "Waiting 60sec for RPKI CA and proxy to startup.."; sleep 60
...
echo "Waiting 60sec for BGP messages to propagate..."; sleep 60
```

Any failure part-way leaves an unrecoverable half-built network; the documented
remedy is a full `cleanup.sh` and restart. Parallelism exists only as an ad-hoc
`_parallel_helper.sh` (36 lines) wrapping backgrounded subshells.

### 2.6 It cannot scale out

Everything assumes one host: `ip netns` symlinks into `/var/run/netns`,
`docker network create` on the local daemon, OVS bridges in the root namespace,
`iptables` NAT rules, and port mappings `2000+X` on one public IP. Estimated
container count for a 30-AS class is ~520; the historical 80–112-AS classes
imply 1,500–2,000+ containers on a single machine, with every container pinned
to `--cpus=2` and the documented prerequisite of raising
`net.ipv4.neigh.default.gc_thresh3` to 131072 and `kernel.pid_max` to 4194304.
There is no path beyond one very large machine.

### 2.7 Grading is the weakest link

Two generations exist and both are problematic:

- **Legacy** (`platform/utils/autograder/bgp/`, ~30 files of bash/Python/Go):
  disconnects a student's AS from the live network with `ovs-vsctl del-port`,
  splices in an ExaBGP container, injects crafted announcements, probes with
  Scapy, then reconnects. Parallel (Go `runner.go`, N workers) but destructive,
  root-heavy, marked EXPERIMENTAL in places, and emits raw SQLite blobs with
  no rubric.
- **Current** (`communication_networks_course/2025_assignment_eth/config_2025/autograder-25/`,
  ~4,400 lines, `grader.py` alone 1,747): a much more complete rewrite that
  builds a "shadow AS" per group and scores each wiki question — but it is
  **fully serial** (`for cur_asn in asn_lst:`), uses `BGP_CONV_WAIT = 20`
  seconds **more than eight times per AS**, tears down and rebuilds the shadow
  AS for every student, mutates the live shared network, depends on
  out-of-band `rsync`/`scp` steps a human must run first, and writes
  grep-able text logs. Realistically hours for one class, and not reproducible.

Notably, generation 2 *lost* the parallelism generation 1 had.

### 2.8 Access control is coarse

One privileged SSH container per group (so 100 groups = 100 extra containers),
students are `root` inside it, `goto.sh` (30 lines) computes target IPs from
`158.X.(10i+1)` arithmetic, and isolation relies on Docker bridge networks
plus `iptables` filters. The maintainers' own README lists "Can I get from one
ssh proxy to another via the network?" as an open question.

### 2.9 No tests, no CI, no release process

There is no test suite, no linting, no CI configuration, and no versioned
release. The `platform/README.md` is a 60-item bullet list of known breakage
("Fix the autograder", "Fix saving (some issue with the script?)", "Plenty of
scripts in /groups are not used anymore. Are they still created? check that.",
"Add a config file for each container name and remove any hardcoded variable in
any script"). Two `.bak-typonet-livefix-<timestamp>` copies of
`website_setup.sh` are committed to the repository.

## 3. Verdict

The *concept* is world-class; the *implementation* has reached the end of its
life. Incremental refactoring is not viable because the configuration format,
the addressing plan, the state model, and the single-host assumption are all
mutually entangled through `source`d bash globals.

**Twinet keeps:** the AS-per-group model, prescribed addressing that students
must enter by hand, per-link bandwidth/delay/queue as pedagogy, the service
federation (matrix, looking glass, DNS, RPKI, IXPs, measurement, VPN, web), the
`save_configs` dump layout as the submission interchange format, and the
black-box "attach a fake BGP peer and observe control + data plane" grading
primitive.

**Twinet discards:** all 35k lines of glue, the eight-file positional config,
bash-function IPAM, PID caching, the serial sleep pipeline, the per-group SSH
container, and the single-host assumption.
