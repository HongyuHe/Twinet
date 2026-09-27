# MSC emulation for TDN experiments

Twinet's `msc` command runs an explicit two-site, two-security-level network on
one Linux worker. The implementation uses the Docker runtime and Twinet's veth
wiring primitives. It has its own appliance model and lifecycle; it does not
instantiate the encryptors as FRR routers or enable OSPF/BGP on them.

The `tdn` branch starts from `dev`. The first profile uses nested, certificate-
authenticated IKEv2/IPsec ESP tunnels. It is a research emulator. It does not
claim approved CSfC products, hardware/implementation diversity, full package
compliance, MACsec support, or a TDN/Lean adapter.

## Use the prepared CloudLab worker

The running worker is node-0, `clnode161.clemson.cloudlab.us`. Nodes 1 and 2 are
not required for this example. Commands run on the worker, not on macOS:

```sh
ssh hy@clnode161.clemson.cloudlab.us
cd ~/Twinet
git switch tdn
sudo bin/twinet msc up
sudo bin/twinet msc check > /tmp/msc-check.json
jq '{passed, checks: (.checks | length)}' /tmp/msc-check.json
```

`up` creates absent containers and reapplies the declared configuration to
existing containers. An active injected fault requires `recover` instead.
Configuration application temporarily disables forwarding while filters and
links are restored. The command can interrupt traffic; it is not a hitless
update mechanism.

## Install on a clean Linux worker

Use a Linux kernel with network namespaces, XFRM/IPsec, veth, bridge, and the
iptables policy match. Root access is required for namespace wiring. Docker and
Go are also required; the repository pins the minimum Go toolchain in `go.mod`.

For Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y docker.io golang-go iproute2 jq tcpdump
sudo systemctl enable --now docker
sudo modprobe xfrm_user
sudo modprobe af_key
sudo modprobe xt_policy

git clone --branch tdn https://github.com/HongyuHe/Twinet.git
cd Twinet
go build -o bin/twinet ./cmd/twinet
sudo docker build -t twinet/msc:tdn images/msc
bin/twinet msc plan > /tmp/msc-plan.json
sudo bin/twinet msc up
sudo bin/twinet msc check > /tmp/msc-check.json
```

The image starts from a pinned Ubuntu image digest. The deployed Docker image
identity is recorded on every container and in live status. Rebuilding the tag
with different contents requires `down` followed by `up`; existing containers
are never silently treated as instances of the new image.

## Understand the network

The profile creates 35 containers and 44 links. There are 23 data-plane
containers: four Red hosts, four inner encryptors, four Gray switches, two Gray
Firewalls, four outer encryptors, four Outer Firewalls, and one Black router.
Six management switches and six administrative workstations provide separate
Red-S1, Red-S2, and Gray management domains at each site.

For each security level `n`, the path is:

```text
R_An -- I_An -- G_An -- O_An -- OF_An -- BLACK -- OF_Bn -- O_Bn -- G_Bn -- I_Bn -- R_Bn
```

Each site's Gray switches connect only through `GF_A` or `GF_B` across levels.
The switches use Linux bridges. They emulate separate Ethernet segments.

| Device example | Role / address |
|---|---|
| `R_A1`, `R_A2` | Site A Red hosts: `10.1.1.10`, `10.1.2.10` |
| `R_B1`, `R_B2` | Site B Red hosts: `10.2.1.10`, `10.2.2.10` |
| `I_A1`, `I_B1` | S1 inner tunnel endpoints: `10.100.1.2`, `10.200.1.2` |
| `I_A2`, `I_B2` | S2 inner tunnel endpoints: `10.100.2.2`, `10.200.2.2` |
| `O_A1`, `O_B1` | S1 outer tunnel endpoints: `172.20.11.1`, `172.20.21.1` |
| `O_A2`, `O_B2` | S2 outer tunnel endpoints: `172.20.12.1`, `172.20.22.1` |
| `AW_A1`, `AW_A2`, `AW_A99` | Site A Red-S1, Red-S2, and Gray administrators |
| `AW_B1`, `AW_B2`, `AW_B99` | Corresponding Site B administrators |

The complete addresses, roles, interfaces, static routes, links, peer identities,
selectors, and trust domains are in `examples/msc/msc.json`. S1 and S2 are
unordered security labels. The profile preserves the device IDs needed by its
checks. Additional topology edits require validation and a down/up cycle.

## Inspect and interact

```sh
sudo bin/twinet msc exec R_A1 -- ping -c 3 10.2.1.10
sudo bin/twinet msc exec R_A1 -- ping -c 3 10.2.2.10
sudo bin/twinet msc exec I_A1 -- \
  swanctl --list-sas
sudo bin/twinet msc exec O_A1 -- ip xfrm policy list
sudo bin/twinet msc exec GF_A -- iptables -nvL
sudo bin/twinet msc status > /tmp/msc-status.json
```

The first ping should succeed. The second should fail because it crosses
security levels. `status` includes observed interfaces, routes, firewall rules,
certificates, SAs, and XFRM state with key material suppressed. Runtime query
failures remain explicit errors in the JSON. The status is an observation
interval, not an atomic snapshot or a proof.

Use a second SSH session for a live packet capture:

```sh
sudo bin/twinet msc exec BLACK -- timeout 15 tcpdump -Z root -nn -i any esp
```

Generate traffic from `R_A1` while the capture runs. On Gray, the visible ESP
endpoints are inner gateways; on Black, they are outer gateways. The profile's
checks combine positive traffic, SA observations, and captures at both layers.
Absence of cleartext during finite probes does not establish a universal theorem.

## Inject faults and recover

```sh
sudo bin/twinet msc fault ipsec-down I_A1
sudo bin/twinet msc exec R_A1 -- ping -c 2 10.2.1.10
sudo bin/twinet msc exec R_A2 -- ping -c 2 10.2.2.10
sudo bin/twinet msc recover
```

S1 should stop working while S2 continues. The fault removes the daemon's SAs
and policies, so fail-closed behavior depends on the persistent firewall guard.
The fault marker prevents an ordinary `up` from silently repairing the incident.
`recover` restores the baseline, renews leaf certificates, restarts the IPsec
control processes, and establishes the outer tunnels before the inner tunnels.

Other supported faults and lifecycle operations are:

```sh
sudo bin/twinet msc fault ipsec-down O_A1
sudo bin/twinet msc recover
sudo bin/twinet msc fault wrong-peer I_A1
sudo bin/twinet msc recover
sudo bin/twinet msc fault revoke I_A1
sudo bin/twinet msc recover
sudo bin/twinet msc fault link-down I_A1 gray
sudo bin/twinet msc recover
sudo bin/twinet msc fault firewall-open GF_A
sudo bin/twinet msc check > /tmp/msc-drift.json
sudo bin/twinet msc recover
sudo bin/twinet msc restart I_A1
```

A firewall fault need not cause cross-level Red delivery: the independent
cryptographic safeguards can still block delivery. `check` reports firewall
configuration drift separately from the packet-delivery tests.

The automated failure exercise runs inner/outer SA loss, wrong peer identity,
certificate revocation, and container restart scenarios. It attempts recovery
after each fault and records both blocked S1 traffic and unaffected S2 traffic:

```sh
sudo bin/twinet msc test-failures > /tmp/msc-failures.json
jq '{passed, checks: (.checks | length)}' /tmp/msc-failures.json
sudo bin/twinet msc check > /tmp/msc-final.json
```

## Persistence, credentials, and cleanup

The default private state directory is `/var/lib/twinet/msc`, with mode 0700.
It contains CA keys, leaf credentials, CRLs, configuration baselines, and the
active fault marker. Private files have mode 0600. Containers receive only their
own leaf keys and applicable public trust material, through read-only binds.
The CA private keys remain outside the containers and the repository.

The inner S1, inner S2, and outer layers have separate certificate trust domains.
Peers use explicit identities and strict CRL checking. The profile selects
AES-256-GCM, P-384, and SHA-384-based IKE PRFs. IKE reauthentication occurs after
three hours and CHILD_SAs have a one-hour maximum lifetime. Separate management
CAs support TLS 1.3 client-authenticated health endpoints on port 8443. Those
endpoints demonstrate management reachability and authentication; they are not
full administrative applications or the omitted CSfC management annexes.

A host reboot stops the containers. Run `msc up` after Docker starts to restore
links, filters, configuration, and fresh tunnel state. Live SA keys and replay
windows are never serialized for restoration. `msc restart DEVICE` exercises a
container restart without rebooting the worker.

```sh
sudo bin/twinet msc down
```

`down` removes only containers owned by the selected lab/state directory and
lets namespace teardown remove their links. It retains private PKI and baseline
state for reuse. It does not remove other Twinet labs or Docker networks. Use
`--spec PATH` and `--state-dir PATH` consistently when choosing another profile
location. Different simultaneous labs also need distinct names in their specs.

The profile is currently a single-worker Docker runner. It does not use the
ordinary distributed AS deployment or grader, so cluster placement, replicated
state, and automatic agent repair are outside its supported contract. Extending
that integration is separate from running the complete example on node-0.
