# Configurable MSC emulation for TDN experiments

The `tdn` branch extends `dev` with an explicit MSC appliance topology. Version 2
uses Twinet's existing FRR router runtime, private FRR control containers, OVS
switch renderer, and interactive access implementation. BLACK and Outer
Firewalls run OSPF. Gray Firewalls use FRR with declared fixed routes. Inner and
outer encryption appliances retain strongSwan and fixed crypto forwarding.

The prepared native deployment runs on **node-1**,
`clnode146.clemson.cloudlab.us`. The earlier Linux bridge deployment on node-0,
`clnode161.clemson.cloudlab.us`, remains at its earlier revision. Version 1 is
retained in `examples/msc/legacy.json`; its container names and runtime remain
compatible. Do not use the version 2 manifest to operate the node-0 deployment.

## Log in and use native device commands

Run the following commands on node-1:

```sh
ssh hy@clnode146.clemson.cloudlab.us
cd ~/Twinet
sudo bin/twinet msc console BLACK
```

FRR routers open `vtysh`. BLACK, `OF_A1`, and `GF_A` provide normal FRR commands:

```text
show running-config
show ip route
show ip ospf neighbor
configure terminal
router ospf
passive-interface p11
end
```

That last example deliberately breaks one BLACK adjacency. Configuration
changes affect the running network and persist until reconciliation or restart.
Use another terminal to inspect the effect, then restore the declared baseline:

```sh
sudo bin/twinet msc check > /tmp/msc-check.json
sudo bin/twinet msc recover
```

Switches open Bash with the native OVS tools. OVS has `ovs-vsctl` and `ovs-ofctl`,
rather than a Cisco-style command interpreter:

```sh
sudo bin/twinet msc console G_A1
ovs-vsctl show
ovs-ofctl dump-flows br0
ovs-ofctl add-flow br0 'priority=100,actions=drop'
exit
sudo bin/twinet msc recover
```

The container names are the device IDs, such as `BLACK`, `OF_A1`, `G_A1`, and
`I_A1`. They have no `twinet-msc-` prefix. FRR's private daemon containers add only
`-frr`, such as `BLACK-frr`. Use the device container for CLI access. The control
container carries FRR's extra startup capabilities and is an internal component.

```sh
sudo docker exec -it OF_A1 vtysh
sudo docker exec -it G_A1 bash
sudo bin/twinet msc console BLACK -- bash
sudo bin/twinet msc exec BLACK -- vtysh -c 'show ip route ospf'
sudo bin/twinet msc exec I_A1 -- swanctl --list-sas
```

`console --no-tty DEVICE -- COMMAND` supports streamed automation. `exec` is the
batch interface. A console can remain open while another terminal runs checks.
There is no per-device SSH daemon; SSH authenticates to the worker first.

## Choose a layout

A small JSON config controls generation. Counts are **per site**. The generator
supports two sites, one to eight security levels, and one to `levels` Outer
Firewalls and Gray Firewalls per site:

```json
{
  "name": "msc",
  "levels": 2,
  "outer_firewalls": 1,
  "gray_firewalls": 1,
  "shared_gray": true
}
```

Generate an explicit manifest before deployment. Explicit CLI flags override
values in the small config file:

```sh
bin/twinet msc init --config examples/msc/layouts/shared.json --spec /tmp/shared.json
bin/twinet msc plan --spec /tmp/shared.json
bin/twinet msc init --levels 4 --outer-firewalls 2 --gray-firewalls 2 \
  --shared-gray --spec /tmp/four-levels.json
```

`init` refuses to overwrite existing files. Edit the small config and generate a
new manifest when changing layout. The expanded manifest exposes every device,
address, route, tunnel, management domain, and cable. It can also be edited for
asymmetric site arrangements. `plan` validates structural consistency; `check`
measures live behavior and the modeled Gray firewall cuts.

Three ready-made layouts are supplied:

| Layout file | Outer Firewalls per site | Gray Firewalls per site | Gray data fabric |
|---|---:|---:|---|
| `layouts/default.json` | 2 | 1 | Separate per level |
| `layouts/shared.json` | 1 | 1 | Shared outer-side switch |
| `layouts/shared-two-gray.json` | 1 | 2 | Shared outer-side switch |

The default has 35 devices and 44 cables, plus seven private FRR control
containers. A level's data path is:

```text
R_An -- I_An -- G_An -- O_An -- OF_An -- BLACK -- OF_Bn -- O_Bn -- G_Bn -- I_Bn -- R_Bn
```

A shared Outer Firewall connects several outer encryptors through distinct
inside interfaces. Its filters allow each encryptor's configured remote peer.
OSPF advertises the outer endpoint subnets over BLACK; management, Red, and Gray
prefixes are excluded. Outer encryptors never run OSPF or BGP.

A shared Gray layout places each inner encryptor behind a Gray Firewall before
the common OVS switch:

```text
I_A1 -- GF_A -- G_A -- O_A1 -- OF_A1 -- BLACK
I_A2 -- GF_A -- G_A -- O_A2 -- OF_A1 -- BLACK
```

With two Gray Firewalls, `I_A1` attaches to `GF_A1` and `I_A2` to `GF_A2`.
Each firewall connects to `G_A`. Every physical cross-level Gray path still
crosses a firewall. The common switch does not directly bridge the inner
interfaces. Gray filters allow only IKE/ESP between the declared same-level
inner peers. Dedicated layouts attach every Gray Firewall to each level's
separate switch. Multiple firewalls model alternative paths; automatic HA or
failover is not configured.

Layout changes require `down` with the **old manifest**, followed by `up` with
the new manifest. Bare names mean manifests with overlapping device IDs cannot
run simultaneously on one worker, even with different lab names. Ownership
labels prevent removal or reuse of another lab's containers.

```sh
sudo bin/twinet msc down
sudo bin/twinet msc --spec /tmp/shared.json up
sudo bin/twinet msc --spec /tmp/shared.json check > /tmp/shared-check.json
```

## Export configurations and live facts

`export` creates a versioned evidence bundle for later TDN theory construction:

```sh
sudo bin/twinet msc export --output /tmp/msc-snapshot-001
sudo bin/twinet msc status > /tmp/msc-status.json
sudo bin/twinet msc check > /tmp/msc-check.json
```

The export destination must be new. The bundle contains:

| File | Meaning |
|---|---|
| `manifest.json` | Schema version, source build identity, observation interval, spec hash, and SHA-256 for every other file |
| `spec.json` | Declared topology, interfaces, roles, zones, routes, tunnel endpoints, and image references |
| `status.json` | Raw sampled device observations, image IDs, timestamps, and observation errors |
| `facts.json` | The same observations with JSON outputs decoded into objects and arrays |
| `devices/ID/declared.json` | That device's declared model |
| `devices/ID/intended.*` | Generated FRR, OVS, firewall, or strongSwan configuration |
| `devices/ID/observed.*` | Live FRR and firewall configuration where available |

Live facts include kernel interfaces/routes/rules, FRR running configurations,
OSPF neighbors and routes, OVS port/VLAN state and OpenFlow rules, software
versions, redacted XFRM state, SA status, and public certificate information.
The exporter never copies private keys, credential stores, or the private state
directory. Intended and observed values remain separate, including during a
misconfiguration. Missing or failed observations carry explicit errors and must
be treated as unknown facts.

The snapshot is sampled sequentially, not atomically. Export does not run active
probes or certify an invariant. Save `msc check` output separately when packet
or reachability evidence is needed. `manifest.json` is written last; an export
without that file is incomplete. No TDN or Lean adapter is implemented yet.

## Verify and recover

`check` verifies device state, native configuration drift, OSPF adjacencies and
routes, permitted same-level traffic, cross-level isolation, Gray firewall cuts,
management TLS authentication, and ESP carriage without observed Red plaintext.

```sh
sudo bin/twinet msc check > /tmp/check.json
jq '{passed, checks: (.checks | length)}' /tmp/check.json
sudo bin/twinet msc test-failures > /tmp/failures.json
sudo bin/twinet msc restart BLACK
sudo bin/twinet msc restart G_A1
```

`test-failures` exercises SA/policy loss, wrong peer identity, revocation,
encryptor restart, an OSPF CLI mistake, an OVS drop rule, and native router/switch
restart. It restores the baseline between scenarios. The demonstration requires
the generated two-site layout with at least two levels. `check`, `status`, and
`export` operate from the explicit topology rather than a fixed appliance count.

Manual injected faults remain available:

```sh
sudo bin/twinet msc fault ipsec-down O_A1
sudo bin/twinet msc recover
sudo bin/twinet msc fault firewall-open GF_A
sudo bin/twinet msc check > /tmp/drift.json
sudo bin/twinet msc recover
```

`up` creates missing devices and reapplies the baseline. `recover` also resets
IPsec state, renews leaf certificates, and clears recorded faults. Both commands
interrupt forwarding during configuration. They deliberately replace native CLI
experiments with the declared configuration. Export experiments before recovery
if their state should be retained.

## Install or rebuild

The worker needs Linux namespaces, veth, XFRM, iptables policy matching, the OVS
kernel module, Docker, and the Go toolchain declared in `go.mod`:

```sh
sudo apt-get update
sudo apt-get install -y docker.io golang-go iproute2 jq tcpdump
sudo systemctl enable --now docker
sudo modprobe openvswitch
sudo modprobe xfrm_user
sudo modprobe af_key
sudo modprobe xt_policy
git clone --branch tdn https://github.com/HongyuHe/Twinet.git
cd Twinet
go build -o bin/twinet ./cmd/twinet
for image in $(jq -r '.image,.router_image,.switch_image' examples/msc/msc.json); do
  sudo docker pull "$image"
done
sudo bin/twinet msc up
```

Published images are `hyhe/twinet-msc`, `hyhe/twinet-msc-router`, and
`hyhe/twinet-msc-switch`. The manifests pin tested digests. Native image sources
extend `images/router` and `images/switch` with tools for observation and TLS
management. They retain those images' entrypoints and networking software.

To rebuild on a Linux worker with Docker access:

```sh
bash examples/msc/build-native-images.sh
```

The script builds the original router helper binaries and base images first.
Use local tags in a separate manifest for a new image build. A changed image or
manifest requires an explicit `down`/`up`; running containers are never silently
adopted under a different image identity.

## State and scope

Private state defaults to `/var/lib/twinet/msc`. It stores CA keys, leaf
credentials, CRLs, expected configurations, and active faults. CA private keys
remain outside containers. Separate inner trust domains protect each security
level; the outer layer has its own trust domain. Management uses separate
per-site/per-domain TLS 1.3 client authentication.

A host reboot stops the lab. Run `msc up` after Docker starts to restore links,
filters, native configuration, and tunnels. `down` removes owned devices and
FRR control containers while retaining PKI state. Use `--spec` and `--state-dir`
consistently for nondefault deployments. Certificates last one month and CRLs
seven days; `up` refreshes CRLs and `recover` renews leaf certificates.

The profile runs on one worker. It shares the worker kernel and does not use
Twinet's distributed AS placement or automatic HA. The prototype models network
behavior; it does not establish CSfC product approval, hardware diversity,
physical protection, or full package compliance. The historical node-0 results
remain in `examples/msc/VALIDATION.md`; native results are recorded separately.
