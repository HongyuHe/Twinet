# Native MSC validation on node-1

The native MSC implementation was exercised on node-1,
`clnode146.clemson.cloudlab.us`, on 2026-09-27. Node-0 was not used or modified
for these changes. The final default deployment remains running on node-1.

The final runtime source is `183287b`. The host runs Ubuntu 24.04.4,
Linux `6.8.0-138-generic`, Docker `29.1.3`, and Go `1.25.0` on amd64. The native
images run FRR `10.0` and OVS `2.17.9`. Their published, immutable references
appear in each version 2 manifest. The earlier node-0 results remain in
[VALIDATION.md](VALIDATION.md).

| Scenario | Passed checks | Evidence |
|---|---:|---|
| Final default: 35 devices, 44 links, 7 private FRR controls | 273 | [final.json](evidence/native-v2/final.json) |
| Shared Outer Firewall and Gray fabric: 31 devices, 38 links, 5 controls | 204 | [shared.json](evidence/native-v2/shared.json) |
| Shared fabric with two Gray Firewalls per site: 33 devices, 42 links, 7 controls | 218 | [shared-two-gray.json](evidence/native-v2/shared-two-gray.json) |
| Inner/outer SA loss, wrong peer, revocation, encryptor restarts | 30 | [crypto-failures.json](evidence/native-v2/crypto-failures.json) |
| Native OSPF/OVS mistakes, recovery, BLACK and switch restarts | 10 | [native-failures.json](evidence/native-v2/native-failures.json) |

The checks cover reachability, cross-level isolation, modeled Gray firewall
cuts, management TLS, baseline configuration, OSPF adjacencies and forwarding
routes, and ESP captures without observed Red plaintext. The final default
report additionally includes 35 deployed-specification identity checks. The
shared-layout reports predate those added identity checks.

The first failure suite exposed an OSPF readiness race. One S2 probe failed
after restarting BLACK because neighbor readiness did not require all forwarding
routes to be installed. [initial-failures.json](evidence/native-v2/initial-failures.json)
preserves that 39/40 result. Startup now requires the expected routes to be
selected and installed in both FRR and the kernel. The focused native rerun
passed all 10 checks after the fix. The 30 previously successful crypto and
encryptor checks are extracted with provenance in `crypto-failures.json`.

The early baseline and failure runs used the same native images through their
`:tdn` tags. [tested-default.json](evidence/native-v2/tested-default.json) preserves
the exact manifest associated with their specification hashes. The shared and
final deployments use the pinned image references in the checked-in manifests.
Reports from different stages remain separate; their specification hashes must
not be treated as interchangeable.

Interactive SSH/PTY sessions opened FRR `vtysh` on BLACK and Bash with native
OVS tools on `G_A1`. FRR accepted configuration edits and `write memory` saved
them to `/etc/frr/frr.conf`. The edits were removed and the final check passed.
Container names are bare device IDs; internal FRR controls add only `-frr`.

The export test changed a live interface description and confirmed that the
observed FRR config and decoded facts contained the edit while the intended
config retained the declared baseline. [export-test.json](evidence/native-v2/export-test.json)
records the checks. The final snapshot contains 140 hashed files plus its
manifest. Every hash was verified, all 35 deployed-spec hashes match the declared
spec, and no private-key PEM material appeared in the bundle. The final export
was produced from a clean source build, as recorded in
[export-manifest.json](evidence/native-v2/export-manifest.json).

The snapshot is available on node-1 at `/users/hy/msc-node1-export-verified` and
locally in the TDN repository at `artifacts/msc-node1/`. Exports are sequential
observations, not atomic snapshots or proofs of CSfC compliance.

`go test ./...` passed. The [package log](evidence/native-v2/go-test.log) records
the run. Focused tests cover 60 generated layout combinations, legacy loading,
native runtime capabilities, installed-route readiness, OpenFlow table identity,
certificate renewal after layout changes, export checksums and exclusion of
private state, and separation of intended versus deployed specification identity.
