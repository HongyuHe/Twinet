# MSC construction experiments

The current reusable topology profiles run on Twinet's native FRR/OVS stack. Black transport routers and Outer Firewalls use FRR OSPF. Gray Firewalls and ordinary Gray routers use FRR static forwarding. Encryptors run strongSwan and Linux XFRM without routing daemons. OVS switches retain their native CLI, database and OpenFlow tables.

The profiles under `examples/msc/construction/` were constructed independently from the specification records. The five current profiles are `native-ipsec-baseline.json`, `native-shared-same-level.json`, `native-shared-four-levels.json`, `native-redundant-four-levels.json` and `native-management-independent.json`. Their device prefixes are NB, NT, NF, NR and NM. The same-level profile declares NETWORK-1 and NETWORK-2 independently from SECRET-US-only. The four-level profiles retain Top Secret, Secret US-only, Secret Coalition and Unclassified. Each shared-Outer path crosses the inline Gray boundary. The redundant profile includes ordinary Gray routers as separate devices.

Historical version1 profiles use Linux containers, Linux bridges and static routes. Their immutable observations remain valid for their recorded scope. They do not establish execution on the native FRR/OVS runtime. The historical `make_shared.py` generator refuses its known unsafe shared-Outer layouts unless explicitly invoked with `--historical-unsafe`. Current native regeneration uses `make_native.py` and the committed corrected input profiles.

## Build and launch

These experiments extend Twinet commit `26f056df61a728144cf83102d109492e44e98eb8` and are included on the `tdn` branch. Use a Linux checkout with Go 1.25 or newer and Docker available. Go module versions are pinned by `go.mod` and `go.sum`. The router and switch Dockerfiles use the pinned Alpine3.20 digest. Exact installed packages and built image IDs are recorded in the public build-input command record. The exported runtime-image archive reproduces those image bytes without resolving package repositories again.

```sh
bash examples/msc/construction/build_images.sh /ABSOLUTE/LAB/exports/native-image-build
python3 examples/msc/construction/make_native.py
go test ./internal/msc
go build -o bin/twinet ./cmd/twinet
sudo bin/twinet msc up --spec examples/msc/construction/native-ipsec-baseline.json --state-dir /ABSOLUTE/LAB/private/native-ipsec-baseline
sudo bin/twinet msc check --spec examples/msc/construction/native-ipsec-baseline.json --state-dir /ABSOLUTE/LAB/private/native-ipsec-baseline --json
```

The build command creates all three native runtime image tags from the source checkout. If you already have the exported image archive, you can use `docker load -i runtime-images-v2.tar.gz` in place of the image build command. The script builds the Linux DHCP/multicast helpers, the pinned Alpine FRR/OVS bases, and the MSC observation layers with Python, process tools and filtering utilities. Run it with Docker access and Go on PATH. Base digests and Go modules are pinned; package repositories can change, so a rebuild may produce different image IDs. The script records exact resulting package lists and hashes. The saved archive supplies the original image bytes.

The replay helper exposes the same commands with explicit profile selection. Run `python3 examples/msc/construction/replay.py --help` for its arguments. A fresh output directory is required for every capture. The launcher verifies ownership before reusing or removing a container. Device IDs must remain unique among concurrently running profiles. Use the exact same spec and state directory for `down`; do not remove unrelated containers or bridges.

## Evidence collection

`collect_native_v2.py` records explicit inventory scope, reciprocal veth peer identities, OVS Bridge/Port/Interface UUID membership, patch/tunnel options, flow/group/meter inventories, FRR running configuration and runtime JSON, public loaded IKE settings, XFRM state without keys, ordered filters, and positive/negative probes. Before/after comparisons cover topology identities, memberships, routes, policies and configuration. Counter values and documented bridge countdown timers are excluded from identity comparisons. The collection interval is sequential and never described as atomic.

`native_inventory.py` adds component process, socket, DNS, startup-file and sanitized account-state records. Host process discovery matches each owned device's network-namespace inode before reading commands. FRR control sidecars have separate PID namespaces and shared device network namespaces, so their processes are included. Password hashes, deployed private keys and authentication secrets are excluded.

Management is an optional independent profile. Management-free data-path evidence does not require management observations. The management profile records separate management attachments and authorized/no-client-certificate TLS trials. Physical and KVM workstation alternatives are separate bounded experiments.

## Supplemental experiments

The following stable scripts use supplemental namespaces or isolated protocol peers. They are not integrated native MSC launcher features. Run each against a fresh owned lab directory, and retain its public exports before cleanup.

| Experiment | Stable entrypoint | Evidence scope |
| --- | --- | --- |
| Eight IP-family combinations and encryption pairings | `matrix_lab.py` | Nested data channels with manually installed test SAs; no negotiated authentication claim |
| GRE/MPLS/OSPF on Red or Black | `routing_variants_v6.py` | Actual routing protocols/encapsulation and useful/loss/recovery probes |
| Placement, management, filtering and time-source cases | `utility_variants_v3.py` | Ten distinct structural/service configurations with complete helper hashes |
| Local, enterprise and central CA arrangements | `ca_variants_v2.py` | Separate Inner/Outer peer authentication with strict CRL checks |
| Negotiated PSK MACsec | `mka_psk_v4.py` | Matching/mismatched test CAKs and actual GCM-AES256 MKA |
| Central-AS EAP-TLS | `eap_tls_v5.py` | Partial authentication/placement evidence; EAP-derived MACsec delivery remains unresolved |
| Objective IKEv2 exchange | `pq_exchange_v4.py` | ECP384, ML-KEM1024, ML-DSA87 and header-only MTU/fragment observations |
| HTTP revocation services | `revocation_services.py` | Good/revoked CRL and OCSP responses through explicit service exceptions |
| Authentication policy enforcement | `auth_constraints_v5.py`, `auth_negative.py` | Loaded SHA384 constraints, fresh sessions and a rejected SHA256 signature |
| Redundant native forwarding | `redundancy_native.py` | FRR route sharing and bounded primary-forwarding loss with restoration |
| Physical/KVM AW placement | `boot_aw_vm.py`, `aw_tls_provision_v2.py`, `aw_client.py` | Actual placement and finite mutual-TLS administrative use |

The supplemental MACsec authentication programs require the recorded wpa_supplicant2.12/hostapd2.12 builds. The hostapd offload callback patch is retained with before/after source hashes. EAP-TLS authentication succeeded, but the subsequent MACsec receive-path failure remains explicit. The objective IKEv2 image uses the upstream experimental ML-DSA branch pinned at `eb72966d2211141c73d4f66e4825c406a0811c3e`; released strongSwan6.1.0 did not load the required keys in the preserved first trial.

The recovery harness installs fresh AES-GCM keys when rebuilding IPsec SAs. MACsec link-down/up recovery retains its SA and packet number, and restores the route removed by link-down. The harness never resets an AES-GCM packet number under the old key as a recovery shortcut.

## Scope and retained failures

The coverage register separates representative arrangements from full CP compliance. Physical separation, product certification, personnel/AO approval, external annex compliance and unbounded temporal behavior require evidence outside the software lab. Software CDS and High Assurance analogues remain partial. Physical serial management is unavailable without a verified cable and an owned encryptor target. Every case and evidence request retains its explicit supplied, partial, unavailable or unresolved disposition.

Failed commands, rejected snapshots, source checkpoints and repaired runs remain preserved. A no-reply ping has an actual exit status1 and a successful observer. Timeout, invocation error and missing container/interface results never count as blocked delivery. Public image archives contain the rebuilt runtime software; deployed credentials remain in private bind mounts and are not embedded in those images.
