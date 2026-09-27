# MSC validation on node-0

The final MSC implementation at commit `ec54a40` was exercised on
`clnode161.clemson.cloudlab.us` on 2026-09-27. The branch descends from `dev`
commit `101f7c900cb1a1e8f4936b2f70114355776fd5b5`. The worker used Ubuntu
24.04.4, Linux 6.8.0-138, Docker 29.1.3, and Go 1.25.0.

The deployed Linux/amd64 image is available on Docker Hub as
[`hyhe/twinet-msc:tdn`](https://hub.docker.com/r/hyhe/twinet-msc).
The spec pins registry digest
`sha256:6cfc920ac8df78b10746e78d730366781d3db2ab957dd13d9368cb7ca63264fa`.
An anonymous registry inspection and a pull by digest both succeeded.
The initial deployment and the additional link/firewall checks ran at
`11fae55`. The full Go suite, fault/restart suite, and final health check ran
again after the management-restart fix in `ec54a40`.

## Recorded results

| Exercise | Result | Evidence |
|---|---|---|
| Full Go suite | Passed | [go-test.log](evidence/go-test.log) |
| Deployment from the published image | 35 containers and 44 links; all 200 baseline checks passed | [baseline.json](evidence/baseline.json) |
| Repeated `up` | Existing matching tunnel pairs remained ready | Baseline recorded after the second `up` |
| SA loss, wrong peer, revocation, and restarts | All 30 checks passed | [failures.json](evidence/failures.json) |
| Link fault, active-fault guard, and firewall drift | All 7 additional assertions passed | [additional.json](evidence/additional.json) |
| Deliberately opened Gray firewall | `check` returned nonzero and flagged `filter/GF_A` plus the active fault | [firewall-drift.json](evidence/firewall-drift.json) |
| Final recovered lab | All 200 checks passed | [final.json](evidence/final.json) |

The baseline checks cover same-level Red connectivity in both directions,
cross-level rejection, forwarding settings, firewall readback, installed IPsec
SAs, Gray Firewall placement, TLS management authentication, and encrypted
traffic captures on Gray and Black. The failure exercise removes SAs and
policies, checks that S1 is blocked while S2 remains reachable, checks for
cleartext leakage, and confirms recovery. Restart cases cover `I_A1` and `O_B2`, including authenticated management
access after each restart.

The additional link test brought `I_A1/gray` down, verified S1 loss and S2
continuity, and confirmed that ordinary `up` refused the active fault. The
firewall test changed `GF_A`'s FORWARD policy to ACCEPT and required the checker
to detect that configuration change. Both scenarios recovered successfully.
The deliberately failing firewall report is expected evidence of detection.

## Reproduce the main checks

Run from the Twinet checkout on the Linux worker:

```sh
go test ./...
python3 scripts/check_docs.py
sudo bin/twinet msc up
sudo bin/twinet msc check > /tmp/msc-baseline.json
sudo bin/twinet msc test-failures > /tmp/msc-failures.json
sudo bin/twinet msc check > /tmp/msc-final.json
```

The [operator guide](../../docs/13_msc.md) gives the commands for the individual
link and firewall faults. A full `down`/`up` cycle was also exercised while
retaining the private PKI directory. Host reboot and multi-worker deployment
were not exercised. Packet probes are finite observations. The prototype does
not establish full CSfC compliance or connect the emulator to Lean proofs.
