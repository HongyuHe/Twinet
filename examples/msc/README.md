# MSC emulation

The [operator guide](../../docs/13_msc.md) covers native CLI access, configuration,
shared firewall/Gray layouts, exports, testing, and recovery. Node-1 hosts the
FRR/OVS version. Node-0 retains the earlier deployment.

```sh
bin/twinet msc init --config examples/msc/layouts/shared.json --spec /tmp/shared.json
bin/twinet msc plan --spec /tmp/shared.json
sudo bin/twinet msc console BLACK
sudo bin/twinet msc console G_A1
sudo bin/twinet msc export --output /tmp/msc-snapshot-001
```

`msc.json` is the default native 35-device/44-link topology. FRR additionally
uses seven private control containers. The small files under `layouts/` select
firewall counts and Gray sharing. `legacy.json` preserves version 1.

[VALIDATION.md](VALIDATION.md) and the original `evidence/` files document the
historical node-0 implementation. New native evidence is recorded separately.
