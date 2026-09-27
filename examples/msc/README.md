# MSC two-site example

See [the MSC operator guide](../../docs/13_msc.md) for setup, topology, checks,
faults, recovery, and cleanup. `msc.json` is the explicit 35-device / 44-link
profile. Generate a separate editable copy with:

```sh
bin/twinet msc init --spec /tmp/my-msc.json
bin/twinet msc plan --spec /tmp/my-msc.json
```

The runtime requires root on Linux, Docker, and the image built from
`images/msc/Dockerfile`. The default commands operate on one worker.
