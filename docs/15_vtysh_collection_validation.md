# Native vtysh command collection validation

Interactive `vtysh` commands and `-c` arguments now produce individual structured
records. The native FRR hook reports accepted command text, the FRR return code,
and the command mode before and after execution. The gateway adds session,
group, AS, and device identity. JSONL/CSV exports and browser playback share the
same stored events.

The implementation was validated on `c220g2-011108.wisc.cloudlab.us` on
November 4, 2026. Twinet replaced the 32 routers through its normal deployment
workflow because the existing containers used read-only root filesystems.
The network retained 64 logical devices and 96 running containers. After the
replacement, AS3 had three configured interface addresses missing from the
kernel. Removing and reapplying those addresses through FRR restored them.
The final check confirmed all 154 BGP neighbor relationships were established.

## Retained evidence

- [Local gateway run](collection-validation/vtysh/local.json)
- [Agent-mediated run](collection-validation/vtysh/agent.json)
- [Terminal collection and recovery regression run](collection-validation/vtysh/regression.json)
- [Router image and binary identity](collection-validation/vtysh/image.json)
- [Per-AS BGP checks](collection-validation/vtysh/network.json)
- [Deployed manifest](collection-validation/vtysh/twinet.yaml)
- [Agent validation manifest](collection-validation/vtysh/agent_twinet.yaml)
- [Sample command records](collection-validation/vtysh/sample_activity.jsonl)
- [Sample CSV export](collection-validation/vtysh/sample_activity.csv)
- [Browser command table](collection-validation/vtysh/browser.png)

Both manifests use the retained
[compact template](collection-validation/vtysh/templates/compact.yaml).
The router image was built locally. Its local image ID and the instrumented
`vtysh` checksum are retained; the image was not published to a registry.

## Correctness checks

Each run used real SSH sessions and the FRR processes in the deployed routers.
The checks covered:

- Interactive commands after backspace editing, tab completion, and history
  recall. The accepted command text matched the structured records.
- Successful commands, unknown commands, ambiguous commands, and incomplete
  commands. Their FRR return codes were 0, 2, 3, and 4 respectively.
- Mode transitions through global configuration, interfaces, BGP, and an
  address family, followed by a return to privileged mode.
- Configuration changes, their removal, `write memory`, and top-level `exit`.
- Multiple `-c` commands and invocation through the absolute binary path.
- stdout/stderr redirection, which preserved the separate reporting descriptor.
- A nested shell and two `vtysh` processes running concurrently in one session.
- A command longer than 5,000 characters, which crossed multiple report
  fragments and was reassembled exactly.
- Disconnecting while a command waited for its pager. The command retained an
  incomplete status and an unknown result.
- Recording disabled, and application collection disabled independently while
  terminal collection remained enabled.
- Exact local/received journal equality, checksums, event sequences, and removal
  of collection frames from terminal playback.

Each native-command run recorded 69 test sessions. Its load batch used 64 SSH connections across
32 ASes and reached 64 simultaneously active recordings. Each load session
executed three FRR commands with expected results of success, success, and
unknown-command. Every resulting command retained the correct AS and device.
The JSON reports contain completion times. These short-command measurements
demonstrate the tested workload and do not establish an upper capacity limit.

The agent run exercised Twinet's gateway-to-agent transport on loopback. It used
two logical node entries with every AS pinned to the running node. The run
validates the agent transport but does not measure cross-host network behavior.

The terminal collection regression run also passed with the final image and
gateway build. It checked binary streams, exit status, shell replacement,
disconnect cleanup, collector outages, gateway crash recovery, and byte-for-byte
upload equality. Its load batches included 32 and 64 concurrent connections.

The full Go suite, focused race checks, lint, and CLI documentation checks passed
on Linux. Documentation link checks, the native image build, and live browser
inspection also passed. The router patch is applied to a
checksum-pinned FRR 10.0 source archive. Its checked patch locations cause an
unexpected source layout to fail the build.

## Repeat the checks

The [validation runner](../scripts/verify_vtysh_collection.py) uses Python 3 and
Paramiko on the lab host. The main recording gateway listens on loopback port
2022; the unrecorded baseline listens on port 2023.

```sh
sudo python3 /users/hy/twinet-collection/scripts/verify_vtysh_collection.py \
  --lab /users/hy/collection-lab \
  --key /users/hy/collection-test-key \
  --spool /users/hy/collection-spool \
  --received /users/hy/collection-received \
  --output /users/hy/vtysh-validation.json
```

The optional `--application-off-port` and `--application-off-spool` arguments
check a separate gateway started with application events disabled. The retained
reports include that check. The additional agent and opt-out services were stopped
after validation. The network, main recording gateway, baseline, and browser
were left running.

The [collection guide](13_collection.md#frr-and-vtysh-commands) explains image
upgrades, configuration, event fields, and the command-collection boundary.
Native command reports remain application reports from inside the device;
gateway terminal recording remains independent of those reports.
