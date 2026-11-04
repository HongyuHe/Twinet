# Collection validation on CloudLab

The collection system was tested on `c220g2-011108.wisc.cloudlab.us` on November 4,
2026. The lab contained **32 ASes, 64 devices, and 109 links**, including 77
inter-AS links. Each AS had one FRR router and one Linux host. Docker also ran a
separate FRR control container for each router, giving 96 running containers.

The host provided 40 logical CPUs and 157 GiB of memory. The test used Ubuntu
with kernel 6.8.0-147-generic, Docker 29.1.3, and FRR 10.0. The router and host
images were selected by their immutable registry digests in the
[retained manifest](collection-validation/twinet.yaml). The lab was deployed in
platform mode first, then configured with the reference solution. Queries across
all 32 routers found all 154 BGP neighbor relationships established. The [network report](collection-validation/network.json) retains
per-AS peer counts and routing-table sizes.

## Workload and measurements

[The retained JSON report](collection-validation/cloudlab.json) contains the
successful run's individual measurements and checks. The runner opened real SSH
connections and executed commands in the lab's containers. It compared two
gateways running the same binary against the same lab: recording enabled on port
2022 and recording disabled on port 2023.

Each bulk session emitted 128 KiB of known output with unique beginning and end
markers. The test checked returned bytes, recorded bytes, AS identity, event
sequences, and completion status. The workload used 32 simultaneous sessions for
three paired repetitions, followed by two batches of 64 simultaneous sessions.
A further 32-session batch ran while the collector was stopped.

| Workload | Batch completion time | Median session completion time |
|---|---:|---:|
| 32 sessions, recording off | 0.403–0.422 s | 0.292–0.311 s |
| 32 sessions, recording on | 1.022–1.104 s | 0.989–1.072 s |
| 64 sessions, recording on | 1.661–1.728 s | 1.587–1.661 s |
| 32 sessions, collector stopped | 1.011 s | 0.977 s |

The recording measurements include session creation and durable finalization.
They measure short, simultaneous command sessions; they are not keystroke-latency
measurements. Recording added roughly 0.7–0.8 seconds to median completion in the
32-session workload. The collector and gateways shared the host and its disk.
These measurements establish the tested workload, not an upper capacity limit.

## Correctness and recovery

The successful run checked the following behavior:

- Binary stdout and stderr, including an old exit-marker byte sequence, were
  preserved exactly alongside a deliberately nonzero exit status.
- Interactive Bash commands produced command records with working directories
  and exit status, including a deliberate failing command.
- Backspace editing, tab completion, and history recall produced accepted command
  text in the structured records.
- Resizing a live terminal to 123 columns and 41 rows changed `stty size` and
  produced a resize event.
- One SSH connection visited both the router and host. The recording retained
  the two device boundaries.
- Interactive `vtysh` output remained in the terminal recording.
- Replacing Bash with `bash --norc` preserved outer terminal recording.
- Closing a live SSH channel marked the recording incomplete and removed the
  tagged device execution.
- Stopping the collector did not stop local recording. Uploads resumed after
  the collector restarted.
- Killing the gateway process caused startup recovery to mark the active session
  incomplete and clean up the interrupted tagged execution.
- Every retained local journal matched its received copy byte for byte and
  matched the completed metadata checksum.

The successful run generated 256 bulk recorded sessions, two interactive checks,
one binary-output check, and one crash-recovery session. Its final verification
covered 1,299 retained sessions and 230,125,250 journal bytes, including earlier
development runs.
The retained development sessions are not counted as additional successful load
repetitions. The browser was also checked with real Chromium playback, including
an incomplete recording, pagination, group filtering, and the joined command
table. JSONL and CSV exports were checked for multiline command preservation
and unknown results on interrupted commands. The
[browser screenshot](collection-validation/browser.png) shows replay and the
joined command table after validation.

The complete Go test suite, targeted race checks for the recording and transport
packages, lint, documentation checks, and source-digest checks passed. The retained
run report includes the compiled source digest; the remote build used an exported
source tree without Git metadata.

## Agent transport check

A second run used the gateway-to-agent connection on loopback. The
[agent manifest](collection-validation/agent-twinet.yaml) names two logical nodes
and pins every AS to `node-0`. The unused node selects Twinet's clustered access
path without moving any device. The [agent counters](collection-validation/agent-metrics.txt) confirmed
260 successful and two canceled streaming executions through the agent API.

The [agent report](collection-validation/agent.json) passed the same byte,
interactive, resize, disconnect, collector-outage, and gateway-crash checks.
Its two 64-session batches completed in 1.640 and 1.758 seconds. The unrecorded
baseline in that report still uses local execution, so the report does not isolate
recording overhead from agent transport overhead. Both processes ran on the same
physical machine; the run does not establish cross-host network behavior.

## Reproduce the checks

The [validation runner](../scripts/verify_collection.py) requires Python 3 and
Paramiko on the lab host. It expects the retained 32-AS topology, a test public
key authorized for each group, and two gateways sharing the lab's host key.
The collector service must have a persistent systemd unit so it can be stopped
and started during the outage test. The gateway unit must restart after failure.

The deployed files are under `/users/hy` on the validation server:

| Path | Purpose |
|---|---|
| `twinet-collection/` | Built source checkout |
| `collection-lab/` | Deployed manifest, templates, and private roster |
| `collection-spool/` | Gateway recordings |
| `collection-received/` | Received recordings |
| `collection-token` | Private browser and upload token |
| `collection-validation.json` | Successful workload report |

The recording gateway uses `twinet-collection-gateway` on port 2022. The
unrecorded baseline uses `twinet-collection-baseline` on port 2023. The agent-path
check uses `twinet-collection-agent-gateway` on port 2024 and
`twinet-collection-agent` on port 7200. The validation gateways use transient systemd units and need to be recreated after a host reboot.
The extra agent and its gateway were stopped after validation; the agent run
report and its recordings remain available. The receiving collector uses the persistent `twinet-collection-viewer` unit on port 7330.

The following command repeats the recording, load, and failure tests. It restarts
only the named validation services:

```sh
sudo python3 /users/hy/twinet-collection/scripts/verify_collection.py \
  --lab /users/hy/collection-lab \
  --key /users/hy/collection-test-key \
  --spool /users/hy/collection-spool \
  --received /users/hy/collection-received \
  --output /users/hy/collection-validation.json \
  --gateway-unit twinet-collection-gateway \
  --collector-unit twinet-collection-viewer
```

Access the deployed browser through an SSH tunnel:

```sh
ssh -N -L 7330:127.0.0.1:7330 hy@c220g2-011108.wisc.cloudlab.us
```

Open `http://127.0.0.1:7330`. The token is in `/users/hy/collection-token` on the
server. The collection services bind to loopback. The 32-AS network, local
recording gateway, unrecorded baseline, and collection browser were left running.

## Validation limits

The load measurements used one physical host and the Docker API runtime.
They do not establish multi-host capacity, Podman/containerd live behavior,
long-duration retention performance, or power-loss recovery. The collection
browser reads session metadata files when listing recordings; course-scale
historical listing performance was not benchmarked. Use separate recording
directories and collectors for independent courses or terms.

Bash command records are shell reports. Commands entered inside `vtysh` have
terminal recordings but no individual structured application command events.
Recorded commands and network state must be interpreted separately when studying
whether a student's changes achieved the intended routing behavior.
