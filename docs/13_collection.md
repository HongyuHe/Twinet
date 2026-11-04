# Terminal session collection

Twinet can record student SSH sessions at the gateway. Collection is **off by
default**. When enabled, it captures terminal output, optional raw input,
terminal size changes, device selections, and command events. A separate
collector can receive recordings automatically and provide browser playback.

The gateway writes recordings outside student containers. Changing `.bashrc`,
starting another shell, or entering `vtysh` does not turn off terminal recording.
No recorder binary or permanent shell modification is required in the devices.
The collector uses the Twinet binary and filesystem storage; it needs no database.

## Enable collection

Add the following block to the lab manifest:

```yaml
access:
  mode: gateway
  listen: ":2022"
  collection:
    enabled: true
    directory: .twinet/recordings
    capture_input: true
    shell_events: true
    application_events: true
    sync_interval: 1s
    max_session_bytes: 268435456
    max_total_bytes: 10737418240
```

Start the gateway with the usual command:

```sh
twinet -m /path/to/lab gateway run
```

For a temporary recording run, use the command-line override:

```sh
twinet -m /path/to/lab gateway run --record --record-dir .twinet/recordings
```

`--record=false` overrides an enabled manifest. A directory or collector URL
alone does not enable collection. Relative recording directories and token-file
paths are resolved under the lab directory.

The defaults, once collection is enabled, are input capture, Bash command
events, and supported application events enabled, a one-second sync interval, a 256 MiB session limit, and a 10 GiB
limit on local journal bytes. The total limit includes retained sessions from
previous gateway runs. The gateway refuses new recorded work when storage cannot
accept it. It closes an active session if recording writes fail or a limit is
reached. It does not continue the session without recording.

Raw input includes characters typed at hidden password prompts. Set
`capture_input: false` or `--record-input=false` to omit raw input. Bash command
text is controlled separately by `shell_events` or `--shell-events=false`.
Application commands are controlled by `application_events` or
`--application-events=false`. Output still contains whatever the application
displays, including echoed commands.

## Identify users

Every recording includes the authenticated group, AS, authentication method,
remote address, and SSH key fingerprint when a key was used. Password logins
identify the group account. Shared credentials cannot identify an individual.

Associate a person's name with a public key when adding it to the roster:

```sh
twinet -m /path/to/lab gateway roster add-key group3 /path/to/alice.pub --actor alice
```

Restart the gateway after changing its roster. A key without an actor name keeps
the group name and its fingerprint. The authentication password and bearer token
are never placed in recording metadata.

## Browse local recordings

Create a private token file and run the browser against the gateway's directory:

```sh
umask 077
openssl rand -hex 32 > /path/to/collection-token
twinet collection serve --dir /path/to/lab/.twinet/recordings --token-file /path/to/collection-token
```

Open `http://127.0.0.1:7330` and enter the token. The browser lists sessions and
supports lab/group filters, playback, command inspection, and event downloads.
An active session can be replayed through its latest available event. Use
**Refresh session** to load newly recorded output.

For a remote host, forward the browser port:

```sh
ssh -N -L 7330:127.0.0.1:7330 user@server
```

The viewer includes Asciinema Player 3.17.0 under its Apache-2.0 license.
Its JavaScript and CSS are bundled into Twinet. Playback does not contact a CDN.
The browser keeps the token in page memory and sends it in an authorization
header. It does not put the token in URLs or browser storage.

## Collect from several gateways

Run a receiving collector in a directory separate from each gateway's local
recordings:

```sh
twinet collection serve --dir /srv/twinet/collected --receive --token-file /etc/twinet/collection-token
```

Configure each gateway to send data there:

```yaml
access:
  mode: gateway
  collection:
    enabled: true
    directory: .twinet/recordings
    collector_url: https://collector.example.edu
    token_file: /etc/twinet/collection-token
    upload_interval: 2s
```

A receiving collector requires the same bearer token as its gateways. The token
grants access to that collector's recordings; use separate collectors and tokens
when courses need separate access. An HTTP collector URL is accepted only on
loopback. HTTPS is required elsewhere. A listener outside loopback requires
`--tls-cert` and `--tls-key`; a TLS reverse proxy can also forward to the default
loopback listener.

Uploads include active sessions. Four workers send bounded chunks, resume from
durable offsets, and retry outages with backoff up to one minute. The receiver
accepts identical retries without duplicating events. Completion requires matching
journal length, event count, sequence, and SHA-256 checksum. A partial receiver
write can be repaired by retransmitting the same bytes. Each collector limits a
single journal to 1 GiB.

Local recordings are retained after upload. `uploaded.json` records the last
acknowledged offset and completed checksum. A restart resumes pending uploads.
A separate command retries pending work when the gateway is stopped:

```sh
twinet collection sync --dir /srv/twinet/spool --url https://collector.example.edu --token-file /etc/twinet/collection-token
```

Only one gateway writes a given local recording directory. Only one receiving
collector writes a given receiving directory. A read-only browser may inspect a
running gateway's directory. The upload command and gateway uploader also share
an exclusive transfer lock.

## Process recordings

Each SSH session channel has a random 128-bit ID and its own directory:

```text
<recording-directory>/<session-id>/
  session.json
  events.jsonl
  uploaded.json
```

`session.json` contains the recording's identity, capture options, start/end times,
status, event count, byte count, and completed checksum. `status` is `recording`,
`complete`, or `incomplete`. An incomplete session includes a reason. A command
that exits with a nonzero status can still have a complete recording.

`events.jsonl` is the authoritative, versioned event journal. Every event contains
`schema`, `session`, `seq`, `time_ns`, and `type`. Events inside a device also carry
`device` and `segment`. The sequence starts at one. `time_ns` is elapsed monotonic
time in nanoseconds, so wall-clock corrections do not reorder a live session.
Use the session's UTC `started` timestamp when comparing separate sessions.

| Event | Meaning |
|---|---|
| `session_start`, `session_end` | Recording boundaries and final status |
| `input`, `output`, `stderr` | Exact bytes in the base64-encoded `data` field |
| `resize` | New `rows` and `cols` in `fields` |
| `device_start`, `device_end` | Selected device, execution ID, and result |
| `application_capability`, `application_start`, `application_end` | Native hook support and invocation boundaries |
| `application_warning` | An application report ended before all fragments arrived |
| `shell_ready` | Bash command collection initialized in this device shell |
| `command_start`, `command_end` | Command fields and a shared `command_id` |
| `command_incomplete` | The shell or application ended before reporting a result |

Export commands directly for analysis:

```sh
twinet collection list --dir /srv/twinet/spool --group group3
twinet collection export SESSION_ID --dir /srv/twinet/spool --format activity > activity.jsonl
twinet collection export SESSION_ID --dir /srv/twinet/spool --format csv > activity.csv
twinet collection export SESSION_ID --dir /srv/twinet/spool --format commands > command-events.jsonl
twinet collection export SESSION_ID --dir /srv/twinet/spool --format events > events.jsonl
twinet collection export SESSION_ID --dir /srv/twinet/spool --format cast > replay.cast
twinet collection verify --dir /srv/twinet/spool
```

The `activity` and `csv` exports provide one row per command. Each row includes
lab, group, AS, actor, device, source, command text or argument array, working
directory, start time, duration, exit code, and completion status. The exporter
joins command start/end events automatically. An interrupted command has an
unknown exit code and duration, rather than a fabricated success. CSV quoting
preserves multiline commands. The `commands` export retains the underlying
command events for custom analysis.

A gateway command event has `source: gateway` and an `argv` array. It records the
explicit SSH command request and its exit status. The original command's internal
spacing and line breaks are preserved after removing a recognized device prefix.

An interactive Bash command event has `source: bash_reported`, `command`, `cwd`,
and `command_id`. The matching end event supplies `exit_code`. Bash supplies the
accepted history entry after line editing, tab completion, and history recall.
Consumers can join start/end events using `session` and `command_id`, then compute
duration from `time_ns`. They do not need to infer shell prompts from screen text.

Bash reports are supplementary evidence. Users can replace the shell, change its
hooks, or forge its reports. A `shell_ready` event confirms initialization, not
permanent coverage. Instrumented `vtysh` supplies separate application command
records as described below. Other applications retain terminal playback and can
add their own command reports without changing the raw recording format. No
command log alone proves the resulting network configuration.

Asciicast v2 export is compatible with Asciinema playback tools. The exporter
handles UTF-8 characters split across output events. Invalid terminal encodings
are replaced in replay strings; the original bytes remain in `events.jsonl`.
Input, output, stderr, timing, device markers, and terminal resizing are retained.
Shell collection control messages become structured events and are removed from
the displayed output.

## FRR and vtysh commands

The Twinet router image includes a small native hook in FRR 10.0's `vtysh`.
When application collection is enabled, the hook reports accepted interactive
commands after line editing, completion, and history recall. It also reports
each command passed with `-c`, including multiple commands in one invocation.
The gateway assigns those records to the authenticated session and selected device.

Each command has `source: vtysh_reported`, a unique `command_id`, an invocation
ID and `mode_before` / `mode_after`. An explicit SSH exec request also supplies
its parent gateway command ID. Interactive reports use the invocation ID to group
commands; the collector does not guess which Bash command launched a background
process from the timing of its first report.
The native hook reports FRR's `result_code` and the gateway supplies a readable
`result_name`. Examples include `success`, `unknown_command`,
`ambiguous_command`, `incomplete_command`, and `daemon_unavailable`.
These FRR command results are distinct from a shell process's `exit_code`.
The JSONL/CSV activity exports join each command with its result and duration.
The browser displays the command's mode transition and result. Durations use
gateway receipt times, so transport and reporting latency are included.

The hook reports the return value after FRR finishes dispatching a command.
A top-level `exit` or `quit` reports success before FRR exits. If the gateway
loses the process during a command, the record remains incomplete with an
unknown result. FRR success means FRR accepted the operation; use network-state
queries to assess routing convergence and the resulting configuration.

Reports use an inherited descriptor separate from normal stdout/stderr
redirection. Nested shells and simultaneous `vtysh` invocations retain separate
invocation IDs. Reports are encoded in bounded fragments and removed from
terminal playback. Each native report is limited to 32 KiB. Oversized or
unwritable reports abort `vtysh` with process status 125. Commands entered at the
prompt and `-c` arguments are the native hook's collection boundary.
Configuration files passed with `-f` retain
the outer command and terminal recording; the hook does not report a separate
result for each imported configuration line. Completion/help keystrokes that do
not execute a command remain terminal input/output only.

Build the updated router image on the Linux build host with:

```sh
make images IMAGES=router REGISTRY=local TAG=vtysh-collection
```

Select `local/twinet-router:vtysh-collection` in the lab's router kind and deploy
normally. An existing stock FRR image does not gain the native hook from a
gateway upgrade alone. The gateway records `application_capability` for each
device, and the browser shows a warning for an unsupported `vtysh` image.
The capability can also be checked directly:

```sh
vtysh --twinet-collection-version
```

The instrumented binary returns `1`. Export capability and application lifecycle
records with:

```sh
twinet collection export SESSION_ID --dir /srv/twinet/spool --format coverage
```

Collection remains off by default. The native hook emits nothing without the
gateway's collection environment. Application collection can be disabled while
retaining Bash events and terminal playback. Application reports remain
supplementary evidence: a user with device-root access can replace a binary,
remove the environment, close the reporting descriptor, or forge reports.

The [router build](../images/router/Dockerfile) verifies the FRR source archive's
checksum and applies [a small checked patch](../images/router/collection/patch.py).
Only `vtysh` uses the private FRR library; the packaged routing daemons retain
their libraries. Updating FRR requires explicitly porting and retesting the patch.
The integration follows FRR's [command loop](https://github.com/FRRouting/frr/blob/frr-10.0/vtysh/vtysh_main.c)
and [command result definitions](https://github.com/FRRouting/frr/blob/frr-10.0/lib/command.h).

## Recovery and storage management

Journal writes are incremental. The gateway syncs open recordings at the configured
interval and syncs them again before reporting session completion. Sudden power
loss can lose data after the last successful sync. Process-crash tests do not
establish survival of a disk failure.

On startup, the gateway checks unfinished journals, removes a torn final line,
and marks those sessions incomplete. Invalid complete events cause startup to fail
with an error. The gateway also cleans up tagged device executions left by its
interrupted recorded sessions. Disconnecting an active session cancels its device
execution. Docker cleanup targets the random execution tag and its inheriting
processes inside that device. Processes that deliberately remove the tag are
outside that cleanup guarantee.

The collector retains raw recordings without automatic expiry. Archive complete
session directories according to the course's needs. Stop the writer before
moving or deleting retained sessions, then restart it so its total-byte accounting
is refreshed. Keep local and received copies until the transfer checksum has been
verified. The bounded operational event ring is not used for recording payloads.

## Scope and implementation

Collection covers SSH shell and exec channels through the Twinet gateway. It does
not intercept administrator commands run directly through Docker, Podman,
containerd, or the Twinet operator CLI. File-transfer SSH subsystems remain
unsupported by the gateway.

The common gateway recorder supports local and agent-mediated execution. The
agent transport carries stdin, resizes, stdout, stderr, and exit status in
separate messages. Binary output cannot be mistaken for an exit-status marker.
Update the gateway and agents together when using collection. Docker and Podman
use their streaming APIs; containerd uses its native task API. The explicitly
selected legacy Docker CLI backend does not support the new streaming interface.

The main implementation files are:

- [Gateway recording and Bash integration](../internal/access/collection.go)
- [Session storage and recovery](../internal/collection/store.go)
- [Uploads and collector API](../internal/collection/transfer.go)
- [Exports](../internal/collection/export.go)
- [Browser](../internal/collection/web/index.html)
- [Collection commands](../internal/cli/collection.go)
- [Live validation runner](../scripts/verify_collection.py)

The collector API provides authenticated `GET /api/sessions` with optional `lab`,
`group`, and `as` filters. Per-session GET resources are `session.json`,
`events.jsonl`, `commands.jsonl`, `activity.jsonl`, `activity.csv`, `coverage.jsonl`, and `replay.cast` under `/api/sessions/<id>/`.
Receiving collectors also accept PUT metadata and journal chunks. Journal PUTs
supply a byte `offset`; clients finalize metadata only after all bytes are present.

[CloudLab validation results](14_collection_validation.md) record the tested
configuration, workload, measurements, and remaining validation limits.

[Native vtysh validation](15_vtysh_collection_validation.md) covers application
commands, concurrent invocations, and the upgraded router image.
