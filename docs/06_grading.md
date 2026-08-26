# 06 — Autograding

> **Documentation status: shipped grading modes and evidence boundaries.**
> Timing and throughput are measurements only when explicitly linked to
> [09 — Implementation status](09_status.md); they are not estimates,
> acceptance claims, or promises for a different cluster.

## Shipped commands and modes

| Command | Purpose | Isolation boundary |
|---|---|---|
| `twinet grade run` | Diagnose one or more ASes as they currently run | Reads the deployed lab; not a class-marking mode |
| `twinet grade class` | Mark submitted work one system at a time in the class lab | Holds repair, restores a blank student system, and keeps the rest at reference |
| `twinet grade batch` | Grade each submission in a disposable harness | A unique lab/harness per submission; capacity-safe waves |
| `twinet grade checks` | List registered checks | Source registry |
| `twinet grade validate` | Validate a rubric | Authoring gate |

`grade class` and `grade run` obtain node holds because automatic repair could
otherwise rewire or re-render a device while it is being assessed. A lost hold
is a quarantine condition, not a successful grade. `grade batch` schedules
workloads against live inventory and retries work that was not admitted rather
than treating host pressure as a student result.

## Observation and scheduling

One grade builds a shared passive observation snapshot: normalized kernel/NOS
state, OSPF/BGP/RPKI facts, OVS inventory, and directly relevant service state.
The native commands that survey a device come from its own NOS provider, so a
BIRD router is read with `birdc` and never with `vtysh`. Identical passive reads
are deduplicated; unavailable state remains an infrastructure error. Active
delivery probes are never cached.

A check whose subject the device's NOS cannot express returns `unsupported`
rather than an error or a failure. It is excluded from the question's
weighting, exactly like a check that could not run, and the question is marked
`needs_review` with a note naming the NOS and the missing capability -- so a
smaller denominator is always visible. A check that reaches a verdict from
fewer witnesses than it was designed around records `reduced_evidence`, which
marks the question for review when it awarded marks. Neither is ever a zero,
and neither disappears from the report.

The runner speculatively schedules all questions and checks concurrently;
dependencies still control scoring and skipped feedback. It serializes only
declared shared probe counters, captures, ports, interfaces, or endpoints,
preserving counter attribution and deterministic report order.
Reports include machine-readable `phase_timings` and `observation_snapshot`
records, per-check cache/exec accounting, lock waits, and a scheduler critical
path. `grade run --check-parallel` bounds total/passive checks; the smaller
`--active-check-parallel` pool protects node runtime pressure.

### How many systems are read at once

`grade run --parallel` is an override, not the default. With it omitted the
outer width is derived from the deployment: the devices each target reads
(its own AS, its neighbour routers, the exchange route servers it peers with,
and the services it is cabled to), where the placer put them, and what each
node agent advertises as its `exec_probe` budget minus what it is already
serving. Grading takes at most half of that budget; the rest belongs to the
node's own reconciler, semantic audit, control sidecars, and any other lab.

Two constraints bind, and both are properties of the deployment rather than of
the request:

- **Per node.** One grade occupies up to one batched-survey fan-out plus its
  in-flight checks on each node it reads, so the width is what the advertised
  budget divides by, not the number of submissions.
- **Per router.** A router's evidence is a full control-plane dump served by
  one daemon in one container, so simultaneous readers of the same router each
  wait for all the others. At most two grades read one router at a time. Hosts
  and services answer cheap commands and are not capped this way.

Targets on independent nodes that share no router are still read together. A
node that cannot be asked is treated as having room for a single system, never
as an idle one. The chosen width and the binding reason are printed before the
run starts; an explicit `--parallel` above the derived width is printed as an
`AUDIT:` line, and checks that run out of time under it are still quarantined
rather than marked.

This replaces a fixed default of eight, which read all eight student systems of
the canonical lab against the single agent that holds all 212 of its
containers: every check exhausted its two-minute budget and all eight reports
were quarantined, while the same lab graded 10.00/10.00 one system at a time.
Canonical placement remains `pack-by-as`: locality is worth having, and a
grading command that only works on a spread lab would still be broken.

The compact `harness.Options.Synthetic` substrate keeps the target AS and IXPs
intact while collapsing each other retained AS to one deterministic
policy/origin router. It is enabled only by a signed release attestation keyed
to the topology hash, rubric hash, compiler version, exact grader-source
digest, and verified image lock; an unattested development lab falls back to a
full isolated harness. The source digest is a deterministic SHA-256 over
`cmd/**/*.go`, `internal/**/*.go`, `go.mod`, and `go.sum`, so source edits and
untracked compiled files receive a distinct identity while documentation does
not. Commit and version remain signed audit provenance. Full
topology fallback remains available through `grade batch --full-harness`,
particularly for disputed marks. The attestation's
`harness.AuditEquivalence` suite must include reference and wrong-answer
fixtures; a compact result is not release evidence by itself.

`grade attest compact` requires a separate, existing submission-signing
private key to derive and re-sign each mutation. It writes a sibling
`<attestation>.evidence/` directory containing the exact suite, reference and
mutation bundles, plus deterministic per-case full/compact report paths,
SHA-256 digests, and timings. The signed artifact binds suite/reference
digests and runtime compact admission verifies the retained evidence. One
isolated full warm harness and one compact warm harness are reset between
cases; a reset or reference-peer undo failure taints and destroys the slot,
causing the audit to fail rather than reusing state.

Release attestations and scale benchmarks read `TWINET_TOKEN` only from the
environment (normally populated from a root-readable credential file). Never
place a bearer token in a command flag: process listings and captured command
traces expose argv.

Harness deployment still verifies rendered files, platform addresses, default
routes, and local readiness. Cross-AS BGP/forwarding is deliberately checked
after the fenced transaction commits, by a whole solved-reference baseline
gate before any submission is loaded, followed by convergence and grading
witnesses. Those routes form concurrently and are not a safe synchronous
transaction predicate. A failed baseline is infrastructure review, never a
student mark; this does not relax any delivery or anti-cheating check.

Ordinary `grade batch` accepts one final submission per group/AS and withdraws
duplicates as contested. Release benchmarks are the narrow exception:
`grade benchmark generate` emits signed archives with unique `attempt`
identities, and `grade batch --all-attempts` is required before repeated
group/AS work is accepted. Each benchmark report retains its attempt and exact
archive SHA-256; the expected-score plan maps that SHA to a score class and
designated check outcomes. This is not a late-work policy or an ordinary
gradebook mode.

For release capacity evidence, run `grade benchmark generate` with the signed
reference archive, mutation suite, and submission key. It cycles the reference
and every deterministic wrong-answer mutation into byte-identical tarballs and
writes an archive-SHA-keyed expected score/check-class plan. Pass that plan,
the compact attestation/key, and the generated directory to
`scripts/scale_benchmark.sh`; its real `grade batch --all-attempts` invocation
requires exactly the planned attempts, one shared attestation hash, compact
warm provenance, no review rows, and the planned score/check classes.

The plan also binds the mutation-suite SHA-256, image lock, topology/rubric
hashes, and grader-source digest. Generation requires the exact non-empty
compact attestation hash expected during the later batch; the runner rejects
any report whose topology, rubric, image, source, or attestation provenance
does not match.

Every emitted grade report carries the build-stamped deterministic
`grader_source` digest. Controller version/commit remain human provenance only
and cannot satisfy the benchmark plan source binding.

The generator, attestation command, and scale runner intentionally have no
token flag in their release invocation examples. Export `TWINET_TOKEN` only
for the process that runs them (from a protected credential file); do not put
it in argv, shell history, report command strings, or logs.

## What a result contains

Checks are registered Go functions that return structured evidence. Reports are
written in JSON, text, and CSV forms; the evidence names the observed
routing/configuration/data-plane fact rather than only a pass/fail string.
The check registry includes the course and advanced-network checks represented
by the bundled rubrics.

This is a source-level statement. It does not claim a future HTML dashboard,
replay bundle, synthetic GoBGP neighbour system, or other historical design
proposal as shipped.

## Multicast and hijacks

The multicast example has PIM/IGMP-oriented rendering and grading checks. The
RPKI exercise has a deliberate hijack path, and the behaviour command can start
and stop declared `bgp-hijack` perturbations. These features are not described
as missing.

The live discrimination evidence for the advanced MPLS/VRF and multicast
examples is **measured** and recorded in
[09 — Remaining work](09_status.md#remaining-work). Source support alone does
not establish every course's acceptance criteria.

## Measured grading evidence

**Measured:** [09 — Measurements](09_status.md#measurements) is the canonical
record for the current class and batch runs, including the topology, convergence
budget, quarantines, concurrency, and the fact that an overloaded batch run did
not complete every harness. Use that table rather than a rounded “minutes per
student” claim.

In particular, the documented class run is a measured run in a named
environment, and the documented batch numbers are capacity-qualified. Neither
is evidence that a hundred submissions can be graded within a target window.

## Targets and historical design

<!-- benchmark: target -->
Synthetic-neighbour grading, broader discrimination suites, faster harness
reduction, and any target for a class-sized deadline remain **targets** until a
new measured run is recorded in [09](09_status.md). The original description
of GoBGP test doubles, fixed polling intervals, and expected single-digit
minutes is retained only as historical design context and is not a shipped
claim.
