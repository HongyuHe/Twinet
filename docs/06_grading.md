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
