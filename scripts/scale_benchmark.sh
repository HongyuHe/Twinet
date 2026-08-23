#!/usr/bin/env bash
# Run the scale manifest as a reproducible, self-cleaning release benchmark.
#
# The report is deliberately assembled from command captures instead of parsed
# terminal prose. A release decision must be traceable to the exact controller,
# manifest, node observations, and commands that produced it.
set -uo pipefail

program_name=$(basename "$0")
repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)

usage() {
    cat <<EOF
Usage: ${program_name} --allow-destructive [options]

Deploy the scale manifest, prove convergence, optionally measure batch grading,
and write one machine-readable JSON evidence record. The deployed lab is always
destroyed before this command exits.

Options:
  --allow-destructive       Required acknowledgement that this deploys and destroys a lab.
  --manifest PATH           Scale manifest directory or twinet.yaml (default: examples/scale).
  --binary PATH             Controller binary (default: bin/twinet).
  --output FILE             Evidence JSON path (default: reports/scale_benchmark/<UTC>.json).
  --submissions DIR         Grade submissions with 'twinet grade batch' and record throughput.
  --compact-attestation F   Signed compact/full equivalence attestation.
  --compact-attestation-key F
                            PEM public key verifying the compact attestation.
  --expected-score-plan F   JSON expected totals/classes/provenance for every submission.
  --expected-submissions N  Required submission count when grading (default: 100).
  --grade-parallel N        Batch-grading concurrency (default: 8).
  --deploy-budget D         Maximum initial deployment duration (default: 10m).
  --grade-budget D          Maximum batch-grading duration (default: 15m).
  --allow-other-labs        Permit unrelated managed labs to remain on the cluster.
  --convergence-as N        Solved AS used by the convergence-aware grade probe (default: 3).
  --converge-timeout D      Grade convergence timeout (default: 10m).
  --help                    Show this help.

Required environment:
  TWINET_TOKEN              Agent credential for the target cluster.

The runner refuses an already-running copy of the target lab. It owns only the
lab it starts, records cleanup even when a phase fails, and removes its own
scratch directory before returning.

When --submissions is set, the archives must be signed benchmark attempts from
'twinet grade benchmark generate'; the runner passes --all-attempts narrowly to
the actual batch command and verifies archive-SHA identities against the plan.
EOF
}

die_usage() {
    printf '%s: %s\n\n' "$program_name" "$1" >&2
    usage >&2
    exit 2
}

require_value() {
    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        die_usage "$1 requires a value"
    fi
}

is_positive_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) [ "$1" -gt 0 ] ;;
    esac
}

is_positive_duration() {
    python3 - "$1" <<'PY'
import re
import sys

match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", sys.argv[1].strip().lower())
raise SystemExit(0 if match and float(match.group(1)) > 0 else 1)
PY
}

argv=("$0" "$@")
binary="bin/twinet"
manifest="examples/scale"
output=""
submissions=""
compact_attestation=""
compact_attestation_key=""
expected_score_plan=""
expected_submissions=100
grade_parallel=8
deploy_budget="10m"
grade_budget="15m"
allow_other_labs=0
convergence_as=3
converge_timeout="10m"
allow_destructive=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allow-destructive)
            allow_destructive=1
            shift
            ;;
        --manifest)
            require_value "$@"
            manifest=$2
            shift 2
            ;;
        --binary)
            require_value "$@"
            binary=$2
            shift 2
            ;;
        --output)
            require_value "$@"
            output=$2
            shift 2
            ;;
        --submissions)
            require_value "$@"
            submissions=$2
            shift 2
            ;;
        --compact-attestation)
            require_value "$@"
            compact_attestation=$2
            shift 2
            ;;
        --compact-attestation-key)
            require_value "$@"
            compact_attestation_key=$2
            shift 2
            ;;
        --expected-score-plan)
            require_value "$@"
            expected_score_plan=$2
            shift 2
            ;;
        --expected-submissions)
            require_value "$@"
            expected_submissions=$2
            shift 2
            ;;
        --grade-parallel)
            require_value "$@"
            grade_parallel=$2
            shift 2
            ;;
        --deploy-budget)
            require_value "$@"
            deploy_budget=$2
            shift 2
            ;;
        --grade-budget)
            require_value "$@"
            grade_budget=$2
            shift 2
            ;;
        --allow-other-labs)
            allow_other_labs=1
            shift
            ;;
        --convergence-as)
            require_value "$@"
            convergence_as=$2
            shift 2
            ;;
        --converge-timeout)
            require_value "$@"
            converge_timeout=$2
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            die_usage "unknown argument $1"
            ;;
    esac
done

if [ "$allow_destructive" -ne 1 ]; then
    die_usage "--allow-destructive is required; this runner deploys and destroys a lab"
fi
if ! is_positive_integer "$grade_parallel"; then
    die_usage "--grade-parallel must be a positive integer"
fi
if ! is_positive_integer "$expected_submissions"; then
    die_usage "--expected-submissions must be a positive integer"
fi
if ! is_positive_integer "$convergence_as"; then
    die_usage "--convergence-as must be a positive integer"
fi
if ! is_positive_duration "$deploy_budget"; then
    die_usage "--deploy-budget must be a positive duration using ms, s, m, or h"
fi
if ! is_positive_duration "$grade_budget"; then
    die_usage "--grade-budget must be a positive duration using ms, s, m, or h"
fi

cd "$repo_root" || {
    printf '%s: cannot enter repository root %s\n' "$program_name" "$repo_root" >&2
    exit 1
}

if [ -d "$manifest" ]; then
    manifest_dir=${manifest%/}
    manifest_file="${manifest_dir}/twinet.yaml"
else
    manifest_file=$manifest
    manifest_dir=$(dirname "$manifest")
fi
if [ ! -f "$manifest_file" ]; then
    die_usage "manifest ${manifest_file} does not exist"
fi
if [ ! -x "$binary" ]; then
    die_usage "controller binary ${binary} is not executable; run make build or pass --binary"
fi
if [ -z "${TWINET_TOKEN:-}" ]; then
    die_usage "TWINET_TOKEN is required to collect cluster evidence"
fi
if [ -n "$submissions" ] && [ ! -d "$submissions" ]; then
    die_usage "submissions directory ${submissions} does not exist"
fi
if [ -n "$submissions" ]; then
    if [ -z "$compact_attestation" ] || [ ! -r "$compact_attestation" ]; then
        die_usage "--compact-attestation is required and must be readable when grading"
    fi
    if [ -z "$compact_attestation_key" ] || [ ! -r "$compact_attestation_key" ]; then
        die_usage "--compact-attestation-key is required and must be readable when grading"
    fi
    if [ -z "$expected_score_plan" ] || [ ! -r "$expected_score_plan" ]; then
        die_usage "--expected-score-plan is required and must be readable when grading"
    fi
fi

if [ -z "$output" ]; then
    output="reports/scale_benchmark/$(date -u +%Y%m%dT%H%M%SZ).json"
fi
output_dir=$(dirname "$output")
if ! mkdir -p "$output_dir"; then
    printf '%s: cannot create evidence directory %s\n' "$program_name" "$output_dir" >&2
    exit 1
fi
output_dir=$(cd "$output_dir" && pwd -P) || exit 1
output="$(cd "$(dirname "$output")" && pwd -P)/$(basename "$output")"
manifest_dir=$(cd "$manifest_dir" && pwd -P) || exit 1
manifest_file="${manifest_dir}/$(basename "$manifest_file")"
binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"

umask 077
scratch_dir=$(mktemp -d "${output_dir}/.scale_benchmark.XXXXXX") || {
    printf '%s: cannot create scratch directory under %s\n' "$program_name" "$output_dir" >&2
    exit 1
}
scratch_dir=$(cd "$scratch_dir" && pwd -P) || exit 1
run_manifest_dir="${scratch_dir}/manifest"
if ! cp -a "$manifest_dir" "$run_manifest_dir"; then
    rm -rf "$scratch_dir"
    printf '%s: cannot copy manifest into isolated benchmark workspace\n' "$program_name" >&2
    exit 1
fi
rm -rf "${run_manifest_dir}/.twinet"
if [ -d "${manifest_dir}/.twinet/pki" ]; then
    if ! mkdir -p "${run_manifest_dir}/.twinet" ||
        ! cp -a "${manifest_dir}/.twinet/pki" "${run_manifest_dir}/.twinet/pki"; then
        rm -rf "$scratch_dir"
        printf '%s: cannot copy controller credentials into benchmark workspace\n' "$program_name" >&2
        exit 1
    fi
fi
if [ "$(basename "$manifest_file")" = "twinet.yaml" ]; then
    run_manifest="$run_manifest_dir"
else
    run_manifest="${run_manifest_dir}/$(basename "$manifest_file")"
fi

start_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start_epoch_ns=$(date +%s%N)
failure=""
deployment_started=0
cleanup_attempted=0
cleanup_succeeded=0
cleanup_recovered_empty=0
submission_count=0
grade_reports=""

cleanup_recovery_attempts=6
cleanup_recovery_wait=3m
cleanup_recovery_command_wait=4m
cleanup_destroy_wait=10m

command_string=""
for argument in "${argv[@]}"; do
    printf -v command_string '%s%q ' "$command_string" "$argument"
done
command_string=${command_string% }

record_failure() {
    if [ -z "$failure" ]; then
        failure=$1
        printf '%s: %s\n' "$program_name" "$failure" >&2
    fi
}

run_capture() {
    local phase=$1
    shift
    local started ended started_epoch_ns ended_epoch_ns status command

    command=""
    for argument in "$@"; do
        printf -v command '%s%q ' "$command" "$argument"
    done
    command=${command% }
    printf '%s\n' "$command" >"${scratch_dir}/${phase}.command"

    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "$started" >"${scratch_dir}/${phase}.started_at"
    started_epoch_ns=$(date +%s%N)
    printf '%s\n' "$started_epoch_ns" >"${scratch_dir}/${phase}.started_epoch_ns"
    if "$@" >"${scratch_dir}/${phase}.stdout" 2>"${scratch_dir}/${phase}.stderr"; then
        status=0
    else
        status=$?
    fi
    ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "$ended" >"${scratch_dir}/${phase}.ended_at"
    ended_epoch_ns=$(date +%s%N)
    printf '%s\n' "$ended_epoch_ns" >"${scratch_dir}/${phase}.ended_epoch_ns"
    printf '%s\n' "$status" >"${scratch_dir}/${phase}.exit_code"
    return "$status"
}

validate_topology() {
    python3 - "${scratch_dir}/topology.stdout" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

try:
    doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"topology JSON cannot be read: {exc}")
if not isinstance(doc, dict):
    raise SystemExit("topology JSON is not an object")
for key in ("lab", "hash", "stats", "devices", "links"):
    if key not in doc:
        raise SystemExit(f"topology JSON lacks required field {key!r}")
if not isinstance(doc["lab"], str) or not doc["lab"]:
    raise SystemExit("topology JSON has no lab name")
if not isinstance(doc["hash"], str) or not doc["hash"]:
    raise SystemExit("topology JSON has no topology hash")
if not isinstance(doc["stats"], dict):
    raise SystemExit("topology JSON has no statistics object")
if not isinstance(doc["devices"], list) or not isinstance(doc["links"], list):
    raise SystemExit("topology JSON has no device/link lists")
pathlib.Path(sys.argv[2]).write_text(doc["lab"])
PY
}

validate_node_status() {
    local file=$1
    python3 - "$file" <<'PY'
import json
import pathlib
import sys

try:
    rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"node status JSON cannot be read: {exc}")
if not isinstance(rows, list) or not rows:
    raise SystemExit("node status JSON contains no nodes")
seen = set()
for row in rows:
    if not isinstance(row, dict):
        raise SystemExit("node status contains a non-object entry")
    node = row.get("node")
    if not isinstance(node, str) or not node:
        raise SystemExit("node status entry has no node name")
    if node in seen:
        raise SystemExit(f"node status repeats {node!r}")
    seen.add(node)
    if row.get("error"):
        raise SystemExit(f"node {node} was not measurable: {row['error']}")
    status = row.get("status")
    if not isinstance(status, dict):
        raise SystemExit(f"node {node} has no status/resource payload")
    for key in ("node", "runtime", "runtime_version", "cpus", "containers"):
        if key not in status:
            raise SystemExit(f"node {node} status lacks required resource field {key!r}")
    if not isinstance(status["cpus"], int) or status["cpus"] < 1:
        raise SystemExit(f"node {node} has invalid CPU capacity")
    if not isinstance(status["containers"], int) or status["containers"] < 0:
        raise SystemExit(f"node {node} has invalid container count")
PY
}

validate_convergence() {
    python3 - "${scratch_dir}/convergence.stdout" <<'PY'
import json
import pathlib
import sys

try:
    doc = json.loads(pathlib.Path(sys.argv[1]).read_text())
except Exception as exc:
    raise SystemExit(f"convergence result is not JSON: {exc}")
if not isinstance(doc, dict):
    raise SystemExit("convergence result is not an object")
for key in ("reports", "duration"):
    if key not in doc:
        raise SystemExit(f"convergence result lacks required field {key!r}")
if not isinstance(doc["reports"], list) or not doc["reports"]:
    raise SystemExit("convergence probe produced no grade report")
PY
}

lab_is_absent() {
    python3 - "${scratch_dir}/node_status_before.stdout" "${scratch_dir}/lab_name" \
        "$allow_other_labs" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = pathlib.Path(sys.argv[2]).read_text().strip()
allow_other_labs = sys.argv[3] == "1"
owners = []
other_labs = set()
for row in rows:
    status = row.get("status", {})
    labs = status.get("labs", [])
    if isinstance(labs, list) and lab in labs:
        owners.append(row.get("node", "<unknown>"))
    if isinstance(labs, list):
        other_labs.update(item for item in labs if isinstance(item, str) and item != lab)
if owners:
    raise SystemExit(
        f"lab {lab!r} already exists on {', '.join(owners)}; refusing to destroy a lab this run did not create"
    )
if other_labs and not allow_other_labs:
    raise SystemExit(
        "cluster is not clean; unrelated managed labs are active: "
        + ", ".join(sorted(other_labs))
        + " (use --allow-other-labs only for an explicitly co-tenant benchmark)"
    )
PY
}

recovery_inventory_is_empty() {
    local file=$1
    python3 - "$file" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text().lstrip()
try:
    report, _ = json.JSONDecoder().raw_decode(raw)
except Exception as exc:
    raise SystemExit(f"recovery report cannot be read: {exc}")
nodes = report.get("nodes") if isinstance(report, dict) else None
if not isinstance(nodes, dict) or not nodes:
    raise SystemExit("recovery report contains no nodes")
for node, status in nodes.items():
    if not isinstance(status, dict):
        raise SystemExit(f"recovery status for {node} is not an object")
    if status.get("consistent") is not True:
        raise SystemExit(f"recovery status for {node} is not consistent")
    for key in (
        "expected_containers", "observed_containers",
        "expected_vnis", "observed_vnis",
        "expected_logical_bindings", "observed_logical_bindings",
        "expected_physical_trunks", "observed_physical_trunks",
    ):
        if key not in status or status[key] != 0:
            raise SystemExit(f"recovery status for {node} has non-empty {key}={status.get(key)!r}")
PY
}

cleanup_status_is_absent() {
    local file=$1
    python3 - "$file" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = pathlib.Path(sys.argv[2]).read_text().strip()
owners = []
for row in rows:
    status = row.get("status", {}) if isinstance(row, dict) else {}
    if lab in status.get("labs", []):
        owners.append(row.get("node", "<unknown>"))
if owners:
    raise SystemExit(f"cleanup left lab {lab!r} active on {', '.join(owners)}")
PY
}

cleanup_lab() {
    local attempt phase lab_name
    local -a recover_args
    lab_name=$(<"${scratch_dir}/lab_name")
    cleanup_attempted=1
    if run_capture cleanup_destroy_1 timeout --signal=TERM --kill-after=30s \
        "$cleanup_destroy_wait" "$binary" destroy -m "$run_manifest" --lab "$lab_name" --yes; then
        cleanup_succeeded=1
        printf '%s\n' cleanup_destroy_1 >"${scratch_dir}/cleanup_result_phase"
        return 0
    fi

    for ((attempt = 1; attempt <= cleanup_recovery_attempts; attempt++)); do
        phase="cleanup_recover_join_${attempt}"
        recover_args=(
            timeout --signal=TERM --kill-after=30s "$cleanup_recovery_command_wait"
            "$binary" --json recover -m "$run_manifest" --strategy rollback
            --wait "$cleanup_recovery_wait"
        )
        if [ "$attempt" -gt 1 ]; then
            phase="cleanup_recover_takeover_${attempt}"
            recover_args+=(--takeover)
        fi
        run_capture "$phase" "${recover_args[@]}" || true
        if recovery_inventory_is_empty "${scratch_dir}/${phase}.stdout" 2>/dev/null; then
            cleanup_recovered_empty=1
        fi
        if run_capture "cleanup_destroy_$((attempt + 1))" \
            timeout --signal=TERM --kill-after=30s "$cleanup_destroy_wait" \
            "$binary" destroy -m "$run_manifest" --lab "$lab_name" --yes; then
            cleanup_succeeded=1
            printf 'cleanup_destroy_%s\n' "$((attempt + 1))" >"${scratch_dir}/cleanup_result_phase"
            return 0
        fi
        if [ "$cleanup_recovered_empty" -eq 1 ]; then
            cleanup_succeeded=1
            printf '%s\n' "$phase" >"${scratch_dir}/cleanup_result_phase"
            return 0
        fi
        # A disconnected deploy can spend tens of seconds quiescing in-flight
        # runtime calls before its lease becomes recoverable. Do not burn every
        # bounded takeover attempt during that legitimate cancellation window.
        sleep 15
    done
    return 1
}

interval_within_budget() {
    local start_phase=$1
    local end_phase=$2
    local budget=$3
    python3 - "${scratch_dir}/${start_phase}.started_epoch_ns" \
        "${scratch_dir}/${end_phase}.ended_epoch_ns" "$budget" <<'PY'
import pathlib
import re
import sys

started = int(pathlib.Path(sys.argv[1]).read_text().strip())
ended = int(pathlib.Path(sys.argv[2]).read_text().strip())
raw = sys.argv[3].strip().lower()
match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", raw)
if not match:
    raise SystemExit(f"invalid duration budget {raw!r}; use ms, s, m, or h")
scale = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]
budget = float(match.group(1)) * scale
elapsed = (ended - started) / 1_000_000_000
if elapsed > budget:
    raise SystemExit(f"{elapsed:.3f}s exceeded the {budget:.3f}s budget")
PY
}

count_submissions() {
    python3 - "$submissions" "${scratch_dir}/submission_count" "$expected_submissions" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
entries = [
    p for p in root.iterdir()
    if not p.name.startswith(".")
    and (p.is_dir() or p.name.endswith(".tar.gz") or p.name.endswith(".tgz"))
]
if not entries:
    raise SystemExit(f"no submissions found under {root}")
expected = int(sys.argv[3])
if len(entries) != expected:
    raise SystemExit(
        f"found {len(entries)} submissions under {root}, expected exactly {expected}"
    )
pathlib.Path(sys.argv[2]).write_text(str(len(entries)))
PY
}

validate_grade_summary() {
    python3 - "${grade_reports}/summary.json" "$submission_count" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = int(sys.argv[2])
try:
    doc = json.loads(path.read_text())
except Exception as exc:
    raise SystemExit(f"grade summary cannot be read: {exc}")
if not isinstance(doc, dict):
    raise SystemExit("grade summary is not an object")
if not isinstance(doc.get("reports"), list):
    raise SystemExit("grade summary has no reports list")
if doc.get("count") != expected:
    raise SystemExit(
        f"grade summary count {doc.get('count')!r} does not match {expected} supplied submissions"
    )
for report in doc["reports"]:
    if not isinstance(report, dict):
        raise SystemExit("grade summary contains a non-object report")
    if report.get("needs_review") or report.get("error"):
        raise SystemExit(
            f"submission {report.get('submission', '<unknown>')} requires infrastructure review"
        )
    if not isinstance(report.get("total"), (int, float)):
        raise SystemExit(
            f"submission {report.get('submission', '<unknown>')} has no numeric total"
        )
PY
}

validate_expected_score_plan() {
    python3 - "${grade_reports}/summary.json" "$expected_score_plan" "$submission_count" <<'PY'
import json
import math
import pathlib
import re
import sys

summary_path = pathlib.Path(sys.argv[1])
plan_path = pathlib.Path(sys.argv[2])
expected_count = int(sys.argv[3])
try:
    summary = json.loads(summary_path.read_text())
    plan = json.loads(plan_path.read_text())
except Exception as exc:
    raise SystemExit(f"cannot read expected-score evidence: {exc}")
if not isinstance(plan, dict) or not isinstance(plan.get("archives"), dict):
    raise SystemExit("expected score plan must contain an archives object keyed by SHA-256")
if plan.get("schema_version") != 1:
    raise SystemExit("expected score plan has an unsupported schema_version")
for key in ("topology_hash", "rubric_hash", "image_lock", "mutation_suite_sha256", "grader_source", "reference_archive_sha256"):
    if not isinstance(plan.get(key), str) or not plan[key]:
        raise SystemExit(f"expected score plan lacks {key}")
for key in ("mutation_suite_sha256", "grader_source", "reference_archive_sha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", plan[key]):
        raise SystemExit(f"expected score plan has invalid {key}")
expected_hash = plan.get("equivalence_audit_hash")
if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
    raise SystemExit("expected score plan has an invalid equivalence_audit_hash")
entries = plan["archives"]
if len(entries) != expected_count:
    raise SystemExit(f"expected score plan has {len(entries)} archives, want {expected_count}")
reports = summary.get("reports")
if not isinstance(reports, list) or len(reports) != expected_count:
    raise SystemExit(f"grade summary has {len(reports) if isinstance(reports, list) else 'no'} reports, want {expected_count}")

def score_class(report):
    total = report.get("total")
    maximum = report.get("max_total")
    if not isinstance(total, (int, float)) or not isinstance(maximum, (int, float)):
        raise SystemExit(f"{report.get('submission', '<unknown>')}: non-numeric total/max_total")
    if maximum <= 0 or total <= 0:
        return "zero"
    if math.isclose(float(total), float(maximum), rel_tol=0, abs_tol=1e-6):
        return "full"
    return "partial"

def check_status(report, expected):
    question_id = expected.get("question_id")
    check_id = expected.get("check_id")
    check_index = expected.get("check_index")
    want = expected.get("status")
    if not isinstance(question_id, str) or not isinstance(check_id, str) or not isinstance(check_index, int) or not isinstance(want, str):
        raise SystemExit("expected_checks contains an invalid check identity")
    questions = report.get("questions")
    if not isinstance(questions, list):
        raise SystemExit(f"{report.get('submission', '<unknown>')}: no questions in report")
    question = next((q for q in questions if isinstance(q, dict) and q.get("id") == question_id), None)
    if question is None:
        raise SystemExit(f"{report.get('submission', '<unknown>')}: missing question {question_id}")
    results = question.get("results")
    if not isinstance(results, list) or check_index < 0 or check_index >= len(results):
        raise SystemExit(f"{report.get('submission', '<unknown>')}: missing check index {question_id}/{check_id}[{check_index}]")
    result = results[check_index]
    if not isinstance(result, dict) or result.get("check") != check_id or result.get("status") != want:
        got = result.get("status") if isinstance(result, dict) else None
        raise SystemExit(
            f"{report.get('submission', '<unknown>')}: {question_id}/{check_id}[{check_index}] "
            f"status={got!r}, want {want!r}"
        )

seen_archives = set()
seen_identities = set()
observed_hashes = set()
for report in reports:
    if not isinstance(report, dict):
        raise SystemExit("grade summary contains a non-object report")
    if report.get("needs_review") or report.get("error"):
        raise SystemExit(f"submission {report.get('submission', '<unknown>')} requires review")
    archive = report.get("archive_sha256")
    attempt = report.get("attempt")
    submission = report.get("submission")
    asn = report.get("as")
    if not isinstance(archive, str) or not re.fullmatch(r"[0-9a-f]{64}", archive):
        raise SystemExit(f"{submission!r}: report lacks exact archive_sha256")
    if not isinstance(attempt, str) or not attempt:
        raise SystemExit(f"{submission!r}: benchmark report lacks a signed attempt")
    identity = (submission, attempt, asn)
    if identity in seen_identities:
        raise SystemExit(f"duplicate benchmark report identity {identity!r}")
    if archive in seen_archives:
        raise SystemExit(f"duplicate benchmark report archive {archive}")
    seen_identities.add(identity)
    seen_archives.add(archive)
    expected = entries.get(archive)
    if not isinstance(expected, dict):
        raise SystemExit(f"report archive {archive} is absent from expected score plan")
    for field, actual in (("submission", submission), ("attempt", attempt), ("as", asn)):
        if expected.get(field) != actual:
            raise SystemExit(f"{archive}: {field}={actual!r}, want {expected.get(field)!r}")
    if report.get("harness_type") != "compact-synthetic-warm":
        raise SystemExit(f"{submission}: harness provenance {report.get('harness_type')!r} is not compact warm")
    for field, plan_field in (
        ("manifest_hash", "topology_hash"),
        ("rubric_hash", "rubric_hash"),
        ("image_lock", "image_lock"),
        ("grader_source", "grader_source"),
    ):
        if report.get(field) != plan.get(plan_field):
            raise SystemExit(f"{submission}: {field}={report.get(field)!r}, want plan {plan_field}={plan.get(plan_field)!r}")
    audit_hash = report.get("equivalence_audit_hash")
    if not isinstance(audit_hash, str) or not audit_hash:
        raise SystemExit(f"{submission}: equivalence audit hash is missing")
    observed_hashes.add(audit_hash)
    if audit_hash != expected_hash:
        raise SystemExit(f"{submission}: equivalence audit hash is mismatched")
    actual_class = score_class(report)
    if actual_class != expected.get("expected_total_class"):
        raise SystemExit(f"{submission}: total class {actual_class!r}, want {expected.get('expected_total_class')!r}")
    expected_total = expected.get("expected_total")
    if expected_total is not None:
        actual_total = report.get("total")
        if not isinstance(expected_total, (int, float)) or not math.isclose(float(actual_total), float(expected_total), rel_tol=0, abs_tol=1e-6):
            raise SystemExit(f"{submission}: total={actual_total!r}, want {expected_total!r}")
    checks = expected.get("expected_checks")
    if not isinstance(checks, list) or not checks:
        raise SystemExit(f"{archive}: expected score plan has no check expectations")
    for expected_check in checks:
        check_status(report, expected_check)

if set(entries) != seen_archives:
    raise SystemExit("grade reports and expected score plan have different archive SHA-256 identities")
if len(observed_hashes) != 1:
    raise SystemExit("benchmark reports do not share one equivalence audit hash")
if observed_hashes != {expected_hash}:
    raise SystemExit("benchmark reports do not carry the plan's equivalence audit hash")
PY
}

manifest_hash=$(
    python3 - "$manifest_dir" "$manifest_file" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
manifest = pathlib.Path(sys.argv[2]).resolve()
if manifest.is_relative_to(root):
    files = sorted(p for p in root.rglob("*.yaml") if ".twinet" not in p.parts)
else:
    files = [manifest]
if not files:
    raise SystemExit("no YAML files found for manifest fingerprint")
digest = hashlib.sha256()
for path in files:
    digest.update(str(path.relative_to(root) if path.is_relative_to(root) else path.name).encode())
    digest.update(b"\0")
    digest.update(path.read_bytes())
    digest.update(b"\0")
print(digest.hexdigest())
PY
) || {
    rm -rf "$scratch_dir"
    printf '%s: cannot calculate manifest fingerprint\n' "$program_name" >&2
    exit 1
}

source_revision=$(git rev-parse HEAD 2>/dev/null) || {
    rm -rf "$scratch_dir"
    printf '%s: cannot determine source revision\n' "$program_name" >&2
    exit 1
}
git_status=$(git status --porcelain 2>/dev/null) || {
    rm -rf "$scratch_dir"
    printf '%s: cannot determine source worktree state\n' "$program_name" >&2
    exit 1
}

write_report() {
    local end_at end_epoch_ns
    end_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    end_epoch_ns=$(date +%s%N)
    python3 - "$output" "$scratch_dir" "$manifest_file" "$manifest_hash" \
        "$source_revision" "$git_status" "$command_string" "$start_at" "$end_at" \
        "$start_epoch_ns" "$end_epoch_ns" "$failure" "$deployment_started" \
        "$cleanup_attempted" "$submission_count" "$grade_reports" "$convergence_as" \
        "$deploy_budget" "$grade_budget" "$allow_other_labs" "$expected_submissions" \
        "$cleanup_succeeded" "$cleanup_recovered_empty" <<'PY'
import json
import pathlib
import sys

(
    output,
    scratch,
    manifest_file,
    manifest_hash,
    source_revision,
    source_status,
    command,
    started_at,
    ended_at,
    started_epoch_ns,
    ended_epoch_ns,
    failure,
    deployment_started,
    cleanup_attempted,
    submission_count,
    grade_reports,
    convergence_as,
    deploy_budget,
    grade_budget,
    allow_other_labs,
    expected_submissions,
    cleanup_succeeded,
    cleanup_recovered_empty,
) = sys.argv[1:]

root = pathlib.Path(scratch)

def text(path):
    p = root / path
    return p.read_text() if p.exists() else ""

def phase(name):
    code = text(f"{name}.exit_code").strip()
    if not code:
        return None
    try:
        exit_code = int(code)
    except ValueError:
        exit_code = None
    result = {
        "command": text(f"{name}.command").strip(),
        "started_at": text(f"{name}.started_at").strip(),
        "ended_at": text(f"{name}.ended_at").strip(),
        "exit_code": exit_code,
        "stdout": text(f"{name}.stdout"),
        "stderr": text(f"{name}.stderr"),
    }
    try:
        start = int(text(f"{name}.started_epoch_ns").strip())
        end = int(text(f"{name}.ended_epoch_ns").strip())
        result["duration_seconds"] = (end - start) / 1_000_000_000
    except ValueError:
        result["duration_seconds"] = None
    return result

def decoded_phase(name):
    p = phase(name)
    if p is None:
        return None
    try:
        p["json"] = json.loads(p["stdout"])
    except json.JSONDecodeError:
        pass
    return p

def json_file(path):
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None

def phase_ok(name):
    p = phase(name)
    return p is not None and p["exit_code"] == 0

def interval_seconds(start_name, end_name):
    try:
        start = int(text(f"{start_name}.started_epoch_ns").strip())
        end = int(text(f"{end_name}.ended_epoch_ns").strip())
        return (end - start) / 1_000_000_000
    except ValueError:
        return None

topology_phase = decoded_phase("topology")
topology = topology_phase.get("json", {}) if topology_phase else {}
devices = topology.get("devices", []) if isinstance(topology, dict) else []
links = topology.get("links", []) if isinstance(topology, dict) else []
nodes = {}
ases = {}
for device in devices if isinstance(devices, list) else []:
    if not isinstance(device, dict):
        continue
    node = device.get("node")
    device_id = device.get("id")
    asn = device.get("as")
    if isinstance(node, str) and node:
        nodes.setdefault(node, {"devices": 0, "ases": set()})
        nodes[node]["devices"] += 1
        if isinstance(asn, int) and asn:
            nodes[node]["ases"].add(asn)
    if isinstance(device_id, str):
        ases[device_id] = node

link_counts = {
    "total": 0,
    "inter_as": 0,
    "cross_node": 0,
    "cross_node_inter_as": 0,
}
for link in links if isinstance(links, list) else []:
    if not isinstance(link, dict):
        continue
    link_counts["total"] += 1
    inter_as = bool(link.get("inter_as"))
    if inter_as:
        link_counts["inter_as"] += 1
    endpoints = [link.get("a"), link.get("b")]
    device_nodes = []
    for endpoint in endpoints:
        if isinstance(endpoint, str):
            device_nodes.append(ases.get(endpoint.split(":", 1)[0]))
    cross = len(device_nodes) == 2 and all(device_nodes) and device_nodes[0] != device_nodes[1]
    if cross:
        link_counts["cross_node"] += 1
        if inter_as:
            link_counts["cross_node_inter_as"] += 1

placement = {
    node: {"devices": values["devices"], "ases": sorted(values["ases"])}
    for node, values in sorted(nodes.items())
}

required = {
    "binary_version": phase_ok("binary_version"),
    "topology": phase_ok("topology"),
    "node_status_before": phase_ok("node_status_before"),
    "underlay_preflight": phase_ok("underlay_preflight"),
    "deploy": phase_ok("deploy"),
    "convergence": phase_ok("convergence"),
    "node_status_after_deploy": phase_ok("node_status_after_deploy"),
    "cleanup": cleanup_succeeded == "1" if cleanup_attempted == "1" else False,
    "node_status_after_cleanup": phase_ok("node_status_after_cleanup") if cleanup_attempted == "1" else False,
}
if submission_count != "0":
    required["grade"] = phase_ok("grade")
missing = sorted(name for name, ok in required.items() if not ok)

grade_phase = decoded_phase("grade")
grade = None
if submission_count != "0":
    duration = grade_phase.get("duration_seconds") if grade_phase else 0
    if not isinstance(duration, (int, float)) or duration <= 0:
        duration = 0
    grade = {
        "submissions": int(submission_count),
        "duration_seconds": duration,
        "throughput_submissions_per_hour": (int(submission_count) * 3600 / duration) if duration > 0 else None,
        "reports_dir": grade_reports,
        "summary": json_file(pathlib.Path(grade_reports, "summary.json")),
        "result": grade_phase,
    }

cleanup_attempts = {
    path.name.removesuffix(".exit_code"): decoded_phase(path.name.removesuffix(".exit_code"))
    for path in sorted(root.glob("cleanup_*.exit_code"))
}
cleanup_result_phase = text("cleanup_result_phase").strip()

try:
    total_duration = (int(ended_epoch_ns) - int(started_epoch_ns)) / 1_000_000_000
except ValueError:
    total_duration = None

report = {
    "schema_version": 1,
    "command": command,
    "started_at": started_at,
    "ended_at": ended_at,
    "duration_seconds": total_duration,
    "source": {
        "revision": source_revision,
        "worktree_dirty": bool(source_status),
        "worktree_status": source_status,
        "binary_version": text("binary_version.stdout").strip(),
    },
    "manifest": {
        "path": manifest_file,
        "sha256": manifest_hash,
        "topology_hash": topology.get("hash") if isinstance(topology, dict) else None,
    },
    "topology": {
        "stats": topology.get("stats") if isinstance(topology, dict) else None,
        "placement": placement,
        "links": link_counts,
    },
    "nodes": {
        "before": decoded_phase("node_status_before"),
        "after_deploy": decoded_phase("node_status_after_deploy"),
        "after_cleanup": decoded_phase("node_status_after_cleanup"),
    },
    "deploy": decoded_phase("deploy"),
    "budgets": {
        "deploy": deploy_budget,
        "grade": grade_budget,
        "expected_submissions": int(expected_submissions),
        "allow_other_labs": allow_other_labs == "1",
    },
    "acceptance": {
        "deploy_and_convergence_seconds": interval_seconds("deploy", "convergence"),
        "grade_seconds": interval_seconds("grade", "grade") if submission_count != "0" else None,
    },
    "convergence": decoded_phase("convergence"),
    "grade": grade,
    "cleanup": {
        "attempted": cleanup_attempted == "1",
        "succeeded": cleanup_succeeded == "1",
        "recovered_empty": cleanup_recovered_empty == "1",
        "result": cleanup_attempts.get(cleanup_result_phase),
        "attempts": cleanup_attempts,
    },
    "required_measurements": required,
    "missing_measurements": missing,
    "result": {
        "passed": not failure and not missing,
        "failure": failure or None,
    },
}
pathlib.Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
}

finish() {
    local original_status=$?
    trap - EXIT INT TERM

    if [ "$deployment_started" -eq 1 ]; then
        if ! cleanup_lab; then
            record_failure "cleanup could not remove the benchmark lab"
        fi
        if ! run_capture node_status_after_cleanup "$binary" --json node status -m "$run_manifest"; then
            record_failure "could not collect per-node status/resources after cleanup"
        elif ! validate_node_status "${scratch_dir}/node_status_after_cleanup.stdout"; then
            record_failure "per-node status/resources after cleanup were incomplete"
        elif ! cleanup_status_is_absent "${scratch_dir}/node_status_after_cleanup.stdout"; then
            record_failure "benchmark lab remained active after cleanup"
        fi
    fi

    if ! write_report; then
        record_failure "could not write machine-readable benchmark evidence"
    fi
    rm -rf "$scratch_dir"
    printf '%s: evidence written to %s\n' "$program_name" "$output" >&2

    if [ -n "$failure" ]; then
        exit 1
    fi
    exit "$original_status"
}

trap finish EXIT
trap 'exit 130' INT TERM

if ! run_capture binary_version "$binary" version; then
    record_failure "could not collect binary version"
    exit 1
fi
if [ -z "$(tr -d '[:space:]' <"${scratch_dir}/binary_version.stdout")" ]; then
    record_failure "binary version command returned no version"
    exit 1
fi

if ! run_capture topology "$binary" --json inspect -m "$run_manifest" --links; then
    record_failure "could not collect expanded topology and placement"
    exit 1
fi
if ! validate_topology; then
    record_failure "expanded topology lacks a hash, counts, placement, or links"
    exit 1
fi

if ! run_capture node_status_before "$binary" --json node status -m "$run_manifest"; then
    record_failure "could not collect per-node status/resources before deployment"
    exit 1
fi
if ! validate_node_status "${scratch_dir}/node_status_before.stdout"; then
    record_failure "per-node status/resources before deployment were incomplete"
    exit 1
fi
if ! lab_is_absent; then
    record_failure "benchmark target is not a clean lab"
    exit 1
fi

if ! run_capture underlay_preflight "$binary" node check -m "$run_manifest"; then
    record_failure "underlay preflight could not establish the required MTU path"
    exit 1
fi

deployment_started=1
if ! run_capture deploy "$binary" deploy -m "$run_manifest" --solve --quiet; then
    record_failure "scale deployment did not converge"
    exit 1
fi
if ! interval_within_budget deploy deploy "$deploy_budget"; then
    record_failure "scale deployment exceeded the ${deploy_budget} acceptance budget"
    exit 1
fi

if ! run_capture convergence "$binary" --json grade run -m "$run_manifest" --as "$convergence_as" \
    --out "${scratch_dir}/convergence_reports" --converge-timeout "$converge_timeout"; then
    record_failure "convergence-aware grade probe did not complete cleanly"
    exit 1
fi
if ! validate_convergence; then
    record_failure "convergence-aware grade probe returned incomplete evidence"
    exit 1
fi
if ! interval_within_budget deploy convergence "$deploy_budget"; then
    record_failure "scale deployment and convergence exceeded the ${deploy_budget} acceptance budget"
    exit 1
fi

if ! run_capture node_status_after_deploy "$binary" --json node status -m "$run_manifest"; then
    record_failure "could not collect per-node status/resources after deployment"
    exit 1
fi
if ! validate_node_status "${scratch_dir}/node_status_after_deploy.stdout"; then
    record_failure "per-node status/resources after deployment were incomplete"
    exit 1
fi

if [ -n "$submissions" ]; then
    if ! count_submissions; then
        record_failure "could not count supplied submissions"
        exit 1
    fi
    submission_count=$(cat "${scratch_dir}/submission_count")
    grade_reports="${output%.json}.grade_reports"
    if ! mkdir -p "$grade_reports"; then
        record_failure "could not create grading evidence directory"
        exit 1
    fi
    if ! run_capture grade "$binary" grade batch -m "$run_manifest" --submissions "$submissions" \
        --out "$grade_reports" --parallel "$grade_parallel" --all-attempts \
        --compact-attestation "$compact_attestation" \
        --compact-attestation-key "$compact_attestation_key"; then
        record_failure "batch grading did not complete without infrastructure review"
        exit 1
    fi
    if ! interval_within_budget grade grade "$grade_budget"; then
        record_failure "batch grading exceeded the ${grade_budget} acceptance budget"
        exit 1
    fi
    if ! validate_grade_summary; then
        record_failure "batch grading did not write a complete machine-readable summary"
        exit 1
    fi
    if ! validate_expected_score_plan; then
        record_failure "batch grading reports did not match compact attestation provenance and expected scores"
        exit 1
    fi
fi
