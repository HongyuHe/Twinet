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
  --grade-parallel N        Batch-grading concurrency (default: 8).
  --convergence-as N        Solved AS used by the convergence-aware grade probe (default: 3).
  --converge-timeout D      Grade convergence timeout (default: 10m).
  --help                    Show this help.

Required environment:
  TWINET_TOKEN              Agent credential for the target cluster.

The runner refuses an already-running copy of the target lab. It owns only the
lab it starts, records cleanup even when a phase fails, and removes its own
scratch directory before returning.
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

argv=("$0" "$@")
binary="bin/twinet"
manifest="examples/scale"
output=""
submissions=""
grade_parallel=8
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
        --grade-parallel)
            require_value "$@"
            grade_parallel=$2
            shift 2
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
if ! is_positive_integer "$convergence_as"; then
    die_usage "--convergence-as must be a positive integer"
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
submission_count=0
grade_reports=""

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
    python3 - "${scratch_dir}/node_status_before.stdout" "${scratch_dir}/lab_name" <<'PY'
import json
import pathlib
import sys

rows = json.loads(pathlib.Path(sys.argv[1]).read_text())
lab = pathlib.Path(sys.argv[2]).read_text().strip()
owners = []
for row in rows:
    status = row.get("status", {})
    labs = status.get("labs", [])
    if isinstance(labs, list) and lab in labs:
        owners.append(row.get("node", "<unknown>"))
if owners:
    raise SystemExit(
        f"lab {lab!r} already exists on {', '.join(owners)}; refusing to destroy a lab this run did not create"
    )
PY
}

count_submissions() {
    python3 - "$submissions" "${scratch_dir}/submission_count" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
entries = [p for p in root.iterdir() if not p.name.startswith(".")]
if not entries:
    raise SystemExit(f"no submissions found under {root}")
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
        "$cleanup_attempted" "$submission_count" "$grade_reports" "$convergence_as" <<'PY'
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
    "cleanup": phase_ok("cleanup") if cleanup_attempted == "1" else False,
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
    "convergence": decoded_phase("convergence"),
    "grade": grade,
    "cleanup": {
        "attempted": cleanup_attempted == "1",
        "result": decoded_phase("cleanup"),
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
        cleanup_attempted=1
        if ! run_capture cleanup "$binary" destroy -m "$run_manifest" --yes; then
            record_failure "cleanup could not remove the benchmark lab"
        fi
        if ! run_capture node_status_after_cleanup "$binary" --json node status -m "$run_manifest"; then
            record_failure "could not collect per-node status/resources after cleanup"
        elif ! validate_node_status "${scratch_dir}/node_status_after_cleanup.stdout"; then
            record_failure "per-node status/resources after cleanup were incomplete"
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

if ! run_capture convergence "$binary" --json grade run -m "$run_manifest" --as "$convergence_as" \
    --out "${scratch_dir}/convergence_reports" --converge-timeout "$converge_timeout"; then
    record_failure "convergence-aware grade probe did not complete cleanly"
    exit 1
fi
if ! validate_convergence; then
    record_failure "convergence-aware grade probe returned incomplete evidence"
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
        --out "$grade_reports" --parallel "$grade_parallel"; then
        record_failure "batch grading did not complete without infrastructure review"
        exit 1
    fi
    if ! validate_grade_summary; then
        record_failure "batch grading did not write a complete machine-readable summary"
        exit 1
    fi
fi
